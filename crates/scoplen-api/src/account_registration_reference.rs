// SPDX-License-Identifier: Apache-2.0
//! Scripted registration/receipt peer for D-128 and D-129 transaction acceptance.
//!
//! This slice verifies real Account and Device signatures and models atomic business state,
//! digest retention and complete restart images. It is not HTTP transport, durable database
//! storage, an audit chain or rate admission. Callers admit work before invoking this peer.
//! Password login and Device admission are separate reference work.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    sync::{Arc, Mutex, MutexGuard},
};

use scoplen_crypto::{
    AccountRequestKind, AccountRequestProof, AccountRequestSignatureInput, DeviceCertificate,
    SecretBytes, SecretVec, account_capability_digest, account_used_id_digest,
    canonical_device_public_key, random_key, validate_server_origin,
};
use uuid::Uuid;

use crate::{
    ApiContractError, ErrorCode, ProblemDetails,
    account_admission::{
        ACCOUNT_ATTEMPT_LIFETIME_MS, AccountAdmissionCodecError, AccountBootstrapSnapshot,
        AccountCommittedConfirmation, AccountPersonalBootstrap, AccountPersonalEpoch,
        AccountRegistrationPayload, AccountRegistrationRequest, AccountRequestChallengeRequest,
        AccountRequestChallengeResponse, AccountRequestIntent, MAX_ACCOUNT_ENTRY_PROBLEM_BYTES,
    },
};

/// The admitted default deployment-lifetime Account-id row ceiling.
pub const DEFAULT_USED_ACCOUNT_ID_CEILING: u64 = 1_048_576;
const MAX_CHALLENGES: usize = 16_384;

/// One fault at the next eligible reference transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReferenceRegistrationFault {
    /// Storage failed before any business COMMIT was sent.
    BeforeCommit,
    /// Mandatory audit failed; its transaction rolls back.
    Audit,
    /// A business COMMIT was sent but rolled back, without a confirmed acknowledgement.
    UnknownRollback,
    /// A business COMMIT succeeded but its acknowledgement was unavailable.
    UnknownCommitted,
    /// The transaction committed but the caller received no response.
    LostResponse,
}

/// Content-free fixture failures, never negative evidence for a missing receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ReferenceRegistrationError {
    /// Invalid request or fixture configuration.
    #[error("invalid Account registration request")]
    InvalidRequest,
    /// A complete request exceeds its encoded or decoded bound.
    #[error("Account registration request too large")]
    TooLarge,
    /// Challenge, origin, exact receipt or cryptographic possession did not match.
    #[error("Account authentication required")]
    AuthenticationRequired,
    /// New registration is disabled; exact confirmation remains available.
    #[error("Account registration is disabled")]
    RegistrationDisabled,
    /// A current identity or retained Account-id digest conflicts.
    #[error("Account registration denied")]
    RegistrationDenied,
    /// A live transient table is full.
    #[error("Account request capacity unavailable")]
    RateLimited,
    /// The permanent Account-id collection has no room for the single required row.
    #[error("Account registration quota exceeded")]
    QuotaExceeded,
    /// Confirmed precommit failure, maintenance, or an unconfirmed non-business transaction.
    #[error("Account registration storage unavailable")]
    StorageUnavailable,
    /// A business COMMIT was attempted; the outcome remains unknown.
    #[error("Account registration outcome unknown")]
    CommitOutcomeUnknown,
    /// No HTTP response reached the caller.
    #[error("Account registration response lost")]
    ResponseLost,
}

impl ReferenceRegistrationError {
    /// Render the bounded D-128 problem, or no problem for a lost response.
    ///
    /// # Errors
    /// Rejects an invalid RFC 9457 instance through the existing common validator.
    pub fn problem(self, instance: &str) -> Result<Option<ProblemDetails>, ApiContractError> {
        let (status, code, changed, retryable) = match self {
            Self::InvalidRequest => (400, "auth.invalid_request", false, false),
            Self::TooLarge => (413, "auth.invalid_request", false, false),
            Self::AuthenticationRequired => (401, "auth.authentication_required", false, false),
            Self::RegistrationDisabled => (403, "policy.denied", false, false),
            Self::RegistrationDenied => (409, "auth.registration_denied", false, false),
            Self::RateLimited => (429, "auth.rate_limited", false, true),
            Self::QuotaExceeded => (413, "auth.quota_exceeded", false, false),
            Self::StorageUnavailable => (503, "auth.storage_unavailable", false, true),
            Self::CommitOutcomeUnknown => (503, "auth.commit_outcome_unknown", true, false),
            Self::ResponseLost => return Ok(None),
        };
        if instance.len() > MAX_ACCOUNT_ENTRY_PROBLEM_BYTES {
            return Err(ApiContractError::InvalidProblem(
                "Account entry problem exceeds its bound".into(),
            ));
        }
        let problem = ProblemDetails::new(
            ErrorCode::new(code)?,
            status,
            "Account registration was not confirmed",
            "Retain the original business bytes and private keys. An unknown result requires explicit exact-receipt confirmation with a fresh challenge.",
            instance,
            changed,
            retryable,
        )?;
        let encoded = serde_json::to_vec(&problem).map_err(|_| {
            ApiContractError::InvalidProblem("Account entry problem encoding failed".into())
        })?;
        if encoded.len() > MAX_ACCOUNT_ENTRY_PROBLEM_BYTES {
            return Err(ApiContractError::InvalidProblem(
                "Account entry problem exceeds its bound".into(),
            ));
        }
        Ok(Some(problem))
    }
}

impl From<AccountAdmissionCodecError> for ReferenceRegistrationError {
    fn from(value: AccountAdmissionCodecError) -> Self {
        match value {
            AccountAdmissionCodecError::TooLarge => Self::TooLarge,
            AccountAdmissionCodecError::Binding => Self::AuthenticationRequired,
            _ => Self::InvalidRequest,
        }
    }
}

/// One route-specific confirmation, with submit's 201 or confirmation's 200 status.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReferenceRegistrationResult {
    /// Exactly 201 for a new business mutation, or 200 for an exact retained receipt.
    pub status: u16,
    /// The bounded response contains no current authorization or key material.
    pub confirmation: AccountCommittedConfirmation,
}

#[derive(Clone)]
struct Challenge {
    kind: AccountRequestKind,
    intent: AccountRequestIntent,
    operation_id: Uuid,
    device_id: Uuid,
    nonce_digest: SecretBytes<32>,
    expires_at_ms: u64,
}

/// Exact immutable receipt material for owned fixture inspection, without current authority.
#[derive(Clone)]
pub struct ReferenceRegistrationReceipt {
    /// Exact original operation result.
    pub confirmation: AccountCommittedConfirmation,
    /// Original Account signing root, independent of later current Account state.
    pub account_root: [u8; 32],
    /// Original normalized Device signing public point.
    pub signing_key: [u8; 65],
    /// Original normalized independent Device KEM public point.
    pub kem_key: [u8; 65],
    /// Trusted commit time; there is no receipt expiry.
    pub committed_at_ms: u64,
}

impl fmt::Debug for ReferenceRegistrationReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ReferenceRegistrationReceipt([REDACTED])")
    }
}

/// Protected current credential/bootstrap material for owned fixture inspection.
#[derive(Clone)]
pub struct ReferenceRegistrationAccountMaterial {
    /// The sole stored password verifier, never the transient `AuthSecret`.
    pub verifier: SecretBytes<32>,
    /// Complete exact protected encrypted bootstrap.
    pub bootstrap: SecretVec,
    /// Scripted current Account availability, independent of historical confirmation.
    pub active: bool,
}

impl fmt::Debug for ReferenceRegistrationAccountMaterial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ReferenceRegistrationAccountMaterial([REDACTED])")
    }
}

#[derive(Clone)]
struct Account {
    username: String,
    vault_id: Uuid,
    device_id: Uuid,
    operation_id: Uuid,
    verifier: SecretBytes<32>,
    bootstrap: SecretVec,
    active: bool,
}

#[derive(Clone)]
struct State {
    origin: String,
    high_water_ms: u64,
    used_id_ceiling: u64,
    used_ids: BTreeSet<[u8; 32]>,
    accounts: BTreeMap<Uuid, Account>,
    usernames: BTreeMap<String, Uuid>,
    vaults: BTreeMap<Uuid, Uuid>,
    devices: BTreeMap<Uuid, Uuid>,
    receipts: BTreeMap<Uuid, ReferenceRegistrationReceipt>,
    challenges: BTreeMap<[u8; 32], Challenge>,
    challenge_expiry: BTreeSet<(u64, [u8; 32])>,
    next_cleanup_ms: u64,
    registration_open: bool,
    maintenance: bool,
    registrations: u64,
    denials: u64,
    ceiling_changes: u64,
    fault: Option<ReferenceRegistrationFault>,
}

impl State {
    fn observe_time(&mut self, observed: u64) -> u64 {
        self.high_water_ms = self.high_water_ms.max(observed);
        self.high_water_ms
    }

    fn retire_challenges(&mut self, now: u64) -> Result<(), ReferenceRegistrationError> {
        if now < self.next_cleanup_ms {
            return Ok(());
        }
        self.next_cleanup_ms =
            now.checked_add(1_000).ok_or(ReferenceRegistrationError::StorageUnavailable)?;
        for _ in 0..100 {
            let Some(&(expiry, id)) = self.challenge_expiry.first() else { break };
            if expiry > now {
                break;
            }
            self.challenge_expiry.remove(&(expiry, id));
            self.challenges.remove(&id);
        }
        Ok(())
    }

    fn consume(&mut self, id: &[u8; 32]) {
        if let Some(challenge) = self.challenges.remove(id) {
            self.challenge_expiry.remove(&(challenge.expires_at_ms, *id));
        }
    }
}

/// Complete opaque fixture image; restoring cannot omit digests while retaining business data.
#[derive(Clone)]
pub struct ReferenceRegistrationImage(State);

impl fmt::Debug for ReferenceRegistrationImage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ReferenceRegistrationImage([REDACTED])")
    }
}

/// Content-free fixture counters; success counts exclude terminal confirmations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReferenceRegistrationSummary {
    /// Current Account rows.
    pub accounts: usize,
    /// Current Personal vault ownership rows.
    pub vaults: usize,
    /// Current Device ownership rows.
    pub devices: usize,
    /// Immutable live-Account receipts.
    pub receipts: usize,
    /// Outstanding request challenges, excluding retired or consumed rows.
    pub challenges: usize,
    /// Deployment-lifetime Account-id digest rows.
    pub used_account_ids: usize,
    /// Admitted durable row ceiling.
    pub used_id_ceiling: u64,
    /// Content-free warning state at ninety percent and exhaustion.
    pub retention_pressure: ReferenceRetentionPressure,
    /// Original business success events.
    pub registrations: u64,
    /// Confirmed denial transactions.
    pub denials: u64,
    /// Confirmed explicit ceiling changes.
    pub ceiling_changes: u64,
}

/// The content-free operator warning class for the permanent collection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReferenceRetentionPressure {
    /// Registration capacity is below the warning threshold.
    Available,
    /// At least ninety percent of the admitted ceiling is retained.
    Warning,
    /// No further registration fits; exact confirmation remains available.
    Exhausted,
}

/// Shared serialized fixture storage for multiple independently cloned API peers.
#[derive(Clone)]
pub struct ReferenceAccountRegistrationPeer(Arc<Mutex<State>>);

impl fmt::Debug for ReferenceAccountRegistrationPeer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ReferenceAccountRegistrationPeer([REDACTED])")
    }
}

impl ReferenceAccountRegistrationPeer {
    /// Create a fixture with the accepted default permanent Account-id ceiling.
    ///
    /// # Errors
    /// Rejects a noncanonical trusted origin.
    pub fn new(origin: &str) -> Result<Self, ReferenceRegistrationError> {
        Self::with_retention_ceiling(origin, DEFAULT_USED_ACCOUNT_ID_CEILING)
    }

    /// Select a smaller positive fixture ceiling to exercise exact capacity boundaries.
    ///
    /// # Errors
    /// Rejects a noncanonical origin, zero ceiling or checked application-byte overflow.
    pub fn with_retention_ceiling(
        origin: &str,
        ceiling: u64,
    ) -> Result<Self, ReferenceRegistrationError> {
        validate_server_origin(origin).map_err(|_| ReferenceRegistrationError::InvalidRequest)?;
        validate_ceiling(ceiling)?;
        Ok(Self(Arc::new(Mutex::new(State {
            origin: origin.into(),
            high_water_ms: 0,
            used_id_ceiling: ceiling,
            used_ids: BTreeSet::new(),
            accounts: BTreeMap::new(),
            usernames: BTreeMap::new(),
            vaults: BTreeMap::new(),
            devices: BTreeMap::new(),
            receipts: BTreeMap::new(),
            challenges: BTreeMap::new(),
            challenge_expiry: BTreeSet::new(),
            next_cleanup_ms: 0,
            registration_open: true,
            maintenance: false,
            registrations: 0,
            denials: 0,
            ceiling_changes: 0,
            fault: None,
        }))))
    }

    fn lock(&self) -> Result<MutexGuard<'_, State>, ReferenceRegistrationError> {
        self.0.lock().map_err(|_| ReferenceRegistrationError::StorageUnavailable)
    }

    /// Take one consistent image of all business, transient and retained-id fixture state.
    ///
    /// # Errors
    /// Fails closed if a previous fixture worker poisoned storage.
    pub fn checkpoint(&self) -> Result<ReferenceRegistrationImage, ReferenceRegistrationError> {
        let mut state = self.lock()?.clone();
        state.fault = None;
        Ok(ReferenceRegistrationImage(state))
    }

    /// Restore a complete image without changing its admitted origin or ceiling.
    ///
    /// # Errors
    /// Rejects configuration mismatch; no partial business-only restore is accepted.
    pub fn restore(
        image: ReferenceRegistrationImage,
        origin: &str,
        ceiling: u64,
    ) -> Result<Self, ReferenceRegistrationError> {
        if image.0.origin != origin || image.0.used_id_ceiling != ceiling {
            return Err(ReferenceRegistrationError::InvalidRequest);
        }
        Ok(Self(Arc::new(Mutex::new(image.0))))
    }

    /// Inspect fixed fixture counts without exposing identity or credential records.
    ///
    /// # Errors
    /// Fails closed if fixture storage is poisoned.
    pub fn summary(&self) -> Result<ReferenceRegistrationSummary, ReferenceRegistrationError> {
        let state = self.lock()?;
        Ok(ReferenceRegistrationSummary {
            accounts: state.accounts.len(),
            vaults: state.vaults.len(),
            devices: state.devices.len(),
            receipts: state.receipts.len(),
            challenges: state.challenges.len(),
            used_account_ids: state.used_ids.len(),
            used_id_ceiling: state.used_id_ceiling,
            retention_pressure: retention_pressure(&state),
            registrations: state.registrations,
            denials: state.denials,
            ceiling_changes: state.ceiling_changes,
        })
    }

    /// Inspect the retained collection's sole 32-byte row values in fixture acceptance tests.
    ///
    /// # Errors
    /// Fails closed if fixture storage is poisoned.
    pub fn retained_account_id_rows(&self) -> Result<Vec<[u8; 32]>, ReferenceRegistrationError> {
        Ok(self.lock()?.used_ids.iter().copied().collect())
    }

    /// Inspect an immutable receipt in an owned fixture; this is not an HTTP read endpoint.
    ///
    /// # Errors
    /// Fails closed if fixture storage is poisoned.
    pub fn retained_receipt(
        &self,
        operation_id: Uuid,
    ) -> Result<Option<ReferenceRegistrationReceipt>, ReferenceRegistrationError> {
        Ok(self.lock()?.receipts.get(&operation_id).cloned())
    }

    /// Inspect current protected fixture material and prove its removal after Account deletion.
    ///
    /// # Errors
    /// Fails closed if fixture storage is poisoned.
    pub fn account_material(
        &self,
        account_id: Uuid,
    ) -> Result<Option<ReferenceRegistrationAccountMaterial>, ReferenceRegistrationError> {
        Ok(self.lock()?.accounts.get(&account_id).map(|account| {
            ReferenceRegistrationAccountMaterial {
                verifier: account.verifier.clone(),
                bootstrap: account.bootstrap.clone(),
                active: account.active,
            }
        }))
    }

    /// Script one eligible transaction fault without replacing cryptographic checks.
    ///
    /// # Errors
    /// Fails closed if fixture storage is poisoned.
    pub fn set_fault(
        &self,
        fault: ReferenceRegistrationFault,
    ) -> Result<(), ReferenceRegistrationError> {
        self.lock()?.fault = Some(fault);
        Ok(())
    }

    /// Disable only new registration; challenge issuance and exact confirmation remain available.
    ///
    /// # Errors
    /// Fails closed if fixture storage is poisoned.
    pub fn set_registration_enabled(
        &self,
        enabled: bool,
    ) -> Result<(), ReferenceRegistrationError> {
        self.lock()?.registration_open = enabled;
        Ok(())
    }

    /// Quiesce this fixture's modeled API writers for explicit deployment maintenance.
    ///
    /// # Errors
    /// Fails closed if fixture storage is poisoned.
    pub fn set_maintenance(&self, enabled: bool) -> Result<(), ReferenceRegistrationError> {
        self.lock()?.maintenance = enabled;
        Ok(())
    }

    /// Raise the admitted ceiling while writers are quiesced, preserving every retained row.
    ///
    /// # Errors
    /// Rejects live writers, reductions, invalid arithmetic and scripted audit/store failure.
    pub fn increase_retention_ceiling(
        &self,
        ceiling: u64,
    ) -> Result<(), ReferenceRegistrationError> {
        validate_ceiling(ceiling)?;
        let mut state = self.lock()?;
        if !state.maintenance || ceiling < state.used_id_ceiling {
            return Err(ReferenceRegistrationError::InvalidRequest);
        }
        if ceiling == state.used_id_ceiling {
            return Ok(());
        }
        if state.fault.take().is_some() {
            return Err(ReferenceRegistrationError::StorageUnavailable);
        }
        let events = state
            .ceiling_changes
            .checked_add(1)
            .ok_or(ReferenceRegistrationError::StorageUnavailable)?;
        state.used_id_ceiling = ceiling;
        state.ceiling_changes = events;
        Ok(())
    }

    /// Reserve externally modeled pre-upgrade Account ids before enabling new registration.
    ///
    /// This owned fixture control models the retention migration only; it does not construct
    /// legacy password credentials or substitute for production migration of current rows.
    /// Only digests enter the image. All API writers must be quiesced, and the whole supplied
    /// batch either fits or leaves every prior row unchanged.
    /// # Errors
    /// Rejects live writers, invalid ids, capacity overflow and scripted storage/audit failure.
    pub fn reserve_upgrade_account_ids(
        &self,
        account_ids: &[Uuid],
    ) -> Result<(), ReferenceRegistrationError> {
        let digests = account_ids
            .iter()
            .copied()
            .map(account_used_id_digest)
            .collect::<Result<BTreeSet<_>, _>>()
            .map_err(|_| ReferenceRegistrationError::InvalidRequest)?;
        let mut state = self.lock()?;
        if !state.maintenance {
            return Err(ReferenceRegistrationError::InvalidRequest);
        }
        let additions = digests.difference(&state.used_ids).count();
        let required = state
            .used_ids
            .len()
            .checked_add(additions)
            .and_then(|count| u64::try_from(count).ok())
            .ok_or(ReferenceRegistrationError::StorageUnavailable)?;
        if required > state.used_id_ceiling {
            return Err(ReferenceRegistrationError::QuotaExceeded);
        }
        if state.fault.take().is_some() {
            return Err(ReferenceRegistrationError::StorageUnavailable);
        }
        state.used_ids.extend(digests);
        Ok(())
    }

    /// Exercise one-use challenge issuance with OS randomness and bounded expiry maintenance.
    ///
    /// The supplied clock is read after acquiring storage and again before committing.
    /// # Errors
    /// Rejects invalid syntax, maintenance, full challenge capacity and randomness/time failure.
    pub fn challenge(
        &self,
        body: &[u8],
        mut clock: impl FnMut() -> u64,
    ) -> Result<AccountRequestChallengeResponse, ReferenceRegistrationError> {
        let request = AccountRequestChallengeRequest::from_json(body)?;
        let mut state = self.lock()?;
        let created = state.observe_time(clock());
        if state.maintenance {
            return Err(ReferenceRegistrationError::StorageUnavailable);
        }
        state.retire_challenges(created)?;
        if state.challenges.len() >= MAX_CHALLENGES {
            return Err(ReferenceRegistrationError::RateLimited);
        }
        let attempt_id =
            random_key().map_err(|_| ReferenceRegistrationError::StorageUnavailable)?;
        let nonce = random_key().map_err(|_| ReferenceRegistrationError::StorageUnavailable)?;
        let expires_at_ms = created
            .checked_add(ACCOUNT_ATTEMPT_LIFETIME_MS)
            .ok_or(ReferenceRegistrationError::StorageUnavailable)?;
        let response = AccountRequestChallengeResponse { attempt_id, nonce, expires_at_ms };
        response.to_json()?;
        let id = account_capability_digest(response.attempt_id.as_bytes());
        if state.challenges.contains_key(&id) || state.observe_time(clock()) >= expires_at_ms {
            return Err(ReferenceRegistrationError::StorageUnavailable);
        }
        state.challenges.insert(
            id,
            Challenge {
                kind: request.kind,
                intent: request.intent,
                operation_id: request.operation_id,
                device_id: request.device_id,
                nonce_digest: SecretBytes::new(account_capability_digest(
                    response.nonce.as_bytes(),
                )),
                expires_at_ms,
            },
        );
        state.challenge_expiry.insert((expires_at_ms, id));
        Ok(response)
    }

    /// Submit a real signed registration or confirm only its exact immutable receipt.
    ///
    /// Transport/rate admission precedes this call. The clock is reread under the lock before
    /// any mutation. A missing receipt never falls through to registration.
    /// # Errors
    /// Rejects syntax, fresh challenge/possession, uniqueness, retention capacity or scripted faults.
    pub fn register(
        &self,
        body: &[u8],
        mut clock: impl FnMut() -> u64,
    ) -> Result<ReferenceRegistrationResult, ReferenceRegistrationError> {
        let (request, payload) = AccountRegistrationRequest::decode_for_authentication(body)?;
        let mut state = self.lock()?;
        let now = state.observe_time(clock());
        if state.maintenance {
            return Err(ReferenceRegistrationError::StorageUnavailable);
        }
        state.retire_challenges(now)?;
        let id = account_capability_digest(request.attempt_id.as_bytes());
        let challenge =
            state.challenges.get(&id).filter(|challenge| challenge.expires_at_ms > now).cloned();
        let fault = state.fault.take();
        let Some(challenge) = challenge else {
            return deny(
                &mut state,
                None,
                fault,
                ReferenceRegistrationError::AuthenticationRequired,
            );
        };
        if challenge.kind != AccountRequestKind::Register
            || challenge.intent != request.intent
            || challenge.operation_id != payload.operation_id
            || challenge.device_id != payload.device_id
            || payload.origin != state.origin
            || challenge.nonce_digest
                != SecretBytes::new(account_capability_digest(request.nonce.as_bytes()))
        {
            return deny(
                &mut state,
                Some(id),
                fault,
                ReferenceRegistrationError::AuthenticationRequired,
            );
        }
        let receipt = state.receipts.get(&payload.operation_id).cloned();
        let Ok(proof) = verify_registration(&state.origin, &request, &payload, receipt.as_ref())
        else {
            return deny(
                &mut state,
                Some(id),
                fault,
                ReferenceRegistrationError::AuthenticationRequired,
            );
        };
        let committed_at_ms = state.observe_time(clock());
        if challenge.expires_at_ms <= committed_at_ms {
            return deny(
                &mut state,
                Some(id),
                fault,
                ReferenceRegistrationError::AuthenticationRequired,
            );
        }
        let transaction =
            VerifiedRegistration { request, payload, proof, id, fault, committed_at_ms };
        if transaction.request.intent == AccountRequestIntent::Confirm {
            match receipt {
                Some(receipt) => confirm_registration(&mut state, transaction, receipt),
                None => deny(
                    &mut state,
                    Some(id),
                    fault,
                    ReferenceRegistrationError::AuthenticationRequired,
                ),
            }
        } else {
            submit_registration(&mut state, transaction)
        }
    }

    /// Script Account suspension without changing the narrow historical receipt result.
    ///
    /// # Errors
    /// Rejects an unknown current Account or poisoned fixture storage.
    pub fn set_account_active(
        &self,
        account_id: Uuid,
        active: bool,
    ) -> Result<(), ReferenceRegistrationError> {
        self.lock()?
            .accounts
            .get_mut(&account_id)
            .ok_or(ReferenceRegistrationError::InvalidRequest)?
            .active = active;
        Ok(())
    }

    /// Delete every modeled current Account record and receipt while retaining only its digest.
    ///
    /// This is an owned fixture control, not a production Account-deletion endpoint.
    /// # Errors
    /// Rejects poisoned storage; unknown Accounts are already absent.
    pub fn delete_account(&self, account_id: Uuid) -> Result<(), ReferenceRegistrationError> {
        let mut state = self.lock()?;
        let Some(account) = state.accounts.remove(&account_id) else { return Ok(()) };
        state.usernames.remove(&account.username);
        state.vaults.remove(&account.vault_id);
        state.devices.remove(&account.device_id);
        state.receipts.remove(&account.operation_id);
        let challenges: Vec<_> = state
            .challenges
            .iter()
            .filter(|(_, challenge)| {
                challenge.device_id == account.device_id
                    || challenge.operation_id == account.operation_id
            })
            .map(|(id, _)| *id)
            .collect();
        for id in challenges {
            state.consume(&id);
        }
        Ok(())
    }
}

struct VerifiedProof {
    digest: [u8; 32],
    certificate: DeviceCertificate,
}

struct VerifiedRegistration {
    request: AccountRegistrationRequest,
    payload: AccountRegistrationPayload,
    proof: VerifiedProof,
    id: [u8; 32],
    fault: Option<ReferenceRegistrationFault>,
    committed_at_ms: u64,
}

fn verify_registration(
    origin: &str,
    request: &AccountRegistrationRequest,
    payload: &AccountRegistrationPayload,
    receipt: Option<&ReferenceRegistrationReceipt>,
) -> Result<VerifiedProof, ReferenceRegistrationError> {
    payload.validate()?;
    let stable =
        AccountRequestSignatureInput::new(AccountRequestKind::Register, request.payload.as_bytes())
            .map_err(|_| ReferenceRegistrationError::InvalidRequest)?;
    let digest = stable.request_digest(&request.account_signature);
    let proof = AccountRequestProof::new(
        AccountRequestKind::Register,
        request.intent,
        origin,
        request.attempt_id.as_bytes(),
        request.nonce.as_bytes(),
        payload.operation_id,
        payload.device_id,
        &digest,
    )
    .map_err(|_| ReferenceRegistrationError::InvalidRequest)?;
    let certificate = DeviceCertificate::decode(&payload.device_certificate)
        .map_err(|_| ReferenceRegistrationError::InvalidRequest)?;
    let (root, signing) = if request.intent == AccountRequestIntent::Confirm {
        let receipt = receipt.ok_or(ReferenceRegistrationError::AuthenticationRequired)?;
        (&receipt.account_root, receipt.signing_key.as_slice())
    } else {
        (&payload.account_signing_public_key, certificate.signing_public_key.as_slice())
    };
    stable
        .verify(root, &request.account_signature)
        .map_err(|_| ReferenceRegistrationError::AuthenticationRequired)?;
    proof
        .verify(signing, &request.device_proof)
        .map_err(|_| ReferenceRegistrationError::AuthenticationRequired)?;
    Ok(VerifiedProof { digest, certificate })
}

fn confirm_registration(
    state: &mut State,
    transaction: VerifiedRegistration,
    receipt: ReferenceRegistrationReceipt,
) -> Result<ReferenceRegistrationResult, ReferenceRegistrationError> {
    let VerifiedRegistration { request, proof, id, fault, .. } = transaction;
    if SecretBytes::new(proof.digest) != SecretBytes::new(receipt.confirmation.request_digest)
        || receipt
            .confirmation
            .validate_for_request(
                AccountRequestKind::Register,
                request.payload.as_bytes(),
                &request.account_signature,
            )
            .is_err()
    {
        return deny(state, Some(id), fault, ReferenceRegistrationError::AuthenticationRequired);
    }
    receipt.confirmation.to_json()?;
    if matches!(
        fault,
        Some(
            ReferenceRegistrationFault::BeforeCommit
                | ReferenceRegistrationFault::Audit
                | ReferenceRegistrationFault::UnknownRollback
        )
    ) {
        return Err(ReferenceRegistrationError::StorageUnavailable);
    }
    state.consume(&id);
    match fault {
        Some(ReferenceRegistrationFault::UnknownCommitted) => {
            Err(ReferenceRegistrationError::StorageUnavailable)
        }
        Some(ReferenceRegistrationFault::LostResponse) => {
            Err(ReferenceRegistrationError::ResponseLost)
        }
        _ => Ok(ReferenceRegistrationResult { status: 200, confirmation: receipt.confirmation }),
    }
}

fn submit_registration(
    state: &mut State,
    transaction: VerifiedRegistration,
) -> Result<ReferenceRegistrationResult, ReferenceRegistrationError> {
    let VerifiedRegistration {
        payload,
        proof: VerifiedProof { digest, certificate },
        id,
        fault,
        committed_at_ms: commit_time,
        ..
    } = transaction;
    if !state.registration_open {
        return deny(state, Some(id), fault, ReferenceRegistrationError::RegistrationDisabled);
    }
    let used_id = account_used_id_digest(payload.account_id)
        .map_err(|_| ReferenceRegistrationError::InvalidRequest)?;
    if state.usernames.contains_key(&payload.username)
        || state.accounts.contains_key(&payload.account_id)
        || state.vaults.contains_key(&payload.personal_vault_id)
        || state.devices.contains_key(&payload.device_id)
        || state.receipts.contains_key(&payload.operation_id)
        || state.used_ids.contains(&used_id)
    {
        return deny(state, Some(id), fault, ReferenceRegistrationError::RegistrationDenied);
    }
    let required = u64::try_from(state.used_ids.len())
        .ok()
        .and_then(|count| count.checked_add(1))
        .ok_or(ReferenceRegistrationError::StorageUnavailable)?;
    if required > state.used_id_ceiling {
        return deny(state, Some(id), fault, ReferenceRegistrationError::QuotaExceeded);
    }
    let bootstrap = registration_snapshot(&payload)?.to_cbor()?;
    let confirmation = AccountCommittedConfirmation {
        kind: AccountRequestKind::Register,
        operation_id: payload.operation_id,
        request_digest: digest,
        account_id: payload.account_id,
        personal_vault_id: payload.personal_vault_id,
        device_id: payload.device_id,
        admitted_key_revision: 1,
    };
    confirmation.to_json()?;
    let receipt = ReferenceRegistrationReceipt {
        confirmation: confirmation.clone(),
        account_root: payload.account_signing_public_key,
        signing_key: canonical_device_public_key(&certificate.signing_public_key)
            .map_err(|_| ReferenceRegistrationError::InvalidRequest)?,
        kem_key: canonical_device_public_key(&certificate.kem_public_key)
            .map_err(|_| ReferenceRegistrationError::InvalidRequest)?,
        committed_at_ms: commit_time,
    };
    if matches!(
        fault,
        Some(ReferenceRegistrationFault::BeforeCommit | ReferenceRegistrationFault::Audit)
    ) {
        return Err(ReferenceRegistrationError::StorageUnavailable);
    }
    if fault == Some(ReferenceRegistrationFault::UnknownRollback) {
        return Err(ReferenceRegistrationError::CommitOutcomeUnknown);
    }
    let registrations =
        state.registrations.checked_add(1).ok_or(ReferenceRegistrationError::StorageUnavailable)?;
    let account = Account {
        username: payload.username.clone(),
        vault_id: payload.personal_vault_id,
        device_id: payload.device_id,
        operation_id: payload.operation_id,
        verifier: SecretBytes::new(payload.verifier),
        bootstrap: SecretVec::new(bootstrap),
        active: true,
    };
    state.usernames.insert(payload.username, payload.account_id);
    state.vaults.insert(payload.personal_vault_id, payload.account_id);
    state.devices.insert(payload.device_id, payload.account_id);
    state.accounts.insert(payload.account_id, account);
    state.receipts.insert(payload.operation_id, receipt);
    state.used_ids.insert(used_id);
    state.registrations = registrations;
    state.consume(&id);
    match fault {
        Some(ReferenceRegistrationFault::UnknownCommitted) => {
            Err(ReferenceRegistrationError::CommitOutcomeUnknown)
        }
        Some(ReferenceRegistrationFault::LostResponse) => {
            Err(ReferenceRegistrationError::ResponseLost)
        }
        _ => Ok(ReferenceRegistrationResult { status: 201, confirmation }),
    }
}

fn validate_ceiling(ceiling: u64) -> Result<(), ReferenceRegistrationError> {
    if ceiling == 0 || ceiling.checked_mul(32).is_none() {
        return Err(ReferenceRegistrationError::InvalidRequest);
    }
    Ok(())
}

fn retention_pressure(state: &State) -> ReferenceRetentionPressure {
    let count = u64::try_from(state.used_ids.len()).unwrap_or(u64::MAX);
    if count >= state.used_id_ceiling {
        ReferenceRetentionPressure::Exhausted
    } else if count >= state.used_id_ceiling - state.used_id_ceiling / 10 {
        ReferenceRetentionPressure::Warning
    } else {
        ReferenceRetentionPressure::Available
    }
}

fn deny(
    state: &mut State,
    challenge: Option<[u8; 32]>,
    fault: Option<ReferenceRegistrationFault>,
    error: ReferenceRegistrationError,
) -> Result<ReferenceRegistrationResult, ReferenceRegistrationError> {
    if matches!(
        fault,
        Some(
            ReferenceRegistrationFault::BeforeCommit
                | ReferenceRegistrationFault::Audit
                | ReferenceRegistrationFault::UnknownRollback
        )
    ) {
        return Err(ReferenceRegistrationError::StorageUnavailable);
    }
    let denials =
        state.denials.checked_add(1).ok_or(ReferenceRegistrationError::StorageUnavailable)?;
    if let Some(challenge) = challenge {
        state.consume(&challenge);
    }
    state.denials = denials;
    match fault {
        Some(ReferenceRegistrationFault::UnknownCommitted) => {
            Err(ReferenceRegistrationError::StorageUnavailable)
        }
        Some(ReferenceRegistrationFault::LostResponse) => {
            Err(ReferenceRegistrationError::ResponseLost)
        }
        _ => Err(error),
    }
}

fn registration_snapshot(
    payload: &AccountRegistrationPayload,
) -> Result<AccountBootstrapSnapshot, AccountAdmissionCodecError> {
    let snapshot = AccountBootstrapSnapshot {
        origin: payload.origin.clone(),
        username: payload.username.clone(),
        account_id: payload.account_id,
        personal_vault_id: payload.personal_vault_id,
        account_signing_public_key: payload.account_signing_public_key,
        account_kem_public_key: payload.account_kem_public_key,
        credential_generation: 1,
        password_salt: payload.password_salt,
        password_ark: payload.password_ark,
        key_bundle: payload.key_bundle.clone(),
        certificates: vec![payload.device_certificate.clone()],
        revocations: Vec::new(),
        personal: AccountPersonalBootstrap {
            current_epoch: 1,
            rotation_pending: false,
            epochs: vec![AccountPersonalEpoch {
                epoch: 1,
                wrapped_key: payload.personal_wrapped_key,
            }],
        },
    };
    snapshot.validate()?;
    Ok(snapshot)
}
