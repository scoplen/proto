// SPDX-License-Identifier: Apache-2.0
//! Password options/login transactions over the registration peer's owned fixture storage.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    sync::Arc,
};

use scoplen_crypto::{
    AccountProbeKey, PasswordVerifier, SecretBytes, SecretVec, account_bootstrap_digest,
    account_capability_digest, random_key,
};
use uuid::Uuid;

use super::{
    ApiContractError, ErrorCode, ProblemDetails, ReferenceAccountRegistrationPeer,
    ReferenceRegistrationError, ReferenceRegistrationFault as Fault, State,
};
use crate::account_admission::{
    ACCOUNT_ADMISSION_LIFETIME_MS, ACCOUNT_ATTEMPT_LIFETIME_MS, AccountAdmissionCodecError,
    AccountBootstrapSnapshot, AccountPasswordLoginRequest, AccountPasswordLoginResponse,
    AccountPasswordOptionsRequest, AccountPasswordOptionsResponse, MAX_ACCOUNT_ENTRY_PROBLEM_BYTES,
};

const MAX_ATTEMPTS: usize = 16_384;
const MAX_CAPABILITIES: usize = 4_096;
const MAX_ACCOUNT_CAPABILITIES: usize = 4;

/// Current password metadata in an owned fixture, separate from encrypted bootstrap bytes.
#[derive(Clone, Eq, PartialEq)]
pub struct ReferencePasswordCredential {
    /// The current fixed KDF profile; unsupported values are only useful for failure fixtures.
    pub profile: u32,
    /// Current client-generated salt.
    pub salt: [u8; 16],
    /// Positive credential generation matching the complete snapshot.
    pub generation: u64,
    /// The sole persisted SHA-256 password verifier.
    pub verifier: SecretBytes<32>,
}

/// Bound password-attempt fields; the map key is only the attempt-id digest.
///
/// The immutable deployment origin is shared by the complete storage image, not copied per row.
#[derive(Clone, Eq, PartialEq)]
pub struct ReferencePasswordAttempt {
    /// Canonical username selected by the original options request.
    pub username: String,
    /// Fixed profile presented by options.
    pub profile: u32,
    /// Exact options salt, checked again against current credentials during login.
    pub salt: [u8; 16],
    /// Trusted expiry; no raw attempt id or authentication secret is retained.
    pub expires_at_ms: u64,
}

/// Bounded digest-keyed admission binding, without a raw token or snapshot copy.
#[derive(Clone, Eq, PartialEq)]
pub struct ReferenceAdmissionCapability {
    /// Established Account owning the current snapshot.
    pub account_id: Uuid,
    /// Transaction-current credential generation.
    pub credential_generation: u64,
    /// Domain-separated digest of the exact returned complete snapshot.
    pub snapshot_digest: [u8; 32],
    /// Exactly five minutes after capability creation.
    pub expires_at_ms: u64,
    /// Initial single-use state; Device-admission consumption is a separate reference slice.
    pub spent: bool,
}

macro_rules! redacted {
    ($($name:ty),+ $(,)?) => {$(impl fmt::Debug for $name {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str(concat!(stringify!($name), "([REDACTED])"))
        }
    })+};
}
redacted!(ReferencePasswordCredential, ReferencePasswordAttempt, ReferenceAdmissionCapability);

/// Content-free password transaction failures, never a committed Account/Device mutation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ReferencePasswordError {
    /// Invalid request or owned fixture control.
    #[error("invalid Account sign-in request")]
    InvalidRequest,
    /// Complete request exceeds its wire bound.
    #[error("Account sign-in request too large")]
    TooLarge,
    /// All credential, current-state and unusable-attempt authentication denials.
    #[error("Account authentication required")]
    AuthenticationRequired,
    /// A pending rotation or unverified root transition forbids a partial admission bootstrap.
    #[error("Account admission state conflict")]
    AdmissionConflict,
    /// Bounded attempt or capability storage has no currently available slot.
    #[error("Account request capacity unavailable")]
    RateLimited,
    /// Storage, integrity, audit or an unconfirmed capability-only transaction.
    #[error("Account sign-in storage unavailable")]
    StorageUnavailable,
    /// No response reached the caller; no raw capability is returned by the fixture.
    #[error("Account sign-in response lost")]
    ResponseLost,
}

impl ReferencePasswordError {
    /// Render the bounded common denial, or no problem when the response was lost.
    ///
    /// # Errors
    /// Rejects invalid instances and problems exceeding the complete encoded four-KiB bound.
    pub fn problem(self, instance: &str) -> Result<Option<ProblemDetails>, ApiContractError> {
        let (status, code, retryable) = match self {
            Self::InvalidRequest => (400, "auth.invalid_request", false),
            Self::TooLarge => (413, "auth.invalid_request", false),
            Self::AuthenticationRequired => (401, "auth.authentication_required", false),
            Self::AdmissionConflict => (409, "auth.admission_conflict", false),
            Self::RateLimited => (429, "auth.rate_limited", true),
            Self::StorageUnavailable => (503, "auth.storage_unavailable", true),
            Self::ResponseLost => return Ok(None),
        };
        if instance.len() > MAX_ACCOUNT_ENTRY_PROBLEM_BYTES {
            return Err(ApiContractError::InvalidProblem(
                "Account sign-in problem exceeds its bound".into(),
            ));
        }
        let problem = ProblemDetails::new(
            ErrorCode::new(code)?,
            status,
            "Account sign in was not confirmed",
            "Start a fresh password-options attempt before explicitly trying to sign in again.",
            instance,
            false,
            retryable,
        )?;
        if serde_json::to_vec(&problem)
            .map_err(|_| {
                ApiContractError::InvalidProblem("Account sign-in problem encoding failed".into())
            })?
            .len()
            > MAX_ACCOUNT_ENTRY_PROBLEM_BYTES
        {
            return Err(ApiContractError::InvalidProblem(
                "Account sign-in problem exceeds its bound".into(),
            ));
        }
        Ok(Some(problem))
    }
}

impl From<AccountAdmissionCodecError> for ReferencePasswordError {
    fn from(value: AccountAdmissionCodecError) -> Self {
        match value {
            AccountAdmissionCodecError::TooLarge => Self::TooLarge,
            AccountAdmissionCodecError::Binding => Self::AuthenticationRequired,
            _ => Self::InvalidRequest,
        }
    }
}

/// Fixed counters for owned fixture inspection, without any identity or credential value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReferencePasswordSummary {
    /// Retained outstanding password-attempt rows.
    pub attempts: usize,
    /// Retained expiring capability rows.
    pub capabilities: usize,
    /// Original confirmed or scripted committed password-success audit events.
    pub successes: u64,
    /// Committed common-denial audit events.
    pub denials: u64,
}

#[derive(Clone)]
pub(super) struct PasswordState {
    probe: Arc<AccountProbeKey>,
    attempts: BTreeMap<[u8; 32], ReferencePasswordAttempt>,
    attempt_expiry: BTreeSet<(u64, [u8; 32])>,
    capabilities: BTreeMap<[u8; 32], ReferenceAdmissionCapability>,
    capability_expiry: BTreeSet<(u64, [u8; 32])>,
    account_capabilities: BTreeMap<Uuid, BTreeSet<[u8; 32]>>,
    next_cleanup_ms: u64,
    successes: u64,
    denials: u64,
}

impl PasswordState {
    pub(super) fn new() -> Result<Self, ReferenceRegistrationError> {
        let bytes = random_key().map_err(|_| ReferenceRegistrationError::StorageUnavailable)?;
        let probe = AccountProbeKey::new(bytes.as_ref())
            .map_err(|_| ReferenceRegistrationError::StorageUnavailable)?;
        Ok(Self {
            probe: Arc::new(probe),
            attempts: BTreeMap::new(),
            attempt_expiry: BTreeSet::new(),
            capabilities: BTreeMap::new(),
            capability_expiry: BTreeSet::new(),
            account_capabilities: BTreeMap::new(),
            next_cleanup_ms: 0,
            successes: 0,
            denials: 0,
        })
    }

    fn consume_attempt(&mut self, id: &[u8; 32]) {
        if let Some(attempt) = self.attempts.remove(id) {
            self.attempt_expiry.remove(&(attempt.expires_at_ms, *id));
        }
    }

    fn remove_capability(&mut self, id: &[u8; 32]) {
        if let Some(capability) = self.capabilities.remove(id) {
            self.capability_expiry.remove(&(capability.expires_at_ms, *id));
            if let Some(ids) = self.account_capabilities.get_mut(&capability.account_id) {
                ids.remove(id);
                if ids.is_empty() {
                    self.account_capabilities.remove(&capability.account_id);
                }
            }
        }
    }

    fn retire(&mut self, now: u64) -> Result<(), ReferencePasswordError> {
        if now < self.next_cleanup_ms {
            return Ok(());
        }
        self.next_cleanup_ms =
            now.checked_add(1_000).ok_or(ReferencePasswordError::StorageUnavailable)?;
        for _ in 0..100 {
            let attempt = self.attempt_expiry.first().copied();
            let capability = self.capability_expiry.first().copied();
            match (attempt, capability) {
                (Some((expiry, id)), other)
                    if expiry <= now && other.is_none_or(|x| expiry <= x.0) =>
                {
                    self.consume_attempt(&id);
                }
                (_, Some((expiry, id))) if expiry <= now => self.remove_capability(&id),
                _ => break,
            }
        }
        Ok(())
    }

    pub(super) fn remove_account(&mut self, account_id: Uuid, username: &str) {
        let ids = self.account_capabilities.get(&account_id).cloned().unwrap_or_default();
        for id in ids {
            self.remove_capability(&id);
        }
        let attempts: Vec<_> = self
            .attempts
            .iter()
            .filter(|(_, attempt)| attempt.username == username)
            .map(|(id, _)| *id)
            .collect();
        for id in attempts {
            self.consume_attempt(&id);
        }
    }
}

impl ReferenceAccountRegistrationPeer {
    /// Issue indistinguishable fixed-profile options using current or stable synthetic salts.
    ///
    /// Caller-owned source/username admission precedes this reference transaction.
    /// # Errors
    /// Rejects syntax, maintenance, bounded capacity and unconfirmed transient transactions.
    pub fn password_options(
        &self,
        body: &[u8],
        mut clock: impl FnMut() -> u64,
    ) -> Result<AccountPasswordOptionsResponse, ReferencePasswordError> {
        let request = AccountPasswordOptionsRequest::from_json(body)?;
        let mut state = self.lock().map_err(|_| ReferencePasswordError::StorageUnavailable)?;
        let created = state.observe_time(clock());
        if state.maintenance {
            return Err(ReferencePasswordError::StorageUnavailable);
        }
        state.password.retire(created)?;
        if state.password.attempts.len() >= MAX_ATTEMPTS {
            return Err(ReferencePasswordError::RateLimited);
        }
        let salt = match state
            .usernames
            .get(&request.username)
            .and_then(|id| state.accounts.get(id))
            .filter(|a| a.active)
        {
            Some(account) => account.credential.salt,
            None => state
                .password
                .probe
                .synthetic_salt(&state.origin, &request.username)
                .map_err(|_| ReferencePasswordError::StorageUnavailable)?,
        };
        let response = AccountPasswordOptionsResponse {
            attempt_id: random_key().map_err(|_| ReferencePasswordError::StorageUnavailable)?,
            salt,
            expires_at_ms: created
                .checked_add(ACCOUNT_ATTEMPT_LIFETIME_MS)
                .ok_or(ReferencePasswordError::StorageUnavailable)?,
        };
        response.to_json().map_err(|_| ReferencePasswordError::StorageUnavailable)?;
        let id = account_capability_digest(response.attempt_id.as_bytes());
        if state.password.attempts.contains_key(&id)
            || state.observe_time(clock()) >= response.expires_at_ms
        {
            return Err(ReferencePasswordError::StorageUnavailable);
        }
        let fault = state.fault.take();
        if matches!(fault, Some(Fault::BeforeCommit | Fault::Audit | Fault::UnknownRollback)) {
            return Err(ReferencePasswordError::StorageUnavailable);
        }
        state.password.attempts.insert(
            id,
            ReferencePasswordAttempt {
                username: request.username,
                profile: 1,
                salt,
                expires_at_ms: response.expires_at_ms,
            },
        );
        state.password.attempt_expiry.insert((response.expires_at_ms, id));
        transient_result(fault)?;
        Ok(response)
    }

    /// Check a one-use password attempt and atomically return a complete snapshot/capability.
    ///
    /// Takes zeroizing ownership of the complete `AuthSecret` body. This never creates an
    /// Account/Device, ordinary session token or terminal receipt. Device admission is separate.
    /// # Errors
    /// Uses the common denial or no-business-change storage error, without returning a token.
    pub fn password_login(
        &self,
        body: SecretVec,
        mut clock: impl FnMut() -> u64,
    ) -> Result<AccountPasswordLoginResponse, ReferencePasswordError> {
        let request = AccountPasswordLoginRequest::from_json(body.as_bytes())?;
        drop(body);
        let id = account_capability_digest(request.attempt_id.as_bytes());
        let presented = SecretVec::new(request.auth_secret.as_ref().to_vec());
        drop(request);
        let mut state = self.lock().map_err(|_| ReferencePasswordError::StorageUnavailable)?;
        let now = state.observe_time(clock());
        if state.maintenance {
            return Err(ReferencePasswordError::StorageUnavailable);
        }
        state.password.retire(now)?;
        let denial = ReferencePasswordError::AuthenticationRequired;
        let attempt = state.password.attempts.get(&id).filter(|a| a.expires_at_ms > now).cloned();
        let Some(attempt) = attempt else {
            drop(presented);
            return deny_login(&mut state, None, denial);
        };
        let Some(account_id) = authenticate(&state, &attempt, presented)? else {
            return deny_login(&mut state, Some(id), denial);
        };
        let snapshot = match current_snapshot(&state, account_id) {
            Err(conflict @ ReferencePasswordError::AdmissionConflict) => {
                let now = state.observe_time(clock());
                let error = if attempt.expires_at_ms > now { conflict } else { denial };
                return deny_login(&mut state, Some(id), error);
            }
            result => result?,
        };
        if state.password.capabilities.len() >= MAX_CAPABILITIES
            || state
                .password
                .account_capabilities
                .get(&account_id)
                .is_some_and(|ids| ids.len() >= MAX_ACCOUNT_CAPABILITIES)
        {
            return Err(ReferencePasswordError::RateLimited);
        }
        let created = state.observe_time(clock());
        if attempt.expires_at_ms <= created {
            return deny_login(&mut state, Some(id), denial);
        }
        let response = AccountPasswordLoginResponse {
            admission_token: random_key()
                .map_err(|_| ReferencePasswordError::StorageUnavailable)?,
            expires_at_ms: created
                .checked_add(ACCOUNT_ADMISSION_LIFETIME_MS)
                .ok_or(ReferencePasswordError::StorageUnavailable)?,
            snapshot,
        };
        let encoded = SecretVec::new(
            response.to_json().map_err(|_| ReferencePasswordError::StorageUnavailable)?,
        );
        drop(encoded);
        let committed = state.observe_time(clock());
        if attempt.expires_at_ms <= committed {
            return deny_login(&mut state, Some(id), denial);
        }
        if response.expires_at_ms <= committed {
            return Err(ReferencePasswordError::StorageUnavailable);
        }
        commit_login(&mut state, id, account_id, response)
    }

    /// Inspect content-free password state and audit counters in an owned fixture.
    /// # Errors
    /// Fails closed when fixture storage is poisoned.
    pub fn password_summary(&self) -> Result<ReferencePasswordSummary, ReferencePasswordError> {
        let state = self.lock().map_err(|_| ReferencePasswordError::StorageUnavailable)?;
        Ok(ReferencePasswordSummary {
            attempts: state.password.attempts.len(),
            capabilities: state.password.capabilities.len(),
            successes: state.password.successes,
            denials: state.password.denials,
        })
    }

    /// Inspect digest-keyed attempt bindings; no raw attempt or `AuthSecret` field exists.
    /// # Errors
    /// Fails closed when fixture storage is poisoned.
    pub fn password_attempt_rows(
        &self,
    ) -> Result<Vec<([u8; 32], ReferencePasswordAttempt)>, ReferencePasswordError> {
        Ok(self
            .lock()
            .map_err(|_| ReferencePasswordError::StorageUnavailable)?
            .password
            .attempts
            .iter()
            .map(|(id, row)| (*id, row.clone()))
            .collect())
    }

    /// Inspect digest-keyed capability bindings, without tokens or per-capability snapshots.
    /// # Errors
    /// Fails closed when fixture storage is poisoned.
    pub fn admission_capability_rows(
        &self,
    ) -> Result<Vec<([u8; 32], ReferenceAdmissionCapability)>, ReferencePasswordError> {
        Ok(self
            .lock()
            .map_err(|_| ReferencePasswordError::StorageUnavailable)?
            .password
            .capabilities
            .iter()
            .map(|(id, row)| (*id, row.clone()))
            .collect())
    }

    /// Inspect current protected password metadata in an owned fixture, not through HTTP.
    /// # Errors
    /// Rejects an unknown Account or poisoned storage.
    pub fn password_credential(
        &self,
        account_id: Uuid,
    ) -> Result<ReferencePasswordCredential, ReferencePasswordError> {
        self.lock()
            .map_err(|_| ReferencePasswordError::StorageUnavailable)?
            .accounts
            .get(&account_id)
            .map(|a| a.credential.clone())
            .ok_or(ReferencePasswordError::InvalidRequest)
    }

    /// Script current credential/bootstrap changes for race and integrity acceptance.
    ///
    /// This control deliberately permits inconsistent fixture state; it is not a credential-
    /// change endpoint or approval of the separately unfrozen password/root lifecycle.
    /// # Errors
    /// Rejects an unknown Account or poisoned storage.
    pub fn script_password_state(
        &self,
        account_id: Uuid,
        credential: ReferencePasswordCredential,
        bootstrap: SecretVec,
    ) -> Result<(), ReferencePasswordError> {
        let mut state = self.lock().map_err(|_| ReferencePasswordError::StorageUnavailable)?;
        let account =
            state.accounts.get_mut(&account_id).ok_or(ReferencePasswordError::InvalidRequest)?;
        account.credential = credential;
        account.bootstrap = bootstrap;
        Ok(())
    }
}

fn authenticate(
    state: &State,
    attempt: &ReferencePasswordAttempt,
    presented: SecretVec,
) -> Result<Option<Uuid>, ReferencePasswordError> {
    let current = state
        .usernames
        .get(&attempt.username)
        .and_then(|id| state.accounts.get(id).map(|a| (*id, a)))
        .filter(|(_, a)| a.active);
    let verifier = match current {
        Some((_, account)) => account.credential.verifier.clone(),
        None => state
            .password
            .probe
            .synthetic_verifier(&state.origin, &attempt.username)
            .map_err(|_| ReferencePasswordError::StorageUnavailable)?,
    };
    let authenticated = PasswordVerifier::from_bytes(verifier.as_ref())
        .map_err(|_| ReferencePasswordError::StorageUnavailable)?
        .verify(presented)
        .is_ok();
    let Some((id, account)) = current else {
        return Ok(None);
    };
    if !authenticated
        || account.credential.profile != attempt.profile
        || account.credential.salt != attempt.salt
    {
        return Ok(None);
    }
    Ok(Some(id))
}

fn current_snapshot(state: &State, account_id: Uuid) -> Result<SecretVec, ReferencePasswordError> {
    let account =
        state.accounts.get(&account_id).ok_or(ReferencePasswordError::StorageUnavailable)?;
    let snapshot = AccountBootstrapSnapshot::from_cbor(account.bootstrap.as_bytes())
        .map_err(|_| ReferencePasswordError::StorageUnavailable)?;
    if account.credential.profile != 1
        || account.credential.generation == 0
        || snapshot.origin != state.origin
        || snapshot.username != account.username
        || snapshot.account_id != account_id
        || snapshot.personal_vault_id != account.vault_id
        || snapshot.password_salt != account.credential.salt
        || snapshot.credential_generation != account.credential.generation
    {
        return Err(ReferencePasswordError::StorageUnavailable);
    }
    if snapshot.personal.rotation_pending
        || snapshot.account_signing_public_key != account.signing_root
        || snapshot.account_kem_public_key != account.kem_root
    {
        return Err(ReferencePasswordError::AdmissionConflict);
    }
    Ok(account.bootstrap.clone())
}

fn transient_result(fault: Option<Fault>) -> Result<(), ReferencePasswordError> {
    match fault {
        Some(Fault::UnknownCommitted) => Err(ReferencePasswordError::StorageUnavailable),
        Some(Fault::LostResponse) => Err(ReferencePasswordError::ResponseLost),
        _ => Ok(()),
    }
}

fn commit_login(
    state: &mut State,
    attempt_id: [u8; 32],
    account_id: Uuid,
    response: AccountPasswordLoginResponse,
) -> Result<AccountPasswordLoginResponse, ReferencePasswordError> {
    let digest = account_capability_digest(response.admission_token.as_bytes());
    if state.password.capabilities.contains_key(&digest) {
        return Err(ReferencePasswordError::StorageUnavailable);
    }
    let capability = ReferenceAdmissionCapability {
        account_id,
        credential_generation: state.accounts[&account_id].credential.generation,
        snapshot_digest: account_bootstrap_digest(response.snapshot.as_bytes()),
        expires_at_ms: response.expires_at_ms,
        spent: false,
    };
    let fault = state.fault.take();
    if matches!(fault, Some(Fault::BeforeCommit | Fault::Audit | Fault::UnknownRollback)) {
        return Err(ReferencePasswordError::StorageUnavailable);
    }
    let successes = state
        .password
        .successes
        .checked_add(1)
        .ok_or(ReferencePasswordError::StorageUnavailable)?;
    state.password.capabilities.insert(digest, capability);
    state.password.capability_expiry.insert((response.expires_at_ms, digest));
    state.password.account_capabilities.entry(account_id).or_default().insert(digest);
    state.password.consume_attempt(&attempt_id);
    state.password.successes = successes;
    transient_result(fault)?;
    Ok(response)
}

fn deny_login(
    state: &mut State,
    attempt: Option<[u8; 32]>,
    denial: ReferencePasswordError,
) -> Result<AccountPasswordLoginResponse, ReferencePasswordError> {
    let fault = state.fault.take();
    if matches!(fault, Some(Fault::BeforeCommit | Fault::Audit | Fault::UnknownRollback)) {
        return Err(ReferencePasswordError::StorageUnavailable);
    }
    let denials =
        state.password.denials.checked_add(1).ok_or(ReferencePasswordError::StorageUnavailable)?;
    if let Some(id) = attempt {
        state.password.consume_attempt(&id);
    }
    state.password.denials = denials;
    transient_result(fault)?;
    Err(denial)
}
