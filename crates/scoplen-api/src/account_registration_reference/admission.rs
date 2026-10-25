// SPDX-License-Identifier: Apache-2.0
//! New Device publication and immutable historical confirmation in owned fixture storage.

use scoplen_crypto::{
    AccountRequestProof, AccountRequestSignatureInput, DeviceCertificate, SecretBytes, SecretVec,
    account_bootstrap_digest, account_capability_digest, canonical_device_public_key,
};
use uuid::Uuid;

use super::{
    ApiContractError, ErrorCode, ProblemDetails, ReferenceAccountRegistrationPeer,
    ReferenceRegistrationFault as Fault, ReferenceRegistrationReceipt, State, password,
};
use crate::{
    account_admission::{
        AccountAdmissionCodecError, AccountBootstrapSnapshot, AccountCommittedConfirmation,
        AccountDeviceAdmissionPayload, AccountDeviceAdmissionRequest, AccountRequestIntent,
        AccountRequestKind, MAX_ACCOUNT_ENTRY_PROBLEM_BYTES,
    },
    sync::{SyncAccountKeyBundle, SyncAccountKeyBundleUpdate},
};

/// Content-free Device-admission failures; a missing receipt is never a negative receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ReferenceDeviceAdmissionError {
    /// Malformed request or owned fixture control.
    #[error("invalid Device admission request")]
    InvalidRequest,
    /// The complete request or protected artifact exceeds its public bound.
    #[error("Device admission request too large")]
    TooLarge,
    /// Unusable challenge/capability, binding or cryptographic possession.
    #[error("Account authentication required")]
    AuthenticationRequired,
    /// Current state, next publication or Device freshness no longer admits this capability.
    #[error("Device admission state conflict")]
    AdmissionConflict,
    /// The Account lifetime receipt ceiling leaves no room for the new immutable receipt.
    #[error("Device admission quota exceeded")]
    QuotaExceeded,
    /// Maintenance, integrity, audit, confirmed rollback or unconfirmed receipt-only work.
    #[error("Device admission storage unavailable")]
    StorageUnavailable,
    /// A business COMMIT was attempted and must be recovered by exact confirmation.
    #[error("Device admission outcome unknown")]
    CommitOutcomeUnknown,
    /// No response reached the caller.
    #[error("Device admission response lost")]
    ResponseLost,
}

impl ReferenceDeviceAdmissionError {
    /// Render one bounded common problem, or no problem for a lost response.
    /// # Errors
    /// Rejects invalid instances or an actual encoded body above four KiB.
    pub fn problem(self, instance: &str) -> Result<Option<ProblemDetails>, ApiContractError> {
        let (status, code, changed, retryable) = match self {
            Self::InvalidRequest => (400, "auth.invalid_request", false, false),
            Self::TooLarge => (413, "auth.invalid_request", false, false),
            Self::AuthenticationRequired => (401, "auth.authentication_required", false, false),
            Self::AdmissionConflict => (409, "auth.admission_conflict", false, false),
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
            "Device admission was not confirmed",
            "Retain the original business bytes and private keys. An unknown result requires explicit exact-receipt confirmation with a fresh challenge.",
            instance,
            changed,
            retryable,
        )?;
        if serde_json::to_vec(&problem)
            .map_err(|_| {
                ApiContractError::InvalidProblem("Account entry problem encoding failed".into())
            })?
            .len()
            > MAX_ACCOUNT_ENTRY_PROBLEM_BYTES
        {
            return Err(ApiContractError::InvalidProblem(
                "Account entry problem exceeds its bound".into(),
            ));
        }
        Ok(Some(problem))
    }
}

impl From<AccountAdmissionCodecError> for ReferenceDeviceAdmissionError {
    fn from(value: AccountAdmissionCodecError) -> Self {
        match value {
            AccountAdmissionCodecError::TooLarge => Self::TooLarge,
            AccountAdmissionCodecError::Binding => Self::AuthenticationRequired,
            AccountAdmissionCodecError::AdmissionConflict => Self::AdmissionConflict,
            _ => Self::InvalidRequest,
        }
    }
}

/// New-admission 201 or exact historical-confirmation 200, without general authorization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReferenceDeviceAdmissionResult {
    /// Exactly 201 for a new Device, or 200 for the exact retained receipt.
    pub status: u16,
    /// The original bounded committed facts, with no current key or capability material.
    pub confirmation: AccountCommittedConfirmation,
}

type Error = ReferenceDeviceAdmissionError;
type AdmissionResult = std::result::Result<ReferenceDeviceAdmissionResult, Error>;

struct Transaction {
    request: AccountDeviceAdmissionRequest,
    payload: AccountDeviceAdmissionPayload,
    challenge_id: [u8; 32],
    challenge_expires_at: u64,
    fault: Option<Fault>,
}

struct Prepared {
    capability_id: [u8; 32],
    capability_expires_at: u64,
    bootstrap: SecretVec,
    receipt: ReferenceRegistrationReceipt,
}

impl ReferenceAccountRegistrationPeer {
    /// Submit one new Device or confirm only its original immutable historical receipt.
    ///
    /// Owns and zeroizes the complete capability-bearing body. Source/rate admission precedes
    /// this call. A confirmation with no exact receipt can never enter the submit branch.
    /// # Errors
    /// Rejects structure, fresh possession, capability/current-state binding, capacity or faults.
    pub fn device_admission(
        &self,
        body: SecretVec,
        mut clock: impl FnMut() -> u64,
    ) -> std::result::Result<ReferenceDeviceAdmissionResult, ReferenceDeviceAdmissionError> {
        let (request, payload) =
            AccountDeviceAdmissionRequest::decode_for_authentication(body.as_bytes())?;
        drop(body);
        let mut state = self.lock().map_err(|_| Error::StorageUnavailable)?;
        let now = state.observe_time(clock());
        if state.maintenance {
            return Err(Error::StorageUnavailable);
        }
        state.retire_challenges(now).map_err(|_| Error::StorageUnavailable)?;
        state.password.retire(now).map_err(|_| Error::StorageUnavailable)?;
        let id = account_capability_digest(request.attempt_id.as_bytes());
        let challenge = state.challenges.get(&id).filter(|row| row.expires_at_ms > now).cloned();
        let fault = state.fault.take();
        let Some(challenge) = challenge else {
            return deny(&mut state, None, None, fault, Error::AuthenticationRequired);
        };
        if challenge.kind != AccountRequestKind::Admit
            || challenge.intent != request.intent
            || challenge.operation_id != payload.operation_id
            || challenge.device_id != payload.device_id
            || payload.origin != state.origin
            || challenge.nonce_digest
                != SecretBytes::new(account_capability_digest(request.nonce.as_bytes()))
        {
            return deny(&mut state, Some(id), None, fault, Error::AuthenticationRequired);
        }
        let transaction = Transaction {
            request,
            payload,
            challenge_id: id,
            challenge_expires_at: challenge.expires_at_ms,
            fault,
        };
        match transaction.request.intent {
            AccountRequestIntent::Submit => submit(&mut state, &transaction, &mut clock),
            AccountRequestIntent::Confirm => confirm(&mut state, &transaction, &mut clock),
        }
    }

    /// Script current trusted public roots in an owned fixture for historical-receipt tests.
    ///
    /// This intentionally permits inconsistent fixture state; it is not a root-change endpoint
    /// or approval of the separately unfrozen root/credential lifecycle.
    /// # Errors
    /// Rejects an unknown Account or poisoned fixture storage.
    pub fn script_account_roots(
        &self,
        account_id: Uuid,
        signing_root: [u8; 32],
        kem_root: [u8; 32],
    ) -> std::result::Result<(), ReferenceDeviceAdmissionError> {
        let mut state = self.lock().map_err(|_| Error::StorageUnavailable)?;
        let account = state.accounts.get_mut(&account_id).ok_or(Error::InvalidRequest)?;
        account.signing_root = signing_root;
        account.kem_root = kem_root;
        Ok(())
    }
}

fn submit(
    state: &mut State,
    transaction: &Transaction,
    mut clock: impl FnMut() -> u64,
) -> AdmissionResult {
    let now = state.observe_time(clock());
    let prepared = match prepare(state, transaction, now) {
        Ok(prepared) => prepared,
        Err(Error::StorageUnavailable) => return Err(Error::StorageUnavailable),
        Err(mut error) => {
            if error == Error::AdmissionConflict {
                let now = state.observe_time(clock());
                let expiry = transaction
                    .request
                    .admission_token
                    .as_ref()
                    .and_then(|token| {
                        state.password.capability(&account_capability_digest(token.as_bytes()))
                    })
                    .map_or(0, |row| row.expires_at_ms);
                if transaction.challenge_expires_at <= now || expiry <= now {
                    error = Error::AuthenticationRequired;
                }
            }
            let invalidated = if error == Error::AdmissionConflict {
                transaction
                    .request
                    .admission_token
                    .as_ref()
                    .map(|token| account_capability_digest(token.as_bytes()))
            } else {
                None
            };
            return deny(
                state,
                Some(transaction.challenge_id),
                invalidated,
                transaction.fault,
                error,
            );
        }
    };
    let committed_at_ms = state.observe_time(clock());
    if transaction.challenge_expires_at <= committed_at_ms
        || prepared.capability_expires_at <= committed_at_ms
    {
        return deny(
            state,
            Some(transaction.challenge_id),
            None,
            transaction.fault,
            Error::AuthenticationRequired,
        );
    }
    if matches!(transaction.fault, Some(Fault::BeforeCommit | Fault::Audit)) {
        return Err(Error::StorageUnavailable);
    }
    if transaction.fault == Some(Fault::UnknownRollback) {
        return Err(Error::CommitOutcomeUnknown);
    }
    let admissions = state.admissions.checked_add(1).ok_or(Error::StorageUnavailable)?;
    let Prepared { capability_id, bootstrap, mut receipt, .. } = prepared;
    receipt.committed_at_ms = committed_at_ms;
    let confirmation = receipt.confirmation.clone();
    let account_id = confirmation.account_id;
    state.accounts.get_mut(&account_id).ok_or(Error::StorageUnavailable)?.bootstrap = bootstrap;
    state.devices.insert(confirmation.device_id, account_id);
    state.account_devices.entry(account_id).or_default().insert(confirmation.device_id);
    state.account_receipts.entry(account_id).or_default().insert(confirmation.operation_id);
    for key in [receipt.signing_key, receipt.kem_key] {
        state.device_key_receipts.entry(key).or_default().insert(confirmation.operation_id);
    }
    state.receipts.insert(confirmation.operation_id, receipt);
    state.password.remove_capability(&capability_id);
    state.consume(&transaction.challenge_id);
    state.admissions = admissions;
    match transaction.fault {
        Some(Fault::UnknownCommitted) => Err(Error::CommitOutcomeUnknown),
        Some(Fault::LostResponse) => Err(Error::ResponseLost),
        _ => Ok(ReferenceDeviceAdmissionResult { status: 201, confirmation }),
    }
}

fn prepare(
    state: &State,
    transaction: &Transaction,
    now: u64,
) -> std::result::Result<Prepared, Error> {
    let Transaction { request, payload, .. } = transaction;
    let token = request.admission_token.as_ref().ok_or(Error::AuthenticationRequired)?;
    let id = account_capability_digest(token.as_bytes());
    let capability = state
        .password
        .capability(&id)
        .filter(|row| !row.spent && row.expires_at_ms > now)
        .ok_or(Error::AuthenticationRequired)?;
    if capability.account_id != payload.account_id
        || capability.credential_generation != payload.credential_generation
        || capability.snapshot_digest != payload.snapshot_digest
        || id != payload.capability_digest
    {
        return Err(Error::AuthenticationRequired);
    }
    let account = state
        .accounts
        .get(&capability.account_id)
        .filter(|account| account.active)
        .ok_or(Error::AuthenticationRequired)?;
    if account.username != payload.username || account.vault_id != payload.personal_vault_id {
        return Err(Error::AuthenticationRequired);
    }
    let certificate = verify_proofs(&state.origin, &account.signing_root, request, payload)?;
    let current = password::current_snapshot(state, capability.account_id).map_err(|error| {
        if error == super::ReferencePasswordError::AdmissionConflict {
            Error::AdmissionConflict
        } else {
            Error::StorageUnavailable
        }
    })?;
    if account.credential.generation != capability.credential_generation
        || account_bootstrap_digest(current.as_bytes()) != capability.snapshot_digest
    {
        return Err(Error::AdmissionConflict);
    }
    if state.vaults.get(&account.vault_id) != Some(&capability.account_id) {
        return Err(Error::StorageUnavailable);
    }
    let mut snapshot = AccountBootstrapSnapshot::from_cbor(current.as_bytes())
        .map_err(|_| Error::StorageUnavailable)?;
    payload.validate_for_snapshot(&snapshot, current.as_bytes(), token.as_bytes())?;
    check_freshness(state, payload, &certificate)?;
    if state.account_receipts.get(&capability.account_id).is_some_and(|ids| {
        ids.len() >= usize::try_from(state.receipt_ceiling).unwrap_or(usize::MAX)
    }) {
        return Err(Error::QuotaExceeded);
    }
    snapshot.certificates.push(payload.device_certificate.clone());
    snapshot.certificates.sort();
    snapshot.key_bundle.clone_from(&payload.key_bundle);
    let bootstrap = preflight_snapshot(&snapshot, payload.device_id)?;
    let revision = SyncAccountKeyBundleUpdate::from_cbor(&payload.key_bundle)
        .map_err(|_| Error::StorageUnavailable)?
        .revision;
    let confirmation = AccountCommittedConfirmation {
        kind: AccountRequestKind::Admit,
        operation_id: payload.operation_id,
        request_digest: AccountRequestSignatureInput::new(
            AccountRequestKind::Admit,
            request.payload.as_bytes(),
        )
        .map_err(|_| Error::InvalidRequest)?
        .request_digest(&request.account_signature),
        account_id: payload.account_id,
        personal_vault_id: payload.personal_vault_id,
        device_id: payload.device_id,
        admitted_key_revision: revision,
    };
    confirmation.to_json().map_err(|_| Error::StorageUnavailable)?;
    let receipt = ReferenceRegistrationReceipt {
        confirmation,
        account_root: account.signing_root,
        signing_key: canonical_device_public_key(&certificate.signing_public_key)
            .map_err(|_| Error::AuthenticationRequired)?,
        kem_key: canonical_device_public_key(&certificate.kem_public_key)
            .map_err(|_| Error::AuthenticationRequired)?,
        committed_at_ms: 0,
    };
    Ok(Prepared {
        capability_id: id,
        capability_expires_at: capability.expires_at_ms,
        bootstrap,
        receipt,
    })
}

fn verify_proofs(
    origin: &str,
    root: &[u8; 32],
    request: &AccountDeviceAdmissionRequest,
    payload: &AccountDeviceAdmissionPayload,
) -> std::result::Result<DeviceCertificate, Error> {
    let input =
        AccountRequestSignatureInput::new(AccountRequestKind::Admit, request.payload.as_bytes())
            .map_err(|_| Error::InvalidRequest)?;
    input.verify(root, &request.account_signature).map_err(|_| Error::AuthenticationRequired)?;
    let certificate = DeviceCertificate::decode(&payload.device_certificate)
        .map_err(|_| Error::InvalidRequest)?;
    certificate.verify(root).map_err(|_| Error::AuthenticationRequired)?;
    let digest = input.request_digest(&request.account_signature);
    AccountRequestProof::new(
        AccountRequestKind::Admit,
        request.intent,
        origin,
        request.attempt_id.as_bytes(),
        request.nonce.as_bytes(),
        payload.operation_id,
        payload.device_id,
        &digest,
    )
    .map_err(|_| Error::InvalidRequest)?
    .verify(&certificate.signing_public_key, &request.device_proof)
    .map_err(|_| Error::AuthenticationRequired)?;
    if certificate.account_id != payload.account_id || certificate.device_id != payload.device_id {
        return Err(Error::AuthenticationRequired);
    }
    Ok(certificate)
}

fn check_freshness(
    state: &State,
    payload: &AccountDeviceAdmissionPayload,
    certificate: &DeviceCertificate,
) -> std::result::Result<(), Error> {
    if state.devices.contains_key(&payload.device_id)
        || state.receipts.contains_key(&payload.operation_id)
    {
        return Err(Error::AdmissionConflict);
    }
    let signing = canonical_device_public_key(&certificate.signing_public_key)
        .map_err(|_| Error::AuthenticationRequired)?;
    let kem = canonical_device_public_key(&certificate.kem_public_key)
        .map_err(|_| Error::AuthenticationRequired)?;
    if signing == kem {
        return Err(Error::AdmissionConflict);
    }
    if state.device_key_receipts.contains_key(&signing)
        || state.device_key_receipts.contains_key(&kem)
    {
        return Err(Error::AdmissionConflict);
    }
    Ok(())
}

fn preflight_snapshot(
    snapshot: &AccountBootstrapSnapshot,
    new_device: Uuid,
) -> std::result::Result<SecretVec, Error> {
    let encoded = SecretVec::new(snapshot.to_cbor().map_err(|error| match error {
        AccountAdmissionCodecError::TooLarge => Error::QuotaExceeded,
        _ => Error::StorageUnavailable,
    })?);
    let bundle = SyncAccountKeyBundleUpdate::from_cbor(&snapshot.key_bundle)
        .map_err(|_| Error::StorageUnavailable)?;
    let wrapped_ark = bundle
        .device_wraps
        .iter()
        .find(|wrap| wrap.device_id == new_device)
        .ok_or(Error::StorageUnavailable)?
        .wrapped_ark
        .clone();
    SyncAccountKeyBundle {
        revision: bundle.revision,
        wrapped_ark,
        account_signing_key: bundle.account_signing_key,
        account_kem_key: bundle.account_kem_key,
        recovery_blob: bundle.recovery_blob,
        certificates: snapshot.certificates.clone(),
        revocations: snapshot.revocations.clone(),
    }
    .to_cbor()
    .map_err(|_| Error::QuotaExceeded)?;
    Ok(encoded)
}

fn confirm(
    state: &mut State,
    transaction: &Transaction,
    mut clock: impl FnMut() -> u64,
) -> AdmissionResult {
    let receipt = state.receipts.get(&transaction.payload.operation_id).cloned();
    let Some(receipt) =
        receipt.filter(|receipt| receipt.confirmation.kind == AccountRequestKind::Admit)
    else {
        return deny(
            state,
            Some(transaction.challenge_id),
            None,
            transaction.fault,
            Error::AuthenticationRequired,
        );
    };
    if verify_confirmation(&state.origin, &transaction.request, &receipt).is_err() {
        return deny(
            state,
            Some(transaction.challenge_id),
            None,
            transaction.fault,
            Error::AuthenticationRequired,
        );
    }
    receipt.confirmation.to_json().map_err(|_| Error::StorageUnavailable)?;
    if transaction.challenge_expires_at <= state.observe_time(clock()) {
        return deny(
            state,
            Some(transaction.challenge_id),
            None,
            transaction.fault,
            Error::AuthenticationRequired,
        );
    }
    if matches!(
        transaction.fault,
        Some(Fault::BeforeCommit | Fault::Audit | Fault::UnknownRollback)
    ) {
        return Err(Error::StorageUnavailable);
    }
    state.consume(&transaction.challenge_id);
    match transaction.fault {
        Some(Fault::UnknownCommitted) => Err(Error::StorageUnavailable),
        Some(Fault::LostResponse) => Err(Error::ResponseLost),
        _ => Ok(ReferenceDeviceAdmissionResult { status: 200, confirmation: receipt.confirmation }),
    }
}

fn verify_confirmation(
    origin: &str,
    request: &AccountDeviceAdmissionRequest,
    receipt: &ReferenceRegistrationReceipt,
) -> std::result::Result<(), Error> {
    let input =
        AccountRequestSignatureInput::new(AccountRequestKind::Admit, request.payload.as_bytes())
            .map_err(|_| Error::InvalidRequest)?;
    let digest = input.request_digest(&request.account_signature);
    if SecretBytes::new(digest) != SecretBytes::new(receipt.confirmation.request_digest) {
        return Err(Error::AuthenticationRequired);
    }
    receipt.confirmation.validate_for_request(
        AccountRequestKind::Admit,
        request.payload.as_bytes(),
        &request.account_signature,
    )?;
    input
        .verify(&receipt.account_root, &request.account_signature)
        .map_err(|_| Error::AuthenticationRequired)?;
    AccountRequestProof::new(
        AccountRequestKind::Admit,
        AccountRequestIntent::Confirm,
        origin,
        request.attempt_id.as_bytes(),
        request.nonce.as_bytes(),
        receipt.confirmation.operation_id,
        receipt.confirmation.device_id,
        &digest,
    )
    .map_err(|_| Error::InvalidRequest)?
    .verify(&receipt.signing_key, &request.device_proof)
    .map_err(|_| Error::AuthenticationRequired)
}

fn deny(
    state: &mut State,
    challenge: Option<[u8; 32]>,
    capability: Option<[u8; 32]>,
    fault: Option<Fault>,
    error: Error,
) -> AdmissionResult {
    if matches!(fault, Some(Fault::BeforeCommit | Fault::Audit | Fault::UnknownRollback)) {
        return Err(Error::StorageUnavailable);
    }
    let denials = state.denials.checked_add(1).ok_or(Error::StorageUnavailable)?;
    if let Some(challenge) = challenge {
        state.consume(&challenge);
    }
    if let Some(capability) = capability {
        state.password.remove_capability(&capability);
    }
    state.denials = denials;
    match fault {
        Some(Fault::UnknownCommitted) => Err(Error::StorageUnavailable),
        Some(Fault::LostResponse) => Err(Error::ResponseLost),
        _ => Err(error),
    }
}
