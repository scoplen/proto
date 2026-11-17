// SPDX-License-Identifier: Apache-2.0
//! Credential-only publication and exact historical confirmation over the shared Account lock.

use std::fmt;

use scoplen_crypto::{
    DeviceCertificate, SecretBytes, SecretVec, account_bootstrap_digest, account_capability_digest,
    canonical_device_public_key,
};
use uuid::Uuid;

use super::{
    ReferenceAccountRegistrationPeer, ReferencePasswordCredential,
    ReferenceRegistrationFault as Fault, State, password,
};
use crate::account_admission::{
    AccountBootstrapSnapshot, AccountPasswordChangeConfirmation, AccountPasswordChangePayload,
    AccountPasswordChangeRequest, AccountPasswordLoginResponse, AccountRequestIntent,
    AccountRequestKind,
};

/// Password replacement uses the existing native mutation error and problem contract.
pub type ReferencePasswordChangeError = super::ReferenceDeviceAdmissionError;
type Error = ReferencePasswordChangeError;
type ChangeResult = Result<ReferencePasswordChangeResult, Error>;

/// Credential replacement 201 or exact historical confirmation 200, without current authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReferencePasswordChangeResult {
    /// Exactly 201 for a new credential generation or 200 for its retained receipt.
    pub status: u16,
    /// Original committed facts; the generation may now be historical.
    pub confirmation: AccountPasswordChangeConfirmation,
}

/// Immutable original public bindings, with no verifier, wrapper, payload or raw capability.
#[derive(Clone)]
pub struct ReferencePasswordChangeReceipt {
    /// Exact original operation result.
    pub confirmation: AccountPasswordChangeConfirmation,
    /// Original trusted Account signing root.
    pub account_root: [u8; 32],
    /// Original certified normalized Device signing key.
    pub signing_key: [u8; 65],
    /// Original certified normalized independent Device KEM key.
    pub kem_key: [u8; 65],
    /// Trusted commit time; receipts have no expiry.
    pub committed_at_ms: u64,
}

impl fmt::Debug for ReferencePasswordChangeReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ReferencePasswordChangeReceipt([REDACTED])")
    }
}

struct Transaction {
    request: AccountPasswordChangeRequest,
    payload: AccountPasswordChangePayload,
    challenge_id: [u8; 32],
    challenge_expires_at: u64,
    fault: Option<Fault>,
}

struct Prepared {
    capability_id: [u8; 32],
    capability_expires_at: u64,
    credential: ReferencePasswordCredential,
    bootstrap: SecretVec,
    receipt: ReferencePasswordChangeReceipt,
}

impl ReferenceAccountRegistrationPeer {
    /// Replace only password credentials with current enrolled Device and Account authority,
    /// or confirm only an exact original receipt using its retained public keys.
    ///
    /// Caller admission precedes this low-level entry. The same Account lock and capability
    /// collection serialize Device admission and password replacement across cloned peers.
    /// # Errors
    /// Rejects syntax, possession/current authority, capability/CAS, quota or transaction faults.
    pub fn password_change(&self, body: SecretVec, mut clock: impl FnMut() -> u64) -> ChangeResult {
        let (request, payload) =
            AccountPasswordChangeRequest::decode_for_authentication(body.as_bytes())?;
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
        if challenge.kind != AccountRequestKind::PasswordChange
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

    /// Inspect the exact bounded historical receipt in an owned fixture, not an HTTP read.
    /// # Errors
    /// Fails closed when fixture storage is poisoned.
    pub fn retained_password_change_receipt(
        &self,
        operation_id: Uuid,
    ) -> Result<Option<ReferencePasswordChangeReceipt>, Error> {
        Ok(self
            .lock()
            .map_err(|_| Error::StorageUnavailable)?
            .password_change_receipts
            .get(&operation_id)
            .cloned())
    }
}

fn submit(state: &mut State, tx: &Transaction, mut clock: impl FnMut() -> u64) -> ChangeResult {
    let now = state.observe_time(clock());
    let prepared = match prepare(state, tx, now) {
        Ok(prepared) => prepared,
        Err(Error::StorageUnavailable) => return Err(Error::StorageUnavailable),
        Err(mut error) => {
            let capability = tx
                .request
                .admission_token
                .as_ref()
                .map(|token| account_capability_digest(token.as_bytes()));
            if error == Error::AdmissionConflict {
                let now = state.observe_time(clock());
                let expiry = capability
                    .as_ref()
                    .and_then(|id| state.password.capability(id))
                    .map_or(0, |row| row.expires_at_ms);
                if tx.challenge_expires_at <= now || expiry <= now {
                    error = Error::AuthenticationRequired;
                }
            }
            return deny(
                state,
                Some(tx.challenge_id),
                capability.filter(|_| error == Error::AdmissionConflict),
                tx.fault,
                error,
            );
        }
    };
    let committed_at_ms = state.observe_time(clock());
    if tx.challenge_expires_at <= committed_at_ms
        || prepared.capability_expires_at <= committed_at_ms
    {
        return deny(state, Some(tx.challenge_id), None, tx.fault, Error::AuthenticationRequired);
    }
    if matches!(tx.fault, Some(Fault::BeforeCommit | Fault::Audit)) {
        return Err(Error::StorageUnavailable);
    }
    if tx.fault == Some(Fault::UnknownRollback) {
        return Err(Error::CommitOutcomeUnknown);
    }
    let successes = state.password_changes.checked_add(1).ok_or(Error::StorageUnavailable)?;
    let Prepared { capability_id, credential, bootstrap, mut receipt, .. } = prepared;
    receipt.committed_at_ms = committed_at_ms;
    let confirmation = receipt.confirmation.clone();
    let account_id = confirmation.account_id;
    let account = state.accounts.get_mut(&account_id).ok_or(Error::StorageUnavailable)?;
    account.credential = credential;
    account.bootstrap = bootstrap;
    state.account_receipts.entry(account_id).or_default().insert(confirmation.operation_id);
    for key in [receipt.signing_key, receipt.kem_key] {
        state.device_key_receipts.entry(key).or_default().insert(confirmation.operation_id);
    }
    state.password_change_receipts.insert(confirmation.operation_id, receipt);
    state.password.remove_capability(&capability_id);
    state.consume(&tx.challenge_id);
    state.password_changes = successes;
    match tx.fault {
        Some(Fault::UnknownCommitted) => Err(Error::CommitOutcomeUnknown),
        Some(Fault::LostResponse) => Err(Error::ResponseLost),
        _ => Ok(ReferencePasswordChangeResult { status: 201, confirmation }),
    }
}

fn prepare(state: &State, tx: &Transaction, now: u64) -> Result<Prepared, Error> {
    let Transaction { request, payload, .. } = tx;
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
        .filter(|row| row.active)
        .ok_or(Error::AuthenticationRequired)?;
    if account.username != payload.username
        || account.vault_id != payload.personal_vault_id
        || state.devices.get(&payload.device_id) != Some(&payload.account_id)
    {
        return Err(Error::AuthenticationRequired);
    }
    let mut snapshot = AccountBootstrapSnapshot::from_cbor(account.bootstrap.as_bytes())
        .map_err(|_| Error::StorageUnavailable)?;
    let certificate = active_certificate(&snapshot, payload.device_id)?;
    let digest = request.verify_proof(
        &state.origin,
        &account.signing_root,
        &certificate.signing_public_key,
    )?;
    let current = password::current_snapshot(state, capability.account_id).map_err(|error| {
        if error == super::ReferencePasswordError::AdmissionConflict {
            Error::AdmissionConflict
        } else {
            Error::StorageUnavailable
        }
    })?;
    if account.credential.generation != capability.credential_generation
        || account_bootstrap_digest(current.as_bytes()) != capability.snapshot_digest
        || state.has_operation(&payload.operation_id)
    {
        return Err(Error::AdmissionConflict);
    }
    if state.vaults.get(&account.vault_id) != Some(&payload.account_id) {
        return Err(Error::StorageUnavailable);
    }
    payload.validate_for_snapshot(&snapshot, current.as_bytes(), token.as_bytes())?;
    if state.account_receipts.get(&payload.account_id).is_some_and(|ids| {
        ids.len() >= usize::try_from(state.receipt_ceiling).unwrap_or(usize::MAX)
    }) {
        return Err(Error::QuotaExceeded);
    }
    snapshot.password_salt = payload.password_salt;
    snapshot.password_ark = payload.password_ark;
    snapshot.credential_generation = payload.new_credential_generation;
    let bootstrap = SecretVec::new(snapshot.to_cbor().map_err(|_| Error::StorageUnavailable)?);
    let encoded = SecretVec::new(
        AccountPasswordLoginResponse {
            admission_token: SecretBytes::new([0; 32]),
            expires_at_ms: u64::MAX,
            snapshot: bootstrap.clone(),
        }
        .to_json()
        .map_err(|_| Error::StorageUnavailable)?,
    );
    drop(encoded);
    let confirmation = AccountPasswordChangeConfirmation {
        operation_id: payload.operation_id,
        request_digest: digest,
        account_id: payload.account_id,
        personal_vault_id: payload.personal_vault_id,
        device_id: payload.device_id,
        credential_generation: payload.new_credential_generation,
    };
    confirmation.to_json().map_err(|_| Error::StorageUnavailable)?;
    Ok(Prepared {
        capability_id: id,
        capability_expires_at: capability.expires_at_ms,
        credential: ReferencePasswordCredential {
            profile: 1,
            salt: payload.password_salt,
            verifier: SecretBytes::new(payload.verifier),
            generation: payload.new_credential_generation,
        },
        bootstrap,
        receipt: ReferencePasswordChangeReceipt {
            confirmation,
            account_root: account.signing_root,
            signing_key: canonical_device_public_key(&certificate.signing_public_key)
                .map_err(|_| Error::StorageUnavailable)?,
            kem_key: canonical_device_public_key(&certificate.kem_public_key)
                .map_err(|_| Error::StorageUnavailable)?,
            committed_at_ms: 0,
        },
    })
}

fn active_certificate(
    snapshot: &AccountBootstrapSnapshot,
    device_id: Uuid,
) -> Result<DeviceCertificate, Error> {
    let bundle = crate::sync::SyncAccountKeyBundleUpdate::from_cbor(&snapshot.key_bundle)
        .map_err(|_| Error::StorageUnavailable)?;
    if !bundle.device_wraps.iter().any(|wrap| wrap.device_id == device_id) {
        return Err(Error::AuthenticationRequired);
    }
    for bytes in &snapshot.certificates {
        let certificate =
            DeviceCertificate::decode(bytes).map_err(|_| Error::StorageUnavailable)?;
        if certificate.device_id == device_id {
            return Ok(certificate);
        }
    }
    Err(Error::AuthenticationRequired)
}

fn confirm(state: &mut State, tx: &Transaction, mut clock: impl FnMut() -> u64) -> ChangeResult {
    let receipt = state.password_change_receipts.get(&tx.payload.operation_id).cloned();
    let Some(receipt) = receipt else {
        return deny(state, Some(tx.challenge_id), None, tx.fault, Error::AuthenticationRequired);
    };
    if tx.request.verify_proof(&state.origin, &receipt.account_root, &receipt.signing_key).is_err()
        || receipt
            .confirmation
            .validate_for_request(tx.request.payload.as_bytes(), &tx.request.account_signature)
            .is_err()
    {
        return deny(state, Some(tx.challenge_id), None, tx.fault, Error::AuthenticationRequired);
    }
    receipt.confirmation.to_json().map_err(|_| Error::StorageUnavailable)?;
    if tx.challenge_expires_at <= state.observe_time(clock()) {
        return deny(state, Some(tx.challenge_id), None, tx.fault, Error::AuthenticationRequired);
    }
    if matches!(tx.fault, Some(Fault::BeforeCommit | Fault::Audit | Fault::UnknownRollback)) {
        return Err(Error::StorageUnavailable);
    }
    state.consume(&tx.challenge_id);
    match tx.fault {
        Some(Fault::UnknownCommitted) => Err(Error::StorageUnavailable),
        Some(Fault::LostResponse) => Err(Error::ResponseLost),
        _ => Ok(ReferencePasswordChangeResult { status: 200, confirmation: receipt.confirmation }),
    }
}

fn deny(
    state: &mut State,
    challenge: Option<[u8; 32]>,
    capability: Option<[u8; 32]>,
    fault: Option<Fault>,
    error: Error,
) -> ChangeResult {
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
