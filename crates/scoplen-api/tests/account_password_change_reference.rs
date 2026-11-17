// SPDX-License-Identifier: Apache-2.0
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use scoplen_api::{
    account_admission::{
        AccountBootstrapSnapshot, AccountDeviceAdmissionPayload, AccountDeviceAdmissionRequest,
        AccountPasswordChangePayload, AccountPasswordChangeRequest, AccountPasswordLoginRequest,
        AccountPasswordLoginResponse, AccountPasswordOptionsRequest, AccountRegistrationPayload,
        AccountRegistrationRequest, AccountRequestChallengeRequest, AccountRequestIntent,
        AccountRequestKind,
    },
    account_registration_reference::{
        DEFAULT_ACCOUNT_RECEIPT_CEILING, DEFAULT_USED_ACCOUNT_ID_CEILING,
        ReferenceAccountRegistrationPeer as Peer, ReferencePasswordChangeError as Error,
        ReferencePasswordError, ReferenceRegistrationFault as Fault,
    },
    sync::{SyncAccountDeviceWrap, SyncAccountKeyBundleUpdate},
};
use scoplen_crypto::{
    AccountRequestProof, AccountRequestSignatureInput, DeviceCertificate, Ed25519SigningKey,
    P256SigningKey, RevocationStatement, SecretBytes, SecretVec, account_bootstrap_digest,
    account_capability_digest,
};
use scoplen_model::cbor::{self, Value};
use scoplen_test_vectors::VectorDocument;
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

const ORIGIN: &str = "https://control.example.com";
const NOW: u64 = 1_700_000_000_000;

struct Account {
    payload: AccountRegistrationPayload,
    root: Ed25519SigningKey,
    index: u16,
}

struct Business {
    payload: AccountDeviceAdmissionPayload,
    request: AccountDeviceAdmissionRequest,
    signer: P256SigningKey,
}

fn key(tag: u8, serial: u16) -> [u8; 32] {
    let mut bytes = [tag; 32];
    bytes[30..].copy_from_slice(&serial.to_be_bytes());
    bytes
}

fn adjacent(id: Uuid, offset: u32) -> Uuid {
    let mut bytes = *id.as_bytes();
    let suffix = u32::from_be_bytes(bytes[12..].try_into().unwrap()).checked_add(offset).unwrap();
    bytes[12..].copy_from_slice(&suffix.to_be_bytes());
    Uuid::from_bytes(bytes)
}

fn register(peer: &Peer, index: u16) -> Account {
    register_with_device_keys(peer, index, index)
}

// A different key_index deliberately repeats keys under the existing registration reference
// behavior. It tests multi-owner index deletion, not compliant fresh client key generation.
fn register_with_device_keys(peer: &Peer, index: u16, key_index: u16) -> Account {
    let document =
        VectorDocument::parse_str(include_str!("../../../vectors/account-admission.json")).unwrap();
    let vector =
        document.vectors.iter().find(|v| v.id == "account-admission-register-submit").unwrap();
    let mut request = AccountRegistrationRequest::from_json(vector.input.as_bytes()).unwrap();
    let mut payload = AccountRegistrationPayload::from_cbor(request.payload.as_bytes()).unwrap();
    for (role, id) in [
        &mut payload.account_id,
        &mut payload.personal_vault_id,
        &mut payload.device_id,
        &mut payload.operation_id,
    ]
    .into_iter()
    .enumerate()
    {
        let mut bytes = *id.as_bytes();
        bytes[12..].copy_from_slice(
            &(u32::from(index) * 100 + u32::try_from(role).unwrap() + 1).to_be_bytes(),
        );
        *id = Uuid::from_bytes(bytes);
    }
    let root = Ed25519SigningKey::from_bytes(&key(1, index)).unwrap();
    let signer = P256SigningKey::from_bytes(&key(2, key_index)).unwrap();
    let kem = P256SigningKey::from_bytes(&key(3, key_index)).unwrap();
    payload.username = format!("fixture.user{index}");
    payload.account_signing_public_key = root.public_key();
    payload.device_certificate = DeviceCertificate::issue(
        &root,
        payload.device_id,
        payload.account_id,
        signer.public_key_sec1(),
        kem.public_key_sec1(),
        "Fixture device".into(),
        "test".into(),
        42,
    )
    .unwrap()
    .encode()
    .unwrap();
    let mut bundle = SyncAccountKeyBundleUpdate::from_cbor(&payload.key_bundle).unwrap();
    bundle.device_wraps[0].device_id = payload.device_id;
    bundle.signature = root.sign(&bundle.signature_input().unwrap()).to_vec();
    payload.key_bundle = bundle.to_cbor().unwrap();
    request.payload = SecretVec::new(payload.to_cbor().unwrap());
    request.account_signature =
        AccountRequestSignatureInput::new(AccountRequestKind::Register, request.payload.as_bytes())
            .unwrap()
            .sign(&root);
    let challenge = peer
        .challenge(
            &AccountRequestChallengeRequest {
                kind: AccountRequestKind::Register,
                intent: AccountRequestIntent::Submit,
                operation_id: payload.operation_id,
                device_id: payload.device_id,
            }
            .to_json()
            .unwrap(),
            || NOW,
        )
        .unwrap();
    request.attempt_id = challenge.attempt_id;
    request.nonce = challenge.nonce;
    let digest =
        AccountRequestSignatureInput::new(AccountRequestKind::Register, request.payload.as_bytes())
            .unwrap()
            .request_digest(&request.account_signature);
    request.device_proof = AccountRequestProof::new(
        AccountRequestKind::Register,
        AccountRequestIntent::Submit,
        ORIGIN,
        request.attempt_id.as_bytes(),
        request.nonce.as_bytes(),
        payload.operation_id,
        payload.device_id,
        &digest,
    )
    .unwrap()
    .sign(&signer)
    .unwrap();
    assert_eq!(peer.register(&request.to_json().unwrap(), || NOW).unwrap().status, 201);
    Account { payload, root, index }
}

fn login(peer: &Peer, account: &Account, now: u64) -> AccountPasswordLoginResponse {
    let options = peer
        .password_options(
            &AccountPasswordOptionsRequest { username: account.payload.username.clone() }
                .to_json()
                .unwrap(),
            || now,
        )
        .unwrap();
    peer.password_login(
        AccountPasswordLoginRequest {
            attempt_id: options.attempt_id,
            auth_secret: SecretBytes::new([0x12; 32]),
        }
        .to_json()
        .unwrap(),
        || now,
    )
    .unwrap()
}

fn business(account: &Account, sequence: u16, login: &AccountPasswordLoginResponse) -> Business {
    let snapshot = AccountBootstrapSnapshot::from_cbor(login.snapshot.as_bytes()).unwrap();
    let serial = account.index.checked_mul(16).unwrap().checked_add(sequence).unwrap();
    let signer = P256SigningKey::from_bytes(&key(4, serial)).unwrap();
    let kem = P256SigningKey::from_bytes(&key(5, serial)).unwrap();
    let device_id = adjacent(account.payload.account_id, 4 + u32::from(sequence) * 2);
    let certificate = DeviceCertificate::issue(
        &account.root,
        device_id,
        snapshot.account_id,
        signer.public_key_sec1(),
        kem.public_key_sec1(),
        "Additional fixture device".into(),
        "test".into(),
        43,
    )
    .unwrap()
    .encode()
    .unwrap();
    let mut bundle = SyncAccountKeyBundleUpdate::from_cbor(&snapshot.key_bundle).unwrap();
    bundle.revision = bundle.revision.checked_add(1).unwrap();
    bundle.device_wraps.push(SyncAccountDeviceWrap {
        device_id,
        wrapped_ark: bundle.device_wraps[0].wrapped_ark.clone(),
    });
    bundle.device_wraps.sort_by_key(|wrap| *wrap.device_id.as_bytes());
    bundle.signature = account.root.sign(&bundle.signature_input().unwrap()).to_vec();
    let payload = AccountDeviceAdmissionPayload {
        operation_id: adjacent(device_id, 1),
        origin: ORIGIN.into(),
        username: snapshot.username,
        account_id: snapshot.account_id,
        personal_vault_id: snapshot.personal_vault_id,
        device_id,
        credential_generation: snapshot.credential_generation,
        snapshot_digest: account_bootstrap_digest(login.snapshot.as_bytes()),
        capability_digest: account_capability_digest(login.admission_token.as_bytes()),
        device_certificate: certificate,
        key_bundle: bundle.to_cbor().unwrap(),
    };
    let request = AccountDeviceAdmissionRequest {
        intent: AccountRequestIntent::Submit,
        payload: SecretVec::new(payload.to_cbor().unwrap()),
        account_signature: [0; 64],
        attempt_id: SecretBytes::new([0; 32]),
        nonce: SecretBytes::new([0; 32]),
        device_proof: [0; 64],
        admission_token: Some(login.admission_token.clone()),
    };
    let mut business = Business { payload, request, signer };
    business.resign(&account.root);
    business
}

impl Business {
    fn resign(&mut self, root: &Ed25519SigningKey) {
        self.request.payload = SecretVec::new(self.payload.to_cbor().unwrap());
        self.request.account_signature = AccountRequestSignatureInput::new(
            AccountRequestKind::Admit,
            self.request.payload.as_bytes(),
        )
        .unwrap()
        .sign(root);
    }

    fn fresh(
        &self,
        peer: &Peer,
        intent: AccountRequestIntent,
        now: u64,
    ) -> AccountDeviceAdmissionRequest {
        let challenge = peer
            .challenge(
                &AccountRequestChallengeRequest {
                    kind: AccountRequestKind::Admit,
                    intent,
                    operation_id: self.payload.operation_id,
                    device_id: self.payload.device_id,
                }
                .to_json()
                .unwrap(),
                || now,
            )
            .unwrap();
        let mut request = self.request.clone();
        request.intent = intent;
        if intent == AccountRequestIntent::Confirm {
            request.admission_token = None;
        }
        request.attempt_id = challenge.attempt_id;
        request.nonce = challenge.nonce;
        self.sign_proof(&mut request);
        request
    }

    fn sign_proof(&self, request: &mut AccountDeviceAdmissionRequest) {
        let digest = AccountRequestSignatureInput::new(
            AccountRequestKind::Admit,
            request.payload.as_bytes(),
        )
        .unwrap()
        .request_digest(&request.account_signature);
        request.device_proof = AccountRequestProof::new(
            AccountRequestKind::Admit,
            request.intent,
            ORIGIN,
            request.attempt_id.as_bytes(),
            request.nonce.as_bytes(),
            self.payload.operation_id,
            self.payload.device_id,
            &digest,
        )
        .unwrap()
        .sign(&self.signer)
        .unwrap();
    }
}

fn body(request: &AccountDeviceAdmissionRequest) -> SecretVec {
    SecretVec::new(request.to_json().unwrap())
}

struct Change {
    payload: AccountPasswordChangePayload,
    request: AccountPasswordChangeRequest,
    signer: P256SigningKey,
}

impl Change {
    fn new(account: &Account, sequence: u8, login: &AccountPasswordLoginResponse) -> Self {
        let snapshot = AccountBootstrapSnapshot::from_cbor(login.snapshot.as_bytes()).unwrap();
        let mut password_ark = snapshot.password_ark;
        password_ark[72] ^= sequence;
        let payload = AccountPasswordChangePayload {
            operation_id: adjacent(account.payload.operation_id, 10_000 + u32::from(sequence)),
            origin: ORIGIN.into(),
            username: snapshot.username,
            account_id: snapshot.account_id,
            personal_vault_id: snapshot.personal_vault_id,
            device_id: account.payload.device_id,
            credential_generation: snapshot.credential_generation,
            new_credential_generation: snapshot.credential_generation.checked_add(1).unwrap(),
            snapshot_digest: account_bootstrap_digest(login.snapshot.as_bytes()),
            capability_digest: account_capability_digest(login.admission_token.as_bytes()),
            password_salt: [sequence; 16],
            verifier: Sha256::digest([sequence; 32]).into(),
            password_ark,
        };
        let request = AccountPasswordChangeRequest {
            intent: AccountRequestIntent::Submit,
            payload: SecretVec::new(payload.to_cbor().unwrap()),
            account_signature: [0; 64],
            attempt_id: SecretBytes::new([0; 32]),
            nonce: SecretBytes::new([0; 32]),
            device_proof: [0; 64],
            admission_token: Some(login.admission_token.clone()),
        };
        let mut change = Self {
            payload,
            request,
            signer: P256SigningKey::from_bytes(&key(2, account.index)).unwrap(),
        };
        change.resign(&account.root);
        change
    }

    fn resign(&mut self, root: &Ed25519SigningKey) {
        self.request.payload = SecretVec::new(self.payload.to_cbor().unwrap());
        self.request.account_signature = AccountRequestSignatureInput::new(
            AccountRequestKind::PasswordChange,
            self.request.payload.as_bytes(),
        )
        .unwrap()
        .sign(root);
    }

    fn fresh(
        &self,
        peer: &Peer,
        intent: AccountRequestIntent,
        now: u64,
    ) -> AccountPasswordChangeRequest {
        let challenge = peer
            .challenge(
                &AccountRequestChallengeRequest {
                    kind: AccountRequestKind::PasswordChange,
                    intent,
                    operation_id: self.payload.operation_id,
                    device_id: self.payload.device_id,
                }
                .to_json()
                .unwrap(),
                || now,
            )
            .unwrap();
        let mut request = self.request.clone();
        request.intent = intent;
        request.admission_token = if intent == AccountRequestIntent::Submit {
            self.request.admission_token.clone()
        } else {
            None
        };
        request.attempt_id = challenge.attempt_id;
        request.nonce = challenge.nonce;
        self.proof(&mut request);
        request
    }

    fn proof(&self, request: &mut AccountPasswordChangeRequest) {
        let digest = AccountRequestSignatureInput::new(
            AccountRequestKind::PasswordChange,
            request.payload.as_bytes(),
        )
        .unwrap()
        .request_digest(&request.account_signature);
        request.device_proof = AccountRequestProof::new(
            AccountRequestKind::PasswordChange,
            request.intent,
            ORIGIN,
            request.attempt_id.as_bytes(),
            request.nonce.as_bytes(),
            self.payload.operation_id,
            self.payload.device_id,
            &digest,
        )
        .unwrap()
        .sign(&self.signer)
        .unwrap();
    }

    fn submit(
        &self,
        peer: &Peer,
        now: u64,
    ) -> Result<scoplen_api::account_registration_reference::ReferencePasswordChangeResult, Error>
    {
        peer.password_change(
            change_body(&self.fresh(peer, AccountRequestIntent::Submit, now)),
            || now,
        )
    }
}

fn change_body(request: &AccountPasswordChangeRequest) -> SecretVec {
    SecretVec::new(request.to_json().unwrap())
}

fn snapshot(peer: &Peer, account: &Account) -> AccountBootstrapSnapshot {
    AccountBootstrapSnapshot::from_cbor(
        peer.account_material(account.payload.account_id).unwrap().unwrap().bootstrap.as_bytes(),
    )
    .unwrap()
}

fn store_snapshot(peer: &Peer, account: &Account, snapshot: &AccountBootstrapSnapshot) {
    peer.script_password_state(
        account.payload.account_id,
        peer.password_credential(account.payload.account_id).unwrap(),
        SecretVec::new(snapshot.to_cbor().unwrap()),
    )
    .unwrap();
}

fn password_login(
    peer: &Peer,
    account: &Account,
    byte: u8,
    now: u64,
) -> Result<AccountPasswordLoginResponse, ReferencePasswordError> {
    let options = peer
        .password_options(
            &AccountPasswordOptionsRequest { username: account.payload.username.clone() }
                .to_json()
                .unwrap(),
            || now,
        )
        .unwrap();
    peer.password_login(
        AccountPasswordLoginRequest {
            attempt_id: options.attempt_id,
            auth_secret: SecretBytes::new([byte; 32]),
        }
        .to_json()
        .unwrap(),
        || now,
    )
}

fn revoke(peer: &Peer, account: &Account) {
    let mut snapshot = snapshot(peer, account);
    snapshot.revocations.push(
        RevocationStatement::issue(&account.root, account.payload.device_id, NOW, "fixture".into())
            .unwrap()
            .encode()
            .unwrap(),
    );
    snapshot.revocations.sort();
    let mut bundle = SyncAccountKeyBundleUpdate::from_cbor(&snapshot.key_bundle).unwrap();
    bundle.device_wraps.retain(|wrap| wrap.device_id != account.payload.device_id);
    bundle.revision += 1;
    bundle.signature = account.root.sign(&bundle.signature_input().unwrap()).to_vec();
    snapshot.key_bundle = bundle.to_cbor().unwrap();
    store_snapshot(peer, account, &snapshot);
}

#[test]
fn changes_only_credentials_and_new_login_can_admit_another_device() {
    let peer = Peer::new(ORIGIN).unwrap();
    let account = register(&peer, 1);
    let login = login(&peer, &account, NOW);
    let old_attempt = peer
        .password_options(
            &AccountPasswordOptionsRequest { username: account.payload.username.clone() }
                .to_json()
                .unwrap(),
            || NOW,
        )
        .unwrap();
    let before = snapshot(&peer, &account);
    let before_counts = peer.summary().unwrap();
    let change = Change::new(&account, 7, &login);
    let result = change.submit(&peer, NOW).unwrap();
    assert_eq!((result.status, result.confirmation.credential_generation), (201, 2));
    result
        .confirmation
        .validate_for_request(change.request.payload.as_bytes(), &change.request.account_signature)
        .unwrap();
    let mut expected = before;
    expected.credential_generation = 2;
    expected.password_salt = change.payload.password_salt;
    expected.password_ark = change.payload.password_ark;
    assert_eq!(snapshot(&peer, &account), expected);
    let credential = peer.password_credential(account.payload.account_id).unwrap();
    assert_eq!((credential.profile, credential.generation, credential.salt), (1, 2, [7; 16]));
    assert_eq!(credential.verifier.as_bytes(), &change.payload.verifier);
    let after = peer.summary().unwrap();
    assert_eq!(
        (after.accounts, after.devices, after.vaults),
        (before_counts.accounts, before_counts.devices, before_counts.vaults)
    );
    assert_eq!((after.receipts, after.password_changes), (2, 1));
    assert_eq!(peer.password_summary().unwrap().capabilities, 0);
    assert_eq!(
        password_login(&peer, &account, 0x12, NOW),
        Err(ReferencePasswordError::AuthenticationRequired)
    );
    assert_eq!(
        peer.password_login(
            AccountPasswordLoginRequest {
                attempt_id: old_attempt.attempt_id,
                auth_secret: SecretBytes::new([7; 32]),
            }
            .to_json()
            .unwrap(),
            || NOW
        ),
        Err(ReferencePasswordError::AuthenticationRequired)
    );
    let new_login = password_login(&peer, &account, 7, NOW).unwrap();
    let admission = business(&account, 1, &new_login);
    assert_eq!(
        peer.device_admission(
            body(&admission.fresh(&peer, AccountRequestIntent::Submit, NOW)),
            || NOW
        )
        .unwrap()
        .status,
        201
    );
    assert_eq!(peer.summary().unwrap().devices, 2);
    assert_eq!(snapshot(&peer, &account).credential_generation, 2);
}

#[test]
fn the_shared_capability_can_commit_only_one_consumer_across_cloned_peers() {
    for shared_token in [true, false] {
        let peer = Peer::new(ORIGIN).unwrap();
        let account = register(&peer, 1);
        let first = login(&peer, &account, NOW);
        let second = if shared_token { first.clone() } else { login(&peer, &account, NOW) };
        let change = Change::new(&account, 7, &first);
        let admission = business(&account, 1, &second);
        let change_body = change_body(&change.fresh(&peer, AccountRequestIntent::Submit, NOW));
        let admission_body = body(&admission.fresh(&peer, AccountRequestIntent::Submit, NOW));
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let (change_result, admission_result) = std::thread::scope(|scope| {
            let other = peer.clone();
            let b = barrier.clone();
            let worker = scope.spawn(move || {
                b.wait();
                other.password_change(change_body, || NOW)
            });
            barrier.wait();
            let admitted = peer.device_admission(admission_body, || NOW);
            (worker.join().unwrap(), admitted)
        });
        assert_eq!(usize::from(change_result.is_ok()) + usize::from(admission_result.is_ok()), 1);
        let denied = change_result.err().or_else(|| admission_result.err()).unwrap();
        assert_eq!(
            denied,
            if shared_token { Error::AuthenticationRequired } else { Error::AdmissionConflict }
        );
        let summary = peer.summary().unwrap();
        assert_eq!((summary.receipts, summary.admissions + summary.password_changes), (2, 1));
        assert_eq!(peer.password_summary().unwrap().capabilities, 0);
    }
}

#[test]
fn another_password_change_invalidates_an_older_snapshot_without_replacing_its_credentials() {
    let peer = Peer::new(ORIGIN).unwrap();
    let account = register(&peer, 1);
    let first = Change::new(&account, 7, &login(&peer, &account, NOW));
    let stale = Change::new(&account, 8, &login(&peer, &account, NOW));
    let original = first.submit(&peer, NOW).unwrap().confirmation;
    assert_eq!(stale.submit(&peer, NOW), Err(Error::AdmissionConflict));
    assert_eq!(peer.password_summary().unwrap().capabilities, 0);
    assert_eq!(
        password_login(&peer, &account, 8, NOW),
        Err(ReferencePasswordError::AuthenticationRequired)
    );
    let next = Change::new(&account, 9, &password_login(&peer, &account, 7, NOW).unwrap());
    assert_eq!(next.submit(&peer, NOW).unwrap().confirmation.credential_generation, 3);
    assert_eq!((peer.summary().unwrap().password_changes, peer.summary().unwrap().devices), (2, 1));
    let confirmation = first.fresh(&peer, AccountRequestIntent::Confirm, NOW);
    assert_eq!(
        peer.password_change(change_body(&confirmation), || NOW).unwrap().confirmation,
        original
    );
    assert_eq!(snapshot(&peer, &account).credential_generation, 3);
}

#[test]
fn every_business_fault_preserves_the_atomic_commit_boundary_and_exact_recovery() {
    for fault in [
        Fault::BeforeCommit,
        Fault::Audit,
        Fault::UnknownRollback,
        Fault::UnknownCommitted,
        Fault::LostResponse,
    ] {
        let peer = Peer::new(ORIGIN).unwrap();
        let account = register(&peer, 1);
        let change = Change::new(&account, 7, &login(&peer, &account, NOW));
        let request = change.fresh(&peer, AccountRequestIntent::Submit, NOW);
        let before = snapshot(&peer, &account);
        peer.set_fault(fault).unwrap();
        let error = peer.password_change(change_body(&request), || NOW).unwrap_err();
        let committed = matches!(fault, Fault::UnknownCommitted | Fault::LostResponse);
        assert_eq!(
            error,
            match fault {
                Fault::BeforeCommit | Fault::Audit => Error::StorageUnavailable,
                Fault::UnknownRollback | Fault::UnknownCommitted => Error::CommitOutcomeUnknown,
                Fault::LostResponse => Error::ResponseLost,
            }
        );
        assert_eq!(peer.summary().unwrap().password_changes, u64::from(committed));
        assert_eq!(peer.summary().unwrap().receipts, 1 + usize::from(committed));
        assert_eq!(peer.password_summary().unwrap().capabilities, usize::from(!committed));
        assert_eq!(peer.summary().unwrap().challenges, usize::from(!committed));
        if !committed {
            assert_eq!(snapshot(&peer, &account), before);
        }
        let confirmation = change.fresh(&peer, AccountRequestIntent::Confirm, NOW);
        let result = peer.password_change(change_body(&confirmation), || NOW);
        if committed {
            assert_eq!(
                (result.unwrap().status, snapshot(&peer, &account).credential_generation),
                (200, 2)
            );
        } else {
            assert_eq!(result, Err(Error::AuthenticationRequired));
            assert_eq!(snapshot(&peer, &account), before);
        }
        assert_eq!(peer.summary().unwrap().password_changes, u64::from(committed));
    }
}

#[test]
fn historical_confirmation_survives_later_changes_revocation_suspension_and_root_replacement() {
    let peer = Peer::new(ORIGIN).unwrap();
    let account = register(&peer, 1);
    let first = Change::new(&account, 7, &login(&peer, &account, NOW));
    let original = first.submit(&peer, NOW).unwrap().confirmation;
    let second = Change::new(&account, 8, &password_login(&peer, &account, 7, NOW).unwrap());
    second.submit(&peer, NOW).unwrap();
    let admission = business(&account, 1, &password_login(&peer, &account, 8, NOW).unwrap());
    peer.device_admission(body(&admission.fresh(&peer, AccountRequestIntent::Submit, NOW)), || NOW)
        .unwrap();
    revoke(&peer, &account);
    peer.set_account_active(account.payload.account_id, false).unwrap();
    peer.script_account_roots(account.payload.account_id, [9; 32], [8; 32]).unwrap();
    let peer =
        Peer::restore(peer.checkpoint().unwrap(), ORIGIN, DEFAULT_USED_ACCOUNT_ID_CEILING).unwrap();
    let request = first.fresh(&peer, AccountRequestIntent::Confirm, NOW + 600_000);
    let before = peer.summary().unwrap();
    let material = peer.account_material(account.payload.account_id).unwrap().unwrap();
    let confirmed = peer.password_change(change_body(&request), || NOW + 600_000).unwrap();
    assert_eq!((confirmed.status, confirmed.confirmation), (200, original));
    let after = peer.summary().unwrap();
    assert_eq!((after.password_changes, after.devices, after.receipts), (2, 2, 4));
    assert_eq!(after.challenges + 1, before.challenges);
    assert_eq!(
        peer.account_material(account.payload.account_id).unwrap().unwrap().bootstrap,
        material.bootstrap
    );
}

#[test]
fn receipt_only_unknown_transactions_never_claim_another_business_change() {
    for fault in [
        Fault::BeforeCommit,
        Fault::Audit,
        Fault::UnknownRollback,
        Fault::UnknownCommitted,
        Fault::LostResponse,
    ] {
        let peer = Peer::new(ORIGIN).unwrap();
        let account = register(&peer, 1);
        let change = Change::new(&account, 7, &login(&peer, &account, NOW));
        let original = change.submit(&peer, NOW).unwrap().confirmation;
        let request = change.fresh(&peer, AccountRequestIntent::Confirm, NOW);
        peer.set_fault(fault).unwrap();
        let error = peer.password_change(change_body(&request), || NOW).unwrap_err();
        assert_eq!(
            error,
            if fault == Fault::LostResponse {
                Error::ResponseLost
            } else {
                Error::StorageUnavailable
            }
        );
        if let Some(problem) = error.problem("/receipt").unwrap() {
            assert!(!problem.changed && problem.retryable);
        }
        let fresh = change.fresh(&peer, AccountRequestIntent::Confirm, NOW);
        assert_eq!(
            peer.password_change(change_body(&fresh), || NOW).unwrap().confirmation,
            original
        );
        assert_eq!(peer.summary().unwrap().password_changes, 1);
    }
}

#[test]
fn shared_receipt_quota_operation_uniqueness_and_deletion_survive_restart() {
    let peer = Peer::with_ceilings(ORIGIN, DEFAULT_USED_ACCOUNT_ID_CEILING, 3).unwrap();
    let account = register(&peer, 1);
    let initial = login(&peer, &account, NOW);
    let mut collision = Change::new(&account, 7, &initial);
    collision.payload.operation_id = account.payload.operation_id;
    collision.resign(&account.root);
    assert_eq!(collision.submit(&peer, NOW), Err(Error::AdmissionConflict));
    let first = Change::new(&account, 7, &login(&peer, &account, NOW));
    first.submit(&peer, NOW).unwrap();
    let new_login = password_login(&peer, &account, 7, NOW).unwrap();
    let mut admission = business(&account, 1, &new_login);
    admission.payload.operation_id = first.payload.operation_id;
    admission.resign(&account.root);
    assert_eq!(
        peer.device_admission(
            body(&admission.fresh(&peer, AccountRequestIntent::Submit, NOW)),
            || NOW
        ),
        Err(Error::AdmissionConflict)
    );
    let new_login = password_login(&peer, &account, 7, NOW).unwrap();
    let admission = business(&account, 1, &new_login);
    peer.device_admission(body(&admission.fresh(&peer, AccountRequestIntent::Submit, NOW)), || NOW)
        .unwrap();
    let denied = Change::new(&account, 8, &password_login(&peer, &account, 7, NOW).unwrap());
    assert_eq!(denied.submit(&peer, NOW), Err(Error::QuotaExceeded));
    let receipt =
        peer.retained_password_change_receipt(first.payload.operation_id).unwrap().unwrap();
    assert!(std::mem::size_of_val(&receipt) <= 512);
    let peer =
        Peer::restore(peer.checkpoint().unwrap(), ORIGIN, DEFAULT_USED_ACCOUNT_ID_CEILING).unwrap();
    assert_eq!(peer.summary().unwrap().receipt_ceiling, 3);
    let confirm = first.fresh(&peer, AccountRequestIntent::Confirm, NOW);
    assert_eq!(peer.password_change(change_body(&confirm), || NOW).unwrap().status, 200);
    peer.delete_account(account.payload.account_id).unwrap();
    assert_eq!((peer.summary().unwrap().receipts, peer.summary().unwrap().devices), (0, 0));
    assert!(peer.retained_password_change_receipt(first.payload.operation_id).unwrap().is_none());
    assert_eq!(peer.password_summary().unwrap().capabilities, 0);
    let confirm = first.fresh(&peer, AccountRequestIntent::Confirm, NOW);
    assert_eq!(
        peer.password_change(change_body(&confirm), || NOW),
        Err(Error::AuthenticationRequired)
    );
    assert_eq!(peer.summary().unwrap().used_account_ids, 1);
    assert_eq!(DEFAULT_ACCOUNT_RECEIPT_CEILING, 65_536);
}

fn altered_body(
    change: &Change,
    request: &AccountPasswordChangeRequest,
    root: &Ed25519SigningKey,
    fields: &[(&str, Value)],
) -> SecretVec {
    let mut envelope: serde_json::Value =
        serde_json::from_slice(&request.to_json().unwrap()).unwrap();
    let mut protected = cbor::decode(request.payload.as_bytes()).unwrap();
    let Value::Map(values) = &mut protected else { panic!("protected map") };
    for (name, replacement) in fields {
        values
            .iter_mut()
            .find(|(key, _)| key == &Value::Text((*name).into()))
            .unwrap()
            .1
            .clone_from(replacement);
    }
    let mut request = request.clone();
    request.payload = SecretVec::new(cbor::encode(&protected).unwrap());
    request.account_signature = AccountRequestSignatureInput::new(
        AccountRequestKind::PasswordChange,
        request.payload.as_bytes(),
    )
    .unwrap()
    .sign(root);
    change.proof(&mut request);
    envelope["payload"] = URL_SAFE_NO_PAD.encode(request.payload.as_bytes()).into();
    envelope["account_signature"] = URL_SAFE_NO_PAD.encode(request.account_signature).into();
    envelope["device_proof"] = URL_SAFE_NO_PAD.encode(request.device_proof).into();
    SecretVec::new(serde_json::to_vec(&envelope).unwrap())
}

#[test]
fn current_device_account_and_signature_authority_is_required_for_submission() {
    for failure in ["proof", "root", "suspended", "unadmitted", "revoked"] {
        let peer = Peer::new(ORIGIN).unwrap();
        let account = register(&peer, 1);
        let enrollment = business(&account, 1, &login(&peer, &account, NOW));
        peer.device_admission(
            body(&enrollment.fresh(&peer, AccountRequestIntent::Submit, NOW)),
            || NOW,
        )
        .unwrap();
        let mut change = Change::new(&account, 7, &login(&peer, &account, NOW));
        match failure {
            "suspended" => peer.set_account_active(account.payload.account_id, false).unwrap(),
            "unadmitted" => {
                change.payload.device_id = adjacent(change.payload.device_id, 999);
                change.resign(&account.root);
            }
            "revoked" => revoke(&peer, &account),
            "root" => change.resign(&Ed25519SigningKey::from_bytes(&key(9, 0)).unwrap()),
            "proof" => change.signer = P256SigningKey::from_bytes(&key(8, 0)).unwrap(),
            _ => unreachable!(),
        }
        let before = peer.account_material(account.payload.account_id).unwrap().unwrap();
        let request = change.fresh(&peer, AccountRequestIntent::Submit, NOW);
        assert_eq!(
            peer.password_change(change_body(&request), || NOW),
            Err(Error::AuthenticationRequired),
            "{failure}"
        );
        assert_eq!(peer.summary().unwrap().challenges, 0);
        assert_eq!(peer.summary().unwrap().denials, 1);
        assert_eq!(peer.password_summary().unwrap().capabilities, 1);
        assert_eq!(peer.summary().unwrap().password_changes, 0);
        assert_eq!(
            peer.account_material(account.payload.account_id).unwrap().unwrap().bootstrap,
            before.bootstrap
        );
    }
}

#[test]
fn stale_current_snapshots_and_non_next_generation_commit_only_denial_claims() {
    for change_kind in ["generation", "revision", "epoch", "rotation", "roots", "non-next"] {
        for audit_fault in [false, true] {
            let peer = Peer::new(ORIGIN).unwrap();
            let account = register(&peer, 1);
            let change = Change::new(&account, 7, &login(&peer, &account, NOW));
            let mut current = snapshot(&peer, &account);
            match change_kind {
                "generation" => {
                    let mut credential =
                        peer.password_credential(account.payload.account_id).unwrap();
                    credential.generation += 1;
                    current.credential_generation = credential.generation;
                    peer.script_password_state(
                        account.payload.account_id,
                        credential,
                        SecretVec::new(current.to_cbor().unwrap()),
                    )
                    .unwrap();
                }
                "revision" => {
                    let mut bundle =
                        SyncAccountKeyBundleUpdate::from_cbor(&current.key_bundle).unwrap();
                    bundle.revision += 1;
                    bundle.signature =
                        account.root.sign(&bundle.signature_input().unwrap()).to_vec();
                    current.key_bundle = bundle.to_cbor().unwrap();
                    store_snapshot(&peer, &account, &current);
                }
                "epoch" => {
                    let mut next = current.personal.epochs.last().unwrap().clone();
                    next.epoch += 1;
                    current.personal.current_epoch = next.epoch;
                    current.personal.epochs.push(next);
                    store_snapshot(&peer, &account, &current);
                }
                "rotation" => {
                    current.personal.rotation_pending = true;
                    store_snapshot(&peer, &account, &current);
                }
                "roots" => peer
                    .script_account_roots(
                        account.payload.account_id,
                        account.root.public_key(),
                        [9; 32],
                    )
                    .unwrap(),
                "non-next" => (),
                _ => unreachable!(),
            }
            let request = change.fresh(&peer, AccountRequestIntent::Submit, NOW);
            let make_body = || {
                if change_kind == "non-next" {
                    altered_body(
                        &change,
                        &request,
                        &account.root,
                        &[("new_credential_generation", Value::UInt(3))],
                    )
                } else {
                    change_body(&request)
                }
            };
            if audit_fault {
                peer.set_fault(Fault::Audit).unwrap();
            }
            let before = peer.account_material(account.payload.account_id).unwrap().unwrap();
            assert_eq!(
                peer.password_change(make_body(), || NOW),
                Err(if audit_fault { Error::StorageUnavailable } else { Error::AdmissionConflict }),
                "{change_kind}"
            );
            assert_eq!(peer.summary().unwrap().password_changes, 0);
            assert_eq!(
                peer.account_material(account.payload.account_id).unwrap().unwrap().bootstrap,
                before.bootstrap
            );
            assert_eq!(peer.summary().unwrap().denials, u64::from(!audit_fault));
            assert_eq!(peer.summary().unwrap().challenges, usize::from(audit_fault));
            assert_eq!(peer.password_summary().unwrap().capabilities, usize::from(audit_fault));
            if audit_fault {
                assert_eq!(
                    peer.password_change(make_body(), || NOW),
                    Err(Error::AdmissionConflict)
                );
                assert_eq!(peer.password_summary().unwrap().capabilities, 0);
            }
        }
    }
}

#[test]
fn malformed_requests_preserve_claims_but_wrong_intent_or_inexact_receipt_consumes_challenge() {
    let peer = Peer::new(ORIGIN).unwrap();
    let account = register(&peer, 1);
    let mut change = Change::new(&account, 7, &login(&peer, &account, NOW));
    let request = change.fresh(&peer, AccountRequestIntent::Submit, NOW);
    let malformed = altered_body(
        &change,
        &request,
        &account.root,
        &[("password_ark", Value::Bytes(vec![0; 73]))],
    );
    assert_eq!(peer.password_change(malformed, || NOW), Err(Error::InvalidRequest));
    assert_eq!((peer.summary().unwrap().challenges, peer.summary().unwrap().denials), (1, 0));
    let mut wrong_intent = request.clone();
    wrong_intent.intent = AccountRequestIntent::Confirm;
    wrong_intent.admission_token = None;
    change.proof(&mut wrong_intent);
    assert_eq!(
        peer.password_change(change_body(&wrong_intent), || NOW),
        Err(Error::AuthenticationRequired)
    );
    assert_eq!(peer.password_summary().unwrap().capabilities, 1);
    let original = change.submit(&peer, NOW).unwrap().confirmation;
    change.payload.password_salt = [99; 16];
    change.resign(&account.root);
    let substituted = change.fresh(&peer, AccountRequestIntent::Confirm, NOW);
    assert_eq!(
        peer.password_change(change_body(&substituted), || NOW),
        Err(Error::AuthenticationRequired)
    );
    let receipt =
        peer.retained_password_change_receipt(change.payload.operation_id).unwrap().unwrap();
    assert_eq!(receipt.confirmation, original);
    assert_eq!(
        (peer.summary().unwrap().password_changes, peer.summary().unwrap().receipts),
        (1, 2)
    );
}

#[test]
fn positive_u64_generation_successor_is_preserved_and_expiry_is_rechecked_at_commit() {
    let peer = Peer::new(ORIGIN).unwrap();
    let account = register(&peer, 1);
    let mut current = snapshot(&peer, &account);
    current.credential_generation = u64::MAX - 1;
    let mut credential = peer.password_credential(account.payload.account_id).unwrap();
    credential.generation = current.credential_generation;
    peer.script_password_state(
        account.payload.account_id,
        credential,
        SecretVec::new(current.to_cbor().unwrap()),
    )
    .unwrap();
    let login = login(&peer, &account, NOW);
    let change = Change::new(&account, 7, &login);
    let request = change.fresh(&peer, AccountRequestIntent::Submit, NOW);
    let mut reads = 0;
    assert_eq!(
        peer.password_change(change_body(&request), || {
            reads += 1;
            if reads < 3 { NOW } else { NOW + 120_000 }
        }),
        Err(Error::AuthenticationRequired)
    );
    assert_eq!(snapshot(&peer, &account).credential_generation, u64::MAX - 1);
    assert_eq!(peer.password_summary().unwrap().capabilities, 1);
    let result = change.submit(&peer, NOW + 120_000).unwrap();
    assert_eq!(result.confirmation.credential_generation, u64::MAX);
    let login = password_login(&peer, &account, 7, NOW + 120_000).unwrap();
    assert_eq!(
        AccountBootstrapSnapshot::from_cbor(login.snapshot.as_bytes())
            .unwrap()
            .credential_generation,
        u64::MAX
    );
    let confirmation = change.fresh(&peer, AccountRequestIntent::Confirm, NOW + 120_000);
    assert_eq!(
        peer.password_change(change_body(&confirmation), || NOW + 120_000).unwrap().confirmation,
        result.confirmation
    );
}
