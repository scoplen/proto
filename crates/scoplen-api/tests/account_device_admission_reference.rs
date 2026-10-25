// SPDX-License-Identifier: Apache-2.0
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use scoplen_api::{
    account_admission::{
        AccountBootstrapSnapshot, AccountDeviceAdmissionPayload, AccountDeviceAdmissionRequest,
        AccountPasswordLoginRequest, AccountPasswordLoginResponse, AccountPasswordOptionsRequest,
        AccountRegistrationPayload, AccountRegistrationRequest, AccountRequestChallengeRequest,
        AccountRequestIntent, AccountRequestKind,
    },
    account_registration_reference::{
        DEFAULT_ACCOUNT_RECEIPT_CEILING, DEFAULT_USED_ACCOUNT_ID_CEILING,
        ReferenceAccountRegistrationPeer as Peer, ReferenceDeviceAdmissionError as Error,
        ReferencePasswordError, ReferenceRegistrationFault as Fault,
    },
    sync::{SyncAccountDeviceWrap, SyncAccountKeyBundle, SyncAccountKeyBundleUpdate},
};
use scoplen_crypto::{
    AccountRequestProof, AccountRequestSignatureInput, DeviceCertificate, Ed25519SigningKey,
    P256SigningKey, RevocationStatement, SecretBytes, SecretVec, account_bootstrap_digest,
    account_capability_digest,
};
use scoplen_model::cbor::{self, Value};
use scoplen_test_vectors::VectorDocument;
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

fn submit(
    peer: &Peer,
    business: &Business,
) -> scoplen_api::account_registration_reference::ReferenceDeviceAdmissionResult {
    peer.device_admission(body(&business.fresh(peer, AccountRequestIntent::Submit, NOW)), || NOW)
        .unwrap()
}

fn stored_snapshot(peer: &Peer, account: &Account) -> AccountBootstrapSnapshot {
    AccountBootstrapSnapshot::from_cbor(
        peer.account_material(account.payload.account_id).unwrap().unwrap().bootstrap.as_bytes(),
    )
    .unwrap()
}

fn store_snapshot(peer: &Peer, account: &Account, snapshot: &AccountBootstrapSnapshot) {
    let credential = peer.password_credential(account.payload.account_id).unwrap();
    peer.script_password_state(
        account.payload.account_id,
        credential,
        SecretVec::new(snapshot.to_cbor().unwrap()),
    )
    .unwrap();
}

fn set_device_keys(
    business: &mut Business,
    account: &Account,
    signer: P256SigningKey,
    kem: Vec<u8>,
) {
    let certificate = DeviceCertificate::decode(&business.payload.device_certificate).unwrap();
    business.payload.device_certificate = DeviceCertificate::issue(
        &account.root,
        certificate.device_id,
        certificate.account_id,
        signer.public_key_sec1(),
        kem,
        certificate.display_name,
        certificate.platform,
        certificate.created_at,
    )
    .unwrap()
    .encode()
    .unwrap();
    business.signer = signer;
    business.resign(&account.root);
}

fn protected_field<'a>(value: &'a mut Value, name: &str) -> &'a mut Value {
    let Value::Map(fields) = value else { panic!("protected map") };
    &mut fields.iter_mut().find(|(key, _)| key == &Value::Text(name.into())).unwrap().1
}

fn malformed_body(request: &AccountDeviceAdmissionRequest, field: &str) -> SecretVec {
    let mut payload = cbor::decode(request.payload.as_bytes()).unwrap();
    *protected_field(&mut payload, field) = Value::Bytes(vec![0xff]);
    let mut envelope: serde_json::Value =
        serde_json::from_slice(&request.to_json().unwrap()).unwrap();
    envelope["payload"] = URL_SAFE_NO_PAD.encode(cbor::encode(&payload).unwrap()).into();
    SecretVec::new(serde_json::to_vec(&envelope).unwrap())
}

fn signed_protected_body(
    business: &Business,
    request: &AccountDeviceAdmissionRequest,
    root: &Ed25519SigningKey,
    field: &str,
    replacement: Value,
) -> SecretVec {
    let mut envelope: serde_json::Value =
        serde_json::from_slice(&request.to_json().unwrap()).unwrap();
    let mut payload = cbor::decode(request.payload.as_bytes()).unwrap();
    *protected_field(&mut payload, field) = replacement;
    let mut request = request.clone();
    request.payload = SecretVec::new(cbor::encode(&payload).unwrap());
    request.account_signature =
        AccountRequestSignatureInput::new(AccountRequestKind::Admit, request.payload.as_bytes())
            .unwrap()
            .sign(root);
    business.sign_proof(&mut request);
    envelope["payload"] = URL_SAFE_NO_PAD.encode(request.payload.as_bytes()).into();
    envelope["account_signature"] = URL_SAFE_NO_PAD.encode(request.account_signature).into();
    envelope["device_proof"] = URL_SAFE_NO_PAD.encode(request.device_proof).into();
    SecretVec::new(serde_json::to_vec(&envelope).unwrap())
}

fn large_certificate(account: &Account, certificate: &DeviceCertificate) -> Vec<u8> {
    let issue = |display_name| {
        DeviceCertificate::issue(
            &account.root,
            certificate.device_id,
            certificate.account_id,
            certificate.signing_public_key.clone(),
            certificate.kem_public_key.clone(),
            display_name,
            certificate.platform.clone(),
            certificate.created_at,
        )
        .unwrap()
        .encode()
        .unwrap()
    };
    let initial = issue("x".repeat(65_000));
    let encoded = issue("x".repeat(65_000 + 65_535 - initial.len()));
    assert_eq!(encoded.len(), 65_535);
    encoded
}

#[test]
fn admission_publishes_exact_complete_state_and_confirms_only_the_original_receipt() {
    let peer = Peer::with_ceilings(ORIGIN, 1, 3).unwrap();
    let account = register(&peer, 0);
    let login = login(&peer, &account, NOW);
    let before = AccountBootstrapSnapshot::from_cbor(login.snapshot.as_bytes()).unwrap();
    let business = business(&account, 0, &login);
    let result = submit(&peer, &business);
    assert_eq!(result.status, 201);
    result
        .confirmation
        .validate_for_request(
            AccountRequestKind::Admit,
            business.request.payload.as_bytes(),
            &business.request.account_signature,
        )
        .unwrap();
    let summary = peer.summary().unwrap();
    assert_eq!((summary.accounts, summary.vaults, summary.devices, summary.receipts), (1, 1, 2, 2));
    assert_eq!((summary.registrations, summary.admissions, summary.used_account_ids), (1, 1, 1));
    assert_eq!(peer.password_summary().unwrap().capabilities, 0);
    let snapshot = stored_snapshot(&peer, &account);
    assert_eq!(snapshot.certificates.len(), 2);
    assert!(snapshot.certificates.contains(&business.payload.device_certificate));
    assert_eq!(snapshot.key_bundle, business.payload.key_bundle);
    assert_eq!(snapshot.personal, before.personal);
    assert_eq!(snapshot.password_ark, before.password_ark);
    assert_eq!(snapshot.password_salt, before.password_salt);
    let receipt = peer.retained_receipt(business.payload.operation_id).unwrap().unwrap();
    assert_eq!(receipt.confirmation, result.confirmation);
    assert_eq!(receipt.account_root, account.root.public_key());
    assert_eq!(receipt.signing_key.as_slice(), business.signer.public_key_sec1());
    let old = SyncAccountKeyBundleUpdate::from_cbor(&before.key_bundle).unwrap();
    let new = SyncAccountKeyBundleUpdate::from_cbor(&snapshot.key_bundle).unwrap();
    assert_eq!((old.revision, new.revision), (1, 2));
    assert_eq!(new.device_wraps[0], old.device_wraps[0]);
    let confirmation = business.fresh(&peer, AccountRequestIntent::Confirm, NOW + 600_000);
    assert!(confirmation.admission_token.is_none());
    let result_again = peer.device_admission(body(&confirmation), || NOW + 600_000).unwrap();
    assert_eq!((result_again.status, result_again.confirmation), (200, result.confirmation));
    assert_eq!(peer.summary().unwrap().admissions, 1);
}

#[test]
fn admission_commit_faults_and_restart_never_split_device_bundle_receipt_capability_or_audit() {
    for (fault, expected, committed) in [
        (Fault::BeforeCommit, Error::StorageUnavailable, false),
        (Fault::Audit, Error::StorageUnavailable, false),
        (Fault::UnknownRollback, Error::CommitOutcomeUnknown, false),
        (Fault::UnknownCommitted, Error::CommitOutcomeUnknown, true),
        (Fault::LostResponse, Error::ResponseLost, true),
    ] {
        let peer = Peer::new(ORIGIN).unwrap();
        let account = register(&peer, 0);
        let login = login(&peer, &account, NOW);
        let business = business(&account, 0, &login);
        let request = business.fresh(&peer, AccountRequestIntent::Submit, NOW);
        peer.set_fault(fault).unwrap();
        assert_eq!(peer.device_admission(body(&request), || NOW), Err(expected));
        let peer =
            Peer::restore(peer.checkpoint().unwrap(), ORIGIN, DEFAULT_USED_ACCOUNT_ID_CEILING)
                .unwrap();
        let summary = peer.summary().unwrap();
        assert_eq!(
            (summary.devices, summary.receipts, summary.admissions),
            (1 + usize::from(committed), 1 + usize::from(committed), u64::from(committed))
        );
        assert_eq!(peer.password_summary().unwrap().capabilities, usize::from(!committed));
        let snapshot = stored_snapshot(&peer, &account);
        assert_eq!(snapshot.certificates.len(), 1 + usize::from(committed));
        let expected_bundle =
            if committed { &business.payload.key_bundle } else { &account.payload.key_bundle };
        assert_eq!(&snapshot.key_bundle, expected_bundle);
        let confirm = business.fresh(&peer, AccountRequestIntent::Confirm, NOW);
        let result = peer.device_admission(body(&confirm), || NOW);
        if committed {
            assert_eq!(result.unwrap().status, 200);
            assert_eq!(peer.summary().unwrap().admissions, 1);
        } else {
            assert_eq!(result, Err(Error::AuthenticationRequired));
            assert_eq!(peer.summary().unwrap().devices, 1);
            assert!(peer.retained_receipt(business.payload.operation_id).unwrap().is_none());
        }
    }
}

#[test]
fn denied_possession_commit_faults_preserve_the_capability_and_atomic_challenge_audit() {
    for (fault, expected, consumed) in [
        (Fault::BeforeCommit, Error::StorageUnavailable, false),
        (Fault::Audit, Error::StorageUnavailable, false),
        (Fault::UnknownRollback, Error::StorageUnavailable, false),
        (Fault::UnknownCommitted, Error::StorageUnavailable, true),
        (Fault::LostResponse, Error::ResponseLost, true),
    ] {
        let peer = Peer::new(ORIGIN).unwrap();
        let account = register(&peer, 0);
        let business = business(&account, 0, &login(&peer, &account, NOW));
        let mut request = business.fresh(&peer, AccountRequestIntent::Submit, NOW);
        request.device_proof[0] ^= 1;
        peer.set_fault(fault).unwrap();
        assert_eq!(peer.device_admission(body(&request), || NOW), Err(expected));
        let peer =
            Peer::restore(peer.checkpoint().unwrap(), ORIGIN, DEFAULT_USED_ACCOUNT_ID_CEILING)
                .unwrap();
        let summary = peer.summary().unwrap();
        assert_eq!((summary.devices, summary.receipts, summary.admissions), (1, 1, 0));
        assert_eq!(
            (summary.challenges, summary.denials),
            (usize::from(!consumed), u64::from(consumed))
        );
        assert_eq!(peer.password_summary().unwrap().capabilities, 1);
    }
}

#[test]
fn two_instances_cannot_spend_the_same_capability_for_different_devices() {
    let peer = Peer::new(ORIGIN).unwrap();
    let account = register(&peer, 0);
    let login = login(&peer, &account, NOW);
    let left = business(&account, 0, &login).fresh(&peer, AccountRequestIntent::Submit, NOW);
    let right = business(&account, 1, &login).fresh(&peer, AccountRequestIntent::Submit, NOW);
    let results = std::thread::scope(|scope| {
        let workers: Vec<_> = [left, right]
            .into_iter()
            .map(|request| {
                let instance = peer.clone();
                scope.spawn(move || instance.device_admission(body(&request), || NOW))
            })
            .collect();
        workers.into_iter().map(|worker| worker.join().unwrap()).collect::<Vec<_>>()
    });
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results.iter().filter(|result| **result == Err(Error::AuthenticationRequired)).count(),
        1
    );
    let summary = peer.summary().unwrap();
    assert_eq!(
        (summary.devices, summary.receipts, summary.admissions, summary.denials),
        (2, 2, 1, 1)
    );
    assert_eq!(peer.password_summary().unwrap().capabilities, 0);
}

#[test]
fn two_capabilities_for_one_snapshot_cannot_both_publish_the_next_revision() {
    let peer = Peer::new(ORIGIN).unwrap();
    let account = register(&peer, 0);
    let left = business(&account, 0, &login(&peer, &account, NOW));
    let right = business(&account, 1, &login(&peer, &account, NOW));
    let requests = [
        left.fresh(&peer, AccountRequestIntent::Submit, NOW),
        right.fresh(&peer, AccountRequestIntent::Submit, NOW),
    ];
    let results = std::thread::scope(|scope| {
        let workers: Vec<_> = requests
            .into_iter()
            .map(|request| {
                let instance = peer.clone();
                scope.spawn(move || instance.device_admission(body(&request), || NOW))
            })
            .collect();
        workers.into_iter().map(|worker| worker.join().unwrap()).collect::<Vec<_>>()
    });
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results.iter().filter(|result| **result == Err(Error::AdmissionConflict)).count(),
        1
    );
    let summary = peer.summary().unwrap();
    assert_eq!(
        (summary.devices, summary.receipts, summary.admissions, summary.denials),
        (2, 2, 1, 1)
    );
    assert_eq!(peer.password_summary().unwrap().capabilities, 0);
}

#[test]
fn historical_confirmation_uses_original_keys_after_current_authority_changes() {
    for change in ["suspend", "generation", "rotation", "revoke", "roots"] {
        let peer = Peer::new(ORIGIN).unwrap();
        let account = register(&peer, 0);
        let business = business(&account, 0, &login(&peer, &account, NOW));
        let original = submit(&peer, &business).confirmation;
        peer.set_registration_enabled(false).unwrap();
        let mut snapshot = stored_snapshot(&peer, &account);
        match change {
            "suspend" => peer.set_account_active(account.payload.account_id, false).unwrap(),
            "generation" => {
                let mut credential = peer.password_credential(account.payload.account_id).unwrap();
                credential.generation = 2;
                snapshot.credential_generation = 2;
                peer.script_password_state(
                    account.payload.account_id,
                    credential,
                    SecretVec::new(snapshot.to_cbor().unwrap()),
                )
                .unwrap();
            }
            "rotation" => {
                snapshot.personal.rotation_pending = true;
                store_snapshot(&peer, &account, &snapshot);
            }
            "revoke" => {
                snapshot.revocations.push(
                    RevocationStatement::issue(
                        &account.root,
                        business.payload.device_id,
                        NOW,
                        "fixture".into(),
                    )
                    .unwrap()
                    .encode()
                    .unwrap(),
                );
                let mut bundle =
                    SyncAccountKeyBundleUpdate::from_cbor(&snapshot.key_bundle).unwrap();
                bundle.device_wraps.retain(|wrap| wrap.device_id != business.payload.device_id);
                bundle.revision += 1;
                bundle.signature = account.root.sign(&bundle.signature_input().unwrap()).to_vec();
                snapshot.key_bundle = bundle.to_cbor().unwrap();
                store_snapshot(&peer, &account, &snapshot);
            }
            "roots" => peer
                .script_account_roots(
                    account.payload.account_id,
                    Ed25519SigningKey::from_bytes(&key(8, 0)).unwrap().public_key(),
                    [9; 32],
                )
                .unwrap(),
            _ => unreachable!(),
        }
        let before = peer.summary().unwrap();
        let confirmation = business.fresh(&peer, AccountRequestIntent::Confirm, NOW + 600_000);
        let result = peer.device_admission(body(&confirmation), || NOW + 600_000).unwrap();
        assert_eq!((result.status, result.confirmation), (200, original));
        assert_eq!(peer.summary().unwrap(), before);
    }
}

#[test]
fn current_snapshot_conflicts_consume_only_capability_challenge_and_denial_audit_atomically() {
    for change in ["generation", "salt", "revision", "epoch", "rotation", "roots"] {
        let peer = Peer::new(ORIGIN).unwrap();
        let account = register(&peer, 0);
        let business = business(&account, 0, &login(&peer, &account, NOW));
        let mut snapshot = stored_snapshot(&peer, &account);
        let mut credential = peer.password_credential(account.payload.account_id).unwrap();
        match change {
            "generation" => {
                credential.generation = 2;
                snapshot.credential_generation = 2;
            }
            "salt" => {
                credential.salt[0] ^= 1;
                snapshot.password_salt = credential.salt;
            }
            "revision" => {
                let mut bundle =
                    SyncAccountKeyBundleUpdate::from_cbor(&snapshot.key_bundle).unwrap();
                bundle.revision += 1;
                bundle.signature = account.root.sign(&bundle.signature_input().unwrap()).to_vec();
                snapshot.key_bundle = bundle.to_cbor().unwrap();
            }
            "epoch" => {
                let mut next = snapshot.personal.epochs[0].clone();
                next.epoch = 2;
                snapshot.personal.epochs.push(next);
                snapshot.personal.current_epoch = 2;
            }
            "rotation" => snapshot.personal.rotation_pending = true,
            "roots" => {
                let next = Ed25519SigningKey::from_bytes(&key(8, 0)).unwrap();
                snapshot.account_signing_public_key = next.public_key();
                snapshot.certificates = snapshot
                    .certificates
                    .iter()
                    .map(|encoded| {
                        let certificate = DeviceCertificate::decode(encoded).unwrap();
                        DeviceCertificate::issue(
                            &next,
                            certificate.device_id,
                            certificate.account_id,
                            certificate.signing_public_key,
                            certificate.kem_public_key,
                            certificate.display_name,
                            certificate.platform,
                            certificate.created_at,
                        )
                        .unwrap()
                        .encode()
                        .unwrap()
                    })
                    .collect();
                let mut bundle =
                    SyncAccountKeyBundleUpdate::from_cbor(&snapshot.key_bundle).unwrap();
                bundle.signature = next.sign(&bundle.signature_input().unwrap()).to_vec();
                snapshot.key_bundle = bundle.to_cbor().unwrap();
            }
            _ => unreachable!(),
        }
        let expected = snapshot.to_cbor().unwrap();
        peer.script_password_state(
            account.payload.account_id,
            credential,
            SecretVec::new(expected.clone()),
        )
        .unwrap();
        let request = business.fresh(&peer, AccountRequestIntent::Submit, NOW);
        peer.set_fault(Fault::Audit).unwrap();
        assert_eq!(peer.device_admission(body(&request), || NOW), Err(Error::StorageUnavailable));
        let summary = peer.summary().unwrap();
        assert_eq!(
            (summary.devices, summary.receipts, summary.challenges, summary.denials),
            (1, 1, 1, 0)
        );
        assert_eq!(peer.password_summary().unwrap().capabilities, 1);
        assert_eq!(peer.device_admission(body(&request), || NOW), Err(Error::AdmissionConflict));
        let summary = peer.summary().unwrap();
        assert_eq!(
            (summary.devices, summary.receipts, summary.challenges, summary.denials),
            (1, 1, 0, 1)
        );
        assert_eq!(peer.password_summary().unwrap().capabilities, 0);
        assert_eq!(stored_snapshot(&peer, &account).to_cbor().unwrap(), expected);
    }
}

#[test]
fn nonnext_revision_changed_old_wrap_or_recovery_artifact_invalidates_the_capability() {
    for change in ["revision", "wrap", "root-artifact", "recovery"] {
        let peer = Peer::new(ORIGIN).unwrap();
        let account = register(&peer, 0);
        let mut business = business(&account, 0, &login(&peer, &account, NOW));
        let mut bundle =
            SyncAccountKeyBundleUpdate::from_cbor(&business.payload.key_bundle).unwrap();
        match change {
            "revision" => bundle.revision += 1,
            "wrap" => *bundle.device_wraps[0].wrapped_ark.last_mut().unwrap() ^= 1,
            "root-artifact" => *bundle.account_signing_key.last_mut().unwrap() ^= 1,
            "recovery" => *bundle.recovery_blob.last_mut().unwrap() ^= 1,
            _ => unreachable!(),
        }
        bundle.signature = account.root.sign(&bundle.signature_input().unwrap()).to_vec();
        business.payload.key_bundle = bundle.to_cbor().unwrap();
        business.resign(&account.root);
        let request = business.fresh(&peer, AccountRequestIntent::Submit, NOW);
        assert_eq!(peer.device_admission(body(&request), || NOW), Err(Error::AdmissionConflict));
        let summary = peer.summary().unwrap();
        assert_eq!(
            (summary.devices, summary.receipts, summary.admissions, summary.denials),
            (1, 1, 0, 1)
        );
        assert_eq!(peer.password_summary().unwrap().capabilities, 0);
        assert_eq!(stored_snapshot(&peer, &account).key_bundle, account.payload.key_bundle);
    }
}

#[test]
fn wrong_bindings_and_all_signature_layers_share_denial_without_consuming_a_valid_capability() {
    for change in ["outer", "proof", "certificate", "bundle", "capability", "snapshot", "nonce"] {
        let peer = Peer::new(ORIGIN).unwrap();
        let account = register(&peer, 0);
        let mut business = business(&account, 0, &login(&peer, &account, NOW));
        match change {
            "certificate" => {
                let mut cert =
                    DeviceCertificate::decode(&business.payload.device_certificate).unwrap();
                cert.signature[0] ^= 1;
                business.payload.device_certificate = cert.encode().unwrap();
            }
            "bundle" => {
                let mut bundle =
                    SyncAccountKeyBundleUpdate::from_cbor(&business.payload.key_bundle).unwrap();
                bundle.signature[0] ^= 1;
                business.payload.key_bundle = bundle.to_cbor().unwrap();
            }
            "capability" => business.payload.capability_digest[0] ^= 1,
            "snapshot" => business.payload.snapshot_digest[0] ^= 1,
            _ => {}
        }
        business.resign(&account.root);
        let mut request = business.fresh(&peer, AccountRequestIntent::Submit, NOW);
        match change {
            "outer" => request.account_signature[0] ^= 1,
            "proof" => request.device_proof[0] ^= 1,
            "nonce" => request.nonce = SecretBytes::new([0; 32]),
            _ => {}
        }
        assert_eq!(
            peer.device_admission(body(&request), || NOW),
            Err(Error::AuthenticationRequired)
        );
        let summary = peer.summary().unwrap();
        assert_eq!(
            (summary.devices, summary.receipts, summary.challenges, summary.denials),
            (1, 1, 0, 1)
        );
        assert_eq!(peer.password_summary().unwrap().capabilities, 1);
    }
}

#[test]
fn receipt_lifetime_capacity_uses_real_submissions_and_does_not_disable_existing_services() {
    assert!(Peer::with_ceilings(ORIGIN, 1, 0).is_err());
    assert!(Peer::with_ceilings(ORIGIN, 1, DEFAULT_ACCOUNT_RECEIPT_CEILING + 1).is_err());
    assert_eq!(Peer::new(ORIGIN).unwrap().summary().unwrap().receipt_ceiling, 65_536);
    let peer = Peer::with_ceilings(ORIGIN, 1, 3).unwrap();
    let account = register(&peer, 0);
    let mut committed = Vec::new();
    for sequence in 0..2 {
        let business = business(&account, sequence, &login(&peer, &account, NOW));
        submit(&peer, &business);
        committed.push(business);
        assert_eq!(peer.password_summary().unwrap().capabilities, 0);
    }
    let business = business(&account, 2, &login(&peer, &account, NOW));
    let request = business.fresh(&peer, AccountRequestIntent::Submit, NOW);
    assert_eq!(peer.device_admission(body(&request), || NOW), Err(Error::QuotaExceeded));
    let peer = Peer::restore(peer.checkpoint().unwrap(), ORIGIN, 1).unwrap();
    let summary = peer.summary().unwrap();
    assert_eq!(
        (summary.receipt_ceiling, summary.receipts, summary.devices, summary.admissions),
        (3, 3, 3, 2)
    );
    assert_eq!(summary.used_account_ids, 1);
    assert!(peer.retained_receipt(business.payload.operation_id).unwrap().is_none());
    let confirm = committed[0].fresh(&peer, AccountRequestIntent::Confirm, NOW);
    assert_eq!(peer.device_admission(body(&confirm), || NOW).unwrap().status, 200);
    login(&peer, &account, NOW);
    assert_eq!(peer.summary().unwrap().admissions, 2);
}

#[test]
fn request_challenge_and_capability_expiry_are_reread_before_commit_and_survive_restart() {
    for expire_capability in [false, true] {
        let peer = Peer::new(ORIGIN).unwrap();
        let account = register(&peer, 0);
        let business = business(&account, 0, &login(&peer, &account, NOW));
        let started = if expire_capability { NOW + 299_999 } else { NOW };
        let request = business.fresh(&peer, AccountRequestIntent::Submit, started);
        let end = if expire_capability { NOW + 300_000 } else { NOW + 120_000 };
        let mut times = [started, started, end].into_iter();
        assert_eq!(
            peer.device_admission(body(&request), || times.next().unwrap()),
            Err(Error::AuthenticationRequired)
        );
        let peer =
            Peer::restore(peer.checkpoint().unwrap(), ORIGIN, DEFAULT_USED_ACCOUNT_ID_CEILING)
                .unwrap();
        assert_eq!(peer.summary().unwrap().admissions, 0);
        assert_eq!(
            peer.device_admission(body(&request), || NOW - 1),
            Err(Error::AuthenticationRequired)
        );
        let fresh = business.fresh(&peer, AccountRequestIntent::Submit, NOW - 1);
        let result = peer.device_admission(body(&fresh), || NOW - 1);
        if expire_capability {
            assert_eq!(result, Err(Error::AuthenticationRequired));
        } else {
            assert_eq!(result.unwrap().status, 201);
        }
    }
}

#[test]
fn confirmation_cannot_borrow_registration_receipts_or_fall_through_after_deletion() {
    let peer = Peer::new(ORIGIN).unwrap();
    let account = register(&peer, 0);
    let login = login(&peer, &account, NOW);
    let mut borrowed = business(&account, 0, &login);
    borrowed.payload.operation_id = account.payload.operation_id;
    borrowed.resign(&account.root);
    let confirm = borrowed.fresh(&peer, AccountRequestIntent::Confirm, NOW);
    assert_eq!(peer.device_admission(body(&confirm), || NOW), Err(Error::AuthenticationRequired));
    let original = business(&account, 1, &login);
    submit(&peer, &original);
    peer.delete_account(account.payload.account_id).unwrap();
    let confirm = original.fresh(&peer, AccountRequestIntent::Confirm, NOW);
    assert_eq!(peer.device_admission(body(&confirm), || NOW), Err(Error::AuthenticationRequired));
    let summary = peer.summary().unwrap();
    assert_eq!(
        (
            summary.accounts,
            summary.vaults,
            summary.devices,
            summary.receipts,
            summary.used_account_ids
        ),
        (0, 0, 0, 0, 1)
    );
}

#[test]
fn deployment_freshness_rejects_both_key_roles_and_account_deletion_removes_their_indexes() {
    for role in 0..4 {
        let peer = Peer::new(ORIGIN).unwrap();
        let owner = register(&peer, 0);
        let old = business(&owner, 0, &login(&peer, &owner, NOW));
        submit(&peer, &old);
        let target = register(&peer, 1);
        let signing_seed = match role {
            0 => key(4, 0),
            1 => key(5, 0),
            _ => key(4, 16),
        };
        let kem_seed = match role {
            2 => key(4, 0),
            3 => key(5, 0),
            _ => key(5, 16),
        };
        for retained in [true, false] {
            if !retained {
                peer.delete_account(owner.payload.account_id).unwrap();
                assert!(peer.retained_receipt(old.payload.operation_id).unwrap().is_none());
                assert!(peer.retained_receipt(owner.payload.operation_id).unwrap().is_none());
            }
            let mut candidate = business(&target, 0, &login(&peer, &target, NOW));
            set_device_keys(
                &mut candidate,
                &target,
                P256SigningKey::from_bytes(&signing_seed).unwrap(),
                P256SigningKey::from_bytes(&kem_seed).unwrap().public_key_sec1(),
            );
            let request = candidate.fresh(&peer, AccountRequestIntent::Submit, NOW);
            let result = peer.device_admission(body(&request), || NOW);
            if retained {
                assert_eq!(result, Err(Error::AdmissionConflict));
            } else {
                assert_eq!(result.unwrap().status, 201);
                let summary = peer.summary().unwrap();
                assert_eq!(
                    (summary.accounts, summary.devices, summary.receipts, summary.used_account_ids),
                    (1, 2, 2, 2)
                );
            }
        }
    }
}

#[test]
fn fixture_shared_registration_keys_remain_reserved_until_all_receipt_owners_are_deleted() {
    let peer = Peer::new(ORIGIN).unwrap();
    let owner = register(&peer, 0);
    let other_owner = register_with_device_keys(&peer, 2, 0);
    let target = register(&peer, 1);
    for owners_remaining in [2, 1, 0] {
        if owners_remaining == 1 {
            peer.delete_account(owner.payload.account_id).unwrap();
        } else if owners_remaining == 0 {
            peer.delete_account(other_owner.payload.account_id).unwrap();
        }
        let mut candidate = business(&target, 0, &login(&peer, &target, NOW));
        set_device_keys(
            &mut candidate,
            &target,
            P256SigningKey::from_bytes(&key(2, 0)).unwrap(),
            P256SigningKey::from_bytes(&key(5, 16)).unwrap().public_key_sec1(),
        );
        let request = candidate.fresh(&peer, AccountRequestIntent::Submit, NOW);
        let result = peer.device_admission(body(&request), || NOW);
        if owners_remaining == 0 {
            assert_eq!(result.unwrap().status, 201);
        } else {
            assert_eq!(result, Err(Error::AdmissionConflict));
        }
    }
    assert_eq!(peer.summary().unwrap().used_account_ids, 3);
}

#[test]
fn original_admission_keys_remain_reserved_after_their_certificate_is_no_longer_current() {
    let peer = Peer::new(ORIGIN).unwrap();
    let account = register(&peer, 0);
    let original = business(&account, 0, &login(&peer, &account, NOW));
    submit(&peer, &original);
    let mut snapshot = stored_snapshot(&peer, &account);
    snapshot.certificates.retain(|certificate| certificate != &original.payload.device_certificate);
    let mut bundle = SyncAccountKeyBundleUpdate::from_cbor(&snapshot.key_bundle).unwrap();
    bundle.device_wraps.retain(|wrap| wrap.device_id != original.payload.device_id);
    bundle.revision += 1;
    bundle.signature = account.root.sign(&bundle.signature_input().unwrap()).to_vec();
    snapshot.key_bundle = bundle.to_cbor().unwrap();
    store_snapshot(&peer, &account, &snapshot);
    let mut candidate = business(&account, 1, &login(&peer, &account, NOW));
    set_device_keys(
        &mut candidate,
        &account,
        P256SigningKey::from_bytes(&key(4, 0)).unwrap(),
        P256SigningKey::from_bytes(&key(5, 1)).unwrap().public_key_sec1(),
    );
    let request = candidate.fresh(&peer, AccountRequestIntent::Submit, NOW);
    assert_eq!(peer.device_admission(body(&request), || NOW), Err(Error::AdmissionConflict));
    assert!(peer.retained_receipt(original.payload.operation_id).unwrap().is_some());
    assert_eq!(peer.summary().unwrap().admissions, 1);
}

#[test]
fn malformed_nested_artifacts_fail_before_challenge_or_fault_consumption() {
    for field in ["device_certificate", "key_bundle"] {
        let peer = Peer::new(ORIGIN).unwrap();
        let account = register(&peer, 0);
        let business = business(&account, 0, &login(&peer, &account, NOW));
        let request = business.fresh(&peer, AccountRequestIntent::Submit, NOW);
        peer.set_fault(Fault::Audit).unwrap();
        assert_eq!(
            peer.device_admission(malformed_body(&request, field), || NOW),
            Err(Error::InvalidRequest)
        );
        let before = peer.summary().unwrap();
        assert_eq!((before.challenges, before.denials, before.admissions), (1, 0, 0));
        let mut denied = request.clone();
        denied.device_proof[0] ^= 1;
        assert_eq!(peer.device_admission(body(&denied), || NOW), Err(Error::StorageUnavailable));
        assert_eq!(peer.summary().unwrap(), before);
        assert_eq!(peer.password_summary().unwrap().capabilities, 1);
        assert_eq!(peer.device_admission(body(&request), || NOW).unwrap().status, 201);
    }
}

#[test]
fn signed_inner_identity_mismatches_are_transactional_denials_after_structural_decoding() {
    for field in ["account", "device"] {
        let peer = Peer::new(ORIGIN).unwrap();
        let account = register(&peer, 0);
        let business = business(&account, 0, &login(&peer, &account, NOW));
        let certificate = DeviceCertificate::decode(&business.payload.device_certificate).unwrap();
        let account_id = if field == "account" {
            adjacent(certificate.account_id, 40)
        } else {
            certificate.account_id
        };
        let device_id = if field == "device" {
            adjacent(certificate.device_id, 40)
        } else {
            certificate.device_id
        };
        let certificate = DeviceCertificate::issue(
            &account.root,
            device_id,
            account_id,
            certificate.signing_public_key,
            certificate.kem_public_key,
            certificate.display_name,
            certificate.platform,
            certificate.created_at,
        )
        .unwrap()
        .encode()
        .unwrap();
        let request = business.fresh(&peer, AccountRequestIntent::Submit, NOW);
        let encoded = signed_protected_body(
            &business,
            &request,
            &account.root,
            "device_certificate",
            Value::Bytes(certificate),
        );
        assert!(AccountDeviceAdmissionRequest::from_json(encoded.as_bytes()).is_err());
        assert!(
            AccountDeviceAdmissionRequest::decode_for_authentication(encoded.as_bytes()).is_ok()
        );
        assert_eq!(peer.device_admission(encoded, || NOW), Err(Error::AuthenticationRequired));
        let summary = peer.summary().unwrap();
        assert_eq!(
            (summary.challenges, summary.denials, summary.devices, summary.receipts),
            (0, 1, 1, 1)
        );
        assert_eq!(peer.password_summary().unwrap().capabilities, 1);
    }
}

#[test]
fn exact_confirmation_faults_can_only_consume_the_fresh_challenge() {
    for (fault, consumed) in [
        (Fault::BeforeCommit, false),
        (Fault::Audit, false),
        (Fault::UnknownRollback, false),
        (Fault::UnknownCommitted, true),
        (Fault::LostResponse, true),
    ] {
        let peer = Peer::new(ORIGIN).unwrap();
        let account = register(&peer, 0);
        let business = business(&account, 0, &login(&peer, &account, NOW));
        let original = submit(&peer, &business).confirmation;
        let request = business.fresh(&peer, AccountRequestIntent::Confirm, NOW);
        peer.set_fault(fault).unwrap();
        let expected = if fault == Fault::LostResponse {
            Error::ResponseLost
        } else {
            Error::StorageUnavailable
        };
        assert_eq!(peer.device_admission(body(&request), || NOW), Err(expected));
        let peer =
            Peer::restore(peer.checkpoint().unwrap(), ORIGIN, DEFAULT_USED_ACCOUNT_ID_CEILING)
                .unwrap();
        let summary = peer.summary().unwrap();
        assert_eq!(
            (summary.admissions, summary.denials, summary.challenges),
            (1, 0, usize::from(!consumed))
        );
        assert_eq!(stored_snapshot(&peer, &account).key_bundle, business.payload.key_bundle);
        assert_eq!(peer.password_summary().unwrap().capabilities, 0);
        if consumed {
            assert_eq!(
                peer.device_admission(body(&request), || NOW),
                Err(Error::AuthenticationRequired)
            );
        } else {
            assert_eq!(
                peer.device_admission(body(&request), || NOW).unwrap().confirmation,
                original
            );
        }
        let request = business.fresh(&peer, AccountRequestIntent::Confirm, NOW);
        assert_eq!(peer.device_admission(body(&request), || NOW).unwrap().confirmation, original);
        assert_eq!(peer.summary().unwrap().admissions, 1);
    }
}

#[test]
fn changed_original_payload_signature_or_device_proof_never_confirms_a_receipt() {
    for change in ["payload", "signature", "proof", "intent"] {
        let peer = Peer::new(ORIGIN).unwrap();
        let account = register(&peer, 0);
        let mut business = business(&account, 0, &login(&peer, &account, NOW));
        let original = submit(&peer, &business).confirmation;
        if change == "payload" {
            let certificate =
                DeviceCertificate::decode(&business.payload.device_certificate).unwrap();
            let certificate = DeviceCertificate::issue(
                &account.root,
                certificate.device_id,
                certificate.account_id,
                certificate.signing_public_key,
                certificate.kem_public_key,
                format!("{}x", certificate.display_name),
                certificate.platform,
                certificate.created_at,
            )
            .unwrap();
            business.payload.device_certificate = certificate.encode().unwrap();
            business.resign(&account.root);
        }
        let mut request = business.fresh(&peer, AccountRequestIntent::Confirm, NOW);
        match change {
            "signature" => {
                request.account_signature[0] ^= 1;
                business.sign_proof(&mut request);
            }
            "proof" => request.device_proof[0] ^= 1,
            "intent" => {
                request.intent = AccountRequestIntent::Submit;
                request.admission_token = business.request.admission_token.clone();
                business.sign_proof(&mut request);
            }
            _ => {}
        }
        assert_eq!(
            peer.device_admission(body(&request), || NOW),
            Err(Error::AuthenticationRequired)
        );
        let summary = peer.summary().unwrap();
        assert_eq!(
            (summary.devices, summary.receipts, summary.admissions, summary.denials),
            (2, 2, 1, 1)
        );
        assert_eq!(
            peer.retained_receipt(original.operation_id).unwrap().unwrap().confirmation,
            original
        );
    }
}

#[test]
fn operation_ids_are_deployment_unique_across_registration_and_admission() {
    let peer = Peer::new(ORIGIN).unwrap();
    let owner = register(&peer, 0);
    let other = register(&peer, 1);
    let committed = business(&owner, 0, &login(&peer, &owner, NOW));
    submit(&peer, &committed);
    for operation in [owner.payload.operation_id, committed.payload.operation_id] {
        let mut candidate = business(&other, 0, &login(&peer, &other, NOW));
        candidate.payload.operation_id = operation;
        candidate.resign(&other.root);
        let request = candidate.fresh(&peer, AccountRequestIntent::Submit, NOW);
        assert_eq!(peer.device_admission(body(&request), || NOW), Err(Error::AdmissionConflict));
        assert_eq!(peer.password_summary().unwrap().capabilities, 0);
    }
    let summary = peer.summary().unwrap();
    assert_eq!(
        (summary.devices, summary.receipts, summary.admissions, summary.denials),
        (3, 3, 1, 2)
    );
}

#[test]
fn deleting_a_multidevice_account_clears_all_ordinary_rows_but_preserves_other_accounts() {
    let peer = Peer::new(ORIGIN).unwrap();
    let owner = register(&peer, 0);
    let other = register(&peer, 1);
    let mut committed = Vec::new();
    for sequence in 0..2 {
        let business = business(&owner, sequence, &login(&peer, &owner, NOW));
        submit(&peer, &business);
        committed.push(business);
    }
    let other_business = business(&other, 0, &login(&peer, &other, NOW));
    let other_receipt = submit(&peer, &other_business).confirmation;
    let pending = business(&owner, 2, &login(&peer, &owner, NOW));
    login(&peer, &other, NOW);
    for account in [&owner, &other] {
        peer.password_options(
            &AccountPasswordOptionsRequest { username: account.payload.username.clone() }
                .to_json()
                .unwrap(),
            || NOW,
        )
        .unwrap();
    }
    for business in &committed {
        business.fresh(&peer, AccountRequestIntent::Confirm, NOW);
    }
    let other_confirmation = other_business.fresh(&peer, AccountRequestIntent::Confirm, NOW);
    assert_eq!(peer.password_summary().unwrap().attempts, 2);
    assert_eq!(peer.password_summary().unwrap().capabilities, 2);
    peer.delete_account(owner.payload.account_id).unwrap();
    let peer =
        Peer::restore(peer.checkpoint().unwrap(), ORIGIN, DEFAULT_USED_ACCOUNT_ID_CEILING).unwrap();
    let summary = peer.summary().unwrap();
    assert_eq!(
        (
            summary.accounts,
            summary.vaults,
            summary.devices,
            summary.receipts,
            summary.used_account_ids
        ),
        (1, 1, 2, 2, 2)
    );
    assert_eq!(summary.challenges, 1);
    assert_eq!(peer.password_summary().unwrap().attempts, 1);
    assert_eq!(peer.password_summary().unwrap().capabilities, 1);
    assert!(peer.account_material(owner.payload.account_id).unwrap().is_none());
    assert!(peer.retained_receipt(owner.payload.operation_id).unwrap().is_none());
    for business in committed {
        assert!(peer.retained_receipt(business.payload.operation_id).unwrap().is_none());
    }
    assert_eq!(
        peer.device_admission(body(&other_confirmation), || NOW).unwrap().confirmation,
        other_receipt
    );
    let request = pending.fresh(&peer, AccountRequestIntent::Submit, NOW);
    assert_eq!(peer.device_admission(body(&request), || NOW), Err(Error::AuthenticationRequired));
    assert_eq!(peer.summary().unwrap().accounts, 1);
    login(&peer, &other, NOW);
}

#[test]
fn maintenance_and_common_errors_never_claim_unconfirmed_business_authority() {
    for (error, status, changed, retryable) in [
        (Error::InvalidRequest, 400, false, false),
        (Error::TooLarge, 413, false, false),
        (Error::AuthenticationRequired, 401, false, false),
        (Error::AdmissionConflict, 409, false, false),
        (Error::QuotaExceeded, 413, false, false),
        (Error::StorageUnavailable, 503, false, true),
        (Error::CommitOutcomeUnknown, 503, true, false),
    ] {
        let problem = error.problem("/account-entry").unwrap().unwrap();
        assert_eq!(
            (problem.status, problem.changed, problem.retryable),
            (status, changed, retryable)
        );
        assert!(serde_json::to_vec(&problem).unwrap().len() <= 4096);
    }
    assert!(Error::ResponseLost.problem("/account-entry").unwrap().is_none());
    assert!(Error::AuthenticationRequired.problem(&"x".repeat(4097)).is_err());
    assert!(Error::AuthenticationRequired.problem(&"\0".repeat(700)).is_err());
    let peer = Peer::new(ORIGIN).unwrap();
    let account = register(&peer, 0);
    let business = business(&account, 0, &login(&peer, &account, NOW));
    let request = business.fresh(&peer, AccountRequestIntent::Submit, NOW);
    let summary = peer.summary().unwrap();
    peer.set_maintenance(true).unwrap();
    assert_eq!(peer.device_admission(body(&request), || NOW), Err(Error::StorageUnavailable));
    assert_eq!(peer.summary().unwrap(), summary);
    peer.set_maintenance(false).unwrap();
    assert_eq!(peer.device_admission(body(&request), || NOW).unwrap().status, 201);
}

#[test]
fn an_expiring_challenge_or_capability_cannot_commit_a_cas_invalidation() {
    for expire_capability in [false, true] {
        let peer = Peer::new(ORIGIN).unwrap();
        let account = register(&peer, 0);
        let business = business(&account, 0, &login(&peer, &account, NOW));
        let started = if expire_capability { NOW + 299_999 } else { NOW };
        let request = business.fresh(&peer, AccountRequestIntent::Submit, started);
        let mut snapshot = stored_snapshot(&peer, &account);
        snapshot.personal.rotation_pending = true;
        store_snapshot(&peer, &account, &snapshot);
        let end = if expire_capability { NOW + 300_000 } else { NOW + 120_000 };
        let mut times = [started, started, end].into_iter();
        assert_eq!(
            peer.device_admission(body(&request), || times.next().unwrap()),
            Err(Error::AuthenticationRequired)
        );
        assert_eq!(peer.password_summary().unwrap().capabilities, 1);
        let summary = peer.summary().unwrap();
        assert_eq!((summary.challenges, summary.denials, summary.admissions), (0, 1, 0));
        assert_eq!((summary.devices, summary.receipts), (1, 1));
    }
}

#[test]
fn complete_get_projection_overflow_returns_quota_without_publishing_partial_state() {
    let peer = Peer::new(ORIGIN).unwrap();
    let account = register(&peer, 0);
    let mut snapshot = stored_snapshot(&peer, &account);
    let original = DeviceCertificate::decode(&snapshot.certificates[0]).unwrap();
    snapshot.certificates[0] = large_certificate(&account, &original);
    let mut bundle = SyncAccountKeyBundleUpdate::from_cbor(&snapshot.key_bundle).unwrap();
    for index in 0..62 {
        let device_id = adjacent(account.payload.account_id, 1_000 + u32::from(index));
        let certificate = DeviceCertificate::issue(
            &account.root,
            device_id,
            account.payload.account_id,
            P256SigningKey::from_bytes(&key(6, index)).unwrap().public_key_sec1(),
            P256SigningKey::from_bytes(&key(7, index)).unwrap().public_key_sec1(),
            "Fixture device".into(),
            "test".into(),
            44,
        )
        .unwrap();
        snapshot.certificates.push(large_certificate(&account, &certificate));
        bundle.device_wraps.push(SyncAccountDeviceWrap {
            device_id,
            wrapped_ark: bundle.device_wraps[0].wrapped_ark.clone(),
        });
    }
    snapshot.certificates.sort();
    bundle.device_wraps.sort_by_key(|wrap| *wrap.device_id.as_bytes());
    bundle.signature = account.root.sign(&bundle.signature_input().unwrap()).to_vec();
    snapshot.key_bundle = bundle.to_cbor().unwrap();
    let mut projection = SyncAccountKeyBundle {
        revision: bundle.revision,
        wrapped_ark: bundle.device_wraps[0].wrapped_ark.clone(),
        account_signing_key: bundle.account_signing_key,
        account_kem_key: bundle.account_kem_key,
        recovery_blob: bundle.recovery_blob,
        certificates: snapshot.certificates.clone(),
        revocations: snapshot.revocations.clone(),
    };
    assert!(projection.to_cbor().is_ok());
    store_snapshot(&peer, &account, &snapshot);
    let before = snapshot.to_cbor().unwrap();
    let mut candidate = business(&account, 0, &login(&peer, &account, NOW));
    let certificate = DeviceCertificate::decode(&candidate.payload.device_certificate).unwrap();
    candidate.payload.device_certificate = large_certificate(&account, &certificate);
    candidate.resign(&account.root);
    snapshot.certificates.push(candidate.payload.device_certificate.clone());
    snapshot.certificates.sort();
    snapshot.key_bundle.clone_from(&candidate.payload.key_bundle);
    assert!(snapshot.to_cbor().is_ok());
    projection.certificates.clone_from(&snapshot.certificates);
    assert!(projection.to_cbor().is_err());
    let request = candidate.fresh(&peer, AccountRequestIntent::Submit, NOW);
    assert_eq!(peer.device_admission(body(&request), || NOW), Err(Error::QuotaExceeded));
    assert_eq!(stored_snapshot(&peer, &account).to_cbor().unwrap(), before);
    let summary = peer.summary().unwrap();
    assert_eq!(
        (summary.devices, summary.receipts, summary.admissions, summary.denials),
        (1, 1, 0, 1)
    );
    assert_eq!(peer.password_summary().unwrap().capabilities, 1);
}

#[test]
fn cas_faults_atomically_invalidate_capability_challenge_and_denial_without_business_changes() {
    for (fault, committed) in [
        (Fault::BeforeCommit, false),
        (Fault::Audit, false),
        (Fault::UnknownRollback, false),
        (Fault::UnknownCommitted, true),
        (Fault::LostResponse, true),
    ] {
        let peer = Peer::new(ORIGIN).unwrap();
        let account = register(&peer, 0);
        let business = business(&account, 0, &login(&peer, &account, NOW));
        let mut snapshot = stored_snapshot(&peer, &account);
        snapshot.personal.rotation_pending = true;
        store_snapshot(&peer, &account, &snapshot);
        let request = business.fresh(&peer, AccountRequestIntent::Submit, NOW);
        peer.set_fault(fault).unwrap();
        let expected = if fault == Fault::LostResponse {
            Error::ResponseLost
        } else {
            Error::StorageUnavailable
        };
        assert_eq!(peer.device_admission(body(&request), || NOW), Err(expected));
        let peer =
            Peer::restore(peer.checkpoint().unwrap(), ORIGIN, DEFAULT_USED_ACCOUNT_ID_CEILING)
                .unwrap();
        let summary = peer.summary().unwrap();
        assert_eq!((summary.devices, summary.receipts, summary.admissions), (1, 1, 0));
        assert_eq!(
            (summary.challenges, summary.denials),
            (usize::from(!committed), u64::from(committed))
        );
        assert_eq!(peer.password_summary().unwrap().capabilities, usize::from(!committed));
        assert_eq!(
            stored_snapshot(&peer, &account).to_cbor().unwrap(),
            snapshot.to_cbor().unwrap()
        );
    }
}

#[test]
fn successful_publication_and_cas_invalidation_each_restore_a_live_account_capability_slot() {
    let peer = Peer::new(ORIGIN).unwrap();
    let account = register(&peer, 0);
    let capabilities: Vec<_> = (0..4).map(|_| login(&peer, &account, NOW)).collect();
    let options = peer
        .password_options(
            &AccountPasswordOptionsRequest { username: account.payload.username.clone() }
                .to_json()
                .unwrap(),
            || NOW,
        )
        .unwrap();
    let request = AccountPasswordLoginRequest {
        attempt_id: options.attempt_id,
        auth_secret: SecretBytes::new([0x12; 32]),
    };
    assert_eq!(
        peer.password_login(request.to_json().unwrap(), || NOW),
        Err(ReferencePasswordError::RateLimited)
    );
    let committed = business(&account, 0, &capabilities[0]);
    submit(&peer, &committed);
    assert_eq!(peer.password_summary().unwrap().capabilities, 3);
    assert!(peer.password_login(request.to_json().unwrap(), || NOW).is_ok());
    assert_eq!(peer.password_summary().unwrap().capabilities, 4);
    let stale = business(&account, 1, &capabilities[1]);
    let request = stale.fresh(&peer, AccountRequestIntent::Submit, NOW);
    assert_eq!(peer.device_admission(body(&request), || NOW), Err(Error::AdmissionConflict));
    assert_eq!(peer.password_summary().unwrap().capabilities, 3);
    login(&peer, &account, NOW);
    assert_eq!(peer.password_summary().unwrap().capabilities, 4);
    assert_eq!(peer.summary().unwrap().admissions, 1);
}
