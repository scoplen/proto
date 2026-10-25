// SPDX-License-Identifier: Apache-2.0
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use scoplen_api::{
    account_admission::{
        AccountAdmissionCodecError, AccountBootstrapSnapshot, AccountRegistrationPayload,
        AccountRegistrationRequest, AccountRequestChallengeRequest,
        AccountRequestChallengeResponse, AccountRequestIntent, AccountRequestKind,
    },
    account_registration_reference::{
        DEFAULT_USED_ACCOUNT_ID_CEILING, ReferenceAccountRegistrationPeer as Peer,
        ReferenceRegistrationError as Error, ReferenceRegistrationFault as Fault,
        ReferenceRetentionPressure as Pressure,
    },
    sync::SyncAccountKeyBundleUpdate,
};
use scoplen_crypto::{
    AccountRequestProof, AccountRequestSignatureInput, DeviceCertificate, Ed25519SigningKey,
    P256SigningKey, SecretVec, account_used_id_digest, canonical_device_public_key,
};
use scoplen_model::cbor::{self, Value};
use scoplen_test_vectors::VectorDocument;
use uuid::Uuid;

const ORIGIN: &str = "https://control.example.com";
const NOW: u64 = 1_700_000_000_000;

struct Business {
    payload: AccountRegistrationPayload,
    request: AccountRegistrationRequest,
    root: Ed25519SigningKey,
    signer: P256SigningKey,
}

fn adjacent(id: Uuid, offset: u8) -> Uuid {
    let mut bytes = *id.as_bytes();
    bytes[15] += offset;
    Uuid::from_bytes(bytes)
}

impl Business {
    fn new(index: u8) -> Self {
        let doc =
            VectorDocument::parse_str(include_str!("../../../vectors/account-admission.json"))
                .unwrap();
        let fixture = doc
            .vectors
            .iter()
            .find(|vector| vector.id == "account-admission-register-submit")
            .unwrap();
        let mut request = AccountRegistrationRequest::from_json(fixture.input.as_bytes()).unwrap();
        let mut payload =
            AccountRegistrationPayload::from_cbor(request.payload.as_bytes()).unwrap();
        for id in [
            &mut payload.account_id,
            &mut payload.personal_vault_id,
            &mut payload.device_id,
            &mut payload.operation_id,
        ] {
            *id = adjacent(*id, index);
        }
        payload.username = format!("fixture.user{index}");
        let root = Ed25519SigningKey::from_bytes(&[index + 1; 32]).unwrap();
        let signer = P256SigningKey::from_bytes(&[index * 2 + 2; 32]).unwrap();
        let kem = P256SigningKey::from_bytes(&[index * 2 + 3; 32]).unwrap();
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
        let mut business = Self { payload, request, root, signer };
        business.resign();
        business
    }

    fn resign(&mut self) {
        self.request.payload = SecretVec::new(self.payload.to_cbor().unwrap());
        self.request.account_signature = AccountRequestSignatureInput::new(
            AccountRequestKind::Register,
            self.request.payload.as_bytes(),
        )
        .unwrap()
        .sign(&self.root);
    }

    fn fresh(
        &self,
        peer: &Peer,
        intent: AccountRequestIntent,
        now: u64,
    ) -> AccountRegistrationRequest {
        let challenge = peer
            .challenge(
                &AccountRequestChallengeRequest {
                    kind: AccountRequestKind::Register,
                    intent,
                    operation_id: self.payload.operation_id,
                    device_id: self.payload.device_id,
                }
                .to_json()
                .unwrap(),
                || now,
            )
            .unwrap();
        self.prove(challenge, intent)
    }

    fn prove(
        &self,
        challenge: AccountRequestChallengeResponse,
        intent: AccountRequestIntent,
    ) -> AccountRegistrationRequest {
        let mut request = self.request.clone();
        request.intent = intent;
        request.attempt_id = challenge.attempt_id;
        request.nonce = challenge.nonce;
        let digest = AccountRequestSignatureInput::new(
            AccountRequestKind::Register,
            request.payload.as_bytes(),
        )
        .unwrap()
        .request_digest(&request.account_signature);
        request.device_proof = AccountRequestProof::new(
            AccountRequestKind::Register,
            intent,
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
        request
    }
}

fn protected_field<'a>(payload: &'a mut Value, name: &str) -> &'a mut Value {
    let Value::Map(fields) = payload else { panic!("protected map") };
    &mut fields.iter_mut().find(|(key, _)| key == &Value::Text(name.into())).unwrap().1
}

fn mutated_request(
    request: &AccountRegistrationRequest,
    mutate: impl FnOnce(&mut Value),
) -> Vec<u8> {
    let mut payload = cbor::decode(request.payload.as_bytes()).unwrap();
    mutate(&mut payload);
    let mut body: serde_json::Value = serde_json::from_slice(&request.to_json().unwrap()).unwrap();
    body["payload"] = URL_SAFE_NO_PAD.encode(cbor::encode(&payload).unwrap()).into();
    serde_json::to_vec(&body).unwrap()
}

fn corrupt_inner_signature(payload: &mut Value, field: &str) {
    let Value::Bytes(bytes) = protected_field(payload, field) else { panic!("artifact bytes") };
    if field == "device_certificate" {
        let mut certificate = DeviceCertificate::decode(bytes).unwrap();
        certificate.signature[0] ^= 1;
        *bytes = certificate.encode().unwrap();
    } else {
        let mut bundle = SyncAccountKeyBundleUpdate::from_cbor(bytes).unwrap();
        bundle.signature[0] ^= 1;
        *bytes = bundle.to_cbor().unwrap();
    }
}

fn submit(peer: &Peer, business: &Business) {
    let request = business.fresh(peer, AccountRequestIntent::Submit, NOW);
    assert_eq!(peer.register(&request.to_json().unwrap(), || NOW).unwrap().status, 201);
}

#[test]
fn registration_stores_complete_material_and_exact_public_receipt() {
    let peer = Peer::new(ORIGIN).unwrap();
    let business = Business::new(0);
    let request = business.fresh(&peer, AccountRequestIntent::Submit, NOW);
    let result = peer.register(&request.to_json().unwrap(), || NOW).unwrap();
    result
        .confirmation
        .validate_for_request(
            AccountRequestKind::Register,
            request.payload.as_bytes(),
            &request.account_signature,
        )
        .unwrap();
    let receipt = peer.retained_receipt(business.payload.operation_id).unwrap().unwrap();
    let cert = DeviceCertificate::decode(&business.payload.device_certificate).unwrap();
    assert_eq!(receipt.signing_key, canonical_device_public_key(&cert.signing_public_key).unwrap());
    assert_eq!(receipt.kem_key, canonical_device_public_key(&cert.kem_public_key).unwrap());
    assert_eq!(receipt.account_root, business.root.public_key());
    assert_eq!(receipt.committed_at_ms, NOW);
    let material = peer.account_material(business.payload.account_id).unwrap().unwrap();
    assert_eq!(material.verifier.as_bytes(), &business.payload.verifier);
    let snapshot = AccountBootstrapSnapshot::from_cbor(material.bootstrap.as_bytes()).unwrap();
    assert_eq!(snapshot.account_id, business.payload.account_id);
    assert_eq!(snapshot.key_bundle, business.payload.key_bundle);
    assert!(material.active);
    let summary = peer.summary().unwrap();
    assert_eq!(
        (
            summary.accounts,
            summary.vaults,
            summary.devices,
            summary.receipts,
            summary.used_account_ids,
            summary.registrations
        ),
        (1, 1, 1, 1, 1, 1)
    );
    assert_eq!(
        peer.retained_account_id_rows().unwrap(),
        vec![account_used_id_digest(business.payload.account_id).unwrap()]
    );
    assert_eq!(format!("{peer:?}"), "ReferenceAccountRegistrationPeer([REDACTED])");
    assert_eq!(format!("{receipt:?}"), "ReferenceRegistrationReceipt([REDACTED])");
    assert_eq!(format!("{material:?}"), "ReferenceRegistrationAccountMaterial([REDACTED])");
}

#[test]
fn denied_possession_consumes_matching_challenge_with_atomic_denial_audit() {
    let peer = Peer::new(ORIGIN).unwrap();
    let business = Business::new(0);
    let original = business.fresh(&peer, AccountRequestIntent::Submit, NOW);
    let mut bad = original.clone();
    bad.device_proof[0] ^= 1;
    assert_eq!(peer.register(&bad.to_json().unwrap(), || NOW), Err(Error::AuthenticationRequired));
    assert_eq!(peer.summary().unwrap().denials, 1);
    assert_eq!(
        peer.register(&original.to_json().unwrap(), || NOW),
        Err(Error::AuthenticationRequired)
    );
    assert_eq!(peer.summary().unwrap().accounts, 0);
    submit(&peer, &business);
}

#[test]
fn invalid_inner_signatures_consume_the_live_challenge_and_public_codecs_remain_strict() {
    for field in ["device_certificate", "key_bundle"] {
        let peer = Peer::new(ORIGIN).unwrap();
        let business = Business::new(0);
        let original = business.fresh(&peer, AccountRequestIntent::Submit, NOW);
        let bad = mutated_request(&original, |payload| corrupt_inner_signature(payload, field));
        assert_eq!(
            AccountRegistrationRequest::from_json(&bad),
            Err(AccountAdmissionCodecError::Binding)
        );
        assert_eq!(peer.register(&bad, || NOW), Err(Error::AuthenticationRequired));
        let summary = peer.summary().unwrap();
        assert_eq!((summary.accounts, summary.challenges, summary.denials), (0, 0, 1));
        assert_eq!(
            peer.register(&original.to_json().unwrap(), || NOW),
            Err(Error::AuthenticationRequired)
        );
        submit(&peer, &business);
    }
}

#[test]
fn canonical_origin_mismatch_consumes_the_existing_attempt_instead_of_hiding_it() {
    let peer = Peer::new(ORIGIN).unwrap();
    let business = Business::new(0);
    let original = business.fresh(&peer, AccountRequestIntent::Submit, NOW);
    let bad = mutated_request(&original, |payload| {
        *protected_field(payload, "origin") = Value::Text("https://other.example.com".into());
    });
    AccountRegistrationRequest::from_json(&bad).unwrap();
    assert_eq!(peer.register(&bad, || NOW), Err(Error::AuthenticationRequired));
    let summary = peer.summary().unwrap();
    assert_eq!((summary.accounts, summary.challenges, summary.denials), (0, 0, 1));
    assert_eq!(
        peer.register(&original.to_json().unwrap(), || NOW),
        Err(Error::AuthenticationRequired)
    );
}

#[test]
fn all_challenge_binding_mismatches_consume_the_live_opaque_attempt() {
    for field in ["kind", "intent", "operation_id", "device_id"] {
        let peer = Peer::new(ORIGIN).unwrap();
        let business = Business::new(0);
        let mut challenge_request = AccountRequestChallengeRequest {
            kind: AccountRequestKind::Register,
            intent: AccountRequestIntent::Submit,
            operation_id: business.payload.operation_id,
            device_id: business.payload.device_id,
        };
        match field {
            "kind" => challenge_request.kind = AccountRequestKind::Admit,
            "intent" => challenge_request.intent = AccountRequestIntent::Confirm,
            "operation_id" => {
                challenge_request.operation_id = adjacent(challenge_request.operation_id, 1);
            }
            "device_id" => {
                challenge_request.device_id = adjacent(challenge_request.device_id, 1);
            }
            _ => unreachable!(),
        }
        let challenge = peer.challenge(&challenge_request.to_json().unwrap(), || NOW).unwrap();
        let request = business.prove(challenge, AccountRequestIntent::Submit);
        assert_eq!(
            peer.register(&request.to_json().unwrap(), || NOW),
            Err(Error::AuthenticationRequired)
        );
        let summary = peer.summary().unwrap();
        assert_eq!((summary.accounts, summary.challenges, summary.denials), (0, 0, 1));
    }
}

#[test]
fn malformed_later_artifacts_do_not_consume_a_challenge_or_pending_audit_fault() {
    for field in ["key_bundle", "personal_wrapped_key"] {
        let peer = Peer::new(ORIGIN).unwrap();
        let business = Business::new(0);
        let original = business.fresh(&peer, AccountRequestIntent::Submit, NOW);
        let bad = mutated_request(&original, |payload| {
            corrupt_inner_signature(payload, "device_certificate");
            *protected_field(payload, field) = if field == "key_bundle" {
                Value::Bytes(vec![0xff])
            } else {
                Value::Bytes(vec![0; 73])
            };
        });
        peer.set_fault(Fault::Audit).unwrap();
        assert_eq!(peer.register(&bad, || NOW), Err(Error::InvalidRequest));
        let summary = peer.summary().unwrap();
        assert_eq!((summary.accounts, summary.challenges, summary.denials), (0, 1, 0));
        assert_eq!(
            peer.register(&original.to_json().unwrap(), || NOW),
            Err(Error::StorageUnavailable)
        );
        assert_eq!(peer.summary().unwrap().challenges, 1);
        assert_eq!(peer.register(&original.to_json().unwrap(), || NOW).unwrap().status, 201);
    }
}

#[test]
fn failed_denial_audit_takes_precedence_and_rolls_back_inner_binding_consumption() {
    for field in ["device_certificate", "key_bundle", "origin"] {
        let peer = Peer::new(ORIGIN).unwrap();
        let business = Business::new(0);
        let original = business.fresh(&peer, AccountRequestIntent::Submit, NOW);
        let bad = mutated_request(&original, |payload| {
            if field == "origin" {
                *protected_field(payload, field) = Value::Text("https://other.example.com".into());
            } else {
                corrupt_inner_signature(payload, field);
            }
        });
        peer.set_fault(Fault::Audit).unwrap();
        assert_eq!(peer.register(&bad, || NOW), Err(Error::StorageUnavailable));
        let summary = peer.summary().unwrap();
        assert_eq!((summary.accounts, summary.challenges, summary.denials), (0, 1, 0));
        assert_eq!(peer.register(&original.to_json().unwrap(), || NOW).unwrap().status, 201);
    }
}

#[test]
fn expiry_is_reread_before_commit_and_restart_preserves_time_high_water() {
    let peer = Peer::new(ORIGIN).unwrap();
    let business = Business::new(0);
    let request = business.fresh(&peer, AccountRequestIntent::Submit, NOW);
    let mut times = [NOW, NOW + 120_000].into_iter();
    assert_eq!(
        peer.register(&request.to_json().unwrap(), || times.next().unwrap()),
        Err(Error::AuthenticationRequired)
    );
    let image = peer.checkpoint().unwrap();
    let restored = Peer::restore(image, ORIGIN, DEFAULT_USED_ACCOUNT_ID_CEILING).unwrap();
    assert_eq!(
        restored.register(&request.to_json().unwrap(), || NOW - 1),
        Err(Error::AuthenticationRequired)
    );
    assert_eq!(restored.summary().unwrap().accounts, 0);
}

#[test]
fn lost_or_unknown_success_recovers_only_exact_receipt_without_duplicate_business_audit() {
    for (fault, error) in [
        (Fault::UnknownCommitted, Error::CommitOutcomeUnknown),
        (Fault::LostResponse, Error::ResponseLost),
    ] {
        let peer = Peer::with_retention_ceiling(ORIGIN, 1).unwrap();
        let business = Business::new(0);
        let request = business.fresh(&peer, AccountRequestIntent::Submit, NOW);
        peer.set_fault(fault).unwrap();
        assert_eq!(peer.register(&request.to_json().unwrap(), || NOW), Err(error));
        peer.set_account_active(business.payload.account_id, false).unwrap();
        peer.set_registration_enabled(false).unwrap();
        let confirmation = business.fresh(&peer, AccountRequestIntent::Confirm, NOW + 10);
        assert_eq!(
            peer.register(&confirmation.to_json().unwrap(), || NOW + 10).unwrap().status,
            200
        );
        let summary = peer.summary().unwrap();
        assert_eq!((summary.registrations, summary.used_account_ids), (1, 1));
        assert!(!peer.account_material(business.payload.account_id).unwrap().unwrap().active);
    }
}

#[test]
fn audit_or_confirmed_precommit_failure_rolls_back_every_business_and_retention_row() {
    for fault in [Fault::BeforeCommit, Fault::Audit] {
        let peer = Peer::new(ORIGIN).unwrap();
        let business = Business::new(0);
        let request = business.fresh(&peer, AccountRequestIntent::Submit, NOW);
        peer.set_fault(fault).unwrap();
        assert_eq!(
            peer.register(&request.to_json().unwrap(), || NOW),
            Err(Error::StorageUnavailable)
        );
        let summary = peer.summary().unwrap();
        assert_eq!(
            (summary.accounts, summary.receipts, summary.used_account_ids, summary.registrations),
            (0, 0, 0, 0)
        );
        submit(&peer, &business);
    }
}

#[test]
fn unknown_rollback_and_missing_receipt_supply_no_creation_or_negative_receipt() {
    let peer = Peer::new(ORIGIN).unwrap();
    let business = Business::new(0);
    let request = business.fresh(&peer, AccountRequestIntent::Submit, NOW);
    peer.set_fault(Fault::UnknownRollback).unwrap();
    assert_eq!(
        peer.register(&request.to_json().unwrap(), || NOW),
        Err(Error::CommitOutcomeUnknown)
    );
    let problem = Error::CommitOutcomeUnknown.problem("/account-entry").unwrap().unwrap();
    assert!(problem.changed);
    assert!(!problem.retryable);
    let request = business.fresh(&peer, AccountRequestIntent::Confirm, NOW + 1);
    assert_eq!(
        peer.register(&request.to_json().unwrap(), || NOW + 1),
        Err(Error::AuthenticationRequired)
    );
    assert_eq!(
        (peer.summary().unwrap().accounts, peer.summary().unwrap().used_account_ids),
        (0, 0)
    );
}

#[test]
fn deletion_and_restore_preserve_digest_only_and_reject_fresh_old_account_recreation() {
    let peer = Peer::new(ORIGIN).unwrap();
    let mut business = Business::new(0);
    submit(&peer, &business);
    peer.delete_account(business.payload.account_id).unwrap();
    let peer =
        Peer::restore(peer.checkpoint().unwrap(), ORIGIN, DEFAULT_USED_ACCOUNT_ID_CEILING).unwrap();
    assert!(peer.account_material(business.payload.account_id).unwrap().is_none());
    assert!(peer.retained_receipt(business.payload.operation_id).unwrap().is_none());
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
    assert_eq!(
        peer.retained_account_id_rows().unwrap(),
        vec![account_used_id_digest(business.payload.account_id).unwrap()]
    );
    let confirmation = business.fresh(&peer, AccountRequestIntent::Confirm, NOW + 1);
    assert_eq!(
        peer.register(&confirmation.to_json().unwrap(), || NOW + 1),
        Err(Error::AuthenticationRequired)
    );
    for changed_operation in [false, true] {
        if changed_operation {
            business.payload.operation_id = adjacent(business.payload.operation_id, 1);
            business.resign();
        }
        let request = business.fresh(&peer, AccountRequestIntent::Submit, NOW + 2);
        assert_eq!(
            peer.register(&request.to_json().unwrap(), || NOW + 2),
            Err(Error::RegistrationDenied)
        );
    }
    assert_eq!(peer.summary().unwrap().registrations, 1);
}

#[test]
fn account_retention_does_not_create_permanent_vault_device_or_operation_sets() {
    let peer = Peer::with_retention_ceiling(ORIGIN, 2).unwrap();
    let old = Business::new(0);
    submit(&peer, &old);
    peer.delete_account(old.payload.account_id).unwrap();
    let mut new = Business::new(1);
    new.payload.personal_vault_id = old.payload.personal_vault_id;
    new.payload.device_id = old.payload.device_id;
    new.payload.operation_id = old.payload.operation_id;
    let certificate = DeviceCertificate::decode(&new.payload.device_certificate).unwrap();
    new.payload.device_certificate = DeviceCertificate::issue(
        &new.root,
        new.payload.device_id,
        new.payload.account_id,
        new.signer.public_key_sec1(),
        certificate.kem_public_key,
        "Fixture device".into(),
        "test".into(),
        42,
    )
    .unwrap()
    .encode()
    .unwrap();
    let mut bundle = SyncAccountKeyBundleUpdate::from_cbor(&new.payload.key_bundle).unwrap();
    bundle.device_wraps[0].device_id = new.payload.device_id;
    bundle.signature = new.root.sign(&bundle.signature_input().unwrap()).to_vec();
    new.payload.key_bundle = bundle.to_cbor().unwrap();
    new.resign();
    submit(&peer, &new);
    let old_confirmation = old.fresh(&peer, AccountRequestIntent::Confirm, NOW);
    assert_eq!(
        peer.register(&old_confirmation.to_json().unwrap(), || NOW),
        Err(Error::AuthenticationRequired)
    );
    let new_confirmation = new.fresh(&peer, AccountRequestIntent::Confirm, NOW);
    assert_eq!(peer.register(&new_confirmation.to_json().unwrap(), || NOW).unwrap().status, 200);
    assert!(peer.account_material(old.payload.account_id).unwrap().is_none());
    let summary = peer.summary().unwrap();
    assert_eq!((summary.accounts, summary.receipts, summary.used_account_ids), (1, 1, 2));
}

#[test]
fn competing_instances_admit_only_one_complete_registration_at_capacity() {
    let peer = Peer::with_retention_ceiling(ORIGIN, 1).unwrap();
    let businesses: Vec<_> = (0..3).map(Business::new).collect();
    let bodies: Vec<_> = businesses
        .iter()
        .map(|business| business.fresh(&peer, AccountRequestIntent::Submit, NOW).to_json().unwrap())
        .collect();
    let results = std::thread::scope(|scope| {
        let workers: Vec<_> = bodies
            .into_iter()
            .map(|body| {
                let instance = peer.clone();
                scope.spawn(move || instance.register(&body, || NOW + 1))
            })
            .collect();
        workers.into_iter().map(|worker| worker.join().unwrap()).collect::<Vec<_>>()
    });
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(results.iter().filter(|result| **result == Err(Error::QuotaExceeded)).count(), 2);
    let winner = results.iter().position(Result::is_ok).unwrap();
    let confirmation = businesses[winner].fresh(&peer, AccountRequestIntent::Confirm, NOW + 2);
    assert_eq!(peer.register(&confirmation.to_json().unwrap(), || NOW + 2).unwrap().status, 200);
    let summary = peer.summary().unwrap();
    assert_eq!(
        (summary.accounts, summary.receipts, summary.used_account_ids, summary.registrations),
        (1, 1, 1, 1)
    );
}

#[test]
fn maintenance_raise_is_audited_atomic_and_restore_rejects_a_configuration_mismatch() {
    let peer = Peer::with_retention_ceiling(ORIGIN, 1).unwrap();
    let business = Business::new(0);
    submit(&peer, &business);
    let retained = peer.retained_account_id_rows().unwrap();
    assert_eq!(peer.increase_retention_ceiling(2), Err(Error::InvalidRequest));
    peer.set_maintenance(true).unwrap();
    peer.set_fault(Fault::Audit).unwrap();
    assert_eq!(peer.increase_retention_ceiling(2), Err(Error::StorageUnavailable));
    assert_eq!(peer.summary().unwrap().used_id_ceiling, 1);
    peer.increase_retention_ceiling(2).unwrap();
    assert_eq!(peer.retained_account_id_rows().unwrap(), retained);
    assert_eq!(peer.summary().unwrap().ceiling_changes, 1);
    assert_eq!(peer.increase_retention_ceiling(1), Err(Error::InvalidRequest));
    let image = peer.checkpoint().unwrap();
    assert!(Peer::restore(image.clone(), ORIGIN, 1).is_err());
    assert!(Peer::restore(image.clone(), "https://other.example.com", 2).is_err());
    let peer = Peer::restore(image, ORIGIN, 2).unwrap();
    peer.set_maintenance(false).unwrap();
    submit(&peer, &Business::new(1));
    assert_eq!(
        (peer.summary().unwrap().used_account_ids, peer.summary().unwrap().registrations),
        (2, 2)
    );
    assert!(Peer::with_retention_ceiling(ORIGIN, 0).is_err());
    assert!(Peer::with_retention_ceiling(ORIGIN, u64::MAX).is_err());
}

#[test]
fn upgrade_reserves_only_digests_and_rolls_back_the_complete_batch_on_failure() {
    let peer = Peer::with_retention_ceiling(ORIGIN, 2).unwrap();
    let old = Business::new(0);
    let second = adjacent(old.payload.account_id, 1);
    let third = adjacent(old.payload.account_id, 2);
    assert_eq!(
        peer.reserve_upgrade_account_ids(&[old.payload.account_id]),
        Err(Error::InvalidRequest)
    );
    peer.set_maintenance(true).unwrap();
    peer.set_fault(Fault::Audit).unwrap();
    assert_eq!(
        peer.reserve_upgrade_account_ids(&[old.payload.account_id]),
        Err(Error::StorageUnavailable)
    );
    assert_eq!(peer.summary().unwrap().used_account_ids, 0);
    peer.reserve_upgrade_account_ids(&[old.payload.account_id, old.payload.account_id]).unwrap();
    let retained = peer.retained_account_id_rows().unwrap();
    assert_eq!(
        peer.reserve_upgrade_account_ids(&[second, Uuid::nil()]),
        Err(Error::InvalidRequest)
    );
    assert_eq!(peer.reserve_upgrade_account_ids(&[second, third]), Err(Error::QuotaExceeded));
    assert_eq!(peer.retained_account_id_rows().unwrap(), retained);
    peer.reserve_upgrade_account_ids(&[second]).unwrap();
    let peer = Peer::restore(peer.checkpoint().unwrap(), ORIGIN, 2).unwrap();
    assert_eq!(peer.summary().unwrap().used_account_ids, 2);
    assert_eq!(peer.summary().unwrap().accounts, 0);
    assert_eq!(peer.summary().unwrap().receipts, 0);
    peer.set_maintenance(false).unwrap();
    let request = old.fresh(&peer, AccountRequestIntent::Submit, NOW);
    assert_eq!(peer.register(&request.to_json().unwrap(), || NOW), Err(Error::RegistrationDenied));
    let request = old.fresh(&peer, AccountRequestIntent::Confirm, NOW);
    assert_eq!(
        peer.register(&request.to_json().unwrap(), || NOW),
        Err(Error::AuthenticationRequired)
    );
    assert_eq!(peer.summary().unwrap().registrations, 0);
}

#[test]
fn retention_pressure_reports_the_exact_content_free_warning_and_exhaustion_thresholds() {
    let peer = Peer::with_retention_ceiling(ORIGIN, 10).unwrap();
    let base = Business::new(0).payload.account_id;
    let ids: Vec<_> = (0..10).map(|offset| adjacent(base, offset)).collect();
    assert_eq!(peer.summary().unwrap().retention_pressure, Pressure::Available);
    peer.set_maintenance(true).unwrap();
    peer.reserve_upgrade_account_ids(&ids[..8]).unwrap();
    assert_eq!(peer.summary().unwrap().retention_pressure, Pressure::Available);
    peer.reserve_upgrade_account_ids(&ids[..9]).unwrap();
    assert_eq!(peer.summary().unwrap().retention_pressure, Pressure::Warning);
    peer.reserve_upgrade_account_ids(&ids).unwrap();
    assert_eq!(peer.summary().unwrap().retention_pressure, Pressure::Exhausted);
    peer.increase_retention_ceiling(11).unwrap();
    assert_eq!(peer.summary().unwrap().retention_pressure, Pressure::Warning);
    peer.increase_retention_ceiling(12).unwrap();
    assert_eq!(peer.summary().unwrap().retention_pressure, Pressure::Available);
    assert_eq!(peer.summary().unwrap().used_account_ids, 10);
}

#[test]
fn unconfirmed_confirmation_is_noncreating_and_requires_another_fresh_proof() {
    let peer = Peer::new(ORIGIN).unwrap();
    let business = Business::new(0);
    submit(&peer, &business);
    let request = business.fresh(&peer, AccountRequestIntent::Confirm, NOW + 1);
    peer.set_fault(Fault::UnknownCommitted).unwrap();
    assert_eq!(
        peer.register(&request.to_json().unwrap(), || NOW + 1),
        Err(Error::StorageUnavailable)
    );
    let problem = Error::StorageUnavailable.problem("/account-entry").unwrap().unwrap();
    assert!(!problem.changed);
    assert!(problem.retryable);
    assert_eq!(
        peer.register(&request.to_json().unwrap(), || NOW + 2),
        Err(Error::AuthenticationRequired)
    );
    let fresh = business.fresh(&peer, AccountRequestIntent::Confirm, NOW + 3);
    assert_eq!(peer.register(&fresh.to_json().unwrap(), || NOW + 3).unwrap().status, 200);
    assert_eq!(peer.summary().unwrap().registrations, 1);
}

#[test]
fn changed_stable_bytes_cannot_borrow_an_old_receipt() {
    let peer = Peer::new(ORIGIN).unwrap();
    let mut business = Business::new(0);
    submit(&peer, &business);
    let original_username = business.payload.username.clone();
    business.payload.username = "fixture.changed".into();
    business.resign();
    let request = business.fresh(&peer, AccountRequestIntent::Confirm, NOW + 1);
    assert_eq!(
        peer.register(&request.to_json().unwrap(), || NOW + 1),
        Err(Error::AuthenticationRequired)
    );
    business.payload.username = original_username;
    business.resign();
    let request = business.fresh(&peer, AccountRequestIntent::Confirm, NOW + 2);
    assert_eq!(peer.register(&request.to_json().unwrap(), || NOW + 2).unwrap().status, 200);
}

#[test]
fn malformed_request_leaves_its_challenge_and_next_audit_fault_untouched() {
    let peer = Peer::new(ORIGIN).unwrap();
    let business = Business::new(0);
    let request = business.fresh(&peer, AccountRequestIntent::Submit, NOW);
    let mut body: serde_json::Value = serde_json::from_slice(&request.to_json().unwrap()).unwrap();
    body["unknown"] = true.into();
    peer.set_fault(Fault::Audit).unwrap();
    assert_eq!(
        peer.register(&serde_json::to_vec(&body).unwrap(), || NOW),
        Err(Error::InvalidRequest)
    );
    assert_eq!(peer.register(&request.to_json().unwrap(), || NOW), Err(Error::StorageUnavailable));
    submit(&peer, &business);
}

#[test]
fn failure_profiles_preserve_conservative_flags_and_complete_problem_bounds() {
    for (error, status, changed, retryable) in [
        (Error::AuthenticationRequired, 401, false, false),
        (Error::RegistrationDenied, 409, false, false),
        (Error::QuotaExceeded, 413, false, false),
        (Error::StorageUnavailable, 503, false, true),
        (Error::CommitOutcomeUnknown, 503, true, false),
    ] {
        let problem = error.problem("/account-entry").unwrap().unwrap();
        assert_eq!(
            (problem.status, problem.changed, problem.retryable),
            (status, changed, retryable)
        );
        assert!(serde_json::to_vec(&problem).unwrap().len() <= 4_096);
    }
    assert!(Error::ResponseLost.problem("/account-entry").unwrap().is_none());
    assert!(Error::AuthenticationRequired.problem(&"x".repeat(4_097)).is_err());
    assert!(Error::AuthenticationRequired.problem(&"\0".repeat(700)).is_err());
}
