// SPDX-License-Identifier: Apache-2.0
use scoplen_api::{
    account_admission::{
        AccountBootstrapSnapshot, AccountPasswordLoginRequest, AccountPasswordLoginResponse,
        AccountPasswordOptionsRequest, AccountPasswordOptionsResponse, AccountRegistrationPayload,
        AccountRegistrationRequest, AccountRequestChallengeRequest, AccountRequestIntent,
        AccountRequestKind,
    },
    account_registration_reference::{
        DEFAULT_USED_ACCOUNT_ID_CEILING, ReferenceAccountRegistrationPeer as Peer,
        ReferencePasswordError as Error, ReferenceRegistrationFault as Fault,
    },
    sync::SyncAccountKeyBundleUpdate,
};
use scoplen_crypto::{
    AccountRequestProof, AccountRequestSignatureInput, DeviceCertificate, Ed25519SigningKey,
    P256SigningKey, SecretBytes, SecretVec, account_bootstrap_digest, account_capability_digest,
};
use scoplen_model::cbor::{self, Value};
use scoplen_test_vectors::VectorDocument;

const ORIGIN: &str = "https://control.example.com";
const NOW: u64 = 1_700_000_000_000;

fn register(peer: &Peer) -> AccountRegistrationPayload {
    register_request(peer, registration_request(), &P256SigningKey::from_bytes(&[2; 32]).unwrap())
}

fn registration_request() -> AccountRegistrationRequest {
    let document =
        VectorDocument::parse_str(include_str!("../../../vectors/account-admission.json")).unwrap();
    let vector =
        document.vectors.iter().find(|v| v.id == "account-admission-register-submit").unwrap();
    AccountRegistrationRequest::from_json(vector.input.as_bytes()).unwrap()
}

fn register_request(
    peer: &Peer,
    mut request: AccountRegistrationRequest,
    signer: &P256SigningKey,
) -> AccountRegistrationPayload {
    let payload = AccountRegistrationPayload::from_cbor(request.payload.as_bytes()).unwrap();
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
    .sign(signer)
    .unwrap();
    assert_eq!(peer.register(&request.to_json().unwrap(), || NOW).unwrap().status, 201);
    payload
}

fn indexed_registration(
    template: &AccountRegistrationRequest,
    index: u16,
) -> (AccountRegistrationRequest, P256SigningKey) {
    let mut request = template.clone();
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
        let suffix = u32::from(index) * 4 + u32::try_from(role).unwrap() + 1;
        bytes[12..].copy_from_slice(&suffix.to_be_bytes());
        *id = uuid::Uuid::from_bytes(bytes);
    }
    let mut seed = [1; 32];
    seed[30..].copy_from_slice(&index.to_be_bytes());
    let root = Ed25519SigningKey::from_bytes(&seed).unwrap();
    seed[0] = 2;
    let signer = P256SigningKey::from_bytes(&seed).unwrap();
    seed[0] = 3;
    let kem = P256SigningKey::from_bytes(&seed).unwrap();
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
    (request, signer)
}

fn options(peer: &Peer, username: &str, now: u64) -> AccountPasswordOptionsResponse {
    peer.password_options(
        &AccountPasswordOptionsRequest { username: username.into() }.to_json().unwrap(),
        || now,
    )
    .unwrap()
}

fn login_body(options: &AccountPasswordOptionsResponse, byte: u8) -> SecretVec {
    AccountPasswordLoginRequest {
        attempt_id: options.attempt_id.clone(),
        auth_secret: SecretBytes::new([byte; 32]),
    }
    .to_json()
    .unwrap()
}

#[test]
fn fixed_options_keep_synthetic_salts_stable_across_instances_restart_and_retirement() {
    let peer = Peer::new(ORIGIN).unwrap();
    let before = options(&peer, "fixture.user", NOW);
    let unknown = options(&peer.clone(), "missing.user", NOW);
    let payload = register(&peer);
    let active = options(&peer, &payload.username, NOW);
    assert_eq!(active.salt, payload.password_salt);
    assert_ne!(active.salt, before.salt);
    peer.set_account_active(payload.account_id, false).unwrap();
    let inactive = options(&peer, &payload.username, NOW);
    assert_eq!(inactive.salt, before.salt);
    let peer =
        Peer::restore(peer.checkpoint().unwrap(), ORIGIN, DEFAULT_USED_ACCOUNT_ID_CEILING).unwrap();
    let restarted = options(&peer, "missing.user", NOW);
    assert_eq!(restarted.salt, unknown.salt);
    assert_ne!(restarted.attempt_id, unknown.attempt_id);
    peer.delete_account(payload.account_id).unwrap();
    let retired = options(&peer, &payload.username, NOW);
    assert_eq!(retired.salt, before.salt);
    for response in [before, unknown, active, inactive, restarted, retired] {
        let encoded = response.to_json().unwrap();
        let value: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
        let map = value.as_object().unwrap();
        assert_eq!(map.len(), 4);
        assert_eq!(map["profile"], 1);
        assert_eq!(response.expires_at_ms, NOW + 120_000);
        assert_eq!(AccountPasswordOptionsResponse::from_json(&encoded).unwrap(), response);
    }
}

#[test]
fn options_failures_return_no_attempt_and_preserve_only_confirmed_or_unknown_committed_rows() {
    let body = AccountPasswordOptionsRequest { username: "missing.user".into() }.to_json().unwrap();
    for (fault, error, retained) in [
        (Fault::BeforeCommit, Error::StorageUnavailable, 0),
        (Fault::Audit, Error::StorageUnavailable, 0),
        (Fault::UnknownRollback, Error::StorageUnavailable, 0),
        (Fault::UnknownCommitted, Error::StorageUnavailable, 1),
        (Fault::LostResponse, Error::ResponseLost, 1),
    ] {
        let peer = Peer::new(ORIGIN).unwrap();
        peer.set_fault(fault).unwrap();
        assert_eq!(peer.password_options(&body, || NOW), Err(error));
        let peer =
            Peer::restore(peer.checkpoint().unwrap(), ORIGIN, DEFAULT_USED_ACCOUNT_ID_CEILING)
                .unwrap();
        let summary = peer.password_summary().unwrap();
        assert_eq!(
            (summary.attempts, summary.capabilities, summary.successes, summary.denials),
            (retained, 0, 0, 0)
        );
        let fresh = options(&peer, "missing.user", NOW + 120_001);
        assert_eq!(fresh.expires_at_ms, NOW + 240_001);
        assert_eq!(peer.password_summary().unwrap().attempts, 1);
    }
}

#[test]
fn options_recheck_expiry_before_commit_and_keep_the_durable_time_high_water() {
    let peer = Peer::new(ORIGIN).unwrap();
    let body = AccountPasswordOptionsRequest { username: "missing.user".into() }.to_json().unwrap();
    let mut times = [NOW, NOW + 120_000].into_iter();
    assert_eq!(
        peer.password_options(&body, || times.next().unwrap()),
        Err(Error::StorageUnavailable)
    );
    assert_eq!(peer.password_summary().unwrap().attempts, 0);
    let peer =
        Peer::restore(peer.checkpoint().unwrap(), ORIGIN, DEFAULT_USED_ACCOUNT_ID_CEILING).unwrap();
    assert_eq!(options(&peer, "missing.user", NOW - 1).expires_at_ms, NOW + 240_000);
}

#[test]
fn valid_login_returns_the_exact_strict_snapshot_and_digest_only_capability_at_full_retention() {
    let peer = Peer::with_retention_ceiling(ORIGIN, 1).unwrap();
    let payload = register(&peer);
    let business = peer.summary().unwrap();
    let options = options(&peer, &payload.username, NOW);
    let attempt_rows = peer.password_attempt_rows().unwrap();
    assert_eq!(attempt_rows.len(), 1);
    assert_eq!(attempt_rows[0].0, account_capability_digest(options.attempt_id.as_bytes()));
    assert_eq!(attempt_rows[0].1.username, payload.username);
    let response = peer.password_login(login_body(&options, 0x12), || NOW).unwrap();
    assert_eq!(response.expires_at_ms, NOW + 300_000);
    assert_eq!(
        response.snapshot,
        peer.account_material(payload.account_id).unwrap().unwrap().bootstrap
    );
    let encoded = response.to_json().unwrap();
    assert_eq!(AccountPasswordLoginResponse::from_json(&encoded).unwrap(), response);
    let snapshot = AccountBootstrapSnapshot::from_cbor(response.snapshot.as_bytes()).unwrap();
    assert_eq!(snapshot.account_id, payload.account_id);
    assert_eq!(snapshot.key_bundle, payload.key_bundle);
    let rows = peer.admission_capability_rows().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].0, account_capability_digest(response.admission_token.as_bytes()));
    assert_eq!(rows[0].1.snapshot_digest, account_bootstrap_digest(response.snapshot.as_bytes()));
    assert_eq!(rows[0].1.credential_generation, 1);
    assert_eq!(rows[0].1.account_id, payload.account_id);
    assert!(!rows[0].1.spent);
    assert_eq!(peer.summary().unwrap(), business);
    let summary = peer.password_summary().unwrap();
    assert_eq!(
        (summary.attempts, summary.capabilities, summary.successes, summary.denials),
        (0, 1, 1, 0)
    );
    assert_eq!(
        peer.password_login(login_body(&options, 0x12), || NOW),
        Err(Error::AuthenticationRequired)
    );
    assert_eq!(peer.password_summary().unwrap().successes, 1);
    assert_eq!(format!("{:?}", rows[0].1), "ReferenceAdmissionCapability([REDACTED])");
    assert_eq!(format!("{:?}", attempt_rows[0].1), "ReferencePasswordAttempt([REDACTED])");
}

#[test]
fn wrong_password_unknown_inactive_and_unusable_attempts_share_the_same_denial() {
    for case in ["wrong", "unknown", "inactive", "unusable"] {
        let peer = Peer::new(ORIGIN).unwrap();
        let payload = register(&peer);
        if case == "inactive" {
            peer.set_account_active(payload.account_id, false).unwrap();
        }
        let username = if case == "unknown" { "missing.user" } else { &payload.username };
        let mut options = options(&peer, username, NOW);
        if case == "unusable" {
            options.attempt_id = SecretBytes::new([0x55; 32]);
        }
        let body = login_body(&options, if case == "wrong" { 0x13 } else { 0x12 });
        assert_eq!(peer.password_login(body, || NOW), Err(Error::AuthenticationRequired));
        let summary = peer.password_summary().unwrap();
        assert_eq!((summary.capabilities, summary.successes, summary.denials), (0, 0, 1));
        assert_eq!(summary.attempts, usize::from(case == "unusable"));
        let problem = Error::AuthenticationRequired.problem("/sign-in").unwrap().unwrap();
        assert_eq!((problem.status, problem.changed, problem.retryable), (401, false, false));
    }
}

#[test]
fn changed_salt_or_profile_denies_and_current_generation_must_match_the_complete_snapshot() {
    for field in ["salt", "profile", "generation", "verifier"] {
        let peer = Peer::new(ORIGIN).unwrap();
        let payload = register(&peer);
        let options = options(&peer, &payload.username, NOW);
        let mut credential = peer.password_credential(payload.account_id).unwrap();
        let bootstrap = peer.account_material(payload.account_id).unwrap().unwrap().bootstrap;
        match field {
            "salt" => credential.salt[0] ^= 1,
            "profile" => credential.profile = 2,
            "generation" => credential.generation = 2,
            "verifier" => credential.verifier = SecretBytes::new([0x34; 32]),
            _ => unreachable!(),
        }
        let writer = peer.clone();
        std::thread::spawn(move || {
            writer.script_password_state(payload.account_id, credential, bootstrap).unwrap();
        })
        .join()
        .unwrap();
        let expected = if field == "generation" {
            Error::StorageUnavailable
        } else {
            Error::AuthenticationRequired
        };
        assert_eq!(peer.password_login(login_body(&options, 0x12), || NOW), Err(expected));
        assert_eq!(peer.password_summary().unwrap().capabilities, 0);
        assert_eq!(peer.password_summary().unwrap().attempts, usize::from(field == "generation"));
    }
}

#[test]
fn login_uses_the_complete_transaction_current_generation_without_inventing_options_fields() {
    let peer = Peer::new(ORIGIN).unwrap();
    let payload = register(&peer);
    let options = options(&peer, &payload.username, NOW);
    let mut credential = peer.password_credential(payload.account_id).unwrap();
    credential.generation = 2;
    let material = peer.account_material(payload.account_id).unwrap().unwrap();
    let mut snapshot = AccountBootstrapSnapshot::from_cbor(material.bootstrap.as_bytes()).unwrap();
    snapshot.credential_generation = 2;
    peer.script_password_state(
        payload.account_id,
        credential,
        SecretVec::new(snapshot.to_cbor().unwrap()),
    )
    .unwrap();
    let response = peer.password_login(login_body(&options, 0x12), || NOW).unwrap();
    assert_eq!(
        AccountBootstrapSnapshot::from_cbor(response.snapshot.as_bytes())
            .unwrap()
            .credential_generation,
        2
    );
    assert_eq!(peer.admission_capability_rows().unwrap()[0].1.credential_generation, 2);
}

#[test]
fn pending_rotation_and_self_consistent_untrusted_roots_deny_atomically_with_conflict() {
    for field in ["rotation", "signing-root", "kem-root"] {
        let peer = Peer::new(ORIGIN).unwrap();
        let payload = register(&peer);
        let business = peer.summary().unwrap();
        let credential = peer.password_credential(payload.account_id).unwrap();
        let material = peer.account_material(payload.account_id).unwrap().unwrap();
        let mut snapshot =
            AccountBootstrapSnapshot::from_cbor(material.bootstrap.as_bytes()).unwrap();
        match field {
            "rotation" => snapshot.personal.rotation_pending = true,
            "signing-root" => {
                let root = Ed25519SigningKey::from_bytes(&[4; 32]).unwrap();
                snapshot.account_signing_public_key = root.public_key();
                let cert = DeviceCertificate::decode(&snapshot.certificates[0]).unwrap();
                snapshot.certificates[0] = DeviceCertificate::issue(
                    &root,
                    cert.device_id,
                    cert.account_id,
                    cert.signing_public_key,
                    cert.kem_public_key,
                    cert.display_name,
                    cert.platform,
                    cert.created_at,
                )
                .unwrap()
                .encode()
                .unwrap();
                let mut bundle =
                    SyncAccountKeyBundleUpdate::from_cbor(&snapshot.key_bundle).unwrap();
                bundle.signature = root.sign(&bundle.signature_input().unwrap()).to_vec();
                snapshot.key_bundle = bundle.to_cbor().unwrap();
            }
            "kem-root" => snapshot.account_kem_public_key[0] ^= 1,
            _ => unreachable!(),
        }
        let bootstrap = snapshot.to_cbor().unwrap();
        assert!(AccountBootstrapSnapshot::from_cbor(&bootstrap).is_ok());
        peer.script_password_state(payload.account_id, credential, SecretVec::new(bootstrap))
            .unwrap();
        let attempt = options(&peer, &payload.username, NOW);
        peer.set_fault(Fault::Audit).unwrap();
        assert_eq!(
            peer.password_login(login_body(&attempt, 0x12), || NOW),
            Err(Error::StorageUnavailable)
        );
        let summary = peer.password_summary().unwrap();
        assert_eq!((summary.attempts, summary.capabilities, summary.denials), (1, 0, 0));
        assert_eq!(
            peer.password_login(login_body(&attempt, 0x12), || NOW),
            Err(Error::AdmissionConflict)
        );
        let summary = peer.password_summary().unwrap();
        assert_eq!((summary.attempts, summary.capabilities, summary.denials), (0, 0, 1));
        let expired = options(&peer, &payload.username, NOW);
        let mut times = [NOW, NOW + 120_000].into_iter();
        assert_eq!(
            peer.password_login(login_body(&expired, 0x12), || times.next().unwrap()),
            Err(Error::AuthenticationRequired)
        );
        assert_eq!(peer.password_summary().unwrap().capabilities, 0);
        assert_eq!(peer.summary().unwrap(), business);
    }
    let problem = Error::AdmissionConflict.problem("/sign-in").unwrap().unwrap();
    assert_eq!((problem.status, problem.changed, problem.retryable), (409, false, false));
}

#[test]
fn expiry_is_checked_again_before_commit_and_clock_high_water_survives_restart() {
    let peer = Peer::new(ORIGIN).unwrap();
    let payload = register(&peer);
    let attempt = options(&peer, &payload.username, NOW);
    let mut times = [NOW, NOW + 1, NOW + 120_000].into_iter();
    assert_eq!(
        peer.password_login(login_body(&attempt, 0x12), || times.next().unwrap()),
        Err(Error::AuthenticationRequired)
    );
    assert_eq!(peer.password_summary().unwrap().capabilities, 0);
    let peer =
        Peer::restore(peer.checkpoint().unwrap(), ORIGIN, DEFAULT_USED_ACCOUNT_ID_CEILING).unwrap();
    assert_eq!(
        peer.password_login(login_body(&attempt, 0x12), || NOW - 1),
        Err(Error::AuthenticationRequired)
    );
    let fresh = options(&peer, &payload.username, NOW - 1);
    assert_eq!(fresh.expires_at_ms, NOW + 240_000);
}

#[test]
fn malformed_requests_do_not_consume_attempts_or_the_next_mandatory_audit_fault() {
    let peer = Peer::new(ORIGIN).unwrap();
    let payload = register(&peer);
    let options = options(&peer, &payload.username, NOW);
    let mut bad = login_body(&options, 0x12).as_bytes().to_vec();
    bad.pop();
    bad.extend_from_slice(b",\"extra\":true}");
    peer.set_fault(Fault::Audit).unwrap();
    assert_eq!(peer.password_login(SecretVec::new(bad), || NOW), Err(Error::InvalidRequest));
    assert_eq!(peer.password_summary().unwrap().attempts, 1);
    assert_eq!(
        peer.password_login(login_body(&options, 0x13), || NOW),
        Err(Error::StorageUnavailable)
    );
    let summary = peer.password_summary().unwrap();
    assert_eq!((summary.attempts, summary.capabilities, summary.denials), (1, 0, 0));
    assert!(peer.password_login(login_body(&options, 0x12), || NOW).is_ok());
}

#[test]
fn precommit_or_audit_failure_rolls_back_attempt_capability_and_password_success_together() {
    for fault in [Fault::BeforeCommit, Fault::Audit, Fault::UnknownRollback] {
        let peer = Peer::new(ORIGIN).unwrap();
        let payload = register(&peer);
        let attempt = options(&peer, &payload.username, NOW);
        peer.set_fault(fault).unwrap();
        assert_eq!(
            peer.password_login(login_body(&attempt, 0x12), || NOW),
            Err(Error::StorageUnavailable)
        );
        let summary = peer.password_summary().unwrap();
        assert_eq!((summary.attempts, summary.capabilities, summary.successes), (1, 0, 0));
        let fresh = options(&peer, &payload.username, NOW);
        assert!(peer.password_login(login_body(&fresh, 0x12), || NOW).is_ok());
    }
}

#[test]
fn denial_commit_faults_keep_attempt_consumption_and_failure_audit_atomic_through_restart() {
    for (fault, error, attempts, denials) in [
        (Fault::BeforeCommit, Error::StorageUnavailable, 1, 0),
        (Fault::Audit, Error::StorageUnavailable, 1, 0),
        (Fault::UnknownRollback, Error::StorageUnavailable, 1, 0),
        (Fault::UnknownCommitted, Error::StorageUnavailable, 0, 1),
        (Fault::LostResponse, Error::ResponseLost, 0, 1),
    ] {
        let peer = Peer::new(ORIGIN).unwrap();
        let payload = register(&peer);
        let business = peer.summary().unwrap();
        let attempt = options(&peer, &payload.username, NOW);
        peer.set_fault(fault).unwrap();
        assert_eq!(peer.password_login(login_body(&attempt, 0x13), || NOW), Err(error));
        let peer =
            Peer::restore(peer.checkpoint().unwrap(), ORIGIN, DEFAULT_USED_ACCOUNT_ID_CEILING)
                .unwrap();
        let summary = peer.password_summary().unwrap();
        assert_eq!(
            (summary.attempts, summary.capabilities, summary.successes, summary.denials),
            (attempts, 0, 0, denials)
        );
        assert_eq!(peer.summary().unwrap(), business);
        let result = peer.password_login(login_body(&attempt, 0x12), || NOW);
        if attempts == 1 {
            assert!(result.is_ok());
        } else {
            assert_eq!(result, Err(Error::AuthenticationRequired));
        }
    }
}

#[test]
fn unknown_capability_commit_and_lost_response_return_no_token_or_business_change() {
    for (fault, error) in [
        (Fault::UnknownCommitted, Error::StorageUnavailable),
        (Fault::LostResponse, Error::ResponseLost),
    ] {
        let peer = Peer::new(ORIGIN).unwrap();
        let payload = register(&peer);
        let business = peer.summary().unwrap();
        let attempt = options(&peer, &payload.username, NOW);
        peer.set_fault(fault).unwrap();
        assert_eq!(peer.password_login(login_body(&attempt, 0x12), || NOW), Err(error));
        let peer =
            Peer::restore(peer.checkpoint().unwrap(), ORIGIN, DEFAULT_USED_ACCOUNT_ID_CEILING)
                .unwrap();
        assert_eq!(peer.summary().unwrap(), business);
        let summary = peer.password_summary().unwrap();
        assert_eq!((summary.attempts, summary.capabilities, summary.successes), (0, 1, 1));
        let row = peer.admission_capability_rows().unwrap().pop().unwrap().1;
        assert_eq!(
            (row.account_id, row.credential_generation, row.expires_at_ms),
            (payload.account_id, 1, NOW + 300_000)
        );
        assert_eq!(
            peer.password_login(login_body(&attempt, 0x12), || NOW),
            Err(Error::AuthenticationRequired)
        );
    }
    let problem = Error::StorageUnavailable.problem("/sign-in").unwrap().unwrap();
    assert_eq!((problem.status, problem.changed, problem.retryable), (503, false, true));
}

#[test]
fn cloned_instances_can_claim_a_password_attempt_only_once() {
    let peer = Peer::new(ORIGIN).unwrap();
    let payload = register(&peer);
    let attempt = options(&peer, &payload.username, NOW);
    let body = login_body(&attempt, 0x12);
    let results = std::thread::scope(|scope| {
        let workers: Vec<_> = (0..3)
            .map(|_| {
                let instance = peer.clone();
                let body = body.clone();
                scope.spawn(move || instance.password_login(body, || NOW))
            })
            .collect();
        workers.into_iter().map(|worker| worker.join().unwrap()).collect::<Vec<_>>()
    });
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    assert_eq!(results.iter().filter(|r| **r == Err(Error::AuthenticationRequired)).count(), 2);
    let summary = peer.password_summary().unwrap();
    assert_eq!(
        (summary.attempts, summary.capabilities, summary.successes, summary.denials),
        (0, 1, 1, 2)
    );
}

#[test]
fn capability_capacity_preserves_the_attempt_and_recovers_after_indexed_expiry() {
    let peer = Peer::new(ORIGIN).unwrap();
    let payload = register(&peer);
    for _ in 0..4 {
        let attempt = options(&peer, &payload.username, NOW);
        peer.password_login(login_body(&attempt, 0x12), || NOW).unwrap();
    }
    let attempt = options(&peer, &payload.username, NOW);
    assert_eq!(peer.password_login(login_body(&attempt, 0x12), || NOW), Err(Error::RateLimited));
    let summary = peer.password_summary().unwrap();
    assert_eq!(
        (summary.attempts, summary.capabilities, summary.successes, summary.denials),
        (1, 4, 4, 0)
    );
    let fresh = options(&peer, &payload.username, NOW + 300_001);
    assert_eq!(peer.password_summary().unwrap().capabilities, 0);
    peer.password_login(login_body(&fresh, 0x12), || NOW + 300_001).unwrap();
}

#[test]
fn deployment_capability_capacity_is_independent_of_per_account_capacity_and_recovers() {
    let peer = Peer::new(ORIGIN).unwrap();
    let template = registration_request();
    for index in 0..1_024 {
        let (request, signer) = indexed_registration(&template, index);
        let payload = register_request(&peer, request, &signer);
        for _ in 0..4 {
            let attempt = options(&peer, &payload.username, NOW);
            peer.password_login(login_body(&attempt, 0x12), || NOW).unwrap();
        }
    }
    let (request, signer) = indexed_registration(&template, 1_024);
    let payload = register_request(&peer, request, &signer);
    let attempt = options(&peer, &payload.username, NOW);
    for _ in 0..2 {
        assert_eq!(
            peer.password_login(login_body(&attempt, 0x12), || NOW),
            Err(Error::RateLimited)
        );
    }
    let summary = peer.password_summary().unwrap();
    assert_eq!(
        (summary.attempts, summary.capabilities, summary.successes, summary.denials),
        (1, 4_096, 4_096, 0)
    );
    assert_eq!(
        peer.password_attempt_rows().unwrap()[0].0,
        account_capability_digest(attempt.attempt_id.as_bytes())
    );
    let fresh = options(&peer, &payload.username, NOW + 300_001);
    assert_eq!(peer.password_summary().unwrap().capabilities, 3_997);
    let response = peer.password_login(login_body(&fresh, 0x12), || NOW + 300_001).unwrap();
    assert_eq!(response.expires_at_ms, NOW + 600_001);
    let summary = peer.password_summary().unwrap();
    assert_eq!((summary.attempts, summary.capabilities, summary.successes), (0, 3_998, 4_097));
}

#[test]
fn attempt_capacity_is_fixed_for_all_usernames_and_cleanup_considers_only_one_bounded_batch() {
    let peer = Peer::new(ORIGIN).unwrap();
    let payload = register(&peer);
    for _ in 0..16_384 {
        options(&peer, "missing.user", NOW);
    }
    for username in [payload.username.as_str(), "missing.user"] {
        let body = AccountPasswordOptionsRequest { username: username.into() }.to_json().unwrap();
        assert_eq!(peer.password_options(&body, || NOW), Err(Error::RateLimited));
    }
    assert_eq!(peer.password_summary().unwrap().attempts, 16_384);
    options(&peer, "missing.user", NOW + 120_001);
    assert_eq!(peer.password_summary().unwrap().attempts, 16_285);
    options(&peer, "missing.user", NOW + 120_001);
    assert_eq!(peer.password_summary().unwrap().attempts, 16_286);
}

#[test]
fn malformed_current_signed_snapshot_never_returns_a_capability() {
    let peer = Peer::new(ORIGIN).unwrap();
    let payload = register(&peer);
    let credential = peer.password_credential(payload.account_id).unwrap();
    let material = peer.account_material(payload.account_id).unwrap().unwrap();
    let Value::Map(mut fields) = cbor::decode(material.bootstrap.as_bytes()).unwrap() else {
        panic!("snapshot map")
    };
    fields.iter_mut().find(|(key, _)| key == &Value::Text("key_bundle".into())).unwrap().1 =
        Value::Bytes(vec![0xff]);
    peer.script_password_state(
        payload.account_id,
        credential,
        SecretVec::new(cbor::encode(&Value::Map(fields)).unwrap()),
    )
    .unwrap();
    let attempt = options(&peer, &payload.username, NOW);
    assert_eq!(
        peer.password_login(login_body(&attempt, 0x12), || NOW),
        Err(Error::StorageUnavailable)
    );
    let summary = peer.password_summary().unwrap();
    assert_eq!((summary.attempts, summary.capabilities, summary.successes), (1, 0, 0));
}

#[test]
fn account_deletion_removes_password_attempts_and_capabilities_but_preserves_account_digest() {
    let peer = Peer::new(ORIGIN).unwrap();
    let payload = register(&peer);
    let attempt = options(&peer, &payload.username, NOW);
    peer.password_login(login_body(&attempt, 0x12), || NOW).unwrap();
    options(&peer, &payload.username, NOW);
    peer.delete_account(payload.account_id).unwrap();
    let summary = peer.password_summary().unwrap();
    assert_eq!((summary.attempts, summary.capabilities), (0, 0));
    assert_eq!(peer.summary().unwrap().used_account_ids, 1);
    assert!(peer.password_credential(payload.account_id).is_err());
}

#[test]
fn maintenance_and_problems_remain_content_free_and_never_claim_business_change() {
    let peer = Peer::new(ORIGIN).unwrap();
    let payload = register(&peer);
    let attempt = options(&peer, &payload.username, NOW);
    peer.set_maintenance(true).unwrap();
    assert_eq!(
        peer.password_options(
            &AccountPasswordOptionsRequest { username: payload.username }.to_json().unwrap(),
            || NOW
        ),
        Err(Error::StorageUnavailable)
    );
    assert_eq!(
        peer.password_login(login_body(&attempt, 0x12), || NOW),
        Err(Error::StorageUnavailable)
    );
    assert_eq!(peer.password_summary().unwrap().attempts, 1);
    for error in [
        Error::InvalidRequest,
        Error::TooLarge,
        Error::AuthenticationRequired,
        Error::AdmissionConflict,
        Error::RateLimited,
        Error::StorageUnavailable,
    ] {
        let problem = error.problem("/sign-in").unwrap().unwrap();
        assert!(!problem.changed);
        assert!(serde_json::to_vec(&problem).unwrap().len() <= 4_096);
    }
    assert!(Error::StorageUnavailable.problem(&"\0".repeat(700)).is_err());
    assert!(Error::ResponseLost.problem("/sign-in").unwrap().is_none());
}
