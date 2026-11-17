// SPDX-License-Identifier: Apache-2.0
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use scoplen_api::account_admission::*;
use scoplen_crypto::{
    AccountRequestProof, AccountRequestSignatureInput, DeviceCertificate, Ed25519SigningKey,
    P256SigningKey, SecretBytes, SecretVec, account_bootstrap_digest, account_capability_digest,
};
use scoplen_model::cbor::{self, Value as Cbor};
use scoplen_test_vectors::VectorDocument;
use serde_json::{Value, json};
use uuid::Uuid;

fn unhex(text: &str) -> Vec<u8> {
    text.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect()
}

fn fixture() -> (AccountBootstrapSnapshot, Vec<u8>, AccountPasswordChangePayload) {
    let vectors =
        VectorDocument::parse_str(include_str!("../../../vectors/account-admission.json")).unwrap();
    let raw = unhex(
        &vectors
            .vectors
            .iter()
            .find(|v| v.kind == "account.admission.snapshot.cbor")
            .unwrap()
            .input,
    );
    let snapshot = AccountBootstrapSnapshot::from_cbor(&raw).unwrap();
    let device = DeviceCertificate::decode(&snapshot.certificates[0]).unwrap();
    let payload = AccountPasswordChangePayload {
        operation_id: Uuid::parse_str("018f3f3a-bcd1-7000-8000-000000000099").unwrap(),
        origin: snapshot.origin.clone(),
        username: snapshot.username.clone(),
        account_id: snapshot.account_id,
        personal_vault_id: snapshot.personal_vault_id,
        device_id: device.device_id,
        credential_generation: snapshot.credential_generation,
        new_credential_generation: snapshot.credential_generation + 1,
        snapshot_digest: account_bootstrap_digest(&raw),
        capability_digest: account_capability_digest(&[0x33; 32]),
        password_salt: [0x44; 16],
        verifier: [0x55; 32],
        password_ark: snapshot.password_ark,
    };
    (snapshot, raw, payload)
}

fn sign_request(request: &mut AccountPasswordChangeRequest) {
    let account = Ed25519SigningKey::from_bytes(&[1; 32]).unwrap();
    let device = P256SigningKey::from_bytes(&[2; 32]).unwrap();
    let (_, _, p) = fixture();
    let input = AccountRequestSignatureInput::new(
        AccountRequestKind::PasswordChange,
        request.payload.as_bytes(),
    )
    .unwrap();
    request.account_signature = input.sign(&account);
    request.device_proof = AccountRequestProof::new(
        AccountRequestKind::PasswordChange,
        request.intent,
        &p.origin,
        request.attempt_id.as_bytes(),
        request.nonce.as_bytes(),
        p.operation_id,
        p.device_id,
        &input.request_digest(&request.account_signature),
    )
    .unwrap()
    .sign(&device)
    .unwrap();
}

fn request(intent: AccountRequestIntent) -> AccountPasswordChangeRequest {
    let (_, _, p) = fixture();
    let mut request = AccountPasswordChangeRequest {
        intent,
        payload: SecretVec::new(p.to_cbor().unwrap()),
        account_signature: [0; 64],
        attempt_id: SecretBytes::new([3; 32]),
        nonce: SecretBytes::new([4; 32]),
        device_proof: [0; 64],
        admission_token: (intent == AccountRequestIntent::Submit)
            .then(|| SecretBytes::new([0x33; 32])),
    };
    sign_request(&mut request);
    request
}

fn body(request: &AccountPasswordChangeRequest) -> Value {
    json!({
        "intent": request.intent.as_str(), "payload": URL_SAFE_NO_PAD.encode(request.payload.as_bytes()),
        "account_signature": URL_SAFE_NO_PAD.encode(request.account_signature),
        "attempt_id": URL_SAFE_NO_PAD.encode(request.attempt_id.as_bytes()),
        "nonce": URL_SAFE_NO_PAD.encode(request.nonce.as_bytes()),
        "device_proof": URL_SAFE_NO_PAD.encode(request.device_proof),
        "admission_token": request.admission_token.as_ref().map(|token| URL_SAFE_NO_PAD.encode(token.as_bytes())),
    })
}

fn confirmation(request: &AccountPasswordChangeRequest) -> AccountPasswordChangeConfirmation {
    let p = AccountPasswordChangePayload::from_cbor(request.payload.as_bytes()).unwrap();
    AccountPasswordChangeConfirmation {
        operation_id: p.operation_id,
        request_digest: AccountRequestSignatureInput::new(
            AccountRequestKind::PasswordChange,
            request.payload.as_bytes(),
        )
        .unwrap()
        .request_digest(&request.account_signature),
        account_id: p.account_id,
        personal_vault_id: p.personal_vault_id,
        device_id: p.device_id,
        credential_generation: p.new_credential_generation,
    }
}

fn protected_field(payload: &mut Cbor, key: &str, value: Cbor) {
    let Cbor::Map(fields) = payload else { panic!("map") };
    fields.iter_mut().find(|(name, _)| name == &Cbor::Text(key.into())).unwrap().1 = value;
}

#[test]
fn password_change_routes_challenges_and_complete_body_bounds() {
    let route = "/api/v1/auth/accounts/password-changes";
    assert_eq!(
        AccountEntryOperation::from_route("POST", route),
        Some(AccountEntryOperation::PasswordChange)
    );
    assert_eq!(AccountEntryOperation::PasswordChange.body_limits(), (16_384, 1_024));
    assert_eq!(AccountEntryOperation::from_route("GET", route), None);
    assert_eq!(AccountEntryOperation::from_route("POST", &format!("{route}/")), None);
    assert_eq!(AccountEntryOperation::from_route("POST", &format!("{route}?a=1")), None);
    for intent in [AccountRequestIntent::Submit, AccountRequestIntent::Confirm] {
        let r = request(intent);
        let (_, p) =
            AccountPasswordChangeRequest::decode_for_authentication(&r.to_json().unwrap()).unwrap();
        let challenge = AccountRequestChallengeRequest {
            kind: AccountRequestKind::PasswordChange,
            intent,
            operation_id: p.operation_id,
            device_id: p.device_id,
        };
        assert_eq!(
            AccountRequestChallengeRequest::from_json(&challenge.to_json().unwrap()),
            Ok(challenge)
        );
        let mut encoded = r.to_json().unwrap();
        encoded.resize(16_384, b' ');
        assert_eq!(AccountPasswordChangeRequest::from_json(&encoded), Ok(r));
        encoded.push(b' ');
        assert_eq!(
            AccountPasswordChangeRequest::from_json(&encoded),
            Err(AccountAdmissionCodecError::TooLarge)
        );
    }
    let mut oversized = body(&request(AccountRequestIntent::Submit));
    oversized["payload"] = URL_SAFE_NO_PAD.encode(vec![0; 8_193]).into();
    assert!(
        AccountPasswordChangeRequest::from_json(&serde_json::to_vec(&oversized).unwrap()).is_err()
    );
    assert_eq!(
        AccountPasswordChangePayload::from_cbor(&vec![0; 8_193]),
        Err(AccountAdmissionCodecError::TooLarge)
    );
}

#[test]
fn password_change_payload_preserves_existing_device_and_exact_snapshot_binding() {
    let (snapshot, raw, p) = fixture();
    let original = snapshot.to_cbor().unwrap();
    assert_eq!(AccountPasswordChangePayload::from_cbor(&p.to_cbor().unwrap()), Ok(p.clone()));
    p.validate_for_snapshot(&snapshot, &raw, &[0x33; 32]).unwrap();
    assert_eq!(snapshot.to_cbor().unwrap(), original);
    assert_eq!(
        p.validate_for_snapshot(&snapshot, &raw, &[0x34; 32]),
        Err(AccountAdmissionCodecError::Binding)
    );
    let mut bad = p.clone();
    bad.device_id = bad.operation_id;
    assert_eq!(
        bad.validate_for_snapshot(&snapshot, &raw, &[0x33; 32]),
        Err(AccountAdmissionCodecError::Binding)
    );
    for field in ["origin", "username", "account", "vault", "generation", "snapshot", "capability"]
    {
        let mut bad = p.clone();
        match field {
            "origin" => bad.origin = "https://other.example.com".into(),
            "username" => bad.username = "other.user".into(),
            "account" => bad.account_id = bad.operation_id,
            "vault" => bad.personal_vault_id = bad.operation_id,
            "generation" => {
                bad.credential_generation += 1;
                bad.new_credential_generation += 1;
            }
            "snapshot" => bad.snapshot_digest[0] ^= 1,
            "capability" => bad.capability_digest[0] ^= 1,
            _ => unreachable!(),
        }
        assert_eq!(
            bad.validate_for_snapshot(&snapshot, &raw, &[0x33; 32]),
            Err(AccountAdmissionCodecError::Binding),
            "{field}"
        );
    }
    let mut pending = snapshot.clone();
    pending.personal.rotation_pending = true;
    let bytes = pending.to_cbor().unwrap();
    assert_eq!(
        p.validate_for_snapshot(&pending, &bytes, &[0x33; 32]),
        Err(AccountAdmissionCodecError::AdmissionConflict)
    );
    let mut trailing = raw;
    trailing.push(0);
    assert_eq!(
        p.validate_for_snapshot(&snapshot, &trailing, &[0x33; 32]),
        Err(AccountAdmissionCodecError::Binding)
    );
}

#[test]
fn password_change_proofs_bind_root_device_domain_intent_and_exact_bytes() {
    let account = Ed25519SigningKey::from_bytes(&[1; 32]).unwrap();
    let device = P256SigningKey::from_bytes(&[2; 32]).unwrap();
    for intent in [AccountRequestIntent::Submit, AccountRequestIntent::Confirm] {
        let original = request(intent);
        let (_, _, p) = fixture();
        let root = account.public_key();
        let key = device.public_key_sec1();
        let digest = original.verify_proof(&p.origin, &root, &key).unwrap();
        assert_eq!(
            digest,
            AccountRequestSignatureInput::new(
                AccountRequestKind::PasswordChange,
                original.payload.as_bytes()
            )
            .unwrap()
            .request_digest(&original.account_signature)
        );
        assert!(original.verify_proof("https://other.example.com", &root, &key).is_err());
        assert!(
            original
                .verify_proof(
                    &p.origin,
                    &Ed25519SigningKey::from_bytes(&[9; 32]).unwrap().public_key(),
                    &key
                )
                .is_err()
        );
        assert!(
            original
                .verify_proof(
                    &p.origin,
                    &root,
                    &P256SigningKey::from_bytes(&[9; 32]).unwrap().public_key_sec1()
                )
                .is_err()
        );
        for field in ["intent", "attempt", "nonce", "account_signature", "device_proof", "payload"]
        {
            let mut bad = original.clone();
            match field {
                "intent" => {
                    bad.intent = if intent == AccountRequestIntent::Submit {
                        AccountRequestIntent::Confirm
                    } else {
                        AccountRequestIntent::Submit
                    }
                }
                "attempt" => bad.attempt_id = SecretBytes::new([8; 32]),
                "nonce" => bad.nonce = SecretBytes::new([8; 32]),
                "account_signature" => bad.account_signature[0] ^= 1,
                "device_proof" => bad.device_proof[0] ^= 1,
                "payload" => {
                    let mut changed = p.clone();
                    changed.password_salt[0] ^= 1;
                    bad.payload = SecretVec::new(changed.to_cbor().unwrap());
                }
                _ => unreachable!(),
            }
            assert_eq!(
                bad.verify_proof(&p.origin, &root, &key),
                Err(AccountAdmissionCodecError::Binding),
                "{field}"
            );
        }
        let mut cross_domain = original;
        cross_domain.account_signature = AccountRequestSignatureInput::new(
            AccountRequestKind::Admit,
            cross_domain.payload.as_bytes(),
        )
        .unwrap()
        .sign(&account);
        assert!(cross_domain.verify_proof(&p.origin, &root, &key).is_err());
    }
}

#[test]
fn password_change_generation_conflicts_are_authenticated_after_structural_decoding() {
    let (_, _, mut p) = fixture();
    p.credential_generation = u64::MAX - 1;
    p.new_credential_generation = u64::MAX;
    assert_eq!(AccountPasswordChangePayload::from_cbor(&p.to_cbor().unwrap()), Ok(p.clone()));
    for (old, new) in [(1, 1), (1, 3), (u64::MAX, 1)] {
        let mut r = request(AccountRequestIntent::Submit);
        let mut fields = cbor::decode(r.payload.as_bytes()).unwrap();
        protected_field(&mut fields, "credential_generation", Cbor::UInt(old));
        protected_field(&mut fields, "new_credential_generation", Cbor::UInt(new));
        r.payload = SecretVec::new(cbor::encode(&fields).unwrap());
        sign_request(&mut r);
        let raw = serde_json::to_vec(&body(&r)).unwrap();
        let (decoded, p) = AccountPasswordChangeRequest::decode_for_authentication(&raw).unwrap();
        assert_eq!(p.validate(), Err(AccountAdmissionCodecError::AdmissionConflict));
        assert_eq!(
            AccountPasswordChangeRequest::from_json(&raw),
            Err(AccountAdmissionCodecError::AdmissionConflict)
        );
        decoded
            .verify_proof(
                &p.origin,
                &Ed25519SigningKey::from_bytes(&[1; 32]).unwrap().public_key(),
                &P256SigningKey::from_bytes(&[2; 32]).unwrap().public_key_sec1(),
            )
            .unwrap();
    }
    for field in ["credential_generation", "new_credential_generation"] {
        let mut r = request(AccountRequestIntent::Submit);
        let mut fields = cbor::decode(r.payload.as_bytes()).unwrap();
        protected_field(&mut fields, field, Cbor::UInt(0));
        r.payload = SecretVec::new(cbor::encode(&fields).unwrap());
        assert_eq!(
            AccountPasswordChangeRequest::decode_for_authentication(
                &serde_json::to_vec(&body(&r)).unwrap()
            ),
            Err(AccountAdmissionCodecError::InvalidProtected)
        );
    }
}

#[test]
fn password_change_rejects_malformed_protected_maps_and_wrappers() {
    let (_, _, p) = fixture();
    let raw = p.to_cbor().unwrap();
    for (field, value) in [
        ("version", Cbor::UInt(2)),
        ("password_profile", Cbor::UInt(2)),
        ("password_salt", Cbor::Bytes(vec![0; 15])),
        ("verifier", Cbor::Bytes(vec![0; 31])),
        ("snapshot_digest", Cbor::Bytes(vec![0; 33])),
        ("password_ark", Cbor::Bytes(vec![0; 73])),
        ("account_id", Cbor::Bytes(vec![0; 16])),
        ("origin", Cbor::Text(format!("{}/", p.origin))),
    ] {
        let mut value_map = cbor::decode(&raw).unwrap();
        protected_field(&mut value_map, field, value);
        assert!(
            AccountPasswordChangePayload::from_cbor(&cbor::encode(&value_map).unwrap()).is_err(),
            "{field}"
        );
    }
    let Cbor::Map(mut fields) = cbor::decode(&raw).unwrap() else { panic!("map") };
    fields.push((Cbor::Text("extra".into()), Cbor::UInt(1)));
    assert!(
        AccountPasswordChangePayload::from_cbor(&cbor::encode(&Cbor::Map(fields)).unwrap())
            .is_err()
    );
    let mut nonshortest = raw.clone();
    nonshortest.splice(..1, [0xb8, 15]);
    assert!(AccountPasswordChangePayload::from_cbor(&nonshortest).is_err());
    let mut trailing = raw;
    trailing.push(0);
    assert!(AccountPasswordChangePayload::from_cbor(&trailing).is_err());
    assert!(
        AccountPasswordChangePayload::from_cbor(b"\xbb\xff\xff\xff\xff\xff\xff\xff\xff").is_err()
    );
}

#[test]
fn password_change_requests_enforce_token_intent_and_strict_json() {
    for intent in [AccountRequestIntent::Submit, AccountRequestIntent::Confirm] {
        let r = request(intent);
        assert_eq!(AccountPasswordChangeRequest::from_json(&r.to_json().unwrap()), Ok(r.clone()));
        let mut wrong_token = r.clone();
        wrong_token.admission_token = if intent == AccountRequestIntent::Submit {
            None
        } else {
            Some(SecretBytes::new([0x33; 32]))
        };
        assert_eq!(wrong_token.to_json(), Err(AccountAdmissionCodecError::InvalidJson));
        assert!(
            AccountPasswordChangeRequest::from_json(
                &serde_json::to_vec(&body(&wrong_token)).unwrap()
            )
            .is_err()
        );
        for field in ["missing", "unknown", "padded", "signature-width"] {
            let mut value = body(&r);
            match field {
                "missing" => {
                    value.as_object_mut().unwrap().remove("admission_token");
                }
                "unknown" => value["extra"] = Value::Null,
                "padded" => {
                    value["nonce"] = format!("{}=", value["nonce"].as_str().unwrap()).into();
                }
                "signature-width" => value["device_proof"] = URL_SAFE_NO_PAD.encode([0; 63]).into(),
                _ => unreachable!(),
            }
            let raw = serde_json::to_vec(&value).unwrap();
            assert!(AccountPasswordChangeRequest::from_json(&raw).is_err(), "{field}");
        }
        let encoded = r.to_json().unwrap();
        let duplicated = format!(
            "{{\"intent\":\"{}\",{}",
            intent.as_str(),
            std::str::from_utf8(&encoded[1..]).unwrap()
        );
        assert!(AccountPasswordChangeRequest::from_json(duplicated.as_bytes()).is_err());
        let mut bom = vec![0xef, 0xbb, 0xbf];
        bom.extend_from_slice(&encoded);
        assert!(AccountPasswordChangeRequest::from_json(&bom).is_err());
        assert!(format!("{r:?}").contains("REDACTED"));
    }
}

#[test]
fn password_change_confirmation_binds_original_generation_ids_digest_and_kind() {
    let r = request(AccountRequestIntent::Submit);
    let p = AccountPasswordChangePayload::from_cbor(r.payload.as_bytes()).unwrap();
    let confirmation = confirmation(&r);
    let encoded = confirmation.to_json().unwrap();
    assert_eq!(AccountPasswordChangeConfirmation::from_json(&encoded), Ok(confirmation.clone()));
    confirmation.validate_for_request(r.payload.as_bytes(), &r.account_signature).unwrap();
    assert_eq!(
        AccountCommittedConfirmation::from_json(&encoded),
        Err(AccountAdmissionCodecError::InvalidJson)
    );
    for field in ["operation", "account", "vault", "device", "digest", "generation"] {
        let mut bad = confirmation.clone();
        match field {
            "operation" => bad.operation_id = p.account_id,
            "account" => bad.account_id = p.operation_id,
            "vault" => bad.personal_vault_id = p.operation_id,
            "device" => bad.device_id = p.operation_id,
            "digest" => bad.request_digest[0] ^= 1,
            "generation" => bad.credential_generation += 1,
            _ => unreachable!(),
        }
        assert_eq!(
            bad.validate_for_request(r.payload.as_bytes(), &r.account_signature),
            Err(AccountAdmissionCodecError::Binding),
            "{field}"
        );
    }
    for value in [json!(2), json!("0"), json!("02"), json!("18446744073709551616")] {
        let mut bad: Value = serde_json::from_slice(&encoded).unwrap();
        bad["credential_generation"] = value;
        assert!(
            AccountPasswordChangeConfirmation::from_json(&serde_json::to_vec(&bad).unwrap())
                .is_err()
        );
    }
    let mut wrong_kind: Value = serde_json::from_slice(&encoded).unwrap();
    wrong_kind["kind"] = "admit".into();
    wrong_kind["admitted_key_revision"] = "1".into();
    assert!(
        AccountPasswordChangeConfirmation::from_json(&serde_json::to_vec(&wrong_kind).unwrap())
            .is_err()
    );
    let old = AccountCommittedConfirmation {
        kind: AccountRequestKind::PasswordChange,
        operation_id: p.operation_id,
        request_digest: [0; 32],
        account_id: p.account_id,
        personal_vault_id: p.personal_vault_id,
        device_id: p.device_id,
        admitted_key_revision: 1,
    };
    assert!(old.to_json().is_err());
    assert!(
        old.validate_for_request(
            AccountRequestKind::PasswordChange,
            r.payload.as_bytes(),
            &r.account_signature
        )
        .is_err()
    );
}

#[test]
fn password_change_confirmation_requires_cache_metadata_and_strict_bounded_json() {
    let confirmation = confirmation(&request(AccountRequestIntent::Submit));
    let encoded = confirmation.to_json().unwrap();
    let mut extension: Value = serde_json::from_slice(&encoded).unwrap();
    extension["extension"] = json!({"value": 1});
    assert_eq!(
        AccountPasswordChangeConfirmation::from_json(&serde_json::to_vec(&extension).unwrap()),
        Ok(confirmation.clone())
    );
    let recursive_duplicate = format!(
        "{{\"extension\":{{\"value\":1,\"value\":2}},{}",
        std::str::from_utf8(&encoded[1..]).unwrap()
    );
    assert!(AccountPasswordChangeConfirmation::from_json(recursive_duplicate.as_bytes()).is_err());
    let mut boundary = encoded;
    boundary.resize(1_024, b' ');
    AccountPasswordChangeConfirmation::from_http_json(
        &boundary,
        Some("no-store"),
        Some("no-cache"),
    )
    .unwrap();
    assert!(
        AccountPasswordChangeConfirmation::from_http_json(&boundary, None, Some("no-cache"))
            .is_err()
    );
    boundary.push(b' ');
    assert_eq!(
        AccountPasswordChangeConfirmation::from_json(&boundary),
        Err(AccountAdmissionCodecError::TooLarge)
    );
    assert!(format!("{confirmation:?}").contains("REDACTED"));
}
