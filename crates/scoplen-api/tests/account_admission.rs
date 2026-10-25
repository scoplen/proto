// SPDX-License-Identifier: Apache-2.0
use scoplen_api::account_admission::*;
use scoplen_crypto::{AccountRequestSignatureInput, SecretBytes};
use scoplen_model::cbor::{self, Value as Cbor};
use scoplen_test_vectors::VectorDocument;
use serde_json::Value;

fn vectors() -> VectorDocument {
    VectorDocument::parse_str(include_str!("../../../vectors/account-admission.json")).unwrap()
}

fn unhex(text: &str) -> Vec<u8> {
    text.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect()
}

fn fixture(kind: &str) -> Vec<u8> {
    let document = vectors();
    let v =
        document.vectors.iter().find(|v| v.kind == format!("account.admission.{kind}")).unwrap();
    if kind.rsplit('.').next() == Some("cbor") {
        unhex(&v.input)
    } else {
        v.input.as_bytes().to_vec()
    }
}

macro_rules! json_case {
    ($ty:ty,$v:expr,$reject:expr) => {{
        let result = <$ty>::from_json($v.input.as_bytes());
        if $reject {
            assert!(result.is_err(), "{}", $v.id);
        } else {
            let value = result.expect(&$v.id);
            let canonical = value.to_json().expect(&$v.id);
            assert_eq!(canonical.as_slice(), $v.expected.as_bytes(), "{}", $v.id);
            assert_eq!(<$ty>::from_json(&canonical), Ok(value), "{}", $v.id);
        }
    }};
}

#[test]
fn independent_vectors_cover_every_native_message_and_protected_map() {
    let mut counts = std::collections::BTreeMap::<String, usize>::new();
    for v in vectors().vectors {
        let base = v.kind.strip_suffix(".reject").unwrap_or(&v.kind);
        let reject = v.kind.ends_with(".reject");
        *counts.entry(base.to_owned()).or_default() += 1;
        match base.strip_prefix("account.admission.").unwrap() {
            "challenge.request" => json_case!(AccountRequestChallengeRequest, v, reject),
            "challenge.response" => json_case!(AccountRequestChallengeResponse, v, reject),
            "options.request" => json_case!(AccountPasswordOptionsRequest, v, reject),
            "options.response" => json_case!(AccountPasswordOptionsResponse, v, reject),
            "login.request" => {
                let value = AccountPasswordLoginRequest::from_json(v.input.as_bytes()).unwrap();
                let canonical = value.to_json().unwrap();
                assert_eq!(canonical.as_bytes(), v.expected.as_bytes());
                assert_eq!(AccountPasswordLoginRequest::from_json(canonical.as_bytes()), Ok(value));
            }
            "login.response" => json_case!(AccountPasswordLoginResponse, v, reject),
            "register.request" => json_case!(AccountRegistrationRequest, v, reject),
            "admit.request" => json_case!(AccountDeviceAdmissionRequest, v, reject),
            "confirmation" => json_case!(AccountCommittedConfirmation, v, reject),
            "registration.cbor" | "admission.cbor" | "snapshot.cbor" => {
                let input = unhex(&v.input);
                let output = match base {
                    "account.admission.registration.cbor" => {
                        AccountRegistrationPayload::from_cbor(&input).and_then(|p| p.to_cbor())
                    }
                    "account.admission.admission.cbor" => {
                        AccountDeviceAdmissionPayload::from_cbor(&input).and_then(|p| p.to_cbor())
                    }
                    _ => AccountBootstrapSnapshot::from_cbor(&input).and_then(|p| p.to_cbor()),
                };
                if reject {
                    assert!(output.is_err(), "{}", v.id);
                } else {
                    assert_eq!(output.unwrap(), unhex(&v.expected), "{}", v.id);
                }
            }
            "snapshot.digest" => assert_eq!(
                scoplen_crypto::account_bootstrap_digest(&unhex(&v.input)).as_slice(),
                unhex(&v.expected)
            ),
            "capability.digest" => assert_eq!(
                scoplen_crypto::account_capability_digest(
                    unhex(&v.input).as_slice().try_into().unwrap()
                )
                .as_slice(),
                unhex(&v.expected)
            ),
            "proof" | "probe" => {}
            other => panic!("unknown D-128 vector kind {other}"),
        }
    }
    assert_eq!(counts.len(), 16);
}

#[test]
fn exact_signatures_and_intent_bind_original_business_material() {
    let document = vectors();
    for kind in ["register", "admit"] {
        let root = unhex(
            serde_json::from_str::<Value>(
                &document
                    .vectors
                    .iter()
                    .find(|v| v.id == format!("account-admission-{kind}-submit-signature-input"))
                    .unwrap()
                    .input,
            )
            .unwrap()["account_public_key"]
                .as_str()
                .unwrap(),
        );
        for intent in ["submit", "confirm"] {
            let bytes = document
                .vectors
                .iter()
                .find(|v| v.id == format!("account-admission-{kind}-{intent}"))
                .unwrap()
                .input
                .as_bytes();
            if kind == "register" {
                let mut request = AccountRegistrationRequest::from_json(bytes).unwrap();
                let digest = request.verify_proof("https://control.example.com").unwrap();
                assert_eq!(
                    digest,
                    AccountRequestSignatureInput::new(
                        AccountRequestKind::Register,
                        request.payload.as_bytes()
                    )
                    .unwrap()
                    .request_digest(&request.account_signature)
                );
                request.intent = if intent == "submit" {
                    AccountRequestIntent::Confirm
                } else {
                    AccountRequestIntent::Submit
                };
                assert_eq!(
                    request.verify_proof("https://control.example.com"),
                    Err(AccountAdmissionCodecError::Binding)
                );
                assert!(request.verify_proof("https://other.example.com").is_err());
            } else {
                let mut request = AccountDeviceAdmissionRequest::from_json(bytes).unwrap();
                request
                    .verify_proof(
                        "https://control.example.com",
                        root.as_slice().try_into().unwrap(),
                    )
                    .unwrap();
                request.nonce = SecretBytes::new([0; 32]);
                assert_eq!(
                    request.verify_proof(
                        "https://control.example.com",
                        root.as_slice().try_into().unwrap()
                    ),
                    Err(AccountAdmissionCodecError::Binding)
                );
            }
        }
    }
}

#[test]
fn exact_confirmation_binds_all_ids_kind_digest_and_original_revision() {
    let document = vectors();
    for (kind, domain) in
        [("register", AccountRequestKind::Register), ("admit", AccountRequestKind::Admit)]
    {
        let value = document
            .vectors
            .iter()
            .find(|v| v.id == format!("account-admission-{kind}-confirmation"))
            .unwrap();
        let confirmation = AccountCommittedConfirmation::from_json(value.input.as_bytes()).unwrap();
        let body = &document
            .vectors
            .iter()
            .find(|v| v.id == format!("account-admission-{kind}-submit"))
            .unwrap()
            .input;
        let (payload, signature) = if kind == "register" {
            let r = AccountRegistrationRequest::from_json(body.as_bytes()).unwrap();
            (r.payload, r.account_signature)
        } else {
            let r = AccountDeviceAdmissionRequest::from_json(body.as_bytes()).unwrap();
            (r.payload, r.account_signature)
        };
        confirmation.validate_for_request(domain, payload.as_bytes(), &signature).unwrap();
        let mut wrong = confirmation.clone();
        wrong.admitted_key_revision += 1;
        assert_eq!(
            wrong.validate_for_request(domain, payload.as_bytes(), &signature),
            Err(AccountAdmissionCodecError::Binding)
        );
        wrong = confirmation.clone();
        wrong.device_id = wrong.operation_id;
        assert_eq!(
            wrong.validate_for_request(domain, payload.as_bytes(), &signature),
            Err(AccountAdmissionCodecError::Binding)
        );
        wrong = confirmation.clone();
        wrong.request_digest[0] ^= 1;
        assert!(wrong.validate_for_request(domain, payload.as_bytes(), &signature).is_err());
    }
}

#[test]
fn snapshot_binds_exact_recipients_epochs_old_wraps_and_capability() {
    let raw = fixture("snapshot.cbor");
    let snapshot = AccountBootstrapSnapshot::from_cbor(&raw).unwrap();
    let admission = AccountDeviceAdmissionPayload::from_cbor(&fixture("admission.cbor")).unwrap();
    admission.validate_for_snapshot(&snapshot, &raw, &[0x33; 32]).unwrap();
    assert_eq!(
        admission.validate_for_snapshot(&snapshot, &raw, &[0x34; 32]),
        Err(AccountAdmissionCodecError::Binding)
    );
    let mut bad = snapshot.clone();
    bad.certificates.clear();
    assert!(bad.validate().is_err());
    bad = snapshot.clone();
    bad.personal.epochs.push(bad.personal.epochs[0].clone());
    assert!(bad.validate().is_err());
    bad = snapshot.clone();
    bad.personal.current_epoch = 2;
    assert!(bad.validate().is_err());
    bad = snapshot.clone();
    bad.personal.rotation_pending = true;
    bad.validate().unwrap();
    assert_eq!(bad.validate_admission_state(), Err(AccountAdmissionCodecError::AdmissionConflict));
    bad = snapshot.clone();
    bad.key_bundle[20] ^= 1;
    assert!(bad.validate().is_err());
    let mut p = admission;
    p.snapshot_digest[0] ^= 1;
    assert!(p.validate_for_snapshot(&snapshot, &raw, &[0x33; 32]).is_err());
}

#[test]
fn protected_parser_rejects_nonshortest_duplicate_unknown_and_trailing_bytes() {
    let bytes = fixture("registration.cbor");
    let Cbor::Map(mut entries) = cbor::decode(&bytes).unwrap() else { panic!() };
    entries.push((Cbor::Text("extra".into()), Cbor::UInt(1)));
    assert!(
        AccountRegistrationPayload::from_cbor(&cbor::encode(&Cbor::Map(entries)).unwrap()).is_err()
    );
    let mut nonshortest = bytes.clone();
    nonshortest.splice(0..1, [0xb8, 0x12]);
    assert!(AccountRegistrationPayload::from_cbor(&nonshortest).is_err());
    let mut trailing = bytes;
    trailing.push(0);
    assert!(AccountRegistrationPayload::from_cbor(&trailing).is_err());
    for declared in [
        b"\xa1\x66epochs\x9b\xff\xff\xff\xff\xff\xff\xff\xff".as_slice(),
        b"\xa1\x6ccertificates\x9a\x00\x01\x00\x01",
    ] {
        assert!(AccountBootstrapSnapshot::from_cbor(declared).is_err());
    }
}

#[test]
fn full_body_limits_include_whitespace_and_ignored_response_extensions() {
    for (bytes, bound, is_options) in
        [(fixture("options.request"), 256, true), (fixture("challenge.request"), 512, false)]
    {
        let mut exact = vec![b' '; bound - bytes.len()];
        exact.extend_from_slice(&bytes);
        if is_options {
            AccountPasswordOptionsRequest::from_json(&exact).unwrap();
        } else {
            AccountRequestChallengeRequest::from_json(&exact).unwrap();
        }
        exact.push(b' ');
        if is_options {
            assert_eq!(
                AccountPasswordOptionsRequest::from_json(&exact),
                Err(AccountAdmissionCodecError::TooLarge)
            );
        } else {
            assert_eq!(
                AccountRequestChallengeRequest::from_json(&exact),
                Err(AccountAdmissionCodecError::TooLarge)
            );
        }
    }
    let raw = fixture("options.response");
    let original = AccountPasswordOptionsResponse::from_json(&raw).unwrap();
    let mut value: Value = serde_json::from_slice(&raw).unwrap();
    value["extension"] = Value::String("allowed".into());
    assert_eq!(
        AccountPasswordOptionsResponse::from_json(&serde_json::to_vec(&value).unwrap()),
        Ok(original)
    );
    let mut oversized = serde_json::to_vec(&value).unwrap();
    oversized.resize(1_025, b' ');
    assert_eq!(
        AccountPasswordOptionsResponse::from_json(&oversized),
        Err(AccountAdmissionCodecError::TooLarge)
    );
    let text =
        String::from_utf8(raw).unwrap().replacen('}', ",\"extension\":{\"same\":1,\"same\":2}}", 1);
    assert_eq!(
        AccountPasswordOptionsResponse::from_json(text.as_bytes()),
        Err(AccountAdmissionCodecError::InvalidJson)
    );
}

#[test]
fn native_metadata_and_exact_routes_do_not_reuse_existing_session_authority() {
    let headers =
        AccountEntryHttpMetadata { content_type: "application/json", ..Default::default() };
    headers.validate("https://control.example.com").unwrap();
    for headers in [
        AccountEntryHttpMetadata { has_cookie: true, ..headers },
        AccountEntryHttpMetadata { has_authorization: true, ..headers },
        AccountEntryHttpMetadata { has_dpop: true, ..headers },
        AccountEntryHttpMetadata { has_query: true, ..headers },
        AccountEntryHttpMetadata { has_idempotency_key: true, ..headers },
        AccountEntryHttpMetadata { has_if_match: true, ..headers },
    ] {
        assert_eq!(
            headers.validate("https://control.example.com"),
            Err(AccountAdmissionCodecError::HttpMetadata)
        );
    }
    assert_eq!(
        AccountEntryHttpMetadata { origin: Some("https://other.example.com"), ..headers }
            .validate("https://control.example.com"),
        Err(AccountAdmissionCodecError::OriginDenied)
    );
    for suffix in [
        "requests/challenge",
        "register",
        "password/options",
        "password/login",
        "device-admissions",
    ] {
        let path = format!("/api/v1/auth/accounts/{suffix}");
        assert!(AccountEntryOperation::from_route("POST", &path).is_some());
        assert_eq!(AccountEntryOperation::from_route("GET", &path), None);
        assert_eq!(AccountEntryOperation::from_route("POST", &format!("{path}/")), None);
        assert_eq!(scoplen_api::auth::DeviceAccessOperation::from_route("POST", &path), None);
        assert_eq!(scoplen_api::auth::OperatorAccessOperation::from_route("POST", &path), None);
    }
    for code in ["auth.registration_denied", "auth.admission_conflict", "auth.quota_exceeded"] {
        assert!(scoplen_api::ErrorCode::new(code).unwrap().is_known());
    }
    let secret = AccountPasswordLoginRequest::from_json(&fixture("login.request")).unwrap();
    assert_eq!(format!("{secret:?}"), "AccountPasswordLoginRequest([REDACTED])");
}

#[test]
fn password_input_rejects_ambiguous_or_mistyped_secrets_without_echoing_them() {
    let original = fixture("login.request");
    let mut value: Value = serde_json::from_slice(&original).unwrap();
    for field in ["attempt_id", "auth_secret"] {
        for replacement in [Value::Null, Value::from(1), Value::String(String::new())] {
            let mut bad = value.clone();
            bad[field] = replacement;
            let error = AccountPasswordLoginRequest::from_json(&serde_json::to_vec(&bad).unwrap())
                .unwrap_err();
            assert_eq!(error, AccountAdmissionCodecError::InvalidJson);
            assert_eq!(error.to_string(), "invalid Account entry request");
        }
    }
    value["attempt_id"] = Value::String("A".repeat(44));
    assert_eq!(
        AccountPasswordLoginRequest::from_json(&serde_json::to_vec(&value).unwrap()),
        Err(AccountAdmissionCodecError::TooLarge)
    );
    let secret = serde_json::from_slice::<Value>(&original).unwrap()["auth_secret"].clone();
    let duplicate = format!("{{\"auth_secret\":{secret},\"auth_secret\":{secret}}}");
    assert_eq!(
        AccountPasswordLoginRequest::from_json(duplicate.as_bytes()),
        Err(AccountAdmissionCodecError::InvalidJson)
    );
}

#[test]
fn response_readers_require_both_cache_prevention_headers() {
    macro_rules! check {
        ($ty:ty, $input:expr) => {{
            let input = $input;
            <$ty>::from_http_json(&input, Some("no-store"), Some("no-cache")).unwrap();
            for (cache, pragma) in [
                (None, Some("no-cache")),
                (Some("no-store"), None),
                (Some("public"), Some("no-cache")),
                (Some("no-store"), Some("cache")),
            ] {
                assert_eq!(
                    <$ty>::from_http_json(&input, cache, pragma),
                    Err(AccountAdmissionCodecError::HttpMetadata)
                );
            }
        }};
    }
    check!(AccountRequestChallengeResponse, fixture("challenge.response"));
    check!(AccountPasswordOptionsResponse, fixture("options.response"));
    check!(AccountPasswordLoginResponse, fixture("login.response"));
    check!(AccountCommittedConfirmation, fixture("confirmation"));
}

#[test]
fn admission_rejects_signed_but_stale_or_recycled_device_material() {
    use scoplen_api::sync::SyncAccountKeyBundleUpdate;
    use scoplen_crypto::{DeviceCertificate, Ed25519SigningKey};

    let raw = fixture("snapshot.cbor");
    let snapshot = AccountBootstrapSnapshot::from_cbor(&raw).unwrap();
    let admission = AccountDeviceAdmissionPayload::from_cbor(&fixture("admission.cbor")).unwrap();
    let root = Ed25519SigningKey::from_bytes(&[1; 32]).unwrap();
    let original_bundle = SyncAccountKeyBundleUpdate::from_cbor(&admission.key_bundle).unwrap();
    for change in 0..3 {
        let mut bundle = original_bundle.clone();
        match change {
            0 => bundle.revision += 1,
            1 => *bundle.device_wraps[0].wrapped_ark.last_mut().unwrap() ^= 1,
            _ => *bundle.account_signing_key.last_mut().unwrap() ^= 1,
        }
        bundle.signature = root.sign(&bundle.signature_input().unwrap()).to_vec();
        let mut bad = admission.clone();
        bad.key_bundle = bundle.to_cbor().unwrap();
        assert_eq!(
            bad.validate_for_snapshot(&snapshot, &raw, &[0x33; 32]),
            Err(AccountAdmissionCodecError::AdmissionConflict)
        );
    }
    let old = DeviceCertificate::decode(&snapshot.certificates[0]).unwrap();
    let new = DeviceCertificate::decode(&admission.device_certificate).unwrap();
    for (signing, kem) in [
        (old.signing_public_key.clone(), new.kem_public_key.clone()),
        (old.kem_public_key.clone(), new.kem_public_key.clone()),
        (new.signing_public_key.clone(), old.signing_public_key.clone()),
        (new.signing_public_key.clone(), old.kem_public_key.clone()),
    ] {
        let mut bad = admission.clone();
        bad.device_certificate = DeviceCertificate::issue(
            &root,
            new.device_id,
            new.account_id,
            signing,
            kem,
            new.display_name.clone(),
            new.platform.clone(),
            new.created_at,
        )
        .unwrap()
        .encode()
        .unwrap();
        assert_eq!(
            bad.validate_for_snapshot(&snapshot, &raw, &[0x33; 32]),
            Err(AccountAdmissionCodecError::AdmissionConflict)
        );
    }
}
