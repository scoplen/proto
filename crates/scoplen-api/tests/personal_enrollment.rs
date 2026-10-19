// SPDX-License-Identifier: Apache-2.0

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use scoplen_api::personal_enrollment::{
    MAX_PERSONAL_ENROLLMENT_REQUEST_BYTES, PersonalEnrollmentCodecError, PersonalEnrollmentRequest,
    PersonalEnrollmentResponse, PersonalInvitationRequest, PersonalInvitationResponse,
};
use scoplen_api::sync::{SyncAccountDeviceWrap, SyncAccountKeyBundleUpdate};
use scoplen_crypto::{DeviceCertificate, DeviceKemKeyPair, Ed25519SigningKey, P256SigningKey};
use serde_json::{Value, json};
use uuid::Uuid;

fn id(last: u8) -> Uuid {
    Uuid::from_bytes([0, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, last])
}

fn reference_enrollment_problem(error: &PersonalEnrollmentCodecError) -> (u16, &'static str) {
    match error {
        PersonalEnrollmentCodecError::IdentityMismatch => (401, "auth.enrollment_denied"),
        PersonalEnrollmentCodecError::OriginMismatch => (403, "policy.denied"),
        PersonalEnrollmentCodecError::EnrollmentRequestTooLarge => (413, "auth.invalid_request"),
        _ => (400, "auth.invalid_request"),
    }
}

fn enrollment() -> PersonalEnrollmentRequest {
    let account_key = Ed25519SigningKey::from_bytes(&[1; 32]).expect("account key");
    let device_key = P256SigningKey::from_bytes(&[
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 1,
    ])
    .expect("device key");
    let kem = DeviceKemKeyPair::from_private_bytes(&[2; 32]).expect("kem key");
    let account_id = id(1);
    let device_id = id(2);
    PersonalEnrollmentRequest {
        invitation_token: [3; 32],
        account_id,
        personal_vault_id: id(3),
        account_signing_public_key: account_key.public_key(),
        account_kem_public_key: [4; 32],
        key_bundle_update: SyncAccountKeyBundleUpdate {
            revision: 1,
            device_wraps: vec![SyncAccountDeviceWrap { device_id, wrapped_ark: vec![5] }],
            account_signing_key: vec![6],
            account_kem_key: vec![7],
            recovery_blob: vec![8],
            signature: vec![9; 64],
        },
        device_certificate: DeviceCertificate::issue(
            &account_key,
            device_id,
            account_id,
            device_key.public_key_sec1(),
            kem.public_key().to_vec(),
            "first device".into(),
            "windows".into(),
            1,
        )
        .expect("certificate"),
        wrapped_personal_vault_key: vec![10],
        device_signature: [11; 64],
    }
}

#[test]
fn invitation_wire_is_bounded_and_secret_redacted() {
    assert_eq!(PersonalInvitationRequest::from_json(b" {} "), Ok(PersonalInvitationRequest));
    assert_eq!(PersonalInvitationRequest.to_json(), b"{}");
    for invalid in [&b"null"[..], &b"[]"[..], &b"{\"extra\":1}"[..], &b"{\"a\":1,\"a\":2}"[..]] {
        assert!(PersonalInvitationRequest::from_json(invalid).is_err());
    }
    assert_eq!(
        PersonalInvitationRequest::from_json(&vec![b' '; 257]),
        Err(PersonalEnrollmentCodecError::InvitationRequestTooLarge)
    );
    assert_eq!(
        PersonalInvitationRequest::from_http_json(b"{}", true),
        Err(PersonalEnrollmentCodecError::ForbiddenHeader("Idempotency-Key"))
    );

    let response = PersonalInvitationResponse {
        invitation_url: format!(
            "https://example.com/invite#token={}",
            URL_SAFE_NO_PAD.encode([7; 32])
        ),
        expires_at: "2026-10-20T12:00:00Z".into(),
    };
    let encoded = response.to_json().expect("encode");
    assert_eq!(PersonalInvitationResponse::from_json(&encoded), Ok(response.clone()));
    assert!(!format!("{response:?}").contains("token="));
    let extension = serde_json::from_slice::<Value>(&encoded).expect("json");
    let mut extension = extension.as_object().expect("object").clone();
    extension.insert("future".into(), json!({"nested": true}));
    assert_eq!(
        PersonalInvitationResponse::from_json(&serde_json::to_vec(&extension).expect("json")),
        Ok(response.clone())
    );
    assert_eq!(
        PersonalInvitationResponse::from_json(&vec![b' '; 4_097]),
        Err(PersonalEnrollmentCodecError::InvitationResponseTooLarge)
    );
    for url in [
        "http://example.com/invite#token=",
        "https://example.com:443/invite#token=",
        "https://example.com/path/invite#token=",
        "https://example.com/invite?x#token=",
    ] {
        let mut invalid = response.clone();
        invalid.invitation_url = format!("{url}{}", URL_SAFE_NO_PAD.encode([7; 32]));
        assert!(invalid.to_json().is_err(), "{url}");
    }
}

#[test]
fn enrollment_round_trip_and_http_boundary() {
    let request = enrollment();
    let encoded = request.to_json().expect("encode");
    assert_eq!(PersonalEnrollmentRequest::from_json(&encoded), Ok(request.clone()));
    assert!(!format!("{request:?}").contains(&URL_SAFE_NO_PAD.encode(request.invitation_token)));
    assert_eq!(
        PersonalEnrollmentRequest::from_http_json(
            &encoded,
            false,
            false,
            false,
            Some("https://example.com"),
            "https://example.com"
        ),
        Ok(request.clone())
    );
    assert_eq!(
        PersonalEnrollmentRequest::from_http_json(
            &encoded,
            false,
            false,
            false,
            Some("https://elsewhere.example"),
            "https://example.com"
        ),
        Err(PersonalEnrollmentCodecError::OriginMismatch)
    );
    for (auth, dpop, idempotency, name) in [
        (true, false, false, "Authorization"),
        (false, true, false, "DPoP"),
        (false, false, true, "Idempotency-Key"),
    ] {
        assert_eq!(
            PersonalEnrollmentRequest::from_http_json(
                &encoded,
                auth,
                dpop,
                idempotency,
                None,
                "https://example.com"
            ),
            Err(PersonalEnrollmentCodecError::ForbiddenHeader(name))
        );
    }

    let response = PersonalEnrollmentResponse {
        account_id: request.account_id,
        device_id: request.device_certificate.device_id,
        personal_vault_id: request.personal_vault_id,
    };
    assert_eq!(
        PersonalEnrollmentResponse::from_json(&response.to_json().expect("encode")),
        Ok(response)
    );
    assert_eq!(
        PersonalEnrollmentResponse::from_json(&vec![b' '; 257]),
        Err(PersonalEnrollmentCodecError::EnrollmentResponseTooLarge)
    );
    assert!(encoded.len() < MAX_PERSONAL_ENROLLMENT_REQUEST_BYTES);
}

#[test]
fn enrollment_rejects_invalid_fields_without_leaking_credentials() {
    let request = enrollment();
    let encoded = request.to_json().expect("encode");
    let mut value: Value = serde_json::from_slice(&encoded).expect("json");
    for (field, replacement) in [
        ("invitation_token", json!("AAAA")),
        ("account_id", json!("00000000-0000-7000-8000-00000000000A")),
        ("personal_vault_id", Value::Null),
        ("account_signing_public_key", json!("a=")),
        ("account_kem_public_key", json!(12)),
        ("key_bundle_update", json!("AA")),
        ("device_certificate", json!("AA")),
        ("wrapped_personal_vault_key", json!("")),
        ("device_signature", json!("AA")),
    ] {
        let original = value[field].clone();
        value[field] = replacement;
        let result =
            PersonalEnrollmentRequest::from_json(&serde_json::to_vec(&value).expect("json"));
        assert_eq!(result, Err(PersonalEnrollmentCodecError::InvalidField(field)), "{field}");
        value[field] = original;
    }
    value["extra"] = json!(1);
    assert_eq!(
        PersonalEnrollmentRequest::from_json(&serde_json::to_vec(&value).expect("json")),
        Err(PersonalEnrollmentCodecError::InvalidJson)
    );
    let duplicated = String::from_utf8(encoded.clone()).expect("utf8").replacen(
        "\"invitation_token\":",
        "\"invitation_token\":\"a\",\"invitation_token\":",
        1,
    );
    assert_eq!(
        PersonalEnrollmentRequest::from_json(duplicated.as_bytes()),
        Err(PersonalEnrollmentCodecError::InvalidJson)
    );
    assert_eq!(
        PersonalEnrollmentRequest::from_json(&vec![
            b' ';
            MAX_PERSONAL_ENROLLMENT_REQUEST_BYTES + 1
        ]),
        Err(PersonalEnrollmentCodecError::EnrollmentRequestTooLarge)
    );
    let mut value: Value = serde_json::from_slice(&encoded).expect("json");
    let mut wrong_revision = request.key_bundle_update.clone();
    wrong_revision.revision = 2;
    value["key_bundle_update"] =
        json!(URL_SAFE_NO_PAD.encode(wrong_revision.to_cbor().expect("cbor")));
    assert_eq!(
        PersonalEnrollmentRequest::from_json(&serde_json::to_vec(&value).expect("json")),
        Err(PersonalEnrollmentCodecError::InvalidField("key_bundle_update"))
    );
    value["key_bundle_update"] =
        json!(URL_SAFE_NO_PAD.encode(request.key_bundle_update.to_cbor().expect("cbor")));
    let mut wrong_certificate = request.device_certificate.clone();
    wrong_certificate.device_id = id(5);
    value["device_certificate"] =
        json!(URL_SAFE_NO_PAD.encode(wrong_certificate.encode().expect("cbor")));
    assert_eq!(
        PersonalEnrollmentRequest::from_json(&serde_json::to_vec(&value).expect("json")),
        Err(PersonalEnrollmentCodecError::IdentityMismatch)
    );
    let mut certificate_bytes = request.device_certificate.encode().expect("cbor");
    certificate_bytes.push(0);
    value["device_certificate"] = json!(URL_SAFE_NO_PAD.encode(certificate_bytes));
    assert_eq!(
        PersonalEnrollmentRequest::from_json(&serde_json::to_vec(&value).expect("json")),
        Err(PersonalEnrollmentCodecError::InvalidField("device_certificate"))
    );
    let mut mismatched = request.clone();
    mismatched.device_certificate.account_id = id(4);
    assert_eq!(mismatched.to_json(), Err(PersonalEnrollmentCodecError::IdentityMismatch));
    let mut mismatched = request;
    mismatched.key_bundle_update.revision = 2;
    assert_eq!(
        mismatched.to_json(),
        Err(PersonalEnrollmentCodecError::InvalidField("key_bundle_update"))
    );
}

#[test]
fn published_personal_wire_vectors_match_public_codecs() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../vectors/personal-enrollment.json");
    let vectors = scoplen_test_vectors::VectorDocument::from_path(path).expect("vectors");
    assert_eq!(vectors.vectors.len(), 8);
    for vector in &vectors.vectors {
        match vector.kind.as_str() {
            "api.personal_invitation.request.json" => {
                let value = PersonalInvitationRequest::from_json(vector.input.as_bytes())
                    .expect(&vector.id);
                assert_eq!(value.to_json(), vector.expected.as_bytes(), "{}", vector.id);
            }
            "api.personal_invitation.request.reject" => {
                assert!(
                    PersonalInvitationRequest::from_json(vector.input.as_bytes()).is_err(),
                    "{}",
                    vector.id
                );
            }
            "api.personal_invitation.response.json" => {
                let value = PersonalInvitationResponse::from_json(vector.input.as_bytes())
                    .expect(&vector.id);
                assert_eq!(
                    value.to_json().expect("encode"),
                    vector.expected.as_bytes(),
                    "{}",
                    vector.id
                );
            }
            "api.personal_enrollment.request.json" => {
                let value = PersonalEnrollmentRequest::from_json(vector.input.as_bytes())
                    .expect(&vector.id);
                assert_eq!(
                    value.to_json().expect("encode"),
                    vector.expected.as_bytes(),
                    "{}",
                    vector.id
                );
            }
            "api.personal_enrollment.request.reject" => {
                let error = PersonalEnrollmentRequest::from_json(vector.input.as_bytes())
                    .expect_err(&vector.id);
                let expected = match vector.expected.as_str() {
                    "invalid" => PersonalEnrollmentCodecError::InvalidJson,
                    "identity_mismatch" => PersonalEnrollmentCodecError::IdentityMismatch,
                    "invitation_token" => {
                        PersonalEnrollmentCodecError::InvalidField("invitation_token")
                    }
                    other => panic!("unexpected expected failure {other}"),
                };
                assert_eq!(error, expected, "{}", vector.id);
            }
            "api.personal_enrollment.response.json" => {
                let value = PersonalEnrollmentResponse::from_json(vector.input.as_bytes())
                    .expect(&vector.id);
                assert_eq!(
                    value.to_json().expect("encode"),
                    vector.expected.as_bytes(),
                    "{}",
                    vector.id
                );
            }
            kind => panic!("unexpected vector kind {kind}"),
        }
    }
}

#[test]
fn reference_enrollment_failure_mapping_keeps_identity_denial_opaque() {
    let encoded = enrollment().to_json().expect("encode");
    let mut body: Value = serde_json::from_slice(&encoded).expect("json");
    body["account_id"] = json!(id(4).to_string());
    let error = PersonalEnrollmentRequest::from_json(&serde_json::to_vec(&body).expect("json"))
        .expect_err("artifact identity mismatch");
    assert_eq!(reference_enrollment_problem(&error), (401, "auth.enrollment_denied"));
    body["device_certificate"] = json!("AA");
    let error = PersonalEnrollmentRequest::from_json(&serde_json::to_vec(&body).expect("json"))
        .expect_err("malformed CBOR");
    assert_eq!(reference_enrollment_problem(&error), (400, "auth.invalid_request"));
    let error = PersonalEnrollmentRequest::from_http_json(
        &encoded,
        false,
        false,
        false,
        Some("https://foreign.example"),
        "https://example.com",
    )
    .expect_err("foreign origin");
    assert_eq!(reference_enrollment_problem(&error), (403, "policy.denied"));
}
