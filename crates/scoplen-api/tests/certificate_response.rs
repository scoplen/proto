// SPDX-License-Identifier: Apache-2.0

use base64::{Engine as _, engine::general_purpose::STANDARD};
use scoplen_api::certificate::{
    CertificateIssuanceRequest, CertificateIssuanceResponse, CertificateResponseCodecError,
    CertificateTargets, MAX_CERTIFICATE_BLOB_BYTES, MAX_CERTIFICATE_ISSUANCE_RESPONSE_BYTES,
    MAX_CERTIFICATE_LINE_BYTES,
};
use scoplen_test_vectors::{Vector, VectorDocument};
use serde_json::{Value, json};
use ssh_key::{Certificate, PrivateKey, PublicKey, certificate, private::Ed25519Keypair};

const HOST: &str = "018f35d4-1f8f-7e2a-9e56-7a5e8a9f11a1";

fn vectors() -> VectorDocument {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../vectors/certificate-issuance-response.json");
    VectorDocument::from_path(path).expect("response vectors")
}

fn sample() -> Vector {
    vectors().vectors.remove(0)
}

fn request(public_key: &str) -> CertificateIssuanceRequest {
    CertificateIssuanceRequest::new(
        public_key,
        CertificateTargets::Hosts(vec![HOST.parse().expect("UUID")]),
        "deploy",
        1_800,
    )
    .expect("request")
}

fn vector_parts(vector: &Vector) -> (String, String) {
    let wrapper: Value = serde_json::from_str(&vector.input).expect("wrapper");
    let public_key = wrapper["request_public_key"].as_str().expect("public key").to_owned();
    let response = serde_json::to_string(&wrapper["response"]).expect("response");
    (public_key, response)
}

#[test]
fn seven_signed_subject_types_match_published_resource_vectors() {
    let document = vectors();
    assert_eq!(document.vectors.len(), 7);
    for vector in &document.vectors {
        assert_eq!(vector.kind, "certificate.issuance.response_json");
        let (public_key, input) = vector_parts(vector);
        let response = CertificateIssuanceResponse::from_json(input.as_bytes())
            .expect("signed synthetic certificate");
        Certificate::from_openssh(&response.certificate)
            .expect("published certificate")
            .verify_signature()
            .expect("published CA signature");
        assert_eq!(response.to_json().expect("canonical response"), vector.expected.as_bytes());
        assert_eq!(
            CertificateIssuanceResponse::from_json(vector.expected.as_bytes()),
            Ok(response.clone())
        );
        response.validate_request_subject(&request(&public_key)).expect("matching subject");
        assert_eq!(
            CertificateIssuanceResponse::from_http_json(
                vector.expected.as_bytes(),
                Some(&response.etag),
                Some("no-store"),
                Some("no-cache")
            ),
            Ok(response),
        );
    }
}

#[test]
fn resource_metadata_and_http_headers_are_exact() {
    let vector = sample();
    let (_, body) = vector_parts(&vector);
    let response = CertificateIssuanceResponse::from_json(body.as_bytes()).expect("response");
    for (etag, cache, pragma) in [
        (None, Some("no-store"), Some("no-cache")),
        (Some("W/\"1\""), Some("no-store"), Some("no-cache")),
        (Some(response.etag.as_str()), None, Some("no-cache")),
        (Some(response.etag.as_str()), Some("public"), Some("no-cache")),
        (Some(response.etag.as_str()), Some("no-store"), None),
        (Some(response.etag.as_str()), Some("no-store"), Some("cache")),
    ] {
        assert_eq!(
            CertificateIssuanceResponse::from_http_json(body.as_bytes(), etag, cache, pragma),
            Err(CertificateResponseCodecError::HttpMetadata)
        );
    }
    for etag in [
        "1",
        "W/\"1\"",
        "\"bad space\"",
        "\"bad\"quote\"",
        "\"é\"",
        &format!("\"{}\"", "x".repeat(255)),
    ] {
        assert!(
            CertificateIssuanceResponse::new(
                response.id,
                etag,
                &response.created_at,
                &response.updated_at,
                &response.certificate
            )
            .is_err()
        );
    }
    let max_etag = format!("\"{}\"", "x".repeat(254));
    assert!(
        CertificateIssuanceResponse::new(
            response.id,
            max_etag,
            &response.created_at,
            &response.updated_at,
            &response.certificate
        )
        .is_ok()
    );
    for etag in ["\"!\"", "\"#\\~\""] {
        assert!(
            CertificateIssuanceResponse::new(
                response.id,
                etag,
                &response.created_at,
                &response.updated_at,
                &response.certificate
            )
            .is_ok()
        );
    }
}

#[test]
fn timestamps_require_valid_utc_calendar_dates() {
    let vector = sample();
    let (_, body) = vector_parts(&vector);
    let response = CertificateIssuanceResponse::from_json(body.as_bytes()).expect("response");
    for valid in ["2024-02-29T23:59:59Z", "2026-10-19T12:34:56.001Z"] {
        assert!(
            CertificateIssuanceResponse::new(
                response.id,
                &response.etag,
                valid,
                valid,
                &response.certificate
            )
            .is_ok()
        );
    }
    for invalid in [
        "2026-02-29T00:00:00Z",
        "2026-04-31T00:00:00Z",
        "2026-01-20T24:00:00Z",
        "2026-01-20T00:60:00Z",
        "2026-01-20T00:00:60Z",
        "2026-01-20T00:00:00+00:00",
        "2026-01-20t00:00:00z",
        "2026-01-20T00:00:00.Z",
        "2026-01-20T00:00:0/Z",
    ] {
        assert!(
            CertificateIssuanceResponse::new(
                response.id,
                &response.etag,
                invalid,
                &response.updated_at,
                &response.certificate
            )
            .is_err(),
            "accepted {invalid}"
        );
    }
}

#[test]
fn signed_host_certificate_is_rejected_even_with_a_valid_subject() {
    let (public_key, body) = vector_parts(&sample());
    let response = CertificateIssuanceResponse::from_json(body.as_bytes()).expect("response");
    let subject = PublicKey::from_openssh(&public_key).expect("subject");
    let ca = PrivateKey::from(Ed25519Keypair::from_seed(&[42; 32]));
    let mut builder =
        certificate::Builder::new(vec![9; 16], &subject, 1, 2).expect("host certificate builder");
    builder.cert_type(certificate::CertType::Host).expect("host role");
    builder.valid_principal("example.com").expect("principal");
    let host_certificate = builder.sign(&ca).expect("signed host certificate");
    let host_line = host_certificate.to_openssh().expect("host certificate line");
    assert_eq!(host_certificate.cert_type(), certificate::CertType::Host);
    assert_eq!(host_certificate.public_key(), subject.key_data());
    assert_eq!(
        CertificateIssuanceResponse::new(
            response.id,
            &response.etag,
            &response.created_at,
            &response.updated_at,
            host_line
        ),
        Err(CertificateResponseCodecError::InvalidField("data.certificate")),
    );
}

#[test]
fn response_rejects_missing_wrong_duplicate_and_oversized_json() {
    let vector = sample();
    let body = &vector.expected;
    let root: Value = serde_json::from_str(body).expect("JSON");
    for field in ["id", "etag", "created_at", "updated_at", "data"] {
        let mut missing = root.clone();
        missing.as_object_mut().expect("object").remove(field);
        assert!(
            CertificateIssuanceResponse::from_json(
                serde_json::to_string(&missing).expect("JSON").as_bytes()
            )
            .is_err()
        );
    }
    let mut missing_certificate = root.clone();
    missing_certificate["data"].as_object_mut().expect("data").remove("certificate");
    assert!(
        CertificateIssuanceResponse::from_json(
            serde_json::to_string(&missing_certificate).expect("JSON").as_bytes()
        )
        .is_err()
    );
    for bad in [
        "null".to_owned(),
        body.replace("\"etag\":\"\\\"1\\\"\"", "\"etag\":null"),
        body.replace("\"data\":{", "\"data\":null,\"extra\":{") + "}",
        body.replace("\"data\":{", "\"extra\":{\"x\":1,\"x\":2},\"data\":{"),
        body.replace("\"data\":{", "\"data\":{\"future\":{\"x\":1,\"x\":2},"),
        body.replace("\"data\":{", "\"data\":{\"certificate\":null,"),
        body.replace("\"id\":", "\"id\":null,\"id\":"),
        body.replace("\"id\":", "\"\\u0069d\":null,\"id\":"),
        body.replace(
            "019bdad6-b800-7000-8000-000000000001",
            "019BDAD6-B800-7000-8000-000000000001",
        ),
        body.replace(
            "019bdad6-b800-7000-8000-000000000001",
            "019bdad6-b800-4000-8000-000000000001",
        ),
    ] {
        assert!(
            CertificateIssuanceResponse::from_json(bad.as_bytes()).is_err(),
            "invalid response accepted"
        );
    }
    let mut extended = root;
    extended["future"] = json!({"nested": [1, 2]});
    extended["data"]["future"] = json!(true);
    assert_eq!(
        CertificateIssuanceResponse::from_json(
            serde_json::to_string(&extended).expect("JSON").as_bytes()
        ),
        CertificateIssuanceResponse::from_json(body.as_bytes()),
    );
    let mut maximum = body.clone();
    maximum.insert_str(0, &" ".repeat(MAX_CERTIFICATE_ISSUANCE_RESPONSE_BYTES - maximum.len()));
    assert!(CertificateIssuanceResponse::from_json(maximum.as_bytes()).is_ok());
    maximum.insert(0, ' ');
    assert_eq!(
        CertificateIssuanceResponse::from_json(maximum.as_bytes()),
        Err(CertificateResponseCodecError::ResponseTooLarge)
    );
}

#[test]
fn certificate_line_rejects_noncanonical_text_and_wrong_binary_shape() {
    let vector = sample();
    let (_, body) = vector_parts(&vector);
    let response = CertificateIssuanceResponse::from_json(body.as_bytes()).expect("response");
    let line = &response.certificate;
    let (algorithm, encoded) = line.split_once(' ').expect("certificate line");
    for bad in [
        format!("{line} comment"),
        format!(" {line}"),
        format!("{line} "),
        format!("{algorithm}  {encoded}"),
        format!("{algorithm}\t{encoded}"),
        format!("{algorithm} {encoded}\n"),
        format!("ssh-rsa-cert-v01@openssh.com {encoded}"),
        format!("{algorithm} {}", encoded.trim_end_matches('=')),
        format!("{algorithm} {encoded}é"),
        format!("{algorithm} {encoded}{}", "A".repeat(MAX_CERTIFICATE_LINE_BYTES)),
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINdamAGCsQq31Uv+08lkBzoO4XLz2qYjJa8CGmj3B1Ea".into(),
    ] {
        assert!(
            CertificateIssuanceResponse::new(
                response.id,
                &response.etag,
                &response.created_at,
                &response.updated_at,
                bad
            )
            .is_err()
        );
    }
    let mut too_large_binary = STANDARD.decode(encoded).expect("Base64");
    too_large_binary.resize(MAX_CERTIFICATE_BLOB_BYTES + 1, 0);
    let too_large_line = format!("{algorithm} {}", STANDARD.encode(too_large_binary));
    assert!(
        CertificateIssuanceResponse::new(
            response.id,
            &response.etag,
            &response.created_at,
            &response.updated_at,
            too_large_line
        )
        .is_err()
    );
    let mut trailing = STANDARD.decode(encoded).expect("Base64");
    trailing.push(0);
    let trailing_line = format!("{algorithm} {}", STANDARD.encode(trailing));
    assert!(
        CertificateIssuanceResponse::new(
            response.id,
            &response.etag,
            &response.created_at,
            &response.updated_at,
            trailing_line
        )
        .is_err()
    );
    let cert = Certificate::from_openssh(line).expect("certificate");
    let mut equal_interval = STANDARD.decode(encoded).expect("Base64");
    let before = cert.valid_before().to_be_bytes();
    let position =
        equal_interval.windows(8).position(|window| window == before).expect("valid_before bytes");
    equal_interval[position..position + 8].copy_from_slice(&cert.valid_after().to_be_bytes());
    let equal_line = format!("{algorithm} {}", STANDARD.encode(equal_interval));
    assert!(
        CertificateIssuanceResponse::new(
            response.id,
            &response.etag,
            &response.created_at,
            &response.updated_at,
            equal_line
        )
        .is_err()
    );
}

#[test]
fn certificate_binary_and_encoded_resource_limits_are_exact() {
    let (public_key, body) = vector_parts(&sample());
    let mut response = CertificateIssuanceResponse::from_json(body.as_bytes()).expect("response");
    let subject = PublicKey::from_openssh(&public_key).expect("subject");
    let ca = PrivateKey::from(Ed25519Keypair::from_seed(&[42; 32]));
    let build = |nonce_len: usize| {
        let mut builder = certificate::Builder::new(vec![9; nonce_len], &subject, 1, 2)
            .expect("certificate builder");
        builder.cert_type(certificate::CertType::User).expect("user role");
        builder.valid_principal("deploy").expect("principal");
        builder.sign(&ca).expect("signed certificate")
    };
    let baseline = build(16);
    let nonce_len = 16 + MAX_CERTIFICATE_BLOB_BYTES - baseline.to_bytes().expect("blob").len();
    let maximum = build(nonce_len);
    assert_eq!(maximum.to_bytes().expect("blob").len(), MAX_CERTIFICATE_BLOB_BYTES);
    assert!(
        CertificateIssuanceResponse::new(
            response.id,
            &response.etag,
            &response.created_at,
            &response.updated_at,
            maximum.to_openssh().expect("line")
        )
        .is_ok()
    );
    assert_eq!(
        build(nonce_len + 1).to_bytes().expect("blob").len(),
        MAX_CERTIFICATE_BLOB_BYTES + 1
    );
    assert!(
        CertificateIssuanceResponse::new(
            response.id,
            &response.etag,
            &response.created_at,
            &response.updated_at,
            build(nonce_len + 1).to_openssh().expect("line")
        )
        .is_err()
    );

    let baseline_len = response.to_json().expect("resource").len();
    let fraction_len = MAX_CERTIFICATE_ISSUANCE_RESPONSE_BYTES - baseline_len - 1;
    response.created_at = format!("2026-01-20T00:00:00.{}Z", "0".repeat(fraction_len));
    assert_eq!(
        response.to_json().expect("maximum resource").len(),
        MAX_CERTIFICATE_ISSUANCE_RESPONSE_BYTES
    );
    response.created_at.insert(response.created_at.len() - 1, '0');
    assert_eq!(response.to_json(), Err(CertificateResponseCodecError::ResponseTooLarge));
}

#[test]
fn altered_signature_retains_wire_shape_but_fails_cryptographic_verification() {
    let (_, body) = vector_parts(&sample());
    let response = CertificateIssuanceResponse::from_json(body.as_bytes()).expect("response");
    let (algorithm, encoded) = response.certificate.split_once(' ').expect("line");
    let mut blob = STANDARD.decode(encoded).expect("Base64");
    *blob.last_mut().expect("signature byte") ^= 1;
    let altered_line = format!("{algorithm} {}", STANDARD.encode(&blob));
    let parsed = Certificate::from_bytes(&blob).expect("well-shaped certificate");
    assert!(parsed.verify_signature().is_err());
    assert!(
        CertificateIssuanceResponse::new(
            response.id,
            &response.etag,
            &response.created_at,
            &response.updated_at,
            altered_line
        )
        .is_ok()
    );
}

#[test]
fn request_subject_comparison_validates_both_messages_and_redacts_debug() {
    let vector = sample();
    let (public_key, body) = vector_parts(&vector);
    let mut response = CertificateIssuanceResponse::from_json(body.as_bytes()).expect("response");
    assert_eq!(response.validate_request_subject(&request(&public_key)), Ok(()));
    let other_key =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINdamAGCsQq31Uv+08lkBzoO4XLz2qYjJa8CGmj3B1Ea";
    assert_eq!(
        response.validate_request_subject(&request(other_key)),
        Err(CertificateResponseCodecError::SubjectMismatch)
    );
    let mut invalid_request = request(&public_key);
    invalid_request.ttl_seconds = 0;
    assert_eq!(
        response.validate_request_subject(&invalid_request),
        Err(CertificateResponseCodecError::InvalidRequest)
    );
    let diagnostic = format!("{response:?}");
    for secret in
        [&response.certificate, &response.etag, &response.created_at, &response.updated_at]
    {
        assert!(!diagnostic.contains(secret));
    }
    response.certificate.push_str(" comment");
    assert!(response.validate_request_subject(&request(&public_key)).is_err());
    assert!(response.to_json().is_err());
}

#[test]
fn encoder_revalidates_every_mutable_resource_field() {
    let (_, body) = vector_parts(&sample());
    let response = CertificateIssuanceResponse::from_json(body.as_bytes()).expect("response");
    let mut changed = response.clone();
    changed.id = uuid::Uuid::nil();
    assert_eq!(changed.to_json(), Err(CertificateResponseCodecError::InvalidField("id")));
    changed = response.clone();
    changed.etag = "W/\"1\"".into();
    assert_eq!(changed.to_json(), Err(CertificateResponseCodecError::InvalidField("etag")));
    changed = response.clone();
    changed.created_at = "2026-02-30T00:00:00Z".into();
    assert_eq!(changed.to_json(), Err(CertificateResponseCodecError::InvalidField("created_at")));
    changed = response.clone();
    changed.updated_at = "2026-01-20T00:00:00+00:00".into();
    assert_eq!(changed.to_json(), Err(CertificateResponseCodecError::InvalidField("updated_at")));
    changed = response;
    changed.certificate.push_str(" comment");
    assert_eq!(
        changed.to_json(),
        Err(CertificateResponseCodecError::InvalidField("data.certificate"))
    );
}
