// SPDX-License-Identifier: Apache-2.0

use scoplen_api::certificate::{
    CertificateIssuanceRequest, CertificateRequestCodecError, CertificateTargets,
    MAX_CERTIFICATE_ISSUANCE_REQUEST_BYTES, MAX_CERTIFICATE_ISSUANCE_TARGETS,
};
use scoplen_api::{ErrorCode, ProblemDetails};
use ssh_key::{
    PublicKey,
    public::{EcdsaPublicKey, KeyData, SkEcdsaSha2NistP256, SkEd25519},
};
use uuid::Uuid;

const HOST: &str = "018f35d4-1f8f-7e2a-9e56-7a5e8a9f11a1";
const NEXT_HOST: &str = "018f35d4-1f8f-7e2a-9e56-7a5e8a9f11a2";
const ED25519: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINdamAGCsQq31Uv+08lkBzoO4XLz2qYjJa8CGmj3B1Ea";
const P256: &str = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMfRu9JB7CUaHM3vfV8UzlkGBglbKrVgSw6UwVsJhkVlAolZxh9OQ7FEYuSPvgBXehl9BxXMQwjmEuPN+lIg0TM=";
const P384: &str = "ecdsa-sha2-nistp384 AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBIIePbsyxT1R3aOU+P5dvWv0puH5VgXWkOTIMldNqeo2LCcfR1uBFNyGeaRMOkYj0eCuXvuVa1JQPZKV/l6oVbVaZeeG9qzL90YHkPM52H+SB7PIMJx5GLEMnwK4ln8VIg==";
const P521: &str = "ecdsa-sha2-nistp521 AAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAAAIbmlzdHA1MjEAAACFBAHnntlsY1AAkvXUZlo2k7n7QS7I1+mWzdD6yEEDl2rBPziO2eMEkluCPkj8TBZbziy+h77w1OTemAHfEdP2RcGT3gGIB2/t60Vw0iQKFBXNqGsCnX9+tb/rtUS51ku6wOUBLhJ4BzkS0JjJVqX/3dvuLRFbzfvBcenQKmw3SN8t1R0vlQ==";
const RSA: &str = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC9bAgFAif4cgDxhD33qIAwLlkHMPqAWFHha9WKWPW1aRqBJrzJ0IvISf5RBRhfDnVwFnq/ABQQAGnzfqFXHIpqyUxBWFd2ApHz1wYKoWXsq7mieh9+vAuXFp3ba8y7oCu8U9HJsOgsVOV4DXH/Y9ePNg4QtJLWCEfU+DIU5Bskks6ybnCJ152WOGSIIOQRR8apEK0hA5CCpFBNgM0sh6iqBsVFkiPIeH+x0I2V3vsIKSLIUj8Y+1umtXDFMUmvPkLsTK1+TLMYsukjJtWfGJcPkpoxo29oDp5oY4BXlYxeArLsncTePgc3GCRqZunzgRHaMx5Xyz7NfQ2skfZ/kzJP";

fn valid_json() -> String {
    format!(
        "{{\"public_key\":\"{ED25519}\",\"hosts\":[\"{HOST}\"],\"remote_user\":\"deploy\",\"ttl_seconds\":1800}}"
    )
}

#[test]
fn public_codec_matches_both_published_selector_vectors() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../vectors/certificate-issuance-request.json");
    let document = scoplen_test_vectors::VectorDocument::from_path(path).expect("vectors");
    assert_eq!(document.vectors.len(), 2);
    for vector in document.vectors {
        assert_eq!(vector.kind, "certificate.issuance.request_json");
        let request = CertificateIssuanceRequest::from_json(vector.input.as_bytes())
            .expect("published request");
        let encoded = request.to_json().expect("encode");
        assert_eq!(encoded, vector.expected.as_bytes(), "{}", vector.id);
        assert_eq!(CertificateIssuanceRequest::from_json(&encoded), Ok(request));
    }
}

#[test]
fn all_seven_raw_key_algorithms_are_accepted() {
    let ed = PublicKey::from_openssh(ED25519).expect("Ed25519 fixture");
    let p256 = PublicKey::from_openssh(P256).expect("P-256 fixture");
    let KeyData::Ed25519(ed_key) = ed.key_data() else { panic!("Ed25519 key data") };
    let KeyData::Ecdsa(EcdsaPublicKey::NistP256(p256_point)) = p256.key_data() else {
        panic!("P-256 key data")
    };
    let sk_ed = PublicKey::new(KeyData::SkEd25519(SkEd25519::new(*ed_key, "ssh:")), "")
        .to_openssh()
        .expect("SK Ed25519 fixture");
    let sk_p256 = PublicKey::new(
        KeyData::SkEcdsaSha2NistP256(SkEcdsaSha2NistP256::new(*p256_point, "ssh:")),
        "",
    )
    .to_openssh()
    .expect("SK P-256 fixture");
    for key in [ED25519, P256, P384, P521, RSA, &sk_ed, &sk_p256] {
        let request = CertificateIssuanceRequest::new(
            key,
            CertificateTargets::Hosts(vec![HOST.parse().expect("UUID")]),
            "deploy",
            86_400,
        )
        .expect("supported raw key");
        assert_eq!(
            CertificateIssuanceRequest::from_json(&request.to_json().expect("encode")),
            Ok(request)
        );
    }
}

#[test]
fn selectors_preserve_order_and_enforce_exclusivity_and_uniqueness() {
    let ids = [NEXT_HOST, HOST].map(|value| value.parse::<Uuid>().expect("UUID"));
    let request = CertificateIssuanceRequest::new(
        ED25519,
        CertificateTargets::HostGroups(ids.to_vec()),
        "ops",
        1,
    )
    .expect("group request");
    assert_eq!(request.targets, CertificateTargets::HostGroups(ids.to_vec()));
    assert!(
        String::from_utf8(request.to_json().expect("encode"))
            .expect("UTF-8")
            .contains(&format!("[\"{NEXT_HOST}\",\"{HOST}\"]"))
    );
    for targets in
        [CertificateTargets::Hosts(vec![]), CertificateTargets::Hosts(vec![ids[0], ids[0]])]
    {
        assert!(CertificateIssuanceRequest::new(ED25519, targets, "ops", 1).is_err());
    }
    let maximum = (0..MAX_CERTIFICATE_ISSUANCE_TARGETS)
        .map(|index| {
            format!("018f35d4-1f8f-7e2a-9e56-7a5e8a9f{:04x}", index + 1).parse().expect("UUID")
        })
        .collect::<Vec<Uuid>>();
    let maximum_request = CertificateIssuanceRequest::new(
        ED25519,
        CertificateTargets::Hosts(maximum.clone()),
        "ops",
        1,
    )
    .expect("64 targets");
    assert!(
        CertificateIssuanceRequest::from_json(&maximum_request.to_json().expect("encode")).is_ok()
    );
    let mut too_many = maximum;
    too_many.push("018f35d4-1f8f-7e2a-9e56-7a5e8a9f1000".parse().expect("UUID"));
    assert!(
        CertificateIssuanceRequest::new(
            ED25519,
            CertificateTargets::Hosts(too_many.clone()),
            "ops",
            1
        )
        .is_err()
    );
    let oversized_selection = valid_json().replace(
        &format!("\"hosts\":[\"{HOST}\"]"),
        &format!(
            "\"hosts\":[{}]",
            too_many.iter().map(|id| format!("\"{id}\"")).collect::<Vec<_>>().join(",")
        ),
    );
    assert!(CertificateIssuanceRequest::from_json(oversized_selection.as_bytes()).is_err());
}

#[test]
fn malformed_unknown_duplicate_and_invalid_fields_are_rejected() {
    let valid = valid_json();
    for bad in [
        "null".to_owned(),
        "{}".to_owned(),
        valid.replace(&format!("\"hosts\":[\"{HOST}\"]"), "\"hosts\":null"),
        valid.replace(&format!("\"hosts\":[\"{HOST}\"]"), "\"hosts\":[]"),
        valid.replace(
            &format!("\"hosts\":[\"{HOST}\"]"),
            &format!("\"hosts\":[\"{HOST}\",\"{HOST}\"]"),
        ),
        valid.replace(HOST, "018F35D4-1F8F-7E2A-9E56-7A5E8A9F11A1"),
        valid.replace(HOST, "018f35d4-1f8f-4e2a-9e56-7a5e8a9f11a1"),
        valid.replace("\"ttl_seconds\":1800", "\"ttl_seconds\":1.0"),
        valid.replace("\"ttl_seconds\":1800", "\"ttl_seconds\":0"),
        valid.replace("\"ttl_seconds\":1800", "\"ttl_seconds\":86401"),
        valid.replace("\"ttl_seconds\":1800", "\"ttl_seconds\":null"),
        valid.replace("\"remote_user\":\"deploy\",", ""),
        valid.replace("deploy", "de\\u0000ploy"),
        valid.replace("deploy", &"x".repeat(256)),
        valid.replace(
            "\"remote_user\":\"deploy\"",
            "\"remote_user\":\"deploy\",\"remote_user\":\"root\"",
        ),
        valid.replace(
            &format!("\"hosts\":[\"{HOST}\"]"),
            &format!("\"hosts\":[\"{HOST}\"],\"\\u0068osts\":[]"),
        ),
        valid.replace("\"remote_user\":\"deploy\"", "\"extra\":7,\"remote_user\":\"deploy\""),
        valid.replace(
            "\"remote_user\":\"deploy\"",
            "\"extra\":{\"x\":1,\"x\":2},\"remote_user\":\"deploy\"",
        ),
        valid.replace(
            &format!("\"hosts\":[\"{HOST}\"]"),
            &format!("\"hosts\":[\"{HOST}\"],\"host_groups\":null"),
        ),
        valid.replace(
            &format!("\"hosts\":[\"{HOST}\"]"),
            &format!("\"hosts\":[\"{HOST}\"],\"host_groups\":[\"{NEXT_HOST}\"]"),
        ),
        valid.replace(ED25519, &format!("{ED25519} comment")),
        valid.replace(ED25519, &"x".repeat(8193)),
        valid.replace(ED25519, &ED25519.replace("B1Ea", "B1E")),
        valid.replace(ED25519, "ssh-rsa not-a-key"),
    ] {
        assert!(
            CertificateIssuanceRequest::from_json(bad.as_bytes()).is_err(),
            "invalid request accepted"
        );
    }
    assert_eq!(
        CertificateIssuanceRequest::from_json(&[0xff]),
        Err(CertificateRequestCodecError::InvalidJson)
    );
}

#[test]
fn whole_body_limit_and_mutated_public_fields_are_checked() {
    let valid = valid_json();
    let mut exact = valid.clone();
    exact.push_str(&" ".repeat(MAX_CERTIFICATE_ISSUANCE_REQUEST_BYTES - exact.len()));
    assert!(CertificateIssuanceRequest::from_json(exact.as_bytes()).is_ok());
    exact.push(' ');
    assert_eq!(
        CertificateIssuanceRequest::from_json(exact.as_bytes()),
        Err(CertificateRequestCodecError::RequestTooLarge)
    );

    let mut request = CertificateIssuanceRequest::from_json(valid.as_bytes()).expect("request");
    request.remote_user = "\u{0000}".into();
    assert!(request.validate().is_err());
    assert!(request.to_json().is_err());
    request.remote_user = "deploy".into();
    request.public_key.push_str(" comment");
    assert!(request.to_json().is_err());
    request.public_key = ED25519.into();
    request.ttl_seconds = 0;
    assert!(request.to_json().is_err());
    request.ttl_seconds = 1;
    request.targets = CertificateTargets::Hosts(vec![]);
    assert!(request.to_json().is_err());
    let debug = format!("{request:?}");
    for secret in [ED25519, HOST, "deploy"] {
        assert!(!debug.contains(secret));
    }
}

#[test]
fn utf8_username_is_preserved_and_bounded_by_bytes() {
    let id = HOST.parse().expect("UUID");
    let name = "é".repeat(127);
    let request = CertificateIssuanceRequest::new(
        ED25519,
        CertificateTargets::Hosts(vec![id]),
        format!(" {name}"),
        1,
    )
    .expect("255-byte username");
    assert_eq!(request.remote_user.len(), 255);
    assert_eq!(
        CertificateIssuanceRequest::from_json(&request.to_json().expect("encode")),
        Ok(request)
    );
    assert!(
        CertificateIssuanceRequest::new(
            ED25519,
            CertificateTargets::Hosts(vec![id]),
            format!("é{name}"),
            1,
        )
        .is_err()
    );
}

#[test]
fn certificate_invalid_request_problem_vectors_are_registered() {
    assert!(ErrorCode::new("certificate.invalid_request").expect("code").is_known());
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../vectors/api-problem.json");
    let document = scoplen_test_vectors::VectorDocument::from_path(path).expect("vectors");
    for (id, status) in [
        ("api-problem-certificate-invalid-request-json", 400),
        ("api-problem-certificate-request-too-large-json", 413),
    ] {
        let vector =
            document.vectors.iter().find(|vector| vector.id == id).expect("problem vector");
        let problem: ProblemDetails = serde_json::from_str(&vector.input).expect("problem");
        assert_eq!(problem.status, status);
        assert_eq!(problem.code.as_str(), "certificate.invalid_request");
        assert!(!problem.changed);
        assert!(!problem.retryable);
        assert_eq!(serde_json::to_string(&problem).expect("encode"), vector.expected);
    }
}
