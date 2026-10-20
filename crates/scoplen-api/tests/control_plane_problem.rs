// SPDX-License-Identifier: Apache-2.0

use scoplen_api::{
    ErrorCode, ProblemDetails as SharedProblemDetails, control_plane::ProblemDetails,
    personal_enrollment::PersonalRateLimitHeaders,
};
use scoplen_model::cbor::{self, Value};
use serde_json::json;

#[test]
fn published_problem_json_vectors_use_registered_codes() {
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../vectors/api-problem.json");
    let document = scoplen_test_vectors::VectorDocument::from_path(path).expect("problem vectors");
    let mut count = 0;
    for vector in document.vectors.iter().filter(|vector| vector.kind == "api.problem.json") {
        let problem: SharedProblemDetails =
            serde_json::from_str(&vector.input).expect("valid published problem");
        assert!(problem.code.is_known(), "{}", vector.id);
        assert_eq!(
            serde_json::to_string(&problem).expect("canonical JSON"),
            vector.expected,
            "{}",
            vector.id
        );
        count += 1;
    }
    assert_eq!(count, 13);
}

#[test]
fn personal_rate_and_storage_failure_vectors_keep_the_public_problem_shape() {
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../vectors/api-problem.json");
    let document = scoplen_test_vectors::VectorDocument::from_path(path).expect("problem vectors");
    for (id, status, code, retryable) in [
        ("api-problem-personal-rate-limited-json", 429, "auth.rate_limited", true),
        ("api-problem-personal-storage-unavailable-json", 503, "auth.storage_unavailable", true),
    ] {
        let vector = document.vectors.iter().find(|vector| vector.id == id).expect(id);
        let problem: SharedProblemDetails =
            serde_json::from_str(&vector.input).expect("valid Personal problem");
        assert_eq!(problem.status, status);
        assert_eq!(problem.code.as_str(), code);
        assert!(!problem.changed);
        assert_eq!(problem.retryable, retryable);
        assert!(!problem.detail.contains("token"));
        assert!(!problem.detail.contains("digest"));
    }
}

#[test]
fn personal_commit_uncertainty_vectors_preserve_recovery_without_automatic_replay() {
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../vectors/api-problem.json");
    let document = scoplen_test_vectors::VectorDocument::from_path(path).expect("problem vectors");
    for (id, recovery) in [
        ("api-problem-personal-enrollment-commit-outcome-unknown-json", "device authentication"),
        ("api-problem-personal-invitation-commit-outcome-unknown-json", "operator must decide"),
    ] {
        let vector = document.vectors.iter().find(|vector| vector.id == id).expect(id);
        let problem: SharedProblemDetails =
            serde_json::from_str(&vector.input).expect("commit uncertainty problem");
        assert_eq!(problem.status, 503);
        assert_eq!(problem.code.as_str(), "auth.commit_outcome_unknown");
        assert!(problem.changed, "the operation may have committed");
        assert!(!problem.retryable, "the original POST must not be automatically replayed");
        assert!(problem.detail.contains(recovery));
        assert!(!problem.detail.contains("token="));
        assert_eq!(serde_json::to_string(&problem).expect("canonical JSON"), vector.expected);
    }
}

#[test]
fn personal_rate_header_vectors_use_one_bounded_non_identifying_profile() {
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../vectors/api-problem.json");
    let document = scoplen_test_vectors::VectorDocument::from_path(path).expect("problem vectors");
    let mut accepted = 0;
    let mut rejected = 0;
    for vector in &document.vectors {
        if !vector.kind.starts_with("api.personal.rate_headers") {
            continue;
        }
        let delay = vector.input.parse::<u16>().expect("decimal delay");
        let result = PersonalRateLimitHeaders::new(delay);
        if vector.kind.ends_with(".reject") {
            assert_eq!(vector.expected, "reject", "{}", vector.id);
            assert!(result.is_err(), "{}", vector.id);
            rejected += 1;
            continue;
        }
        let headers = result.expect("accepted delay");
        let actual = json!({
            "Retry-After": headers.retry_after_seconds().to_string(),
            "RateLimit-Policy": headers.rate_limit_policy(),
            "RateLimit": headers.rate_limit(),
        });
        let expected: serde_json::Value =
            serde_json::from_str(&vector.expected).expect("header vector");
        assert_eq!(actual, expected, "{}", vector.id);
        accepted += 1;
    }
    assert_eq!((accepted, rejected), (2, 2));
}

#[test]
fn control_plane_problem_requires_the_shared_error_fields() {
    let complete = json!({
        "type": "about:blank",
        "title": "Denied",
        "status": 403,
        "detail": "The request was denied; no data changed and retrying will not help.",
        "instance": "request-7",
        "code": "policy.denied",
        "changed": false,
        "retryable": false
    });
    let problem: ProblemDetails = serde_json::from_value(complete.clone()).expect("eight fields");
    let shared: SharedProblemDetails = problem.clone();
    assert_eq!(serde_json::to_value(&shared).expect("JSON"), complete);
    let cbor = problem.to_cbor().expect("CBOR");
    assert_eq!(ProblemDetails::from_cbor(&cbor).expect("control-plane CBOR"), problem);
    assert_eq!(SharedProblemDetails::from_cbor(&cbor).expect("shared CBOR"), problem);

    let mut with_extension = complete.clone();
    with_extension["x_trace"] = json!("future response field");
    assert_eq!(
        serde_json::from_value::<ProblemDetails>(with_extension).expect("unknown response field"),
        problem
    );
    let Value::Map(mut fields) = cbor::decode(&cbor).expect("CBOR map") else {
        panic!("problem must be a CBOR map");
    };
    fields.push((Value::Text("x_trace".into()), Value::UInt(1)));
    let extended_cbor = cbor::encode(&Value::Map(fields)).expect("encode extension");
    assert_eq!(ProblemDetails::from_cbor(&extended_cbor).expect("CBOR extension"), problem);

    for field in ["type", "title", "status", "detail", "instance", "code", "changed", "retryable"] {
        let mut missing = complete.clone();
        missing.as_object_mut().expect("object").remove(field);
        assert!(serde_json::from_value::<ProblemDetails>(missing).is_err(), "missing {field}");
    }

    for (field, wrong) in [
        ("type", json!(false)),
        ("title", json!(1)),
        ("status", json!("403")),
        ("detail", json!(null)),
        ("instance", json!(0)),
        ("code", json!(true)),
        ("changed", json!("false")),
        ("retryable", json!(0)),
    ] {
        let mut invalid = complete.clone();
        invalid[field] = wrong;
        assert!(serde_json::from_value::<ProblemDetails>(invalid).is_err(), "invalid {field}");
    }

    let mut unknown = complete;
    unknown["code"] = json!("future.new_code");
    let unknown: ProblemDetails = serde_json::from_value(unknown).expect("valid future code");
    assert_eq!(unknown.code, ErrorCode::new("future.new_code").expect("valid code"));
    assert!(!unknown.code.is_known());
    assert_eq!(
        ProblemDetails::from_cbor(&unknown.to_cbor().expect("encode future code"))
            .expect("decode future code")
            .code,
        unknown.code
    );

    let mut invalid_code = serde_json::to_value(&problem).expect("JSON");
    invalid_code["code"] = json!("Future.Invalid");
    assert!(serde_json::from_value::<ProblemDetails>(invalid_code).is_err());
}
