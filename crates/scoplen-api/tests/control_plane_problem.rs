// SPDX-License-Identifier: Apache-2.0

use scoplen_api::{
    ErrorCode, ProblemDetails as SharedProblemDetails, control_plane::ProblemDetails,
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
        let problem = SharedProblemDetails::from_json(vector.input.as_bytes(), vector.input.len())
            .expect("valid published problem");
        assert!(problem.code.is_known(), "{}", vector.id);
        assert_eq!(
            serde_json::to_string(&problem).expect("canonical JSON"),
            vector.expected,
            "{}",
            vector.id
        );
        count += 1;
    }
    assert_eq!(count, 12);
}

#[test]
fn sync_storage_failure_vectors_distinguish_rollback_from_uncertain_commit() {
    assert_sync_storage_failure_vectors("api-problem-sync-storage");
}

#[test]
fn account_key_storage_failure_vectors_distinguish_rollback_from_uncertain_commit() {
    assert_sync_storage_failure_vectors("api-problem-sync-keys-storage");
}

fn assert_sync_storage_failure_vectors(prefix: &str) {
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../vectors/api-problem.json");
    let document = scoplen_test_vectors::VectorDocument::from_path(path).expect("problem vectors");
    for (outcome, changed, retryable) in
        [("precommit", false, true), ("commit-outcome-unknown", true, false)]
    {
        let id = format!("{prefix}-{outcome}");
        let json = document
            .vectors
            .iter()
            .find(|vector| vector.id == format!("{id}-json"))
            .expect("JSON vector");
        let cbor = document
            .vectors
            .iter()
            .find(|vector| vector.id == format!("{id}-cbor"))
            .expect("CBOR vector");
        assert_eq!(json.input, cbor.input);
        let problem: SharedProblemDetails =
            serde_json::from_str(&json.input).expect("published sync storage problem");
        assert_eq!(problem.status, 503);
        assert_eq!(problem.code.as_str(), "sync.storage_unavailable");
        assert_eq!(problem.changed, changed);
        assert_eq!(problem.retryable, retryable);
        assert_eq!(serde_json::to_string(&problem).expect("JSON"), json.expected);
        let expected = cbor
            .expected
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).expect("ASCII hex"), 16))
            .collect::<Result<Vec<_>, _>>()
            .expect("CBOR hex");
        assert_eq!(problem.to_cbor().expect("CBOR"), expected);
        assert_eq!(SharedProblemDetails::from_cbor(&expected).expect("CBOR round trip"), problem);
        let seed_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join(format!("../../fuzz/corpus/sync_data/seed-16-{id}-cbor"));
        let seed = std::fs::read(seed_path).expect("tracked sync_data seed");
        assert_eq!(seed.first(), Some(&16), "problem parser selector");
        assert_eq!(&seed[1..], expected);
        assert_eq!(SharedProblemDetails::from_cbor(&seed[1..]).expect("seed problem"), problem);
        let decoded: SharedProblemDetails =
            serde_json::from_slice(&serde_json::to_vec(&problem).expect("JSON"))
                .expect("JSON round trip");
        assert_eq!(decoded, problem);
    }
}

#[test]
fn control_plane_problem_requires_the_shared_error_fields() {
    let complete = complete_json_problem();
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

fn complete_json_problem() -> serde_json::Value {
    json!({
        "type": "about:blank", "title": "Denied", "status": 403,
        "detail": "The request was denied; no data changed and retrying will not help.",
        "instance": "request-7", "code": "policy.denied",
        "changed": false, "retryable": false
    })
}

#[test]
fn public_json_reader_requires_every_field_type_and_validates_values() {
    let complete = complete_json_problem();
    for field in ["type", "title", "status", "detail", "instance", "code", "changed", "retryable"] {
        let mut missing = complete.clone();
        missing.as_object_mut().unwrap().remove(field);
        assert!(
            ProblemDetails::from_json(&serde_json::to_vec(&missing).unwrap(), 4096).is_err(),
            "missing {field}"
        );
    }
    for (field, invalid) in [
        ("type", json!(false)),
        ("title", json!(1)),
        ("status", json!("403")),
        ("detail", json!(null)),
        ("instance", json!(0)),
        ("code", json!(true)),
        ("changed", json!("false")),
        ("retryable", json!(0)),
        ("type", json!(" ")),
        ("title", json!("\n")),
        ("detail", json!("")),
        ("instance", json!("\t")),
        ("code", json!("Future.Invalid")),
        ("status", json!(99)),
        ("status", json!(600)),
        ("status", json!(-1)),
        ("status", json!(403.0)),
        ("status", json!(65_536)),
    ] {
        let mut value = complete.clone();
        value[field] = invalid;
        assert!(
            ProblemDetails::from_json(&serde_json::to_vec(&value).unwrap(), 4096).is_err(),
            "invalid {field}"
        );
    }
    for status in [100, 599] {
        let mut value = complete.clone();
        value["status"] = json!(status);
        assert_eq!(
            ProblemDetails::from_json(&serde_json::to_vec(&value).unwrap(), 4096).unwrap().status,
            status
        );
    }
}

#[test]
fn public_json_reader_accepts_future_codes_and_ignores_unique_nested_extensions() {
    let mut value = complete_json_problem();
    value["code"] = json!("future.new_code");
    let encoded = serde_json::to_vec(&value).unwrap();
    let expected = ProblemDetails::from_json(&encoded, encoded.len()).unwrap();
    value["extension"] = json!({"values": [null, true, 1, {"nested": "future data"}]});
    let encoded = serde_json::to_vec(&value).unwrap();
    assert_eq!(SharedProblemDetails::from_json(&encoded, encoded.len()).unwrap(), expected);
    assert_eq!(expected.code.as_str(), "future.new_code");
    assert!(!expected.code.is_known());
}

#[test]
fn public_json_reader_rejects_duplicates_in_fields_and_every_extension_depth() {
    let complete = serde_json::to_string(&complete_json_problem()).unwrap();
    let prefix = complete.strip_suffix('}').unwrap();
    for extra in [
        r#", "changed":true"#,
        r#", "ch\u0061nged":false"#,
        r#", "extension":1, "extension":2"#,
        r#", "extension":{"a":1,"a":2}"#,
        r#", "extension":[0,{"nested":[{"a":1,"\u0061":2}]}]"#,
    ] {
        let encoded = format!("{prefix}{extra}}}");
        assert!(ProblemDetails::from_json(encoded.as_bytes(), encoded.len()).is_err());
    }
}

#[test]
fn public_json_reader_enforces_strict_utf8_one_object_and_content_free_errors() {
    let encoded = serde_json::to_vec(&complete_json_problem()).unwrap();
    for input in [
        b"".as_slice(),
        b"null",
        b"[]",
        b"true",
        b"\"private-marker\"",
        b"{",
        b"{\"private-marker\":}",
        b"{\"private-marker\":\"\xff\"}",
        b"{\"private-marker\":\"\\uD800\"}",
    ] {
        let error = ProblemDetails::from_json(input, 4096).unwrap_err();
        assert!(!error.to_string().contains("private-marker"));
        assert!(!format!("{error:?}").contains("private-marker"));
    }
    for (prefix, suffix) in
        [(b"\xef\xbb\xbf".as_slice(), b"".as_slice()), (b"", b"{}"), (b"", b"x")]
    {
        let mut malformed = prefix.to_vec();
        malformed.extend_from_slice(&encoded);
        malformed.extend_from_slice(suffix);
        assert!(ProblemDetails::from_json(&malformed, malformed.len()).is_err());
    }
    for extension in [b",\"extension\":\"\xff\"}".as_slice(), b",\"extension\":\"\\uD800\"}"] {
        let mut malformed = encoded.strip_suffix(b"}").unwrap().to_vec();
        malformed.extend_from_slice(extension);
        assert!(ProblemDetails::from_json(&malformed, malformed.len()).is_err());
    }
    let mut invalid = complete_json_problem();
    invalid["code"] = json!("private-marker");
    let error =
        ProblemDetails::from_json(&serde_json::to_vec(&invalid).unwrap(), 4096).unwrap_err();
    assert!(!error.to_string().contains("private-marker"));
    assert!(!format!("{error:?}").contains("private-marker"));
}

#[test]
fn public_json_reader_applies_exact_endpoint_budget_without_a_global_size_cap() {
    use scoplen_api::account_admission::MAX_ACCOUNT_ENTRY_PROBLEM_BYTES;

    let mut value = complete_json_problem();
    value["title"] = json!("caf\u{e9}");
    let encoded = serde_json::to_vec(&value).unwrap();
    let problem = ProblemDetails::from_json(&encoded, encoded.len()).unwrap();
    assert!(ProblemDetails::from_json(&encoded, encoded.len() - 1).is_err());
    assert!(ProblemDetails::from_json(&encoded, 0).is_err());
    let mut padded = encoded;
    padded.resize(MAX_ACCOUNT_ENTRY_PROBLEM_BYTES, b' ');
    assert_eq!(
        ProblemDetails::from_json(&padded, MAX_ACCOUNT_ENTRY_PROBLEM_BYTES).unwrap(),
        problem
    );
    padded.push(b' ');
    assert!(ProblemDetails::from_json(&padded, MAX_ACCOUNT_ENTRY_PROBLEM_BYTES).is_err());
    padded.resize(2 * MAX_ACCOUNT_ENTRY_PROBLEM_BYTES, b' ');
    assert_eq!(ProblemDetails::from_json(&padded, padded.len()).unwrap(), problem);
}
