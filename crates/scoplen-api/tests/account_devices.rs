// SPDX-License-Identifier: Apache-2.0

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use scoplen_api::account_devices::{
    AccountDeviceStatements, AccountDeviceStatementsCodecError as Error,
    MAX_ACCOUNT_DEVICE_ARTIFACT_BYTES, MAX_ACCOUNT_DEVICE_DECODED_BYTES,
    MAX_ACCOUNT_DEVICE_STATEMENTS_BYTES, validate_account_devices_request,
};
use scoplen_test_vectors::VectorDocument;
use serde_json::{Value, json};
use uuid::Uuid;

const ACCOUNT: &str = "019bdad6-b800-7000-8000-000000000001";

fn empty() -> AccountDeviceStatements {
    AccountDeviceStatements::new(Uuid::parse_str(ACCOUNT).expect("UUIDv7"), vec![], vec![])
        .expect("empty snapshot")
}

fn invalid_field(body: &Value, field: &'static str) {
    assert_eq!(
        AccountDeviceStatements::from_json(&serde_json::to_vec(body).expect("test JSON")),
        Err(Error::InvalidField(field)),
    );
}

#[test]
fn published_vectors_match_the_public_codec() {
    let document = VectorDocument::parse_str(include_str!("../../../vectors/account-devices.json"))
        .expect("device snapshot vectors");
    assert!(document.vectors.len() >= 15);
    for vector in document.vectors {
        match vector.kind.as_str() {
            "account.devices.response_json" => {
                let snapshot =
                    AccountDeviceStatements::from_json(vector.input.as_bytes()).expect(&vector.id);
                assert_eq!(snapshot.to_json().expect("encode"), vector.expected.as_bytes());
                assert_eq!(
                    AccountDeviceStatements::from_json(vector.expected.as_bytes()),
                    Ok(snapshot)
                );
            }
            "account.devices.response_invalid" => {
                let error = AccountDeviceStatements::from_json(vector.input.as_bytes())
                    .expect_err(&vector.id);
                let expected = match error {
                    Error::InvalidField(name) => format!("InvalidField({name})"),
                    Error::InvalidJson => "InvalidJson".to_owned(),
                    other => panic!("unexpected error: {other:?}"),
                };
                assert_eq!(expected, vector.expected, "{}", vector.id);
            }
            other => panic!("unexpected vector kind {other}"),
        }
    }
}

#[test]
fn tracked_parser_seeds_preserve_public_round_trip_and_rejection() {
    for input in [
        &include_bytes!("../../../fuzz/corpus/api_json/seed-account-devices-empty-v1")[..],
        &include_bytes!(
            "../../../fuzz/corpus/api_json/seed-account-devices-raw-order-and-independent-arrays-v1"
        )[..],
    ] {
        let snapshot = AccountDeviceStatements::from_json(input).expect("accepted seed");
        let encoded = snapshot.to_json().expect("seed encodes");
        assert_eq!(AccountDeviceStatements::from_json(&encoded), Ok(snapshot));
        assert_eq!(
            AccountDeviceStatements::from_json(&encoded).expect("decode").to_json(),
            Ok(encoded)
        );
    }
    for (input, expected) in [
        (
            &include_bytes!(
                "../../../fuzz/corpus/api_json/seed-account-devices-duplicate-extension-v1"
            )[..],
            Error::InvalidJson,
        ),
        (
            &include_bytes!("../../../fuzz/corpus/api_json/seed-account-devices-pad-bits-v1")[..],
            Error::InvalidField("revocations"),
        ),
        (
            &include_bytes!(
                "../../../fuzz/corpus/api_json/seed-account-devices-reverse-raw-order-v1"
            )[..],
            Error::InvalidField("certificates"),
        ),
    ] {
        assert_eq!(AccountDeviceStatements::from_json(input), Err(expected));
    }
}

#[test]
fn required_fields_types_and_canonical_account_identity_are_checked() {
    let base: Value = serde_json::from_slice(&empty().to_json().expect("body")).expect("JSON");
    for field in ["account_id", "certificates", "revocations"] {
        let mut missing = base.clone();
        missing.as_object_mut().expect("object").remove(field);
        invalid_field(&missing, field);
        for value in [Value::Null, json!(true), json!(1), json!({})] {
            let mut wrong = base.clone();
            wrong[field] = value;
            invalid_field(&wrong, field);
        }
    }
    for account in [
        ACCOUNT.to_uppercase(),
        ACCOUNT.replace('-', ""),
        format!("urn:uuid:{ACCOUNT}"),
        "019bdad6-b800-4000-8000-000000000001".to_owned(),
        "019bdad6-b800-7000-0000-000000000001".to_owned(),
        "not-an-account".to_owned(),
    ] {
        let mut body = base.clone();
        body["account_id"] = json!(account);
        invalid_field(&body, "account_id");
    }
    for field in ["certificates", "revocations"] {
        for value in [json!("AA"), json!([null]), json!([1]), json!([[]])] {
            let mut body = base.clone();
            body[field] = value;
            invalid_field(&body, field);
        }
    }
}

#[test]
fn base64url_and_each_array_are_canonical_and_strictly_raw_byte_sorted() {
    let base = json!({"account_id": ACCOUNT, "certificates": [], "revocations": []});
    for field in ["certificates", "revocations"] {
        for invalid in ["", "AA==", "AA=", "AB", "AAB", "/w", "+w", "_w\n", "é", "A"] {
            let mut body = base.clone();
            body[field] = json!([invalid]);
            invalid_field(&body, field);
        }
        for invalid in [json!(["AA", "AA"]), json!(["0A", "AA"])] {
            let mut body = base.clone();
            body[field] = invalid;
            invalid_field(&body, field);
        }
    }
    // Base64 text orders "0A" before "AA", opposite to decoded [0] before [208].
    let snapshot = AccountDeviceStatements::new(
        empty().account_id,
        vec![vec![0], vec![208]],
        vec![vec![0], vec![208]],
    )
    .expect("independent raw-byte ordered arrays");
    assert_eq!(
        String::from_utf8(snapshot.to_json().expect("encode")).expect("UTF-8"),
        format!(
            r#"{{"account_id":"{ACCOUNT}","certificates":["AA","0A"],"revocations":["AA","0A"]}}"#
        ),
    );
    assert_eq!(
        AccountDeviceStatements::from_json(&snapshot.to_json().expect("body")),
        Ok(snapshot)
    );
}

#[test]
fn recursive_duplicates_and_nonobject_or_trailing_json_are_rejected() {
    let body = String::from_utf8(empty().to_json().expect("body")).expect("UTF-8");
    for invalid in [
        format!("{},\"account_id\":\"{ACCOUNT}\"}}", &body[..body.len() - 1]),
        format!("{},\"x\":{{\"same\":1,\"same\":2}}}}", &body[..body.len() - 1]),
        format!("{},\"x\":[{{\"nested\":[{{\"same\":1,\"same\":2}}]}}]}}", &body[..body.len() - 1]),
        format!("{body} null"),
        "[]".to_owned(),
        "null".to_owned(),
    ] {
        assert_eq!(AccountDeviceStatements::from_json(invalid.as_bytes()), Err(Error::InvalidJson));
    }
    assert_eq!(AccountDeviceStatements::from_json(&[0xff]), Err(Error::InvalidJson));
}

#[test]
fn complete_body_budget_includes_whitespace_escapes_and_ignored_extensions() {
    let canonical = empty().to_json().expect("body");
    for length in [MAX_ACCOUNT_DEVICE_STATEMENTS_BYTES, MAX_ACCOUNT_DEVICE_STATEMENTS_BYTES + 1] {
        let mut body = canonical.clone();
        body.resize(length, b' ');
        if length == MAX_ACCOUNT_DEVICE_STATEMENTS_BYTES {
            assert_eq!(AccountDeviceStatements::from_json(&body), Ok(empty()));
        } else {
            assert_eq!(AccountDeviceStatements::from_json(&body), Err(Error::ResponseTooLarge));
        }
    }
    let prefix = format!(
        "{},\"extension\":\"",
        std::str::from_utf8(&canonical[..canonical.len() - 1]).expect("JSON")
    );
    let body = format!(
        "{prefix}{}\"}}",
        "x".repeat(MAX_ACCOUNT_DEVICE_STATEMENTS_BYTES - prefix.len() - 2)
    );
    assert_eq!(body.len(), MAX_ACCOUNT_DEVICE_STATEMENTS_BYTES);
    assert_eq!(AccountDeviceStatements::from_json(body.as_bytes()), Ok(empty()));
    let escaped = body.replace("xxx", "\\u0078");
    assert!(escaped.len() > MAX_ACCOUNT_DEVICE_STATEMENTS_BYTES);
    assert_eq!(
        AccountDeviceStatements::from_json(escaped.as_bytes()),
        Err(Error::ResponseTooLarge)
    );
}

#[test]
fn artifact_and_combined_decoded_budgets_accept_exact_limits_and_reject_one_over() {
    assert_eq!(MAX_ACCOUNT_DEVICE_DECODED_BYTES, 64 * MAX_ACCOUNT_DEVICE_ARTIFACT_BYTES);
    let artifacts: Vec<_> = (0_u8..64)
        .map(|index| {
            let mut bytes = vec![0; MAX_ACCOUNT_DEVICE_ARTIFACT_BYTES];
            bytes[0] = index;
            bytes
        })
        .collect();
    let mut snapshot = AccountDeviceStatements::new(empty().account_id, artifacts, vec![])
        .expect("exact aggregate and item bounds");
    let body = snapshot.to_json().expect("4 MiB decoded set fits");
    assert_eq!(AccountDeviceStatements::from_json(&body), Ok(snapshot.clone()));
    snapshot.revocations = vec![vec![0]];
    assert_eq!(snapshot.validate(), Err(Error::DecodedTooLarge));
    assert_eq!(snapshot.to_json(), Err(Error::DecodedTooLarge));
    let mut over: Value = serde_json::from_slice(&body).expect("JSON");
    over["revocations"] = json!(["AA"]);
    assert_eq!(
        AccountDeviceStatements::from_json(&serde_json::to_vec(&over).expect("JSON")),
        Err(Error::DecodedTooLarge)
    );
    for field in ["certificates", "revocations"] {
        let mut body = json!({"account_id": ACCOUNT, "certificates": [], "revocations": []});
        body[field] =
            json!([URL_SAFE_NO_PAD.encode(vec![0; MAX_ACCOUNT_DEVICE_ARTIFACT_BYTES + 1])]);
        invalid_field(&body, field);
    }
}

#[test]
fn no_arbitrary_count_cap_but_encoder_enforces_complete_json_budget() {
    let make_artifacts =
        |count: u32| (0..count).map(|value| value.to_be_bytes()[1..].to_vec()).collect();
    let snapshot = AccountDeviceStatements::new(empty().account_id, make_artifacts(1_001), vec![])
        .expect("no K-4 wrap-count restriction on statements");
    assert_eq!(
        AccountDeviceStatements::from_json(&snapshot.to_json().expect("body")),
        Ok(snapshot)
    );
    let mut snapshot = empty();
    snapshot.certificates = make_artifacts(900_000);
    assert_eq!(snapshot.to_json(), Err(Error::ResponseTooLarge));
}

#[test]
fn mutation_is_revalidated_and_debug_and_errors_disclose_no_content() {
    let mut snapshot = empty();
    snapshot.certificates = vec![b"private-device-name".to_vec()];
    snapshot.revocations = vec![b"private-platform".to_vec()];
    let debug = format!("{snapshot:?}");
    for private in [ACCOUNT, "private-device-name", "private-platform"] {
        assert!(!debug.contains(private));
    }
    snapshot.certificates.push(vec![]);
    let error = snapshot.to_json().expect_err("invalid mutable fields");
    for output in [format!("{error:?}"), error.to_string()] {
        assert!(!output.contains(ACCOUNT));
        assert!(!output.contains("private"));
    }
    let mut snapshot = empty();
    snapshot.account_id = Uuid::nil();
    assert_eq!(snapshot.to_json(), Err(Error::InvalidField("account_id")));
}

#[test]
fn http_requires_exact_cache_headers_and_requests_have_no_input() {
    let body = empty().to_json().expect("body");
    assert_eq!(
        AccountDeviceStatements::from_http_json(&body, Some("no-store"), Some("no-cache")),
        Ok(empty())
    );
    for (cache, pragma) in [
        (None, Some("no-cache")),
        (Some("no-store"), None),
        (Some("private, no-store"), Some("no-cache")),
        (Some("no-store"), Some("no-cache ")),
    ] {
        assert_eq!(
            AccountDeviceStatements::from_http_json(&body, cache, pragma),
            Err(Error::HttpMetadata)
        );
    }
    assert_eq!(validate_account_devices_request(None, &[], false, false), Ok(()));
    for (query, body, idempotency, if_match) in [
        (Some(""), &b""[..], false, false),
        (Some("limit=50"), &b""[..], false, false),
        (Some("unknown=value"), &b""[..], false, false),
        (None, &b"{}"[..], false, false),
        (None, &b" "[..], false, false),
        (None, &b""[..], true, false),
        (None, &b""[..], false, true),
    ] {
        assert_eq!(
            validate_account_devices_request(query, body, idempotency, if_match),
            Err(Error::InvalidRequest)
        );
    }
}
