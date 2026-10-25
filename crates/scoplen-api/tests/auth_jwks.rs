// SPDX-License-Identifier: Apache-2.0
use scoplen_api::{
    ProblemDetails,
    auth::{
        AUTH_RATE_LIMIT_POLICY, AuthJwk, AuthJwks, AuthJwksCodecError, AuthRateLimitHeaders,
        MAX_AUTH_JWKS_BYTES,
    },
};
use scoplen_test_vectors::VectorDocument;

const PUBLIC_X: &str = "11qYAYdk9Jwu2eNzMeK3GaE3ncyQ0bcYDBfZxe2CNyo";

fn published_vectors() -> VectorDocument {
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../vectors/auth-admission.json");
    VectorDocument::from_path(path).expect("D-106 public vectors")
}

fn one_key() -> Vec<u8> {
    format!(
        r#"{{"keys":[{{"kty":"OKP","crv":"Ed25519","x":"{PUBLIC_X}","kid":"access-1","alg":"Ed25519","use":"sig"}}]}}"#
    )
    .into_bytes()
}

#[test]
fn published_jwks_vectors_use_public_codec_and_canonical_bytes() {
    let mut accepted = 0;
    let mut rejected = 0;
    for vector in published_vectors().vectors {
        match vector.kind.as_str() {
            "auth.jwks" => {
                let document = AuthJwks::from_json(vector.input.as_bytes()).expect(&vector.id);
                let bytes = document.to_json().expect("encode JWKS");
                assert_eq!(bytes, vector.expected.as_bytes(), "{}", vector.id);
                assert_eq!(AuthJwks::from_json(&bytes), Ok(document));
                accepted += 1;
            }
            "auth.jwks.reject" => {
                assert!(AuthJwks::from_json(vector.input.as_bytes()).is_err(), "{}", vector.id);
                assert_eq!(vector.expected, "reject");
                rejected += 1;
            }
            _ => {}
        }
    }
    assert!(accepted >= 2 && rejected >= 15);
}

#[test]
fn constructors_sort_keys_and_reject_duplicate_identifiers() {
    let parsed = AuthJwks::from_json(&one_key()).expect("RFC 8037 public key");
    let first = AuthJwk::new("z-last", *parsed.keys()[0].public_key()).expect("public key");
    let second = AuthJwk::new("A.first_-", [0x42; 32]).expect("public key");
    let document = AuthJwks::new(vec![first.clone(), second.clone()]).expect("two keys");
    assert_eq!(document.keys()[0].kid(), "A.first_-");
    assert_eq!(document.keys()[0].public_key(), &[0x42; 32]);
    assert_eq!(document.keys()[1].kid(), "z-last");
    assert_eq!(AuthJwks::from_json(&document.to_json().expect("JSON")), Ok(document));
    assert!(AuthJwks::new(vec![]).is_err());
    assert!(AuthJwks::new(vec![first.clone(), first.clone()]).is_err());
    assert!(AuthJwks::new(vec![first.clone(), second, first]).is_err());
}

#[test]
fn key_identifier_boundaries_follow_d100() {
    for valid in ["a".to_owned(), "A9._-".to_owned(), "a".repeat(128)] {
        assert!(AuthJwk::new(valid, [0; 32]).is_ok());
    }
    for invalid in [String::new(), "a".repeat(129), "é".into(), "bad/key".into(), "a b".into()] {
        assert!(AuthJwk::new(invalid, [0; 32]).is_err());
    }
    let document = AuthJwks::new(vec![
        AuthJwk::new("a".repeat(128), [0; 32]).expect("long id"),
        AuthJwk::new("z".repeat(128), [0xff; 32]).expect("long id"),
    ])
    .expect("maximum fields");
    assert!(document.to_json().expect("JSON").len() < MAX_AUTH_JWKS_BYTES);
}

#[test]
fn complete_jwks_bound_counts_whitespace_extensions_and_utf8() {
    let canonical = one_key();
    let mut exact = canonical.clone();
    exact.resize(MAX_AUTH_JWKS_BYTES, b' ');
    assert!(AuthJwks::from_json(&exact).is_ok());
    exact.push(b' ');
    assert_eq!(AuthJwks::from_json(&exact), Err(AuthJwksCodecError::TooLarge));

    let canonical = String::from_utf8(canonical).expect("UTF-8");
    let prefix = r#"{"future":"é","padding":""#;
    let suffix = format!(r#"",{}"#, &canonical[1..]);
    let extended = format!(
        "{prefix}{}{suffix}",
        "a".repeat(MAX_AUTH_JWKS_BYTES - prefix.len() - suffix.len())
    );
    assert_eq!(extended.len(), MAX_AUTH_JWKS_BYTES);
    assert!(AuthJwks::from_json(extended.as_bytes()).is_ok());
    assert_eq!(AuthJwks::from_json((extended + " ").as_bytes()), Err(AuthJwksCodecError::TooLarge));
}

#[test]
fn private_key_member_is_rejected_for_every_json_type_without_echoing_it() {
    let original = String::from_utf8(one_key()).expect("UTF-8");
    for value in ["null", "true", "42", r#""private-marker""#, "[]", "{}"] {
        let input = original.replace(r#""kty":"OKP""#, &format!(r#""d":{value},"kty":"OKP""#));
        let error = AuthJwks::from_json(input.as_bytes()).expect_err("private d rejected");
        assert_eq!(error, AuthJwksCodecError::InvalidField("d"));
        assert!(!format!("{error:?} {error}").contains("private-marker"));
    }
}

#[test]
fn every_required_public_key_field_rejects_missing_and_mistyped_values() {
    let original: serde_json::Value = serde_json::from_slice(&one_key()).expect("public document");
    for field in ["kty", "crv", "x", "kid", "alg", "use"] {
        let mut missing = original.clone();
        missing["keys"][0].as_object_mut().expect("key object").remove(field);
        assert!(AuthJwks::from_json(&serde_json::to_vec(&missing).expect("JSON")).is_err());
        for value in [serde_json::Value::Null, serde_json::json!(42), serde_json::json!([])] {
            let mut mistyped = original.clone();
            mistyped["keys"][0][field] = value;
            assert!(AuthJwks::from_json(&serde_json::to_vec(&mistyped).expect("JSON")).is_err());
        }
    }
    assert_eq!(AuthJwks::from_json(b"\xff"), Err(AuthJwksCodecError::InvalidJson));
}

#[test]
fn tracked_jwks_parser_seeds_preserve_public_round_trip_invariant() {
    let directory =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fuzz/corpus/api_json");
    let mut accepted = 0;
    let mut rejected = 0;
    for entry in std::fs::read_dir(directory).expect("API parser corpus") {
        let entry = entry.expect("seed entry");
        if !entry.file_name().to_string_lossy().starts_with("seed-auth-jwks-") {
            continue;
        }
        let input = std::fs::read(entry.path()).expect("parser seed");
        if let Ok(document) = AuthJwks::from_json(&input) {
            let encoded = document.to_json().expect("accepted document encodes");
            assert_eq!(AuthJwks::from_json(&encoded), Ok(document));
            let decoded = AuthJwks::from_json(&encoded).expect("canonical document decodes");
            assert_eq!(decoded.to_json().expect("canonical document encodes"), encoded);
            accepted += 1;
        } else {
            rejected += 1;
        }
    }
    assert!(accepted >= 3 && rejected >= 20);
}

#[test]
fn authentication_rate_headers_have_an_independent_bounded_profile() {
    assert_eq!(AUTH_RATE_LIMIT_POLICY, "\"authentication\";q=30;w=60");
    for delay in [1, 30, 99, 100, 299, 300] {
        let headers = AuthRateLimitHeaders::new(delay).expect("bounded delay");
        assert_eq!(headers.retry_after_seconds(), delay);
        assert_eq!(headers.rate_limit(), format!("\"authentication\";r=0;t={delay}"));
        assert_eq!(headers.rate_limit_policy(), AUTH_RATE_LIMIT_POLICY);
    }
    for invalid in [0, 301, u16::MAX] {
        assert!(AuthRateLimitHeaders::new(invalid).is_err());
    }
}

#[test]
fn published_admission_and_failure_vectors_preserve_shared_public_values() {
    let mut rate = 0;
    let mut problems = 0;
    for vector in published_vectors().vectors {
        match vector.kind.as_str() {
            "auth.rate-limit" => {
                let headers = AuthRateLimitHeaders::new(vector.input.parse().expect("u16 delay"))
                    .expect("valid delay");
                assert_eq!(
                    format!(
                        "Retry-After: {}\nRateLimit-Policy: {}\nRateLimit: {}",
                        headers.retry_after_seconds(),
                        headers.rate_limit_policy(),
                        headers.rate_limit()
                    ),
                    vector.expected,
                    "{}",
                    vector.id
                );
                rate += 1;
            }
            "auth.rate-limit.reject" => {
                assert!(AuthRateLimitHeaders::new(vector.input.parse().expect("u16")).is_err());
            }
            "auth.problem" => {
                let problem: ProblemDetails =
                    serde_json::from_str(&vector.input).expect(&vector.id);
                assert_eq!(serde_json::to_string(&problem).expect("problem JSON"), vector.expected);
                assert_eq!(
                    serde_json::from_str::<ProblemDetails>(&vector.expected).expect("read"),
                    problem
                );
                problems += 1;
            }
            _ => {}
        }
    }
    assert!(rate >= 2 && problems >= 5);
}
