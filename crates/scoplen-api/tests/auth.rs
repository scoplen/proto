// SPDX-License-Identifier: Apache-2.0
use scoplen_api::auth::{
    ACCESS_TOKEN_EXPIRES_IN, AuthChallengeRequest, AuthChallengeResponse, AuthDeviceRequest,
    AuthRefreshRequest, AuthTokenResponse, BrowserAuthRefreshRequest, BrowserAuthTokenResponse,
    MAX_CHALLENGE_REQUEST_BYTES, MAX_DEVICE_REQUEST_BYTES, MAX_REFRESH_REQUEST_BYTES,
    MAX_REFRESH_TOKEN_BYTES, REFRESH_TOKEN_EXPIRES_IN,
};
use scoplen_test_vectors::VectorDocument;
use uuid::Uuid;

#[test]
fn published_auth_vectors_round_trip_with_canonical_json() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../vectors/api-auth.json");
    let document = VectorDocument::from_path(path).expect("auth vectors");
    assert_eq!(document.vectors.len(), 10);
    for vector in document.vectors {
        let actual = match vector.kind.as_str() {
            "auth.challenge.request" => AuthChallengeRequest::from_json(&vector.input)
                .expect("challenge request")
                .to_json()
                .expect("challenge request JSON"),
            "auth.device.signature-input" => continue,
            "auth.challenge.response" => AuthChallengeResponse::from_json(&vector.input)
                .expect("challenge")
                .to_json()
                .expect("challenge JSON"),
            "auth.device.request" => AuthDeviceRequest::from_json(&vector.input)
                .expect("device")
                .to_json()
                .expect("device JSON"),
            "auth.token.response" => AuthTokenResponse::from_json(&vector.input)
                .expect("token")
                .to_json()
                .expect("token JSON"),
            "auth.refresh.native.request" => AuthRefreshRequest::from_json(&vector.input)
                .expect("native refresh request")
                .to_json()
                .expect("native refresh JSON"),
            "auth.refresh.browser.request" => BrowserAuthRefreshRequest::from_json(&vector.input)
                .expect("browser refresh request")
                .to_json()
                .to_owned(),
            "auth.refresh.native.response" => AuthTokenResponse::from_json(&vector.input)
                .expect("native refresh response")
                .to_json()
                .expect("native refresh response JSON"),
            "auth.refresh.browser.response" => BrowserAuthTokenResponse::from_json(&vector.input)
                .expect("browser refresh response")
                .to_json()
                .expect("browser refresh response JSON"),
            other => panic!("unexpected auth vector kind {other}"),
        };
        assert_eq!(actual, vector.expected, "{}", vector.id);
    }
}

#[test]
fn challenge_request_requires_exact_fields_and_canonical_device() {
    let device_id = "00000000-0000-7000-8000-000000000001";
    let json = format!("{{\"device_id\":\"{device_id}\"}}");
    let request = AuthChallengeRequest::from_json(&json).expect("valid challenge request");
    assert_eq!(request.to_json().expect("encoded challenge request"), json);

    for invalid in [
        "{}".to_owned(),
        format!("{{\"device_id\":\"{device_id}\",\"device_id\":\"{device_id}\"}}"),
        format!("{{\"device_id\":\"{device_id}\",\"extra\":true}}"),
        "{\"device_id\":42}".to_owned(),
        json.replace(device_id, "00000000-0000-4000-8000-000000000001"),
        json.replace(device_id, "00000000-0000-7000-8000-00000000000A"),
    ] {
        assert!(AuthChallengeRequest::from_json(&invalid).is_err(), "{invalid}");
    }
}

#[test]
fn auth_request_limits_count_encoded_bytes_including_whitespace() {
    let device_id = "00000000-0000-7000-8000-000000000001";
    let challenge = format!("{{\"device_id\":\"{device_id}\"}}");
    let exact_challenge =
        format!("{challenge}{}", " ".repeat(MAX_CHALLENGE_REQUEST_BYTES - challenge.len()));
    assert_eq!(exact_challenge.len(), MAX_CHALLENGE_REQUEST_BYTES);
    assert!(AuthChallengeRequest::from_json(&exact_challenge).is_ok());
    assert!(AuthChallengeRequest::from_json(&(exact_challenge + " ")).is_err());

    let nonce = "00".repeat(32);
    let signature = "00".repeat(64);
    let device = format!(
        "{{\"device_id\":\"{device_id}\",\"nonce\":\"{nonce}\",\"signature\":\"{signature}\"}}"
    );
    let exact_device = format!("{device}{}", " ".repeat(MAX_DEVICE_REQUEST_BYTES - device.len()));
    assert_eq!(exact_device.len(), MAX_DEVICE_REQUEST_BYTES);
    assert!(AuthDeviceRequest::from_json(&exact_device).is_ok());
    assert!(AuthDeviceRequest::from_json(&(exact_device + " ")).is_err());
    let reencoded = AuthDeviceRequest::from_json(&device)
        .expect("valid device request")
        .to_json()
        .expect("encoded device request");
    assert!(reencoded.len() < MAX_DEVICE_REQUEST_BYTES);
}

#[test]
fn token_response_debug_redacts_both_opaque_tokens() {
    let response =
        AuthTokenResponse::new("access-token-synthetic-unique", "refresh-token-synthetic-unique")
            .expect("valid tokens");
    let debug = format!("{response:?}");
    assert!(!debug.contains("access-token-synthetic-unique"));
    assert!(!debug.contains("refresh-token-synthetic-unique"));
    assert_eq!(debug.matches("[REDACTED]").count(), 2);
    assert!(debug.contains("token_type: \"DPoP\""));
    assert!(debug.contains("expires_in: 600"));
    assert!(debug.contains("refresh_expires_in: 2592000"));
}

#[test]
fn auth_public_types_enforce_failure_paths() {
    let nonce = "00".repeat(32);
    let challenge_nonce = "ab".repeat(32);
    let signature = "00".repeat(64);
    let device_id = Uuid::parse_str("00000000-0000-7000-8000-000000000001").expect("UUIDv7");
    let valid_device = format!(
        "{{\"device_id\":\"{device_id}\",\"nonce\":\"{nonce}\",\"signature\":\"{signature}\"}}"
    );

    assert!(
        AuthChallengeResponse::from_json(&format!(
            "{{\"nonce\":\"{nonce}\",\"server_time\":\"2026-10-07T12:34:56+00:00\"}}"
        ))
        .is_err()
    );
    assert!(
        AuthChallengeResponse::from_json(&format!(
            "{{\"nonce\":\"{}\",\"server_time\":\"2026-10-07T12:34:56Z\"}}",
            challenge_nonce.to_uppercase()
        ))
        .is_err()
    );
    assert!(AuthDeviceRequest::from_json(&valid_device).is_ok());
    assert!(
        AuthDeviceRequest::from_json(
            &valid_device
                .replace("\"signature\":\"", "\"signature\":\"00\",\"unknown\":true,\"unused\":\"")
        )
        .is_err()
    );
    assert!(AuthTokenResponse::from_json(
        "{\"access_token\":\"a\",\"token_type\":\"DPoP\",\"expires_in\":600,\"refresh_token\":\"r\",\"refresh_expires_in\":2592000,\"extra\":true}"
    )
    .is_ok());
    assert!(AuthTokenResponse::from_json(
        "{\"access_token\":\"a\",\"token_type\":\"DPoP\",\"expires_in\":1,\"refresh_token\":\"r\",\"refresh_expires_in\":2}"
    )
    .is_ok());
    assert!(AuthTokenResponse::from_json(
        "{\"access_token\":\"a\",\"token_type\":\"DPoP\",\"expires_in\":0,\"refresh_token\":\"r\",\"refresh_expires_in\":1}"
    )
    .is_err());
    assert!(AuthTokenResponse::from_json(
        "{\"access_token\":\"a\",\"token_type\":\"DPoP\",\"expires_in\":1,\"refresh_token\":\"r\",\"refresh_expires_in\":0}"
    )
    .is_err());
    assert!(AuthTokenResponse::from_json(&format!(
        "{{\"access_token\":\"a\",\"token_type\":\"DPoP\",\"expires_in\":{ACCESS_TOKEN_EXPIRES_IN},\"refresh_token\":\"r\",\"refresh_expires_in\":{REFRESH_TOKEN_EXPIRES_IN}}}"
    ))
    .is_ok());
    assert!(AuthTokenResponse::from_json(
        "{\"access_token\":\"a\",\"token_type\":\"Bearer\",\"expires_in\":600,\"refresh_token\":\"r\",\"refresh_expires_in\":2592000}"
    )
    .is_err());
}

#[test]
fn refresh_requests_reject_other_shapes_and_count_utf8_bytes() {
    let native = AuthRefreshRequest::new("synthetic-refresh-secret").expect("native request");
    assert_eq!(
        native.to_json().expect("encode"),
        "{\"refresh_token\":\"synthetic-refresh-secret\"}"
    );
    assert!(!format!("{native:?}").contains("synthetic-refresh-secret"));
    for invalid in [
        "{}",
        "null",
        "[\"synthetic-refresh-secret\"]",
        "{\"refresh_token\":null}",
        "{\"refresh_token\":false}",
        "{\"refresh_token\":\"\"}",
        "{\"refresh_token\":\"one\",\"refresh_token\":\"two\"}",
        "{\"refresh_token\":\"one\",\"extra\":true}",
    ] {
        assert!(AuthRefreshRequest::from_json(invalid).is_err());
        assert!(serde_json::from_str::<AuthRefreshRequest>(invalid).is_err());
    }
    let unicode_at_limit = "é".repeat(MAX_REFRESH_TOKEN_BYTES / 2);
    assert_eq!(unicode_at_limit.len(), MAX_REFRESH_TOKEN_BYTES);
    assert!(AuthRefreshRequest::new(&unicode_at_limit).is_ok());
    let unicode_over_limit = format!("{unicode_at_limit}é");
    assert!(AuthRefreshRequest::new(&unicode_over_limit).is_err());
    let oversized_token = format!("{{\"refresh_token\":\"{unicode_over_limit}\"}}");
    assert!(serde_json::from_str::<AuthRefreshRequest>(&oversized_token).is_err());
    let secret = "synthetic-refresh-secret";
    let valid = format!("{{\"refresh_token\":\"{secret}\"}}");
    let exact = format!("{valid}{}", " ".repeat(MAX_REFRESH_REQUEST_BYTES - valid.len()));
    assert_eq!(exact.len(), MAX_REFRESH_REQUEST_BYTES);
    assert!(AuthRefreshRequest::from_json(&exact).is_ok());
    let error = AuthRefreshRequest::from_json(&(exact + " ")).expect_err("body cap");
    assert!(!format!("{error:?}").contains(secret));
    let browser_exact = format!("{{}}{}", " ".repeat(MAX_REFRESH_REQUEST_BYTES - 2));
    assert!(BrowserAuthRefreshRequest::from_json(&browser_exact).is_ok());
    assert!(BrowserAuthRefreshRequest::from_json(&(browser_exact + " ")).is_err());
    for invalid in ["null", "[]", "{\"refresh_token\":\"secret\"}", "{\"extra\":null}"] {
        assert!(BrowserAuthRefreshRequest::from_json(invalid).is_err());
        assert!(serde_json::from_str::<BrowserAuthRefreshRequest>(invalid).is_err());
    }
}

#[test]
fn browser_response_never_accepts_native_refresh_token_field() {
    let browser = BrowserAuthTokenResponse::new("synthetic-access-secret").expect("browser token");
    let json = browser.to_json().expect("browser JSON");
    assert_eq!(
        json,
        "{\"access_token\":\"synthetic-access-secret\",\"token_type\":\"DPoP\",\"expires_in\":600,\"refresh_expires_in\":2592000}"
    );
    assert!(!format!("{browser:?}").contains("synthetic-access-secret"));
    assert!(!json.contains("refresh_token"));
    assert_eq!(
        BrowserAuthTokenResponse::from_json(&json.replace('}', ",\"extension\":true}"))
            .expect("unknown extension"),
        browser
    );
    for native_only in ["\"secret\"", "null", "false", "0", "{}"] {
        let invalid = json.replace('}', &format!(",\"refresh_token\":{native_only}}}"));
        let error = BrowserAuthTokenResponse::from_json(&invalid).expect_err("known native field");
        assert!(!format!("{error:?}").contains("synthetic-access-secret"));
        assert!(serde_json::from_str::<BrowserAuthTokenResponse>(&invalid).is_err());
    }
    for invalid in [
        json.replace("\"DPoP\"", "\"Bearer\""),
        json.replace("\"expires_in\":600", "\"expires_in\":0"),
        json.replace("\"refresh_expires_in\":2592000", "\"refresh_expires_in\":0"),
        json.replace("\"access_token\":\"synthetic-access-secret\",", ""),
        json.replace("\"access_token\":\"synthetic-access-secret\"", "\"access_token\":\"\""),
    ] {
        assert!(BrowserAuthTokenResponse::from_json(&invalid).is_err());
    }
    let varying = BrowserAuthTokenResponse::from_json(
        "{\"access_token\":\"a\",\"token_type\":\"DPoP\",\"expires_in\":1,\"refresh_expires_in\":18446744073709551615}"
    ).expect("positive lifetimes");
    assert_eq!(varying.refresh_expires_in, u64::MAX);
}
