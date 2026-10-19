// SPDX-License-Identifier: Apache-2.0
use scoplen_api::auth::{
    ACCESS_TOKEN_EXPIRES_IN, AuthChallengeRequest, AuthChallengeResponse, AuthDeviceRequest,
    AuthTokenResponse, MAX_CHALLENGE_REQUEST_BYTES, MAX_DEVICE_REQUEST_BYTES,
    REFRESH_TOKEN_EXPIRES_IN,
};
use scoplen_test_vectors::VectorDocument;
use uuid::Uuid;

#[test]
fn published_auth_vectors_round_trip_with_canonical_json() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../vectors/api-auth.json");
    let document = VectorDocument::from_path(path).expect("auth vectors");
    assert_eq!(document.vectors.len(), 6);
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
