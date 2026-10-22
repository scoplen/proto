// SPDX-License-Identifier: Apache-2.0
//! Exercise K-3 `DPoP` through the public crypto API and RFC 9449 material.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use scoplen_crypto::{
    DeviceSigner, DpopError, DpopProof, DpopTarget, DpopToken, P256SigningKey, PrimitiveError,
    dpop_jwk_thumbprint,
};
use scoplen_test_vectors::VectorDocument;
use serde_json::{Value, json};

const ACCESS_TOKEN: &str = "Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU";
const RFC_JKT: &str = "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I";
const P256_ORDER: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
];

fn key() -> P256SigningKey {
    P256SigningKey::from_bytes(&[1; 32]).expect("synthetic key")
}

fn target(method: &str, path: &str) -> DpopTarget {
    DpopTarget::new(method, "https://example.com", path).expect("trusted target")
}

fn jwk() -> Value {
    let sec1 = key().public_key_sec1();
    json!({
        "kty": "EC", "crv": "P-256",
        "x": URL_SAFE_NO_PAD.encode(&sec1[1..33]),
        "y": URL_SAFE_NO_PAD.encode(&sec1[33..65])
    })
}

fn header() -> Value {
    json!({"typ":"dpop+jwt", "alg":"ES256", "jwk":jwk()})
}

fn claims(method: &str, path: &str, iat: u64) -> Value {
    json!({"jti":"test-jti", "htm":method, "htu":format!("https://example.com{path}"), "iat":iat})
}

fn sign_raw(header: &str, claims: &str) -> DpopProof {
    let input = format!("{}.{}", URL_SAFE_NO_PAD.encode(header), URL_SAFE_NO_PAD.encode(claims));
    let signature = key().sign(input.as_bytes());
    DpopProof::parse(&format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature)))
        .expect("compact proof")
}

fn sign_json(header: &Value, claims: &Value) -> DpopProof {
    sign_raw(&header.to_string(), &claims.to_string())
}

fn local_jkt() -> String {
    dpop_jwk_thumbprint(&key().public_key_sec1()).expect("thumbprint")
}

#[test]
fn rfc_9449_protected_vector_verifies_without_reserializing() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../vectors/api-dpop.json");
    let document = VectorDocument::from_path(path).expect("D-80 vectors");
    let vector =
        document.vectors.iter().find(|v| v.kind == "crypto.dpop.protected").expect("RFC vector");
    let expected: Vec<_> = vector.expected.split('|').collect();
    assert_eq!(expected.len(), 5);
    let target = DpopTarget::new("GET", "https://resource.example.org", "/protectedresource")
        .expect("target");
    let proof = DpopProof::parse(&vector.input).expect("RFC compact proof");
    let verified = proof
        .verify(&target, DpopToken::Protected(ACCESS_TOKEN), RFC_JKT, 1_562_262_618, None)
        .expect("RFC signature");
    assert_eq!(verified.jkt, expected[0]);
    assert_eq!(verified.jti, expected[1]);
    assert_eq!(verified.iat.to_string(), expected[2]);
    assert_eq!(verified.last_accepted_at.to_string(), expected[3]);
    assert_eq!(
        proof.verify_presented_key(
            &target,
            DpopToken::Protected(ACCESS_TOKEN),
            1_562_262_618,
            None
        ),
        Ok(verified.clone())
    );
    let encoded_claims = vector.input.split('.').nth(1).expect("RFC claims");
    let claims: Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(encoded_claims).expect("base64url"))
            .expect("RFC JSON claims");
    assert_eq!(claims["ath"], expected[4]);
    assert!(format!("{proof:?}").contains("REDACTED"));
    assert!(format!("{verified:?}").contains("REPLAY NOT CLAIMED"));
}

#[test]
fn generated_proofs_bind_method_uri_token_and_nonce() {
    let key = key();
    let jkt = local_jkt();
    for method in ["GET", "CONNECT"] {
        let request_target = target(method, "/sync/v1/notify");
        let proof = DpopProof::sign(
            &key,
            &key.public_key_sec1(),
            &request_target,
            DpopToken::Protected("access.jwt"),
            1_000,
            Some("nonce-1"),
        )
        .expect("signed proof");
        let verified = proof
            .verify(
                &request_target,
                DpopToken::Protected("access.jwt"),
                &jkt,
                1_000,
                Some("nonce-1"),
            )
            .expect("valid proof");
        assert_eq!(verified.last_accepted_at, 1_060);
        assert_eq!(verified.jti.len(), 22);
        assert_eq!(
            proof.verify(
                &request_target,
                DpopToken::Protected("other.jwt"),
                &jkt,
                1_000,
                Some("nonce-1")
            ),
            Err(DpopError::InvalidProof)
        );
        assert_eq!(
            proof.verify(
                &request_target,
                DpopToken::Protected("access.jwt"),
                &jkt,
                1_000,
                Some("nonce-2")
            ),
            Err(DpopError::InvalidProof)
        );
        assert_eq!(
            proof.verify(
                &request_target,
                DpopToken::Protected("access.jwt"),
                &jkt,
                1_061,
                Some("nonce-1")
            ),
            Err(DpopError::InvalidProof)
        );
        assert_eq!(
            proof.verify(
                &request_target,
                DpopToken::Protected("access.jwt"),
                &jkt,
                939,
                Some("nonce-1")
            ),
            Err(DpopError::InvalidProof)
        );
        assert!(
            proof
                .verify(
                    &request_target,
                    DpopToken::Protected("access.jwt"),
                    &jkt,
                    940,
                    Some("nonce-1")
                )
                .is_ok()
        );
        assert!(
            proof
                .verify(
                    &request_target,
                    DpopToken::Protected("access.jwt"),
                    &jkt,
                    1_060,
                    Some("nonce-1")
                )
                .is_ok()
        );
        assert_eq!(
            proof.verify(
                &target("POST", "/sync/v1/notify"),
                DpopToken::Protected("access.jwt"),
                &jkt,
                1_000,
                Some("nonce-1")
            ),
            Err(DpopError::InvalidProof)
        );
    }
}

#[test]
fn refresh_proofs_omit_and_do_not_require_ath() {
    let key = key();
    let jkt = local_jkt();
    let target = target("POST", "/api/v1/auth/refresh");
    let refresh =
        DpopProof::sign(&key, &key.public_key_sec1(), &target, DpopToken::Refresh, 1_000, None)
            .expect("refresh proof");
    let parts: Vec<_> = refresh.as_str().split('.').collect();
    let claims: Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).expect("claims")).expect("JSON");
    assert!(claims.get("ath").is_none());
    assert!(refresh.verify(&target, DpopToken::Refresh, &jkt, 1_000, None).is_ok());
    assert_eq!(
        refresh.verify(&target, DpopToken::Protected("access.jwt"), &jkt, 1_000, None),
        Err(DpopError::InvalidProof)
    );
    let mut extra = claims;
    extra["ath"] = json!("ignored-even-if-invalid");
    let extra = sign_json(&header(), &extra);
    assert!(extra.verify(&target, DpopToken::Refresh, &jkt, 1_000, None).is_ok());
    assert!(extra.verify_presented_key(&target, DpopToken::Refresh, 1_000, None).is_ok());
}

#[test]
fn presented_key_verification_preserves_signed_bytes_and_leaves_replay_to_consumer() {
    let path = "/api/v1/auth/operator/setup/options";
    let request_target = target("POST", path);
    let signed_header = serde_json::to_string_pretty(&header()).expect("header");
    let signed_claims = serde_json::to_string_pretty(&claims("POST", path, 1_000)).expect("claims");
    let proof = sign_raw(&signed_header, &signed_claims);
    let verified = proof
        .verify_presented_key(&request_target, DpopToken::Refresh, 1_000, None)
        .expect("presented-key possession");
    assert_eq!(verified.jkt, local_jkt());
    assert_eq!(verified.jti, "test-jti");
    assert_eq!(verified.iat, 1_000);
    assert_eq!(verified.last_accepted_at, 1_060);
    assert_eq!(
        proof.verify(&request_target, DpopToken::Refresh, RFC_JKT, 1_000, None),
        Err(DpopError::InvalidProof),
        "possession cannot replace an existing different trusted key binding"
    );
    let second = proof
        .verify_presented_key(&request_target, DpopToken::Refresh, 1_000, None)
        .expect("stateless verification does not claim a replay");
    assert_eq!(second, verified);
    let mut replay_claims = std::collections::BTreeSet::new();
    assert!(replay_claims.insert((verified.jkt, verified.jti)));
    assert!(!replay_claims.insert((second.jkt, second.jti)));

    let signature = proof.as_str().rsplit('.').next().expect("signature");
    let reserialized = DpopProof::parse(&format!(
        "{}.{}.{signature}",
        URL_SAFE_NO_PAD.encode(header().to_string()),
        URL_SAFE_NO_PAD.encode(claims("POST", path, 1_000).to_string())
    ))
    .expect("canonical compact envelope");
    assert_ne!(reserialized, proof);
    assert_eq!(
        reserialized.verify_presented_key(&request_target, DpopToken::Refresh, 1_000, None),
        Err(DpopError::InvalidProof)
    );
}

#[test]
fn presented_key_verification_keeps_signature_target_token_time_and_nonce_checks() {
    let path = "/api/v1/auth/operator/setup/finish";
    let request_target = target("POST", path);
    let proof = DpopProof::sign(
        &key(),
        &key().public_key_sec1(),
        &request_target,
        DpopToken::Protected("access.jwt"),
        1_000,
        Some("nonce-1"),
    )
    .expect("proof");
    assert!(
        proof
            .verify_presented_key(
                &request_target,
                DpopToken::Protected("access.jwt"),
                1_000,
                Some("nonce-1")
            )
            .is_ok()
    );
    for (request_target, token, now, nonce) in [
        (target("GET", path), DpopToken::Protected("access.jwt"), 1_000, Some("nonce-1")),
        (
            target("POST", "/api/v1/auth/operator/setup/options"),
            DpopToken::Protected("access.jwt"),
            1_000,
            Some("nonce-1"),
        ),
        (target("POST", path), DpopToken::Protected("other.jwt"), 1_000, Some("nonce-1")),
        (target("POST", path), DpopToken::Protected("access.jwt"), 939, Some("nonce-1")),
        (target("POST", path), DpopToken::Protected("access.jwt"), 1_061, Some("nonce-1")),
        (target("POST", path), DpopToken::Protected("access.jwt"), 1_000, Some("nonce-2")),
    ] {
        assert_eq!(
            proof.verify_presented_key(&request_target, token, now, nonce),
            Err(DpopError::InvalidProof)
        );
    }
    for invalid_token in ["", "non-ascii-é"] {
        assert_eq!(
            proof.verify_presented_key(
                &request_target,
                DpopToken::Protected(invalid_token),
                1_000,
                None
            ),
            Err(DpopError::InvalidContext)
        );
    }
    assert_eq!(
        proof.verify_presented_key(&request_target, DpopToken::Refresh, 1_000, Some("bad nonce")),
        Err(DpopError::InvalidContext)
    );
    let parts: Vec<_> = proof.as_str().split('.').collect();
    let mut signature = URL_SAFE_NO_PAD.decode(parts[2]).expect("signature bytes");
    signature[0] ^= 1;
    let tampered = DpopProof::parse(&format!(
        "{}.{}.{}",
        parts[0],
        parts[1],
        URL_SAFE_NO_PAD.encode(signature)
    ))
    .expect("compact proof");
    assert_eq!(
        tampered.verify_presented_key(&request_target, DpopToken::Refresh, 1_000, None),
        Err(DpopError::InvalidProof)
    );
}

#[test]
fn target_rejects_bare_hexadecimal_host_marker() {
    for origin in ["https://0x", "https://edge.0x", "https://0x:8443", "https://edge.0x:8443"] {
        assert_eq!(
            DpopTarget::new("POST", origin, "/api/v1/auth/refresh"),
            Err(DpopError::InvalidTarget),
            "{origin}"
        );
    }
    for origin in ["https://0.0.0.0", "https://0.0.0.0:8443", "https://0x.example.com"] {
        assert!(DpopTarget::new("POST", origin, "/api/v1/auth/refresh").is_ok(), "{origin}");
    }
}

#[test]
fn target_rejects_route_aliases_and_noncanonical_origins() {
    let invalid = [
        "", "relative", "//double", "/a//b", "/.", "/..", "/a/./b", "/a/../b", "/a%2Fb", "/a%5Cb",
        "/%2e", "/%41", "/%7E", "/%00", "/%7F", "/%1F", "/%2f", "/%aa", "/%GG", "/%", "/a\\b",
        "/a?x=1", "/a#f", "/é",
    ];
    for path in invalid {
        assert_eq!(
            DpopTarget::new("GET", "https://example.com", path),
            Err(DpopError::InvalidTarget),
            "{path}"
        );
    }
    assert!(DpopTarget::new("GET", "https://example.com", "/a%3Fb/%25").is_ok());
    assert_eq!(
        DpopTarget::new("GET", "https://example.com:443", "/a"),
        Err(DpopError::InvalidTarget)
    );
    assert_eq!(
        DpopTarget::new("GET", "https://example.com", &format!("/{}", "x".repeat(4_096))),
        Err(DpopError::InvalidTarget)
    );
    let maximum_path = format!("/{}", "x".repeat(4_096 - "https://example.com".len() - 1));
    assert_eq!(
        DpopTarget::new("GET", "https://example.com", &maximum_path)
            .expect("maximum target")
            .uri()
            .len(),
        4_096
    );
    for method in ["", "GET ", "G\nET", "é", "X".repeat(33).as_str()] {
        assert_eq!(
            DpopTarget::new(method, "https://example.com", "/a"),
            Err(DpopError::InvalidTarget)
        );
    }
}

#[test]
fn signed_claims_and_headers_reject_ambiguity_and_wrong_types() {
    let target = target("GET", "/x");
    let jkt = local_jkt();
    let good_header = header();
    let good_claims = claims("GET", "/x", 1_000);
    let check = |header: &Value, claims: &Value| {
        let proof = sign_json(header, claims);
        let bound = proof.verify(&target, DpopToken::Refresh, &jkt, 1_000, None);
        assert_eq!(bound, proof.verify_presented_key(&target, DpopToken::Refresh, 1_000, None));
        bound
    };
    for (field, value) in [
        ("typ", json!("jwt")),
        ("alg", json!("none")),
        ("crit", json!([])),
        ("b64", json!(true)),
        ("jwk", json!({"kty":"oct"})),
    ] {
        let mut altered = good_header.clone();
        altered[field] = value;
        assert_eq!(check(&altered, &good_claims), Err(DpopError::InvalidProof), "{field}");
    }
    for (field, value) in [
        ("jti", json!("")),
        ("htm", json!("POST")),
        ("htu", json!("https://example.com/x?q=1")),
        ("iat", json!(-1)),
        ("nonce", json!("bad nonce")),
    ] {
        let mut altered = good_claims.clone();
        altered[field] = value;
        assert_eq!(check(&good_header, &altered), Err(DpopError::InvalidProof), "{field}");
    }
    for field in ["jti", "htm", "htu", "iat"] {
        let mut altered = good_claims.clone();
        altered.as_object_mut().expect("object").remove(field);
        assert_eq!(check(&good_header, &altered), Err(DpopError::InvalidProof), "{field}");
    }
    let mut upper_type = good_header.clone();
    upper_type["typ"] = json!("DPoP+JWT");
    assert!(check(&upper_type, &good_claims).is_ok());
    let mut extension = good_header.clone();
    extension["kid"] = json!("ignored");
    assert!(check(&extension, &good_claims).is_ok());
    for private in [json!("hidden"), Value::Null] {
        let mut altered = good_header.clone();
        altered["jwk"]["d"] = private;
        assert_eq!(check(&altered, &good_claims), Err(DpopError::InvalidProof));
    }
    let jwk_json = jwk().to_string();
    let duplicate_jwk = jwk_json.replacen("\"kty\":\"EC\"", "\"kty\":\"EC\",\"kty\":\"EC\"", 1);
    assert_ne!(duplicate_jwk, jwk_json);
    for malformed in [
        format!(
            "{{\"typ\":\"dpop+jwt\",\"typ\":\"dpop+jwt\",\"alg\":\"ES256\",\"jwk\":{}}}",
            jwk()
        ),
        format!("{{\"typ\":\"dpop+jwt\",\"alg\":\"ES256\",\"jwk\":{duplicate_jwk}}}"),
    ] {
        assert_eq!(
            sign_raw(&malformed, &good_claims.to_string()).verify(
                &target,
                DpopToken::Refresh,
                &jkt,
                1_000,
                None
            ),
            Err(DpopError::InvalidProof)
        );
    }
    let duplicate_claims =
        r#"{"jti":"a","jti":"b","htm":"GET","htu":"https://example.com/x","iat":1000}"#;
    assert_eq!(
        sign_raw(&good_header.to_string(), duplicate_claims).verify(
            &target,
            DpopToken::Refresh,
            &jkt,
            1_000,
            None
        ),
        Err(DpopError::InvalidProof)
    );
}

#[test]
fn invalid_key_binding_signature_and_limits_fail() {
    let target = target("GET", "/x");
    let good_header = header();
    let good_claims = claims("GET", "/x", 1_000);
    let jkt = local_jkt();
    let proof = sign_json(&good_header, &good_claims);
    assert_eq!(
        proof.verify(&target, DpopToken::Refresh, RFC_JKT, 1_000, None),
        Err(DpopError::InvalidProof)
    );
    assert_eq!(
        proof.verify(&target, DpopToken::Refresh, "bad", 1_000, None),
        Err(DpopError::InvalidContext)
    );
    let mut malformed = good_header.clone();
    malformed["jwk"]["crv"] = json!("P-384");
    assert_eq!(
        sign_json(&malformed, &good_claims).verify(&target, DpopToken::Refresh, &jkt, 1_000, None),
        Err(DpopError::InvalidProof)
    );
    malformed = good_header.clone();
    malformed["jwk"]["x"] = json!("A".repeat(43));
    assert_eq!(
        sign_json(&malformed, &good_claims).verify(&target, DpopToken::Refresh, &jkt, 1_000, None),
        Err(DpopError::InvalidProof)
    );
    let mut tampered = proof.as_str().to_owned().into_bytes();
    *tampered.last_mut().expect("signature") = b'A';
    if tampered != proof.as_str().as_bytes() {
        let tampered =
            DpopProof::parse(std::str::from_utf8(&tampered).expect("ASCII")).expect("compact");
        assert_eq!(
            tampered.verify(&target, DpopToken::Refresh, &jkt, 1_000, None),
            Err(DpopError::InvalidProof)
        );
    }
    let mut oversized = good_claims.clone();
    oversized["jti"] = json!("x".repeat(129));
    assert_eq!(
        sign_json(&good_header, &oversized).verify(&target, DpopToken::Refresh, &jkt, 1_000, None),
        Err(DpopError::InvalidProof)
    );
    oversized["jti"] = json!("é".repeat(64));
    assert!(
        sign_json(&good_header, &oversized)
            .verify(&target, DpopToken::Refresh, &jkt, 1_000, None)
            .is_ok()
    );
    oversized["jti"] = json!("é".repeat(65));
    assert_eq!(
        sign_json(&good_header, &oversized).verify(&target, DpopToken::Refresh, &jkt, 1_000, None),
        Err(DpopError::InvalidProof)
    );
    assert!(DpopProof::parse(&"A".repeat(8_193)).is_err());
    for invalid in ["", "a.b", "a.b.c.d", "a..c", "a.b.c=", "a.b.ç", "a.b.\n", "a.a.a", "AB.AB.AB"]
    {
        assert!(DpopProof::parse(invalid).is_err(), "{invalid}");
    }
    assert_eq!(
        proof.verify(&target, DpopToken::Protected("é"), &jkt, 1_000, None),
        Err(DpopError::InvalidContext)
    );
    assert_eq!(
        proof.verify(&target, DpopToken::Protected(""), &jkt, 1_000, None),
        Err(DpopError::InvalidContext)
    );
    assert_eq!(
        proof.verify(&target, DpopToken::Protected(&"x".repeat(4_097)), &jkt, 1_000, None),
        Err(DpopError::InvalidContext)
    );
}

struct WrongSigner;

impl DeviceSigner for WrongSigner {
    fn sign(&self, message: &[u8]) -> Result<[u8; 64], PrimitiveError> {
        Ok(P256SigningKey::from_bytes(&[2; 32]).expect("other key").sign(message))
    }
}

#[test]
fn signer_output_must_match_supplied_public_key_and_debug_is_redacted() {
    let target = target("POST", "/api/v1/auth/refresh");
    let key = key();
    assert_eq!(
        DpopProof::sign(
            &WrongSigner,
            &key.public_key_sec1(),
            &target,
            DpopToken::Refresh,
            1_000,
            None
        ),
        Err(DpopError::SignerFailed)
    );
    assert_eq!(
        DpopProof::sign(&key, &key.public_key_sec1(), &target, DpopToken::Refresh, u64::MAX, None),
        Err(DpopError::InvalidContext)
    );
    assert_eq!(
        DpopProof::sign(
            &key,
            &key.public_key_sec1(),
            &target,
            DpopToken::Refresh,
            1_000,
            Some("a b")
        ),
        Err(DpopError::InvalidContext)
    );
    assert_eq!(
        DpopProof::sign(
            &key,
            &key.public_key_sec1(),
            &target,
            DpopToken::Refresh,
            1_000,
            Some("a\\b")
        ),
        Err(DpopError::InvalidContext)
    );
    assert!(!format!("{:?}", DpopToken::Protected("secret-token")).contains("secret-token"));
    assert!(!format!("{:?}", DpopError::InvalidContext).contains("secret-token"));
}

struct FailingSigner;

impl DeviceSigner for FailingSigner {
    fn sign(&self, _message: &[u8]) -> Result<[u8; 64], PrimitiveError> {
        Err(PrimitiveError::Randomness("private signer diagnostic".to_owned()))
    }
}

#[test]
fn boundary_values_and_signer_failure_are_bounded() {
    let request_target = target("GET", "/x");
    let key = key();
    let jkt = local_jkt();
    let at_zero =
        DpopProof::sign(&key, &key.public_key_sec1(), &request_target, DpopToken::Refresh, 0, None)
            .expect("epoch proof");
    assert!(at_zero.verify(&request_target, DpopToken::Refresh, &jkt, 0, None).is_ok());
    assert!(at_zero.verify(&request_target, DpopToken::Refresh, &jkt, 60, None).is_ok());
    assert_eq!(
        at_zero.verify(&request_target, DpopToken::Refresh, &jkt, 61, None),
        Err(DpopError::InvalidProof)
    );
    let near_max = DpopProof::sign(
        &key,
        &key.public_key_sec1(),
        &request_target,
        DpopToken::Refresh,
        u64::MAX - 60,
        None,
    )
    .expect("safe upper edge");
    assert!(near_max.verify(&request_target, DpopToken::Refresh, &jkt, u64::MAX, None).is_ok());
    assert_eq!(
        DpopProof::sign(
            &key,
            &key.public_key_sec1(),
            &request_target,
            DpopToken::Refresh,
            u64::MAX - 59,
            None
        ),
        Err(DpopError::InvalidContext)
    );

    let nonce = "n".repeat(1_024);
    let proof = DpopProof::sign(
        &key,
        &key.public_key_sec1(),
        &request_target,
        DpopToken::Refresh,
        1_000,
        Some(&nonce),
    )
    .expect("max nonce");
    assert!(proof.verify(&request_target, DpopToken::Refresh, &jkt, 1_000, Some(&nonce)).is_ok());
    for invalid in
        ["n".repeat(1_025), "n\"n".to_owned(), "n\\n".to_owned(), "n\nn".to_owned(), String::new()]
    {
        assert_eq!(
            DpopProof::sign(
                &key,
                &key.public_key_sec1(),
                &request_target,
                DpopToken::Refresh,
                1_000,
                Some(&invalid)
            ),
            Err(DpopError::InvalidContext)
        );
    }
    assert_eq!(
        proof.verify(&request_target, DpopToken::Refresh, &jkt, 1_000, Some("n\"n")),
        Err(DpopError::InvalidContext)
    );

    let exact_limit = format!("AA.AA.{}", "A".repeat(8_186));
    assert_eq!(exact_limit.len(), 8_192);
    assert!(DpopProof::parse(&exact_limit).is_ok());
    assert_eq!(DpopProof::parse(&format!("{exact_limit}A")), Err(DpopError::InvalidProof));

    let error = DpopProof::sign(
        &FailingSigner,
        &key.public_key_sec1(),
        &request_target,
        DpopToken::Refresh,
        1_000,
        None,
    )
    .expect_err("fallible signer");
    assert_eq!(error, DpopError::SignerFailed);
    assert!(!format!("{error:?} {error}").contains("private signer diagnostic"));
}

#[test]
fn jwk_and_access_token_hash_reject_wrong_shape() {
    let request_target = target("GET", "/x");
    let jkt = local_jkt();
    let good_header = header();
    let mut good_claims = claims("GET", "/x", 1_000);
    good_claims["ath"] = json!("SKXYSb28tYYi0t2NoU53KmfXCShzWjyxQiYpzcrz9fA");
    let check = |header: &Value, claims: &Value| {
        sign_json(header, claims).verify(
            &request_target,
            DpopToken::Protected("access.jwt"),
            &jkt,
            1_000,
            None,
        )
    };
    for x in [json!("AA"), json!(URL_SAFE_NO_PAD.encode([0_u8; 32])), json!(123)] {
        let mut altered = good_header.clone();
        altered["jwk"]["x"] = x;
        assert_eq!(check(&altered, &good_claims), Err(DpopError::InvalidProof));
    }
    let mut noncurve = good_header.clone();
    noncurve["jwk"]["x"] = json!(URL_SAFE_NO_PAD.encode([0_u8; 32]));
    noncurve["jwk"]["y"] = json!(URL_SAFE_NO_PAD.encode([0_u8; 32]));
    assert_eq!(check(&noncurve, &good_claims), Err(DpopError::InvalidProof));
    for ath in [
        json!(null),
        json!(false),
        json!(123),
        json!("AA"),
        json!("SKXYSb28tYYi0t2NoU53KmfXCShzWjyxQiYpzcrz9fA="),
    ] {
        let mut altered = good_claims.clone();
        altered["ath"] = ath;
        assert_eq!(check(&good_header, &altered), Err(DpopError::InvalidProof));
    }
    let valid = DpopProof::sign(
        &key(),
        &key().public_key_sec1(),
        &request_target,
        DpopToken::Protected("access.jwt"),
        1_000,
        None,
    )
    .expect("real ath");
    assert!(
        valid
            .verify(&request_target, DpopToken::Protected("access.jwt"), &jkt, 1_000, None)
            .is_ok()
    );
}

#[test]
fn es256_accepts_both_signature_s_forms() {
    let request_target = target("GET", "/x");
    let proof = DpopProof::sign(
        &key(),
        &key().public_key_sec1(),
        &request_target,
        DpopToken::Refresh,
        1_000,
        None,
    )
    .expect("proof");
    let parts: Vec<_> = proof.as_str().split('.').collect();
    let mut signature = URL_SAFE_NO_PAD.decode(parts[2]).expect("signature");
    let mut borrow = 0_i16;
    for index in (0..32).rev() {
        let difference = i16::from(P256_ORDER[index]) - i16::from(signature[32 + index]) - borrow;
        signature[32 + index] = u8::try_from(difference.rem_euclid(256)).expect("byte difference");
        borrow = i16::from(difference < 0);
    }
    assert_eq!(borrow, 0);
    let equivalent = DpopProof::parse(&format!(
        "{}.{}.{}",
        parts[0],
        parts[1],
        URL_SAFE_NO_PAD.encode(&signature)
    ))
    .expect("equivalent JWS");
    assert_ne!(proof, equivalent);
    assert!(proof.verify(&request_target, DpopToken::Refresh, &local_jkt(), 1_000, None).is_ok());
    assert!(
        equivalent.verify(&request_target, DpopToken::Refresh, &local_jkt(), 1_000, None).is_ok()
    );
}
