// SPDX-License-Identifier: Apache-2.0
//! Public D-111 JWT evidence, profile separation, and sender-constrained use.

use std::cell::Cell;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use scoplen_crypto::{
    DeviceAccessToken, DeviceAccessTokenClaims, DpopProof, DpopTarget, DpopToken,
    Ed25519SigningKey, OperatorAccessToken, OperatorAccessTokenClaims, OperatorAccessTokenError,
    OperatorAccessTokenSigner, P256SigningKey, TrustedDeviceAccessTokenKeys,
    TrustedOperatorAccessTokenKeys, dpop_jwk_thumbprint,
};
use scoplen_test_vectors::VectorDocument;
use serde_json::{Value, json};
use uuid::Uuid;

const ISSUER: &str = "https://control.example.com";
const IAT: u64 = 1_700_000_000;

fn id(n: u8) -> Uuid {
    Uuid::parse_str(&format!("00000000-0000-7000-8000-{n:012x}")).expect("UUIDv7")
}

fn key() -> Ed25519SigningKey {
    Ed25519SigningKey::from_bytes(&[0x62; 32]).expect("synthetic Operator key")
}

fn browser_key() -> P256SigningKey {
    P256SigningKey::from_bytes(&[0x24; 32]).expect("synthetic browser key")
}

fn claims() -> OperatorAccessTokenClaims {
    OperatorAccessTokenClaims {
        iss: ISSUER.to_owned(),
        sub: id(1),
        sid: id(2),
        jti: id(3),
        cnf_jkt: dpop_jwk_thumbprint(&browser_key().public_key_sec1()).expect("JKT"),
        scope: "personal-invitation:issue".to_owned(),
        iat: IAT,
        exp: IAT + 600,
    }
}

fn trusted() -> TrustedOperatorAccessTokenKeys {
    let mut trusted = TrustedOperatorAccessTokenKeys::new(ISSUER).expect("issuer");
    trusted.insert("operator-1", &key().public_key()).expect("Operator key");
    trusted
}

fn signed() -> OperatorAccessToken {
    OperatorAccessToken::sign(&key(), &trusted(), "operator-1", &claims()).expect("Operator token")
}

fn header() -> Value {
    json!({"alg":"Ed25519","kid":"operator-1","typ":"spl-operator-access+jwt"})
}

fn payload() -> Value {
    let token = signed();
    let payload = token.as_str().split('.').nth(1).expect("payload");
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).expect("base64url")).expect("JSON")
}

fn raw_compact(header: &str, payload: &str) -> String {
    let input = format!("{}.{}", URL_SAFE_NO_PAD.encode(header), URL_SAFE_NO_PAD.encode(payload));
    format!("{input}.{}", URL_SAFE_NO_PAD.encode(key().sign(input.as_bytes())))
}

fn raw(header: &str, payload: &str) -> OperatorAccessToken {
    OperatorAccessToken::parse(&raw_compact(header, payload)).expect("bounded envelope")
}

fn raw_json(header: &Value, payload: &Value) -> OperatorAccessToken {
    raw(&header.to_string(), &payload.to_string())
}

#[test]
fn independent_signed_vectors_and_redacted_stateless_evidence() {
    let document =
        VectorDocument::parse_str(include_str!("../../../vectors/operator-access-token.json"))
            .expect("public vectors independently signed using Node crypto");
    assert_eq!(document.vectors.len(), 6);
    for vector in document.vectors {
        let token = OperatorAccessToken::parse(&vector.input).expect("compact token");
        if vector.kind == "crypto.operator_access_token.valid" {
            assert_eq!(signed().as_str(), token.as_str());
            let verified = token.verify(&trusted(), IAT).expect("signed profile");
            assert_eq!(verified.claims(), &claims());
            assert_eq!(verified.expires_at(), IAT + 600);
            assert_eq!(vector.expected, format!("{}|{}", claims().jti, IAT + 600));
            let diagnostic = format!("{token:?}{verified:?}{:?}{:?}", verified.claims(), trusted());
            for secret in [ISSUER, token.as_str(), &claims().cnf_jkt, &claims().sub.to_string()] {
                assert!(!diagnostic.contains(secret));
            }
        } else {
            assert_eq!(vector.kind, "crypto.operator_access_token.invalid");
            assert_eq!(
                token.verify(&trusted(), IAT).err(),
                Some(OperatorAccessTokenError::InvalidToken),
                "{}",
                vector.id
            );
        }
        let seed = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fuzz/corpus/crypto_decoders")
            .join(&vector.id);
        assert_eq!(std::fs::read_to_string(seed).expect("parser seed"), vector.input);
    }
}

#[test]
fn device_and_operator_tokens_are_separate_even_with_the_same_configured_public_key() {
    let mut device_trust = TrustedDeviceAccessTokenKeys::new(ISSUER).expect("issuer");
    device_trust.insert("operator-1", &key().public_key()).expect("test key");
    assert!(
        DeviceAccessToken::parse(signed().as_str())
            .expect("envelope")
            .verify(&device_trust, IAT)
            .is_err()
    );
    let device_claims = DeviceAccessTokenClaims {
        iss: ISSUER.to_owned(),
        sub: id(1),
        did: id(4),
        jti: id(3),
        cnf_jkt: claims().cnf_jkt,
        org: vec![],
        scope: "personal-invitation:issue".to_owned(),
        iat: IAT,
        exp: IAT + 600,
    };
    let device = DeviceAccessToken::sign(
        &key(),
        &device_trust,
        "operator-1",
        &browser_key().public_key_sec1(),
        &device_claims,
    )
    .expect("device token");
    assert!(
        OperatorAccessToken::parse(device.as_str())
            .expect("envelope")
            .verify(&trusted(), IAT)
            .is_err()
    );
}

#[test]
fn signing_and_verification_use_only_the_configured_operator_keys_and_issuer() {
    let token = signed();
    let mut wrong = TrustedOperatorAccessTokenKeys::new(ISSUER).expect("issuer");
    assert!(token.verify(&wrong, IAT).is_err());
    wrong
        .insert(
            "operator-1",
            &Ed25519SigningKey::from_bytes(&[0x63; 32]).expect("other key").public_key(),
        )
        .expect("key");
    assert!(token.verify(&wrong, IAT).is_err());
    let mut other =
        TrustedOperatorAccessTokenKeys::new("https://other.example.com").expect("issuer");
    other.insert("operator-1", &key().public_key()).expect("key");
    assert!(token.verify(&other, IAT).is_err());
    assert!(OperatorAccessToken::sign(&key(), &other, "operator-1", &claims()).is_err());
    assert!(trusted().insert("operator-1", &key().public_key()).is_err());
    assert!(trusted().insert("other", &[0; 31]).is_err());
    for issuer in [
        "http://control.example.com",
        "https://control.example.com/",
        "https://user@control.example.com",
        "https://control.example.com:443",
    ] {
        assert!(TrustedOperatorAccessTokenKeys::new(issuer).is_err(), "{issuer}");
    }
    for kid in ["", "bad/name", "é", &"a".repeat(129)] {
        assert!(trusted().insert(kid, &key().public_key()).is_err());
        assert!(OperatorAccessToken::sign(&key(), &trusted(), kid, &claims()).is_err());
    }
}

struct BrokenSigner;
impl OperatorAccessTokenSigner for BrokenSigner {
    fn sign(&self, _: &[u8]) -> Result<[u8; 64], OperatorAccessTokenError> {
        Err(OperatorAccessTokenError::SignerFailed)
    }
}
struct WrongSigner;
impl OperatorAccessTokenSigner for WrongSigner {
    fn sign(&self, input: &[u8]) -> Result<[u8; 64], OperatorAccessTokenError> {
        Ok(Ed25519SigningKey::from_bytes(&[0x63; 32]).expect("other key").sign(input))
    }
}
struct CountingSigner(Cell<usize>);
impl OperatorAccessTokenSigner for CountingSigner {
    fn sign(&self, _: &[u8]) -> Result<[u8; 64], OperatorAccessTokenError> {
        self.0.set(self.0.get() + 1);
        Err(OperatorAccessTokenError::SignerFailed)
    }
}

#[test]
fn failed_signers_return_no_token_and_invalid_context_does_not_call_signer() {
    for signer in [&BrokenSigner as &dyn OperatorAccessTokenSigner, &WrongSigner] {
        assert_eq!(
            OperatorAccessToken::sign(signer, &trusted(), "operator-1", &claims()).err(),
            Some(OperatorAccessTokenError::SignerFailed)
        );
    }
    let signer = CountingSigner(Cell::new(0));
    let mut invalid = claims();
    invalid.sid = Uuid::nil();
    assert_eq!(
        OperatorAccessToken::sign(&signer, &trusted(), "operator-1", &invalid).err(),
        Some(OperatorAccessTokenError::InvalidContext)
    );
    assert!(
        OperatorAccessToken::sign(
            &signer,
            &TrustedOperatorAccessTokenKeys::new(ISSUER).expect("issuer"),
            "operator-1",
            &claims()
        )
        .is_err()
    );
    assert_eq!(signer.0.get(), 0);
}

#[test]
fn time_and_scope_validation_preserve_the_exact_signed_profile() {
    let token = signed();
    assert!(token.verify(&trusted(), IAT - 1).is_err());
    assert!(token.verify(&trusted(), IAT + 599).is_ok());
    assert!(token.verify(&trusted(), IAT + 600).is_err());
    for scope in ["", "a  b", "b a", "a a", "a\"b", "a\\b", "é", &"a".repeat(65)] {
        let mut invalid = claims();
        invalid.scope = scope.to_owned();
        assert!(invalid.validate().is_err(), "{scope}");
    }
    let mut invalid = claims();
    invalid.iat = u64::MAX;
    invalid.exp = u64::MAX;
    assert!(invalid.validate().is_err());
    let mut unknown = claims();
    unknown.scope = "future:permission".to_owned();
    let token = OperatorAccessToken::sign(&key(), &trusted(), "operator-1", &unknown)
        .expect("scope syntax");
    assert_eq!(
        token.verify(&trusted(), IAT).expect("syntax only").claims().scope,
        "future:permission"
    );
}

#[test]
fn protected_headers_claim_types_and_prohibited_device_fields_are_rejected() {
    for (field, value) in [
        ("alg", json!("EdDSA")),
        ("alg", json!("none")),
        ("typ", json!("JWT")),
        ("typ", json!("spl-device-access+jwt")),
        ("kid", json!("unknown")),
    ] {
        let mut changed = header();
        changed[field] = value;
        assert!(raw_json(&changed, &payload()).verify(&trusted(), IAT).is_err(), "{field}");
    }
    for field in ["jwk", "jku", "x5u", "x5c", "crit", "b64", "cty", "extra"] {
        let mut changed = header();
        changed[field] = Value::Null;
        assert!(raw_json(&changed, &payload()).verify(&trusted(), IAT).is_err(), "{field}");
    }
    for (field, value) in [
        ("aud", json!(["spl-admin/1"])),
        ("aud", json!("spl-api/1")),
        ("iss", json!("https://other.example.com")),
        ("sub", json!("invalid")),
        ("sid", json!("00000000-0000-4000-8000-000000000002")),
        ("jti", json!("00000000-0000-7000-8000-00000000000A")),
        ("cnf", json!({"jkt":"bad"})),
        ("cnf", json!({"jkt":claims().cnf_jkt,"x":null})),
        ("scope", json!("b a")),
        ("iat", json!(-1)),
        ("exp", json!(IAT + 601)),
        ("did", Value::Null),
        ("org", Value::Null),
    ] {
        let mut changed = payload();
        changed[field] = value;
        assert!(raw_json(&header(), &changed).verify(&trusted(), IAT).is_err(), "{field}");
    }
    for field in ["iss", "aud", "sub", "sid", "jti", "cnf", "scope", "iat", "exp"] {
        let mut changed = payload();
        changed.as_object_mut().expect("object").remove(field);
        assert!(raw_json(&header(), &changed).verify(&trusted(), IAT).is_err(), "{field}");
    }
}

#[test]
fn original_signing_bytes_and_recursive_unique_names_are_enforced() {
    let h = format!("\n {} \t", header());
    let mut extended = payload();
    extended["extension"] = json!({"nested":[{"ok":true}]});
    let p = format!("\n {extended} \t");
    assert_eq!(
        raw(&h, &p).verify(&trusted(), IAT).expect("original whitespace").claims(),
        &claims()
    );
    let duplicate_header = h.replace("\"alg\":", "\"alg\":\"Ed25519\",\"alg\":");
    assert_ne!(h, duplicate_header);
    let duplicate_claim = p.replace("\"sid\":", "\"sid\":null,\"sid\":");
    let duplicate_binding = p.replace("\"jkt\":", "\"jkt\":null,\"jkt\":");
    let duplicate_extension = p.replace("\"ok\":true", "\"ok\":true,\"ok\":false");
    assert!(raw(&duplicate_header, &p).verify(&trusted(), IAT).is_err());
    for duplicate in [duplicate_claim, duplicate_binding, duplicate_extension] {
        assert_ne!(p, duplicate);
        assert!(raw(&h, &duplicate).verify(&trusted(), IAT).is_err());
    }
    let mut parts: Vec<_> = signed().as_str().split('.').map(str::to_owned).collect();
    let mut signature = URL_SAFE_NO_PAD.decode(&parts[2]).expect("signature");
    signature[0] ^= 1;
    parts[2] = URL_SAFE_NO_PAD.encode(signature);
    assert!(
        OperatorAccessToken::parse(&parts.join("."))
            .expect("envelope")
            .verify(&trusted(), IAT)
            .is_err()
    );
    for malformed in [
        String::new(),
        "a.b.c.d".to_owned(),
        "a".repeat(4097),
        format!("{}=", signed().as_str()),
        "é.e.e".to_owned(),
        "e30.e30.AA".to_owned(),
    ] {
        assert!(OperatorAccessToken::parse(&malformed).is_err());
    }
}

#[test]
fn complete_token_limit_includes_ignored_extensions() {
    let mut at_limit = None;
    let mut over_limit = None;
    let base = payload();
    'search: for header_padding in 0..3 {
        let h = format!("{}{}", header(), " ".repeat(header_padding));
        for padding in 0..4096 {
            let mut p = base.clone();
            p["x_padding"] = json!("a".repeat(padding));
            let p = p.to_string();
            let length =
                URL_SAFE_NO_PAD.encode(&h).len() + 1 + URL_SAFE_NO_PAD.encode(&p).len() + 87;
            if length == 4096 {
                at_limit = Some(raw_compact(&h, &p));
            } else if length == 4097 {
                over_limit = Some(raw_compact(&h, &p));
            }
            if at_limit.is_some() && over_limit.is_some() {
                break 'search;
            }
        }
    }
    assert!(
        OperatorAccessToken::parse(&at_limit.expect("exact bound"))
            .expect("bounded")
            .verify(&trusted(), IAT)
            .is_ok()
    );
    assert!(OperatorAccessToken::parse(&over_limit.expect("one over bound")).is_err());
}

#[test]
fn operator_token_dpop_binds_exact_invitation_request_key_and_token_hash() {
    let token = signed();
    let verified = token.verify(&trusted(), IAT).expect("Operator evidence");
    let target =
        DpopTarget::new("POST", ISSUER, "/api/v1/admin/personal-invitations").expect("target");
    let browser = browser_key();
    let proof = DpopProof::sign(
        &browser,
        &browser.public_key_sec1(),
        &target,
        DpopToken::Protected(token.as_str()),
        IAT,
        None,
    )
    .expect("proof");
    assert!(
        proof
            .verify(
                &target,
                DpopToken::Protected(token.as_str()),
                &verified.claims().cnf_jkt,
                IAT,
                None
            )
            .is_ok()
    );
    let wrong =
        DpopTarget::new("POST", ISSUER, "/api/v1/auth/operator/setup/finish").expect("target");
    assert!(
        proof
            .verify(
                &wrong,
                DpopToken::Protected(token.as_str()),
                &verified.claims().cnf_jkt,
                IAT,
                None
            )
            .is_err()
    );
    assert!(
        proof
            .verify(
                &target,
                DpopToken::Protected("other.jwt"),
                &verified.claims().cnf_jkt,
                IAT,
                None
            )
            .is_err()
    );
    assert!(
        proof
            .verify(
                &target,
                DpopToken::Protected(token.as_str()),
                &URL_SAFE_NO_PAD.encode([7; 32]),
                IAT,
                None
            )
            .is_err()
    );
}
