// SPDX-License-Identifier: Apache-2.0
//! Public enrolled-device access-token contract and failure boundaries.

use std::cell::Cell;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use scoplen_crypto::{
    DeviceAccessToken, DeviceAccessTokenClaims, DeviceAccessTokenError, DeviceAccessTokenSigner,
    DeviceOrganizationSnapshot, Ed25519SigningKey, P256SigningKey, TrustedDeviceAccessTokenKeys,
    dpop_jwk_thumbprint,
};
use scoplen_test_vectors::VectorDocument;
use serde_json::{Value, json};
use uuid::Uuid;

const ISSUER: &str = "https://control.example.com";
const IAT: u64 = 1_700_000_000;

fn id(suffix: u8) -> Uuid {
    Uuid::parse_str(&format!("00000000-0000-7000-8000-{suffix:012x}")).expect("UUIDv7")
}

fn key() -> Ed25519SigningKey {
    Ed25519SigningKey::from_bytes(&[0x42; 32]).expect("fixed synthetic key")
}

fn device_key() -> P256SigningKey {
    P256SigningKey::from_bytes(&[0x24; 32]).expect("fixed synthetic device key")
}

fn claims() -> DeviceAccessTokenClaims {
    DeviceAccessTokenClaims {
        iss: ISSUER.to_owned(),
        sub: id(1),
        did: id(2),
        jti: id(3),
        cnf_jkt: dpop_jwk_thumbprint(&device_key().public_key_sec1()).expect("thumbprint"),
        org: vec![
            DeviceOrganizationSnapshot { id: id(4), sso_authenticated_at: None },
            DeviceOrganizationSnapshot { id: id(5), sso_authenticated_at: Some(IAT) },
        ],
        scope: "hosts:read sessions:write".to_owned(),
        iat: IAT,
        exp: IAT + 600,
    }
}

fn trusted() -> TrustedDeviceAccessTokenKeys {
    let mut keys = TrustedDeviceAccessTokenKeys::new(ISSUER).expect("trusted origin");
    keys.insert("access-1", &key().public_key()).expect("trusted public key");
    keys
}

fn signed() -> DeviceAccessToken {
    DeviceAccessToken::sign(
        &key(),
        &trusted(),
        "access-1",
        &device_key().public_key_sec1(),
        &claims(),
    )
    .expect("signed device access token")
}

fn signed_compact(header: &str, payload: &str) -> String {
    let input = format!("{}.{}", URL_SAFE_NO_PAD.encode(header), URL_SAFE_NO_PAD.encode(payload));
    format!("{input}.{}", URL_SAFE_NO_PAD.encode(key().sign(input.as_bytes())))
}

fn raw(header: &str, payload: &str) -> DeviceAccessToken {
    DeviceAccessToken::parse(&signed_compact(header, payload)).expect("bounded envelope")
}

fn header() -> Value {
    json!({"alg":"Ed25519", "kid":"access-1", "typ":"spl-device-access+jwt"})
}

fn payload() -> Value {
    let token = signed();
    let encoded = token.as_str().split('.').nth(1).expect("payload segment");
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(encoded).expect("payload bytes"))
        .expect("payload JSON")
}

fn raw_json(header: &Value, payload: &Value) -> DeviceAccessToken {
    raw(&header.to_string(), &payload.to_string())
}

#[test]
fn exact_signed_vector_and_stateless_evidence() {
    let document =
        VectorDocument::parse_str(include_str!("../../../vectors/device-access-token.json"))
            .expect("portable vector document");
    let vector = document
        .vectors
        .iter()
        .find(|v| v.kind == "crypto.device_access_token.valid")
        .expect("signed vector");
    let token = signed();
    assert_eq!(token.as_str(), vector.input);
    let verified = token.verify(&trusted(), IAT).expect("valid signature and claims");
    assert_eq!(verified.claims(), &claims());
    assert_eq!(verified.expires_at(), IAT + 600);
    assert_eq!(vector.expected, format!("{}|{}", claims().jti, IAT + 600));
    for negative in
        document.vectors.iter().filter(|v| v.kind == "crypto.device_access_token.invalid")
    {
        assert_eq!(negative.expected, "invalid");
        let expected = match negative.id.as_str() {
            "device-access-token-wrong-purpose-v1" => {
                let mut h = header();
                h["typ"] = json!("spl-gw-ticket+jwt");
                signed_compact(&h.to_string(), &payload().to_string())
            }
            "device-access-token-wrong-audience-v1" => {
                let mut p = payload();
                p["aud"] = json!("spl-gw/1");
                signed_compact(&header().to_string(), &p.to_string())
            }
            _ => panic!("unknown negative vector"),
        };
        assert_eq!(negative.input, expected, "{}", negative.id);
        assert_eq!(
            DeviceAccessToken::parse(&negative.input)
                .expect("signed envelope")
                .verify(&trusted(), IAT)
                .err(),
            Some(DeviceAccessTokenError::InvalidToken),
            "{}",
            negative.id
        );
    }
    assert!(
        !format!("{token:?}{verified:?}{:?}{:?}", verified.claims(), trusted()).contains(ISSUER)
    );
}

#[test]
fn signing_context_and_key_isolation_are_strict() {
    let token = signed();
    let mut wrong = TrustedDeviceAccessTokenKeys::new(ISSUER).expect("issuer");
    assert_eq!(token.verify(&wrong, IAT).err(), Some(DeviceAccessTokenError::InvalidToken));
    wrong
        .insert("access-1", &Ed25519SigningKey::from_bytes(&[0x43; 32]).expect("key").public_key())
        .expect("other key");
    assert_eq!(token.verify(&wrong, IAT).err(), Some(DeviceAccessTokenError::InvalidToken));
    let mut wrong_issuer =
        TrustedDeviceAccessTokenKeys::new("https://other.example.com").expect("issuer");
    wrong_issuer.insert("access-1", &key().public_key()).expect("key");
    assert_eq!(token.verify(&wrong_issuer, IAT).err(), Some(DeviceAccessTokenError::InvalidToken));
    assert!(TrustedDeviceAccessTokenKeys::new("http://control.example.com").is_err());
    assert!(trusted().insert("access-1", &key().public_key()).is_err());

    let mut wrong_binding = claims();
    wrong_binding.cnf_jkt = URL_SAFE_NO_PAD.encode([7; 32]);
    assert_eq!(
        DeviceAccessToken::sign(
            &key(),
            &trusted(),
            "access-1",
            &device_key().public_key_sec1(),
            &wrong_binding
        )
        .err(),
        Some(DeviceAccessTokenError::InvalidContext)
    );
    for kid in ["", "bad/name", "é", "x".repeat(129).as_str()] {
        assert_eq!(
            DeviceAccessToken::sign(
                &key(),
                &trusted(),
                kid,
                &device_key().public_key_sec1(),
                &claims()
            )
            .err(),
            Some(DeviceAccessTokenError::InvalidContext)
        );
    }
}

struct BrokenSigner;
impl DeviceAccessTokenSigner for BrokenSigner {
    fn sign(&self, _: &[u8]) -> Result<[u8; 64], DeviceAccessTokenError> {
        Err(DeviceAccessTokenError::SignerFailed)
    }
}
struct WrongSigner;
impl DeviceAccessTokenSigner for WrongSigner {
    fn sign(&self, input: &[u8]) -> Result<[u8; 64], DeviceAccessTokenError> {
        Ok(Ed25519SigningKey::from_bytes(&[0x43; 32]).expect("other key").sign(input))
    }
}
struct CountingSigner(Cell<usize>);
impl DeviceAccessTokenSigner for CountingSigner {
    fn sign(&self, _: &[u8]) -> Result<[u8; 64], DeviceAccessTokenError> {
        self.0.set(self.0.get() + 1);
        Err(DeviceAccessTokenError::SignerFailed)
    }
}

#[test]
fn signer_failure_and_oversized_snapshot_fail_before_output() {
    for signer in [&BrokenSigner as &dyn DeviceAccessTokenSigner, &WrongSigner] {
        assert_eq!(
            DeviceAccessToken::sign(
                signer,
                &trusted(),
                "access-1",
                &device_key().public_key_sec1(),
                &claims()
            )
            .err(),
            Some(DeviceAccessTokenError::SignerFailed)
        );
    }
    let signer = CountingSigner(Cell::new(0));
    let mut oversized = claims();
    oversized.org = (4..100)
        .map(|n| DeviceOrganizationSnapshot { id: id(n), sso_authenticated_at: None })
        .collect();
    assert_eq!(
        DeviceAccessToken::sign(
            &signer,
            &trusted(),
            "access-1",
            &device_key().public_key_sec1(),
            &oversized
        )
        .err(),
        Some(DeviceAccessTokenError::InvalidContext)
    );
    assert_eq!(signer.0.get(), 0);
    let empty = TrustedDeviceAccessTokenKeys::new(ISSUER).expect("issuer");
    assert_eq!(
        DeviceAccessToken::sign(
            &signer,
            &empty,
            "access-1",
            &device_key().public_key_sec1(),
            &claims()
        )
        .err(),
        Some(DeviceAccessTokenError::InvalidContext)
    );
    assert_eq!(signer.0.get(), 0);
}

#[test]
fn time_scope_and_membership_are_exact() {
    let token = signed();
    assert_eq!(token.verify(&trusted(), IAT - 1).err(), Some(DeviceAccessTokenError::InvalidToken));
    assert!(token.verify(&trusted(), IAT + 599).is_ok());
    assert_eq!(
        token.verify(&trusted(), IAT + 600).err(),
        Some(DeviceAccessTokenError::InvalidToken)
    );
    let mut invalid = claims();
    for scope in ["", "a  b", "b a", "a a", "a\"b", "a\\b", "é", "a".repeat(65).as_str()] {
        invalid.scope = scope.to_owned();
        assert_eq!(invalid.validate(), Err(DeviceAccessTokenError::InvalidContext));
    }
    invalid = claims();
    invalid.org.reverse();
    assert_eq!(invalid.validate(), Err(DeviceAccessTokenError::InvalidContext));
    invalid = claims();
    invalid.org[1].id = invalid.org[0].id;
    assert_eq!(invalid.validate(), Err(DeviceAccessTokenError::InvalidContext));
    invalid = claims();
    invalid.org[0].sso_authenticated_at = Some(IAT + 1);
    assert_eq!(invalid.validate(), Err(DeviceAccessTokenError::InvalidContext));
    invalid = claims();
    invalid.exp += 1;
    assert_eq!(invalid.validate(), Err(DeviceAccessTokenError::InvalidContext));
    invalid = claims();
    invalid.iat = u64::MAX;
    invalid.exp = u64::MAX;
    assert_eq!(invalid.validate(), Err(DeviceAccessTokenError::InvalidContext));
    invalid = claims();
    invalid.org.clear();
    assert!(invalid.validate().is_ok());
}

#[test]
fn signed_header_and_claim_substitutions_fail() {
    for (name, replacement) in [
        ("alg", json!("EdDSA")),
        ("alg", json!("none")),
        ("typ", json!("JWT")),
        ("typ", json!("spl-gw-ticket+jwt")),
        ("kid", json!("unknown")),
    ] {
        let mut h = header();
        h[name] = replacement;
        assert_eq!(
            raw_json(&h, &payload()).verify(&trusted(), IAT).err(),
            Some(DeviceAccessTokenError::InvalidToken)
        );
    }
    for prohibited in ["jwk", "jku", "x5u", "x5c", "crit", "b64", "cty", "extra"] {
        let mut h = header();
        h[prohibited] = Value::Null;
        assert_eq!(
            raw_json(&h, &payload()).verify(&trusted(), IAT).err(),
            Some(DeviceAccessTokenError::InvalidToken)
        );
    }
    for (name, replacement) in [
        ("aud", json!(["spl-api/1"])),
        ("aud", json!("spl-gw/1")),
        ("iss", json!("https://other.example.com")),
        ("sub", json!("invalid")),
        ("did", json!("00000000-0000-4000-8000-000000000001")),
        ("jti", json!("00000000-0000-7000-8000-00000000000A")),
        ("cnf", json!({"jkt":"bad"})),
        ("cnf", json!({"jkt":claims().cnf_jkt,"x":null})),
        ("org", json!([{"id":id(4).to_string(),"sso_authenticated_at":null,"x":null}])),
        (
            "org",
            json!([{"id":id(5).to_string(),"sso_authenticated_at":null},{"id":id(4).to_string(),"sso_authenticated_at":null}]),
        ),
        ("scope", json!("sessions:write hosts:read")),
        ("iat", json!(-1)),
        ("exp", json!(IAT + 601)),
    ] {
        let mut p = payload();
        p[name] = replacement;
        assert_eq!(
            raw_json(&header(), &p).verify(&trusted(), IAT).err(),
            Some(DeviceAccessTokenError::InvalidToken),
            "{name}"
        );
    }
}

#[test]
fn duplicate_json_and_envelope_fail_but_payload_extensions_are_ignored() {
    let base = payload();
    let duplicate_header =
        r#"{"alg":"Ed25519","alg":"Ed25519","kid":"access-1","typ":"spl-device-access+jwt"}"#;
    assert_eq!(
        raw(duplicate_header, &base.to_string()).verify(&trusted(), IAT).err(),
        Some(DeviceAccessTokenError::InvalidToken)
    );
    let serialized = base.to_string();
    let nested = serialized.replace("\"jkt\":", "\"jkt\":\"x\",\"jkt\":");
    assert_ne!(nested, serialized);
    assert_eq!(
        raw(&header().to_string(), &nested).verify(&trusted(), IAT).err(),
        Some(DeviceAccessTokenError::InvalidToken)
    );
    let mut extended = base;
    extended["extension"] = json!({"nested": [1, {"ok":true}]});
    assert_eq!(
        raw_json(&header(), &extended).verify(&trusted(), IAT).expect("extension").claims(),
        &claims()
    );
    let duplicate_extension =
        extended.to_string().replace("\"ok\":true", "\"ok\":true,\"ok\":false");
    assert_eq!(
        raw(&header().to_string(), &duplicate_extension).verify(&trusted(), IAT).err(),
        Some(DeviceAccessTokenError::InvalidToken)
    );

    let segments: Vec<_> = signed().as_str().split('.').map(str::to_owned).collect();
    for candidate in [
        String::new(),
        "a.b.c.d".to_owned(),
        "a".repeat(4097),
        format!("{}.{}.{}=", segments[0], segments[1], segments[2]),
        format!("{}.{}.{}", segments[0], segments[1], "A"),
        format!("{}.{}.{}", segments[0], segments[1], "é"),
    ] {
        assert_eq!(
            DeviceAccessToken::parse(&candidate).err(),
            Some(DeviceAccessTokenError::InvalidToken)
        );
    }
}

#[test]
fn exact_complete_token_size_boundary() {
    let mut at_limit = None;
    let mut over_limit = None;
    let header = header().to_string();
    let base = payload();
    for payload_padding in 0..4_096 {
        let mut p = base.clone();
        p["x_padding"] = json!("a".repeat(payload_padding));
        let payload = p.to_string();
        let length =
            URL_SAFE_NO_PAD.encode(&header).len() + 1 + URL_SAFE_NO_PAD.encode(&payload).len() + 87;
        if length == 4_096 {
            at_limit = Some(signed_compact(&header, &payload));
        } else if length == 4_097 {
            over_limit = Some(signed_compact(&header, &payload));
        }
        if at_limit.is_some() && over_limit.is_some() {
            break;
        }
    }
    let accepted = at_limit.expect("exact 4,096-byte JWS");
    assert!(
        DeviceAccessToken::parse(&accepted).expect("bounded token").verify(&trusted(), IAT).is_ok()
    );
    assert_eq!(
        DeviceAccessToken::parse(&over_limit.expect("4,097-byte JWS")).err(),
        Some(DeviceAccessTokenError::InvalidToken)
    );
}
