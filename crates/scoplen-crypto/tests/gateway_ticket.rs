// SPDX-License-Identifier: Apache-2.0
//! Public K-6 signed gateway ticket contract and negative boundaries.

use std::cell::Cell;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use scoplen_crypto::{
    Ed25519SigningKey, GatewayTicket, GatewayTicketClaims, GatewayTicketError, GatewayTicketSigner,
    TrustedGatewayTicketKeys, gateway_ssh_key_sha256,
};
use scoplen_test_vectors::VectorDocument;
use serde_json::{Value, json};
use uuid::Uuid;

const ISSUER: &str = "https://control.example.com";
const IAT: u64 = 1_700_000_000;

fn id(suffix: u8) -> Uuid {
    Uuid::parse_str(&format!("00000000-0000-7000-8000-{suffix:012x}"))
        .expect("canonical test UUIDv7")
}

fn key() -> Ed25519SigningKey {
    Ed25519SigningKey::from_bytes(&[0x42; 32]).expect("fixed synthetic signer")
}

fn claims() -> GatewayTicketClaims {
    GatewayTicketClaims {
        iss: ISSUER.to_owned(),
        jti: id(1),
        sub: id(2),
        did: id(3),
        org: id(4),
        host: id(5),
        gateway_network: id(6),
        remote_user: "deploy-α".to_owned(),
        ssh_key_sha256: gateway_ssh_key_sha256(b"validated raw SSH key blob"),
        cnf_jkt: URL_SAFE_NO_PAD.encode([7; 32]),
        iat: IAT,
        exp: IAT + 60,
    }
}

fn trusted() -> TrustedGatewayTicketKeys {
    let mut trusted = TrustedGatewayTicketKeys::new(ISSUER).expect("trusted issuer");
    trusted.insert("ticket-1", &key().public_key()).expect("ticket key");
    trusted
}

fn signed() -> GatewayTicket {
    GatewayTicket::sign(&key(), &key().public_key(), "ticket-1", &claims()).expect("ticket")
}

fn raw(header: &str, payload: &str, signer: &Ed25519SigningKey) -> GatewayTicket {
    GatewayTicket::parse(&signed_compact(header, payload, signer)).expect("structurally sound JWS")
}

fn signed_compact(header: &str, payload: &str, signer: &Ed25519SigningKey) -> String {
    let input = format!("{}.{}", URL_SAFE_NO_PAD.encode(header), URL_SAFE_NO_PAD.encode(payload));
    let signature = signer.sign(input.as_bytes());
    format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature))
}

fn raw_json(header: &Value, payload: &Value) -> GatewayTicket {
    raw(&header.to_string(), &payload.to_string(), &key())
}

fn header() -> Value {
    json!({"alg":"Ed25519", "kid":"ticket-1", "typ":"spl-gw-ticket+jwt"})
}

fn payload() -> Value {
    let signed = signed();
    let segment = signed.as_str().split('.').nth(1).expect("payload segment");
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(segment).expect("payload bytes"))
        .expect("payload JSON")
}

#[test]
fn exact_signed_vector_and_stateless_evidence() {
    let document =
        VectorDocument::parse_str(include_str!("../../../vectors/gateway-signed-ticket.json"))
            .expect("portable vectors");
    let vector = document
        .vectors
        .iter()
        .find(|v| v.kind == "crypto.gateway.ticket.valid")
        .expect("signed ticket vector");
    let ticket = signed();
    assert_eq!(ticket.as_str(), vector.input);
    let verified = ticket.verify(&trusted(), IAT).expect("valid ticket");
    assert_eq!(verified.claims(), &claims());
    assert_eq!(verified.expires_at(), IAT + 60);
    assert_eq!(vector.expected, format!("{}|{}", verified.claims().jti, verified.expires_at()));
    assert!(format!("{ticket:?}").contains("REDACTED"));
    assert!(format!("{verified:?}").contains("REPLAY NOT CLAIMED"));
    assert!(!format!("{:?}", verified.claims()).contains("deploy"));
    assert!(!format!("{:?}", trusted()).contains(ISSUER));
}

#[test]
fn exact_lifetime_and_claim_context_are_enforced() {
    let ticket = signed();
    assert_eq!(ticket.verify(&trusted(), IAT - 1).err(), Some(GatewayTicketError::InvalidTicket));
    assert!(ticket.verify(&trusted(), IAT + 59).is_ok());
    assert_eq!(ticket.verify(&trusted(), IAT + 60).err(), Some(GatewayTicketError::InvalidTicket));

    let mut value = claims();
    for mutate in [("origin", "https://control.example.com/"), ("username", "bad\u{0000}user")] {
        let mut candidate = value.clone();
        if mutate.0 == "origin" {
            candidate.iss = mutate.1.to_owned();
        } else {
            candidate.remote_user = mutate.1.to_owned();
        }
        assert_eq!(candidate.validate(), Err(GatewayTicketError::InvalidContext));
    }
    value.jti = Uuid::nil();
    assert_eq!(value.validate(), Err(GatewayTicketError::InvalidContext));
    let mut value = claims();
    value.exp += 1;
    assert_eq!(value.validate(), Err(GatewayTicketError::InvalidContext));
    let mut value = claims();
    value.iat = u64::MAX;
    value.exp = u64::MAX;
    assert_eq!(value.validate(), Err(GatewayTicketError::InvalidContext));
    let mut value = claims();
    value.cnf_jkt = "not-a-thumbprint".to_owned();
    assert_eq!(value.validate(), Err(GatewayTicketError::InvalidContext));
    let mut value = claims();
    value.ssh_key_sha256.push('=');
    assert_eq!(value.validate(), Err(GatewayTicketError::InvalidContext));
    let mut value = claims();
    value.remote_user = "α".repeat(128);
    assert_eq!(value.validate(), Err(GatewayTicketError::InvalidContext));
}

struct BrokenSigner;

impl GatewayTicketSigner for BrokenSigner {
    fn sign(&self, _: &[u8]) -> Result<[u8; 64], GatewayTicketError> {
        Err(GatewayTicketError::SignerFailed)
    }
}

struct WrongSigner;

impl GatewayTicketSigner for WrongSigner {
    fn sign(&self, message: &[u8]) -> Result<[u8; 64], GatewayTicketError> {
        Ok(Ed25519SigningKey::from_bytes(&[0x24; 32]).expect("other key").sign(message))
    }
}

struct CountingSigner(Cell<usize>);

impl GatewayTicketSigner for CountingSigner {
    fn sign(&self, _: &[u8]) -> Result<[u8; 64], GatewayTicketError> {
        self.0.set(self.0.get() + 1);
        Err(GatewayTicketError::SignerFailed)
    }
}

#[test]
fn signer_failure_wrong_output_and_kid_are_rejected() {
    for signer in [&BrokenSigner as &dyn GatewayTicketSigner, &WrongSigner] {
        assert_eq!(
            GatewayTicket::sign(signer, &key().public_key(), "ticket-1", &claims()).err(),
            Some(GatewayTicketError::SignerFailed)
        );
    }
    for kid in ["", "bad/name", "é", "x".repeat(129).as_str()] {
        assert_eq!(
            GatewayTicket::sign(&key(), &key().public_key(), kid, &claims()).err(),
            Some(GatewayTicketError::InvalidContext)
        );
    }
    assert_eq!(
        GatewayTicket::sign(&key(), &[0; 31], "ticket-1", &claims()).err(),
        Some(GatewayTicketError::InvalidContext)
    );
}

#[test]
fn trusted_issuer_key_and_algorithm_are_pinned() {
    let ticket = signed();
    let mut other_issuer =
        TrustedGatewayTicketKeys::new("https://other.example.com").expect("origin");
    other_issuer.insert("ticket-1", &key().public_key()).expect("key");
    assert_eq!(ticket.verify(&other_issuer, IAT).err(), Some(GatewayTicketError::InvalidTicket));
    let mut wrong_key = TrustedGatewayTicketKeys::new(ISSUER).expect("origin");
    wrong_key
        .insert("ticket-1", &Ed25519SigningKey::from_bytes(&[0x24; 32]).expect("key").public_key())
        .expect("key");
    assert_eq!(ticket.verify(&wrong_key, IAT).err(), Some(GatewayTicketError::InvalidTicket));
    assert_eq!(
        ticket.verify(&TrustedGatewayTicketKeys::new(ISSUER).expect("origin"), IAT).err(),
        Some(GatewayTicketError::InvalidTicket)
    );
    assert_eq!(
        TrustedGatewayTicketKeys::new("http://control.example.com").err(),
        Some(GatewayTicketError::InvalidContext)
    );
    let mut keys = trusted();
    assert_eq!(
        keys.insert("ticket-1", &key().public_key()),
        Err(GatewayTicketError::InvalidContext)
    );
    assert_eq!(
        keys.insert("bad/name", &key().public_key()),
        Err(GatewayTicketError::InvalidContext)
    );

    for alg in ["EdDSA", "ES256", "none"] {
        let mut h = header();
        h["alg"] = json!(alg);
        assert_eq!(
            raw_json(&h, &payload()).verify(&trusted(), IAT).err(),
            Some(GatewayTicketError::InvalidTicket)
        );
    }
    let mut h = header();
    h["typ"] = json!("JWT");
    assert_eq!(
        raw_json(&h, &payload()).verify(&trusted(), IAT).err(),
        Some(GatewayTicketError::InvalidTicket)
    );
    let mut h = header();
    h["kid"] = json!("other");
    assert_eq!(
        raw_json(&h, &payload()).verify(&trusted(), IAT).err(),
        Some(GatewayTicketError::InvalidTicket)
    );
    for prohibited in ["jwk", "jku", "x5u", "x5c", "crit", "b64"] {
        let mut h = header();
        h[prohibited] = Value::Null;
        assert_eq!(
            raw_json(&h, &payload()).verify(&trusted(), IAT).err(),
            Some(GatewayTicketError::InvalidTicket),
            "{prohibited}"
        );
    }
}

#[test]
fn claim_substitutions_and_nested_duplicates_fail() {
    let base = payload();
    for (name, replacement) in [
        ("aud", json!(["spl-gw/1"])),
        ("iss", json!("https://other.example.com")),
        ("jti", json!("00000000-0000-7000-8000-00000000000A")),
        ("sub", Value::Null),
        ("did", json!("00000000-0000-4000-8000-000000000003")),
        ("org", json!("invalid")),
        ("host", json!("invalid")),
        ("gateway_network", json!("invalid")),
        ("remote_user", json!("bad\nuser")),
        ("ssh_key_sha256", json!("bad")),
        ("cnf", json!({"jkt":"bad"})),
        ("iat", json!(-1)),
        ("exp", json!(IAT + 61)),
    ] {
        let mut modified = base.clone();
        modified[name] = replacement;
        assert_eq!(
            raw_json(&header(), &modified).verify(&trusted(), IAT).err(),
            Some(GatewayTicketError::InvalidTicket),
            "{name}"
        );
    }
    let mut modified = base.clone();
    modified["aud"] = json!("other");
    assert_eq!(
        raw_json(&header(), &modified).verify(&trusted(), IAT).err(),
        Some(GatewayTicketError::InvalidTicket)
    );
    let h = r#"{"alg":"Ed25519","alg":"Ed25519","kid":"ticket-1","typ":"spl-gw-ticket+jwt"}"#;
    assert_eq!(
        raw(h, &base.to_string(), &key()).verify(&trusted(), IAT).err(),
        Some(GatewayTicketError::InvalidTicket)
    );
    let duplicate_cnf = base.to_string().replace(
        &format!("\"jkt\":\"{}\"", claims().cnf_jkt),
        &format!("\"jkt\":\"{}\",\"jkt\":\"{}\"", claims().cnf_jkt, claims().cnf_jkt),
    );
    assert_eq!(
        raw(&header().to_string(), &duplicate_cnf, &key()).verify(&trusted(), IAT).err(),
        Some(GatewayTicketError::InvalidTicket)
    );
}

#[test]
fn allowed_extensions_and_original_json_serialization_verify() {
    let header = r#"{ "typ": "spl-gw-ticket+jwt", "x_header": {"ok": true}, "kid":"ticket-1", "alg":"Ed25519" }"#;
    let mut base = payload();
    base["cnf"]["x_cnf"] = json!({"nested": [1, 2]});
    base["x_claim"] = json!({"nested": {"ok": true}});
    let serialized = base.to_string();
    let payload = format!("{{ \"x_first\": true, {} }}", &serialized[1..serialized.len() - 1]);
    let ticket = raw(header, &payload, &key());
    assert_eq!(ticket.verify(&trusted(), IAT).expect("signed extensions").claims(), &claims());

    let duplicate = serialized.replace(
        "\"x_claim\":{\"nested\":{\"ok\":true}}",
        "\"x_claim\":{\"nested\":{\"ok\":true,\"ok\":false}}",
    );
    assert_ne!(duplicate, serialized, "nested extension fixture must change");
    assert_eq!(
        raw(header, &duplicate, &key()).verify(&trusted(), IAT).err(),
        Some(GatewayTicketError::InvalidTicket)
    );
}

#[test]
fn exact_ticket_length_boundary_and_pre_sign_rejection() {
    let mut headers = vec![header().to_string()];
    for length in 0..3 {
        let mut candidate = header();
        candidate["x_padding"] = json!("b".repeat(length));
        headers.push(candidate.to_string());
    }
    let base = payload();
    let mut at_limit = None;
    let mut over_limit = None;
    for header in headers {
        for padding in 0..4_096 {
            let mut payload = base.clone();
            payload["x_padding"] = json!("a".repeat(padding));
            let payload = payload.to_string();
            let len = URL_SAFE_NO_PAD.encode(&header).len()
                + 1
                + URL_SAFE_NO_PAD.encode(&payload).len()
                + 1
                + 86;
            if len == 4_096 {
                at_limit = Some((header.clone(), payload));
            } else if len == 4_097 {
                over_limit = Some((header.clone(), payload));
            }
            if at_limit.is_some() && over_limit.is_some() {
                break;
            }
        }
        if at_limit.is_some() && over_limit.is_some() {
            break;
        }
    }
    let (header, payload) = at_limit.expect("4,096-byte ticket");
    let ticket = raw(&header, &payload, &key());
    assert_eq!(ticket.as_str().len(), 4_096);
    assert!(ticket.verify(&trusted(), IAT).is_ok());
    let (header, payload) = over_limit.expect("4,097-byte ticket");
    let oversized = signed_compact(&header, &payload, &key());
    assert_eq!(oversized.len(), 4_097);
    assert_eq!(GatewayTicket::parse(&oversized).err(), Some(GatewayTicketError::InvalidTicket));

    let signer = CountingSigner(Cell::new(0));
    let mut invalid = claims();
    invalid.remote_user = "a".repeat(256);
    assert_eq!(
        GatewayTicket::sign(&signer, &key().public_key(), "ticket-1", &invalid).err(),
        Some(GatewayTicketError::InvalidContext)
    );
    assert_eq!(signer.0.get(), 0);
}

#[test]
fn envelope_bounds_canonical_segments_and_redaction() {
    let signed = signed();
    let segments: Vec<_> = signed.as_str().split('.').collect();
    for candidate in [
        String::new(),
        "not.as.ticket.extra".to_owned(),
        format!("{}.{}.{}=", segments[0], segments[1], segments[2]),
        format!("{}.{}.{}", segments[0], segments[1], "A"),
        "a".repeat(4_097),
        format!("{}.{}.{}", segments[0], segments[1], "é"),
    ] {
        assert_eq!(GatewayTicket::parse(&candidate).err(), Some(GatewayTicketError::InvalidTicket));
    }
    let mut tampered = signed.as_str().to_owned();
    tampered.pop();
    tampered.push('Q');
    assert_eq!(
        GatewayTicket::parse(&tampered).expect("canonical envelope").verify(&trusted(), IAT).err(),
        Some(GatewayTicketError::InvalidTicket)
    );
    assert!(!format!("{:?}", GatewayTicketError::InvalidTicket).contains(signed.as_str()));
    assert!(!format!("{}", GatewayTicketError::InvalidTicket).contains(signed.as_str()));
}
