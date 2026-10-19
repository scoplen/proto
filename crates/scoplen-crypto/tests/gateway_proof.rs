// SPDX-License-Identifier: Apache-2.0
//! Public K-6 raw-TLS proof and trusted-ticket binding boundaries.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use scoplen_crypto::{
    DeviceSigner, Ed25519SigningKey, GatewayProof, GatewayProofError, GatewayTicket,
    GatewayTicketClaims, P256SigningKey, PrimitiveError, TrustedGatewayTicketKeys,
    dpop_jwk_thumbprint, gateway_ssh_key_sha256, p256_verify,
};
use scoplen_test_vectors::VectorDocument;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

const ISSUER: &str = "https://control.example.com";
const IAT: u64 = 1_700_000_000;

fn id(suffix: u8) -> Uuid {
    Uuid::parse_str(&format!("00000000-0000-7000-8000-{suffix:012x}")).expect("UUIDv7")
}

fn device_key() -> P256SigningKey {
    P256SigningKey::from_bytes(&[0x24; 32]).expect("synthetic device key")
}

fn ticket_key() -> Ed25519SigningKey {
    Ed25519SigningKey::from_bytes(&[0x42; 32]).expect("synthetic ticket key")
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
        remote_user: "deploy".to_owned(),
        ssh_key_sha256: gateway_ssh_key_sha256(b"validated raw SSH key blob"),
        cnf_jkt: dpop_jwk_thumbprint(&device_key().public_key_sec1()).expect("thumbprint"),
        iat: IAT,
        exp: IAT + 60,
    }
}

fn ticket_with_claims(claims: &GatewayTicketClaims) -> GatewayTicket {
    GatewayTicket::sign(&ticket_key(), &ticket_key().public_key(), "ticket-1", claims)
        .expect("ticket")
}

fn ticket() -> GatewayTicket {
    ticket_with_claims(&claims())
}

fn trusted() -> TrustedGatewayTicketKeys {
    let mut trusted = TrustedGatewayTicketKeys::new(ISSUER).expect("origin");
    trusted.insert("ticket-1", &ticket_key().public_key()).expect("ticket key");
    trusted
}

fn header() -> Value {
    header_for(&device_key())
}

fn header_for(key: &P256SigningKey) -> Value {
    let public = key.public_key_sec1();
    json!({
        "alg": "ES256", "typ": "spl-gw-proof+jwt",
        "jwk": {
            "crv": "P-256", "kty": "EC",
            "x": URL_SAFE_NO_PAD.encode(&public[1..33]),
            "y": URL_SAFE_NO_PAD.encode(&public[33..65])
        }
    })
}

fn payload(ticket: &GatewayTicket) -> Value {
    let proof = GatewayProof::sign(&device_key(), &device_key().public_key_sec1(), ticket, IAT)
        .expect("signed proof");
    let segment = proof.as_str().split('.').nth(1).expect("payload segment");
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(segment).expect("base64url"))
        .expect("proof JSON")
}

fn compact(header: &str, payload: &str) -> String {
    compact_with_key(header, payload, &device_key())
}

fn compact_with_key(header: &str, payload: &str, key: &P256SigningKey) -> String {
    let input = format!("{}.{}", URL_SAFE_NO_PAD.encode(header), URL_SAFE_NO_PAD.encode(payload));
    format!("{input}.{}", URL_SAFE_NO_PAD.encode(key.sign(input.as_bytes())))
}

fn raw(header: &Value, payload: &Value) -> GatewayProof {
    GatewayProof::parse(&compact(&header.to_string(), &payload.to_string())).expect("proof shape")
}

#[test]
fn signed_proof_binds_trusted_ticket_and_has_fresh_identifier() {
    let ticket = ticket();
    let first = GatewayProof::sign(&device_key(), &device_key().public_key_sec1(), &ticket, IAT)
        .expect("first proof");
    let second = GatewayProof::sign(&device_key(), &device_key().public_key_sec1(), &ticket, IAT)
        .expect("second proof");
    let verified = first.verify(&ticket, &trusted(), IAT).expect("verified proof");
    assert_eq!(verified.ticket().claims(), &claims());
    assert_eq!(verified.expires_at(), IAT + 60);
    assert_eq!(verified.proof_issued_at(), IAT);
    assert_ne!(verified.proof_jti(), second.verify(&ticket, &trusted(), IAT).unwrap().proof_jti());
    assert_eq!(URL_SAFE_NO_PAD.decode(verified.proof_jti()).unwrap().len(), 16);
    assert!(format!("{first:?}").contains("REDACTED"));
    assert!(format!("{verified:?}").contains("REPLAY NOT CLAIMED"));
    assert!(!format!("{verified:?}").contains(&claims().remote_user));
}

#[test]
fn trusted_ticket_exact_bytes_and_key_are_required() {
    let ticket = ticket();
    let proof = GatewayProof::sign(&device_key(), &device_key().public_key_sec1(), &ticket, IAT)
        .expect("proof");
    let mut other_claims = claims();
    other_claims.jti = id(7);
    let other_ticket = ticket_with_claims(&other_claims);
    assert_eq!(
        proof.verify(&other_ticket, &trusted(), IAT).err(),
        Some(GatewayProofError::InvalidProof)
    );
    let mut other_issuer =
        TrustedGatewayTicketKeys::new("https://other.example.com").expect("origin");
    other_issuer.insert("ticket-1", &ticket_key().public_key()).expect("ticket key");
    assert_eq!(
        proof.verify(&ticket, &other_issuer, IAT).err(),
        Some(GatewayProofError::InvalidProof)
    );
    let mut other_claims = claims();
    let other_key = P256SigningKey::from_bytes(&[0x25; 32]).expect("other key");
    other_claims.cnf_jkt = dpop_jwk_thumbprint(&other_key.public_key_sec1()).expect("thumbprint");
    let other_ticket = ticket_with_claims(&other_claims);
    assert_eq!(
        proof.verify(&other_ticket, &trusted(), IAT).err(),
        Some(GatewayProofError::InvalidProof)
    );
}

#[test]
fn another_valid_device_signature_and_correct_ticket_hash_cannot_bypass_cnf_binding() {
    let ticket = ticket();
    let other_key = P256SigningKey::from_bytes(&[0x25; 32]).expect("other key");
    assert_ne!(
        dpop_jwk_thumbprint(&other_key.public_key_sec1()).expect("thumbprint"),
        claims().cnf_jkt
    );
    let payload = payload(&ticket);
    let expected_ath = URL_SAFE_NO_PAD.encode(Sha256::digest(ticket.as_str().as_bytes()));
    assert_eq!(payload["ath"], expected_ath);
    let compact =
        compact_with_key(&header_for(&other_key).to_string(), &payload.to_string(), &other_key);
    let segments: Vec<_> = compact.split('.').collect();
    let signing_input = format!("{}.{}", segments[0], segments[1]);
    let signature = URL_SAFE_NO_PAD.decode(segments[2]).expect("signature bytes");
    p256_verify(&other_key.public_key_sec1(), signing_input.as_bytes(), &signature)
        .expect("valid alternative signature");
    let proof = GatewayProof::parse(&compact).expect("proof envelope");
    assert_eq!(proof.verify(&ticket, &trusted(), IAT).err(), Some(GatewayProofError::InvalidProof));
}

#[test]
fn identical_ticket_claims_with_different_signed_bytes_do_not_share_proofs() {
    let first = ticket();
    let proof = GatewayProof::sign(&device_key(), &device_key().public_key_sec1(), &first, IAT)
        .expect("first ticket proof");
    let segments: Vec<_> = first.as_str().split('.').collect();
    let mut header: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(segments[0]).unwrap())
        .expect("ticket header");
    header["x_header"] = json!(true);
    let payload =
        String::from_utf8(URL_SAFE_NO_PAD.decode(segments[1]).unwrap()).expect("ticket payload");
    let spaced_payload = format!(" {{ {} }} ", &payload[1..payload.len() - 1]);
    let input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header.to_string()),
        URL_SAFE_NO_PAD.encode(spaced_payload)
    );
    let second = GatewayTicket::parse(&format!(
        "{input}.{}",
        URL_SAFE_NO_PAD.encode(ticket_key().sign(input.as_bytes()))
    ))
    .expect("second ticket envelope");
    assert_ne!(first.as_str(), second.as_str());
    let first_claims = first.verify(&trusted(), IAT).expect("first ticket");
    let second_claims = second.verify(&trusted(), IAT).expect("second ticket");
    assert_eq!(first_claims.claims(), second_claims.claims());
    assert!(proof.verify(&first, &trusted(), IAT).is_ok());
    assert_eq!(proof.verify(&second, &trusted(), IAT).err(), Some(GatewayProofError::InvalidProof));
}

#[test]
fn proof_time_is_inside_ticket_and_not_in_future() {
    let ticket = ticket();
    for (proof_iat, now, accepted) in [
        (IAT - 1, IAT, false),
        (IAT, IAT, true),
        (IAT + 1, IAT, false),
        (IAT + 59, IAT + 59, true),
        (IAT + 59, IAT + 60, false),
        (u64::MAX, IAT, false),
    ] {
        let proof =
            GatewayProof::sign(&device_key(), &device_key().public_key_sec1(), &ticket, proof_iat)
                .expect("signed proof");
        assert_eq!(proof.verify(&ticket, &trusted(), now).is_ok(), accepted);
    }
}

struct FailingSigner;

impl DeviceSigner for FailingSigner {
    fn sign(&self, _: &[u8]) -> Result<[u8; 64], PrimitiveError> {
        Err(PrimitiveError::InvalidSignature)
    }
}

struct WrongSigner;

impl DeviceSigner for WrongSigner {
    fn sign(&self, message: &[u8]) -> Result<[u8; 64], PrimitiveError> {
        let key = P256SigningKey::from_bytes(&[0x25; 32]).expect("other key");
        Ok(key.sign(message))
    }
}

#[test]
fn signer_failure_and_mismatched_output_fail_closed() {
    let ticket = ticket();
    for signer in [&FailingSigner as &dyn DeviceSigner, &WrongSigner] {
        assert_eq!(
            GatewayProof::sign(signer, &device_key().public_key_sec1(), &ticket, IAT).err(),
            Some(GatewayProofError::SignerFailed)
        );
    }
    assert_eq!(
        GatewayProof::sign(&device_key(), &[0; 65], &ticket, IAT).err(),
        Some(GatewayProofError::InvalidContext)
    );
}

#[test]
fn header_claim_and_nested_json_substitutions_fail() {
    let ticket = ticket();
    let base_header = header();
    let base_payload = payload(&ticket);
    for (name, value) in
        [("typ", json!("dpop+jwt")), ("alg", json!("none")), ("jwk", json!({"kty":"oct"}))]
    {
        let mut changed = base_header.clone();
        changed[name] = value;
        assert_eq!(
            raw(&changed, &base_payload).verify(&ticket, &trusted(), IAT).err(),
            Some(GatewayProofError::InvalidProof),
            "{name}"
        );
    }
    for name in ["jku", "x5u", "x5c", "crit", "b64"] {
        let mut changed = base_header.clone();
        changed[name] = Value::Null;
        assert_eq!(
            raw(&changed, &base_payload).verify(&ticket, &trusted(), IAT).err(),
            Some(GatewayProofError::InvalidProof),
            "{name}"
        );
    }
    let mut changed = base_header.clone();
    changed["jwk"]["d"] = Value::Null;
    assert_eq!(
        raw(&changed, &base_payload).verify(&ticket, &trusted(), IAT).err(),
        Some(GatewayProofError::InvalidProof)
    );
    for (name, value) in [
        ("aud", json!(["spl-gw/1"])),
        ("ath", json!("not-a-hash")),
        ("jti", json!("not-a-jti")),
        ("iat", json!(-1)),
    ] {
        let mut changed = base_payload.clone();
        changed[name] = value;
        assert_eq!(
            raw(&base_header, &changed).verify(&ticket, &trusted(), IAT).err(),
            Some(GatewayProofError::InvalidProof),
            "{name}"
        );
    }
    for name in ["htm", "htu", "nonce"] {
        let mut changed = base_payload.clone();
        changed[name] = Value::Null;
        assert_eq!(
            raw(&base_header, &changed).verify(&ticket, &trusted(), IAT).err(),
            Some(GatewayProofError::InvalidProof),
            "{name}"
        );
    }
    let mut changed = base_payload.clone();
    changed["aud"] = json!("other");
    assert_eq!(
        raw(&base_header, &changed).verify(&ticket, &trusted(), IAT).err(),
        Some(GatewayProofError::InvalidProof)
    );
    let mut changed = base_payload.clone();
    changed["ath"] = json!(URL_SAFE_NO_PAD.encode([0; 32]));
    assert_eq!(
        raw(&base_header, &changed).verify(&ticket, &trusted(), IAT).err(),
        Some(GatewayProofError::InvalidProof)
    );
}

#[test]
fn extensions_and_original_json_bytes_are_accepted_but_nested_duplicates_are_not() {
    let ticket = ticket();
    let mut header = header();
    header["x_header"] = json!({"ok": true});
    header["jwk"]["x_jwk"] = json!([1, 2]);
    let mut payload = payload(&ticket);
    payload["x_claim"] = json!({"nested": {"ok": true}});
    let serialized = payload.to_string();
    let reordered = format!("{{ \"x_first\": true, {} }}", &serialized[1..serialized.len() - 1]);
    let proof = GatewayProof::parse(&compact(&header.to_string(), &reordered)).expect("proof");
    assert!(proof.verify(&ticket, &trusted(), IAT).is_ok());
    let duplicate = serialized.replace(
        "\"x_claim\":{\"nested\":{\"ok\":true}}",
        "\"x_claim\":{\"nested\":{\"ok\":true,\"ok\":false}}",
    );
    assert_ne!(duplicate, serialized, "duplicate fixture must change");
    assert_eq!(
        GatewayProof::parse(&compact(&header.to_string(), &duplicate))
            .unwrap()
            .verify(&ticket, &trusted(), IAT)
            .err(),
        Some(GatewayProofError::InvalidProof)
    );
    let duplicate_header =
        header.to_string().replace("\"alg\":\"ES256\"", "\"alg\":\"ES256\",\"alg\":\"ES256\"");
    assert_eq!(
        GatewayProof::parse(&compact(&duplicate_header, &serialized))
            .unwrap()
            .verify(&ticket, &trusted(), IAT)
            .err(),
        Some(GatewayProofError::InvalidProof)
    );
    let duplicate_payload =
        serialized.replace("\"aud\":\"spl-gw/1\"", "\"aud\":\"spl-gw/1\",\"aud\":\"spl-gw/1\"");
    assert_eq!(
        GatewayProof::parse(&compact(&header.to_string(), &duplicate_payload))
            .unwrap()
            .verify(&ticket, &trusted(), IAT)
            .err(),
        Some(GatewayProofError::InvalidProof)
    );
}

#[test]
fn exact_proof_length_boundary() {
    let ticket = ticket();
    let base = payload(&ticket);
    let mut headers = vec![header().to_string()];
    for length in 0..3 {
        let mut candidate = header();
        candidate["x_padding"] = json!("b".repeat(length));
        headers.push(candidate.to_string());
    }
    let mut at_limit = None;
    let mut over_limit = None;
    for header in headers {
        for padding in 0..8_192 {
            let mut candidate = base.clone();
            candidate["x_padding"] = json!("a".repeat(padding));
            let payload = candidate.to_string();
            let length =
                URL_SAFE_NO_PAD.encode(&header).len() + URL_SAFE_NO_PAD.encode(&payload).len() + 88;
            if length == 8_192 {
                at_limit = Some((header.clone(), payload));
            } else if length == 8_193 {
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
    let (header, payload) = at_limit.expect("8,192-byte proof");
    let valid = GatewayProof::parse(&compact(&header, &payload)).expect("exact-limit proof");
    assert_eq!(valid.as_str().len(), 8_192);
    assert!(valid.verify(&ticket, &trusted(), IAT).is_ok());
    let (header, payload) = over_limit.expect("8,193-byte proof");
    let oversized = compact(&header, &payload);
    assert_eq!(oversized.len(), 8_193);
    assert_eq!(GatewayProof::parse(&oversized).err(), Some(GatewayProofError::InvalidProof));
}

#[test]
fn compact_envelope_and_signature_bounds_are_enforced() {
    let ticket = ticket();
    let proof = GatewayProof::sign(&device_key(), &device_key().public_key_sec1(), &ticket, IAT)
        .expect("proof");
    let segments: Vec<_> = proof.as_str().split('.').collect();
    for malformed in [
        String::new(),
        "a.b".to_owned(),
        "a.b.c.d".to_owned(),
        format!("{}.{}.{}=", segments[0], segments[1], segments[2]),
        format!("{}.{}.A", segments[0], segments[1]),
        "a".repeat(8_193),
        format!("{}.{}.é", segments[0], segments[1]),
    ] {
        assert_eq!(GatewayProof::parse(&malformed).err(), Some(GatewayProofError::InvalidProof));
    }
    let mut tampered = proof.as_str().to_owned();
    let last = tampered.pop().expect("signature byte");
    tampered.push(if last == 'A' { 'Q' } else { 'A' });
    assert_eq!(
        GatewayProof::parse(&tampered).unwrap().verify(&ticket, &trusted(), IAT).err(),
        Some(GatewayProofError::InvalidProof)
    );
    assert!(!format!("{:?}", GatewayProofError::InvalidProof).contains(proof.as_str()));
}

#[test]
fn published_signed_vector_matches_exact_compact_bytes() {
    let document =
        VectorDocument::parse_str(include_str!("../../../vectors/gateway-signed-proof.json"))
            .expect("portable vector");
    let vector = document
        .vectors
        .iter()
        .find(|v| v.kind == "crypto.gateway.proof.valid")
        .expect("signed proof vector");
    let input: Value = serde_json::from_str(&vector.input).expect("ticket and proof");
    let vector_ticket =
        GatewayTicket::parse(input["ticket"].as_str().expect("ticket")).expect("ticket envelope");
    let proof =
        GatewayProof::parse(input["proof"].as_str().expect("proof")).expect("proof envelope");
    let verified = proof.verify(&vector_ticket, &trusted(), IAT).expect("signed vector");
    assert_eq!(vector_ticket.as_str(), ticket().as_str());
    assert_eq!(verified.ticket().claims(), &claims());
    assert_eq!(vector.expected, format!("{}|{}", verified.proof_jti(), verified.expires_at()));
    let seed = include_str!("../../../fuzz/corpus/crypto_decoders/seed-gateway-proof-valid");
    let (seed_ticket, seed_proof) = seed.split_once('\n').expect("ticket and proof seed");
    assert_eq!(seed_ticket.strip_suffix('\r').unwrap_or(seed_ticket), vector_ticket.as_str());
    assert_eq!(
        seed_proof
            .strip_suffix("\r\n")
            .or_else(|| seed_proof.strip_suffix('\n'))
            .unwrap_or(seed_proof),
        proof.as_str()
    );
}
