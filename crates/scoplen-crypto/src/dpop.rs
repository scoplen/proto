// SPDX-License-Identifier: Apache-2.0
//! Bounded ES256 `DPoP` proof construction and stateless verification.

use std::{collections::BTreeMap, fmt};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::{Map, Value};
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;
use thiserror::Error;

use crate::{DeviceSigner, device_auth::validate_origin, p256_verify, random_bytes};

const MAX_PROOF_BYTES: usize = 8_192;
const MAX_TARGET_BYTES: usize = 4_096;
const MAX_METHOD_BYTES: usize = 32;
const MAX_JTI_BYTES: usize = 128;
const MAX_NONCE_BYTES: usize = 1_024;
const MAX_TOKEN_BYTES: usize = 4_096;
const TIME_WINDOW_SECONDS: u64 = 60;

/// A rejected `DPoP` target, credential context, proof, or signer operation.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum DpopError {
    /// The trusted method or target is not canonical.
    #[error("DPoP request target is invalid")]
    InvalidTarget,
    /// A token, thumbprint, nonce, or timestamp violates the shared profile.
    #[error("DPoP credential context is invalid")]
    InvalidContext,
    /// The compact proof or one of its required values is invalid.
    #[error("DPoP proof is invalid")]
    InvalidProof,
    /// The fallible device signer could not sign the proof.
    #[error("DPoP signer failed")]
    SignerFailed,
    /// Operating-system randomness was unavailable.
    #[error("DPoP proof identifier generation failed")]
    RandomnessFailed,
}

/// A method and exact HTTPS URI built from trusted deployment and router values.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DpopTarget {
    method: String,
    uri: String,
}

impl DpopTarget {
    /// Validate and combine a canonical origin, HTTP method, and canonical absolute route path.
    /// The caller must reject route aliases before creating this target.
    ///
    /// # Errors
    ///
    /// Rejects noncanonical origins and paths, invalid method tokens, or an oversized URI.
    pub fn new(method: &str, origin: &str, path: &str) -> Result<Self, DpopError> {
        if method.is_empty()
            || method.len() > MAX_METHOD_BYTES
            || !method.bytes().all(is_method_token_byte)
            || validate_origin(origin).is_err()
            || path.len() > MAX_TARGET_BYTES
            || origin.len() > MAX_TARGET_BYTES - path.len()
            || !valid_path(path)
        {
            return Err(DpopError::InvalidTarget);
        }
        Ok(Self { method: method.to_owned(), uri: format!("{origin}{path}") })
    }

    /// Return the exact method used in a proof.
    #[must_use]
    pub fn method(&self) -> &str {
        &self.method
    }

    /// Return the exact HTTPS URI, without query or fragment.
    #[must_use]
    pub fn uri(&self) -> &str {
        &self.uri
    }
}

/// A protected access token or an access-token-free refresh exchange.
#[derive(Clone, Copy)]
pub enum DpopToken<'a> {
    /// Bind the proof to an ASCII access token via `ath`.
    Protected(&'a str),
    /// Do not write or require `ath`; an extra claim in an incoming proof is ignored.
    Refresh,
}

impl fmt::Debug for DpopToken<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DpopToken([REDACTED])")
    }
}

/// A bounded compact JWS. Parsing this type does not verify its signature or authorize use.
#[derive(Clone, Eq, PartialEq)]
pub struct DpopProof(String);

impl fmt::Debug for DpopProof {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DpopProof([REDACTED])")
    }
}

impl DpopProof {
    /// Parse only the bounded canonical compact-JWS envelope.
    ///
    /// # Errors
    ///
    /// Rejects an oversized, non-ASCII, padded, malformed, or empty-segment proof.
    pub fn parse(value: &str) -> Result<Self, DpopError> {
        let (header, claims, signature) = split_compact(value)?;
        for segment in [header, claims, signature] {
            let _ = decode_segment(segment)?;
        }
        Ok(Self(value.to_owned()))
    }

    /// Construct a fresh signed proof with a random 128-bit proof identifier.
    /// The supplied uncompressed SEC1 key must match the signer's actual private key.
    ///
    /// # Errors
    ///
    /// Rejects invalid inputs or a signature that fails verification under the supplied key.
    pub fn sign(
        signer: &impl DeviceSigner,
        public_key_sec1: &[u8],
        target: &DpopTarget,
        token: DpopToken<'_>,
        iat: u64,
        nonce: Option<&str>,
    ) -> Result<Self, DpopError> {
        let mut jti = [0_u8; 16];
        random_bytes(&mut jti).map_err(|_| DpopError::RandomnessFailed)?;
        Self::sign_with_jti(
            signer,
            public_key_sec1,
            target,
            token,
            iat,
            nonce,
            &URL_SAFE_NO_PAD.encode(jti),
        )
    }

    fn sign_with_jti(
        signer: &impl DeviceSigner,
        public_key_sec1: &[u8],
        target: &DpopTarget,
        token: DpopToken<'_>,
        iat: u64,
        nonce: Option<&str>,
        jti: &str,
    ) -> Result<Self, DpopError> {
        let jwk = PublicJwk::from_sec1(public_key_sec1).map_err(|_| DpopError::InvalidContext)?;
        if iat.checked_add(TIME_WINDOW_SECONDS).is_none()
            || !valid_jti(jti)
            || nonce.is_some_and(|value| !valid_nonce(value))
        {
            return Err(DpopError::InvalidContext);
        }
        let ath = token_hash(token)?;
        let header = serde_json::json!({
            "alg": "ES256",
            "jwk": {"crv": "P-256", "kty": "EC", "x": jwk.x, "y": jwk.y},
            "typ": "dpop+jwt"
        });
        let mut claims = Map::new();
        claims.insert("htm".to_owned(), Value::String(target.method.clone()));
        claims.insert("htu".to_owned(), Value::String(target.uri.clone()));
        claims.insert("iat".to_owned(), Value::from(iat));
        claims.insert("jti".to_owned(), Value::String(jti.to_owned()));
        if let Some(value) = nonce {
            claims.insert("nonce".to_owned(), Value::String(value.to_owned()));
        }
        if let Some(value) = ath {
            claims.insert("ath".to_owned(), Value::String(value));
        }
        let header = serde_json::to_vec(&header).map_err(|_| DpopError::InvalidContext)?;
        let claims = serde_json::to_vec(&claims).map_err(|_| DpopError::InvalidContext)?;
        let input =
            format!("{}.{}", URL_SAFE_NO_PAD.encode(header), URL_SAFE_NO_PAD.encode(claims));
        let signature = signer.sign(input.as_bytes()).map_err(|_| DpopError::SignerFailed)?;
        p256_verify(public_key_sec1, input.as_bytes(), &signature)
            .map_err(|_| DpopError::SignerFailed)?;
        Self::parse(&format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature)))
    }

    /// Return the compact JWS for transport. Keep it out of logs and diagnostics.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Verify signature, key binding, exact request, token hash, nonce, and freshness.
    /// The caller must atomically claim the returned `(jkt, jti)` across instances before use.
    ///
    /// # Errors
    ///
    /// Rejects an invalid proof or credential context without exposing input values.
    pub fn verify(
        &self,
        target: &DpopTarget,
        token: DpopToken<'_>,
        expected_jkt: &str,
        now: u64,
        required_nonce: Option<&str>,
    ) -> Result<VerifiedDpopProof, DpopError> {
        let expected = decode_fixed_32(expected_jkt).map_err(|_| DpopError::InvalidContext)?;
        if required_nonce.is_some_and(|value| !valid_nonce(value)) {
            return Err(DpopError::InvalidContext);
        }
        let ath = token_hash(token)?;
        let (encoded_header, encoded_claims, encoded_signature) = split_compact(&self.0)?;
        let header = parse_unique_json(&decode_segment(encoded_header)?)?;
        let header = header.as_object().ok_or(DpopError::InvalidProof)?;
        if !header
            .get("typ")
            .and_then(Value::as_str)
            .is_some_and(|v| v.eq_ignore_ascii_case("dpop+jwt"))
            || header.get("alg").and_then(Value::as_str) != Some("ES256")
            || header.contains_key("crit")
            || header.contains_key("b64")
        {
            return Err(DpopError::InvalidProof);
        }
        let jwk = PublicJwk::from_value(header.get("jwk").ok_or(DpopError::InvalidProof)?)?;
        let thumbprint = jwk.thumbprint();
        let actual = decode_fixed_32(&thumbprint)?;
        if !bool::from(actual.ct_eq(&expected)) {
            return Err(DpopError::InvalidProof);
        }
        let signature = decode_segment(encoded_signature)?;
        if signature.len() != 64 {
            return Err(DpopError::InvalidProof);
        }
        let signing_input = format!("{encoded_header}.{encoded_claims}");
        p256_verify(&jwk.sec1, signing_input.as_bytes(), &signature)
            .map_err(|_| DpopError::InvalidProof)?;

        let claims = parse_unique_json(&decode_segment(encoded_claims)?)?;
        let claims = claims.as_object().ok_or(DpopError::InvalidProof)?;
        let jti = claims.get("jti").and_then(Value::as_str).ok_or(DpopError::InvalidProof)?;
        let method = claims.get("htm").and_then(Value::as_str).ok_or(DpopError::InvalidProof)?;
        let uri = claims.get("htu").and_then(Value::as_str).ok_or(DpopError::InvalidProof)?;
        let iat = claims.get("iat").and_then(Value::as_u64).ok_or(DpopError::InvalidProof)?;
        let last_accepted_at =
            iat.checked_add(TIME_WINDOW_SECONDS).ok_or(DpopError::InvalidProof)?;
        if !valid_jti(jti)
            || method != target.method
            || uri != target.uri
            || iat > now.saturating_add(TIME_WINDOW_SECONDS)
            || now > last_accepted_at
        {
            return Err(DpopError::InvalidProof);
        }
        if let Some(value) = claims.get("nonce")
            && !value.as_str().is_some_and(valid_nonce)
        {
            return Err(DpopError::InvalidProof);
        }
        if let Some(expected_nonce) = required_nonce {
            let actual_nonce =
                claims.get("nonce").and_then(Value::as_str).ok_or(DpopError::InvalidProof)?;
            if !bool::from(actual_nonce.as_bytes().ct_eq(expected_nonce.as_bytes())) {
                return Err(DpopError::InvalidProof);
            }
        }
        if let Some(expected_ath) = ath {
            let actual_ath =
                claims.get("ath").and_then(Value::as_str).ok_or(DpopError::InvalidProof)?;
            let decoded = decode_fixed_32(actual_ath)?;
            let expected = decode_fixed_32(&expected_ath)?;
            if !bool::from(decoded.ct_eq(&expected)) {
                return Err(DpopError::InvalidProof);
            }
        }
        Ok(VerifiedDpopProof { jkt: thumbprint, jti: jti.to_owned(), iat, last_accepted_at })
    }
}

/// Signature and binding evidence only; authorization and replay prevention remain with the caller.
#[derive(Clone, Eq, PartialEq)]
pub struct VerifiedDpopProof {
    /// The RFC 7638 public JWK thumbprint.
    pub jkt: String,
    /// The signed proof identifier, to atomically claim with `jkt` before use.
    pub jti: String,
    /// Signed proof creation time, in Unix seconds.
    pub iat: u64,
    /// Last inclusive integer second at which this proof may be accepted.
    pub last_accepted_at: u64,
}

impl fmt::Debug for VerifiedDpopProof {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("VerifiedDpopProof([STATELESS; REPLAY NOT CLAIMED])")
    }
}

/// Compute the canonical RFC 7638 thumbprint of an uncompressed P-256 SEC1 public key.
///
/// # Errors
///
/// Rejects malformed, compressed, or non-curve public keys.
pub fn dpop_jwk_thumbprint(public_key_sec1: &[u8]) -> Result<String, DpopError> {
    Ok(PublicJwk::from_sec1(public_key_sec1)?.thumbprint())
}

struct PublicJwk {
    x: String,
    y: String,
    sec1: [u8; 65],
}

impl PublicJwk {
    fn from_sec1(value: &[u8]) -> Result<Self, DpopError> {
        let sec1: [u8; 65] = value.try_into().map_err(|_| DpopError::InvalidProof)?;
        if sec1[0] != 4 || p256::PublicKey::from_sec1_bytes(&sec1).is_err() {
            return Err(DpopError::InvalidProof);
        }
        Ok(Self {
            x: URL_SAFE_NO_PAD.encode(&sec1[1..33]),
            y: URL_SAFE_NO_PAD.encode(&sec1[33..65]),
            sec1,
        })
    }

    fn from_value(value: &Value) -> Result<Self, DpopError> {
        let object = value.as_object().ok_or(DpopError::InvalidProof)?;
        if object.contains_key("d")
            || object.get("kty").and_then(Value::as_str) != Some("EC")
            || object.get("crv").and_then(Value::as_str) != Some("P-256")
        {
            return Err(DpopError::InvalidProof);
        }
        let x = object.get("x").and_then(Value::as_str).ok_or(DpopError::InvalidProof)?;
        let y = object.get("y").and_then(Value::as_str).ok_or(DpopError::InvalidProof)?;
        let x_bytes = decode_fixed_32(x)?;
        let y_bytes = decode_fixed_32(y)?;
        let mut sec1 = [0_u8; 65];
        sec1[0] = 4;
        sec1[1..33].copy_from_slice(&x_bytes);
        sec1[33..65].copy_from_slice(&y_bytes);
        Self::from_sec1(&sec1)
    }

    fn thumbprint(&self) -> String {
        let json = format!(
            "{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{}\",\"y\":\"{}\"}}",
            self.x, self.y
        );
        URL_SAFE_NO_PAD.encode(Sha256::digest(json.as_bytes()))
    }
}

fn token_hash(token: DpopToken<'_>) -> Result<Option<String>, DpopError> {
    match token {
        DpopToken::Refresh => Ok(None),
        DpopToken::Protected(value)
            if !value.is_empty() && value.len() <= MAX_TOKEN_BYTES && value.is_ascii() =>
        {
            Ok(Some(URL_SAFE_NO_PAD.encode(Sha256::digest(value.as_bytes()))))
        }
        DpopToken::Protected(_) => Err(DpopError::InvalidContext),
    }
}

fn split_compact(value: &str) -> Result<(&str, &str, &str), DpopError> {
    if value.is_empty() || value.len() > MAX_PROOF_BYTES || !value.is_ascii() {
        return Err(DpopError::InvalidProof);
    }
    let mut parts = value.split('.');
    let first = parts.next().ok_or(DpopError::InvalidProof)?;
    let second = parts.next().ok_or(DpopError::InvalidProof)?;
    let third = parts.next().ok_or(DpopError::InvalidProof)?;
    if parts.next().is_some() || first.is_empty() || second.is_empty() || third.is_empty() {
        return Err(DpopError::InvalidProof);
    }
    for part in [first, second, third] {
        if !part.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
            return Err(DpopError::InvalidProof);
        }
    }
    Ok((first, second, third))
}

pub(crate) fn decode_segment(value: &str) -> Result<Vec<u8>, DpopError> {
    let bytes = URL_SAFE_NO_PAD.decode(value).map_err(|_| DpopError::InvalidProof)?;
    if URL_SAFE_NO_PAD.encode(&bytes) != value {
        return Err(DpopError::InvalidProof);
    }
    Ok(bytes)
}

pub(crate) fn decode_fixed_32(value: &str) -> Result<[u8; 32], DpopError> {
    if value.len() != 43 {
        return Err(DpopError::InvalidProof);
    }
    let bytes = decode_segment(value)?;
    bytes.try_into().map_err(|_| DpopError::InvalidProof)
}

pub(crate) fn parse_unique_json(bytes: &[u8]) -> Result<Value, DpopError> {
    serde_json::from_slice::<UniqueValue>(bytes)
        .map(|value| value.0)
        .map_err(|_| DpopError::InvalidProof)
}

struct UniqueValue(Value);

impl<'de> Deserialize<'de> for UniqueValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct UniqueVisitor;
        impl<'de> Visitor<'de> for UniqueVisitor {
            type Value = UniqueValue;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("JSON with unique object member names")
            }
            fn visit_bool<E: de::Error>(self, value: bool) -> Result<Self::Value, E> {
                Ok(UniqueValue(Value::Bool(value)))
            }
            fn visit_i64<E: de::Error>(self, value: i64) -> Result<Self::Value, E> {
                Ok(UniqueValue(Value::from(value)))
            }
            fn visit_u64<E: de::Error>(self, value: u64) -> Result<Self::Value, E> {
                Ok(UniqueValue(Value::from(value)))
            }
            fn visit_f64<E: de::Error>(self, value: f64) -> Result<Self::Value, E> {
                serde_json::Number::from_f64(value)
                    .map(|number| UniqueValue(Value::Number(number)))
                    .ok_or_else(|| E::custom("invalid JSON number"))
            }
            fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
                Ok(UniqueValue(Value::String(value.to_owned())))
            }
            fn visit_string<E: de::Error>(self, value: String) -> Result<Self::Value, E> {
                Ok(UniqueValue(Value::String(value)))
            }
            fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
                Ok(UniqueValue(Value::Null))
            }
            fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
                Ok(UniqueValue(Value::Null))
            }
            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut sequence: A,
            ) -> Result<Self::Value, A::Error> {
                let mut values = Vec::new();
                while let Some(value) = sequence.next_element::<UniqueValue>()? {
                    values.push(value.0);
                }
                Ok(UniqueValue(Value::Array(values)))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut object: A) -> Result<Self::Value, A::Error> {
                let mut values = BTreeMap::new();
                while let Some((key, value)) = object.next_entry::<String, UniqueValue>()? {
                    if values.insert(key, value.0).is_some() {
                        return Err(de::Error::custom("duplicate JSON member"));
                    }
                }
                Ok(UniqueValue(Value::Object(values.into_iter().collect())))
            }
        }
        deserializer.deserialize_any(UniqueVisitor)
    }
}

fn valid_jti(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_JTI_BYTES
}

fn valid_nonce(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_NONCE_BYTES
        && value
            .bytes()
            .all(|b| b == 0x21 || (0x23..=0x5b).contains(&b) || (0x5d..=0x7e).contains(&b))
}

fn is_method_token_byte(value: u8) -> bool {
    value.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&value)
}

fn valid_path(value: &str) -> bool {
    let bytes = value.as_bytes();
    if !value.is_ascii() || !value.starts_with('/') || value.contains("//") {
        return false;
    }
    for segment in value.split('/') {
        if segment == "." || segment == ".." {
            return false;
        }
    }
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == b'%' {
            if index + 2 >= bytes.len()
                || !is_upper_hex(bytes[index + 1])
                || !is_upper_hex(bytes[index + 2])
            {
                return false;
            }
            let decoded = (hex_value(bytes[index + 1]) << 4) | hex_value(bytes[index + 2]);
            if is_unreserved(decoded)
                || decoded == b'/'
                || decoded == b'\\'
                || decoded < 0x20
                || decoded == 0x7f
            {
                return false;
            }
            index += 3;
        } else {
            if byte != b'/' && !is_unreserved(byte) && !b"!$&'()*+,;=:@".contains(&byte) {
                return false;
            }
            index += 1;
        }
    }
    true
}

fn is_unreserved(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"-._~".contains(&byte)
}

fn is_upper_hex(byte: u8) -> bool {
    byte.is_ascii_digit() || (b'A'..=b'F').contains(&byte)
}

fn hex_value(byte: u8) -> u8 {
    if byte.is_ascii_digit() { byte - b'0' } else { byte - b'A' + 10 }
}
