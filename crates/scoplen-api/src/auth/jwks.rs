// SPDX-License-Identifier: Apache-2.0
//! Bounded public-only D-106 access-token key discovery document.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Serialize;
use serde_json::Value;
use thiserror::Error;

use crate::request_wire;

/// Maximum complete UTF-8 JWKS response, including whitespace and extensions.
pub const MAX_AUTH_JWKS_BYTES: usize = 4_096;

/// A discovery document violates its bounded public-key profile.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum AuthJwksCodecError {
    /// The complete JSON document exceeds its byte limit.
    #[error("authentication JWKS exceeds 4096 bytes")]
    TooLarge,
    /// JSON is malformed, has recursively duplicate members, or is not an object.
    #[error("invalid authentication JWKS JSON")]
    InvalidJson,
    /// A required field is missing, mistyped, or outside the public-key profile.
    #[error("invalid authentication JWKS field: {0}")]
    InvalidField(&'static str),
}

/// One public Ed25519 discovery key. Parsing this value does not establish trust.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthJwk {
    kid: String,
    public_key: [u8; 32],
}

impl AuthJwk {
    /// Construct a public discovery key with a D-100 key identifier.
    ///
    /// # Errors
    ///
    /// Rejects an identifier outside 1..128 ASCII letters, digits, dots, hyphens, or underscores.
    pub fn new(kid: impl Into<String>, public_key: [u8; 32]) -> Result<Self, AuthJwksCodecError> {
        let kid = kid.into();
        if kid.is_empty()
            || kid.len() > 128
            || !kid.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
        {
            return Err(AuthJwksCodecError::InvalidField("kid"));
        }
        Ok(Self { kid, public_key })
    }

    /// The key's identifier, without implying configured trust or current validity.
    #[must_use]
    pub fn kid(&self) -> &str {
        &self.kid
    }

    /// The decoded 32-byte Ed25519 public key.
    #[must_use]
    pub fn public_key(&self) -> &[u8; 32] {
        &self.public_key
    }
}

/// Public discovery keys in canonical identifier order.
///
/// This codec never fetches keys, verifies tokens, or constructs a trusted issuer/keyring.
/// Consumers explicitly select their trusted deployment and configured verification keys.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthJwks {
    keys: Vec<AuthJwk>,
}

impl AuthJwks {
    /// Construct a document of one or two distinct public keys, sorted by identifier.
    ///
    /// # Errors
    ///
    /// Rejects an empty, oversized, or duplicate-identifier key set.
    pub fn new(mut keys: Vec<AuthJwk>) -> Result<Self, AuthJwksCodecError> {
        if !(1..=2).contains(&keys.len()) {
            return Err(AuthJwksCodecError::InvalidField("keys"));
        }
        keys.sort_unstable_by(|left, right| left.kid.cmp(&right.kid));
        if keys.windows(2).any(|pair| pair[0].kid == pair[1].kid) {
            return Err(AuthJwksCodecError::InvalidField("kid"));
        }
        Ok(Self { keys })
    }

    /// The public keys sorted by identifier. Discovery alone does not authorize any key.
    #[must_use]
    pub fn keys(&self) -> &[AuthJwk] {
        &self.keys
    }

    /// Decode a complete bounded JSON document, accepting member and key array order.
    ///
    /// Unknown non-private extensions are ignored after recursive duplicate-name checks.
    ///
    /// # Errors
    ///
    /// Rejects over-budget input, malformed or duplicate JSON members, duplicate key ids,
    /// any key entry's private `d` member, and invalid public-key fields.
    pub fn from_json(input: &[u8]) -> Result<Self, AuthJwksCodecError> {
        if input.len() > MAX_AUTH_JWKS_BYTES {
            return Err(AuthJwksCodecError::TooLarge);
        }
        let mut fields = request_wire::decode_unique_object(input)
            .map_err(|()| AuthJwksCodecError::InvalidJson)?;
        let Some(Value::Array(entries)) = fields.remove("keys") else {
            return Err(AuthJwksCodecError::InvalidField("keys"));
        };
        if !(1..=2).contains(&entries.len()) {
            return Err(AuthJwksCodecError::InvalidField("keys"));
        }
        let keys = entries
            .into_iter()
            .map(|entry| {
                let Value::Object(mut key) = entry else {
                    return Err(AuthJwksCodecError::InvalidField("keys"));
                };
                if key.contains_key("d") {
                    return Err(AuthJwksCodecError::InvalidField("d"));
                }
                for (field, expected) in
                    [("kty", "OKP"), ("crv", "Ed25519"), ("alg", "Ed25519"), ("use", "sig")]
                {
                    if key.get(field).and_then(Value::as_str) != Some(expected) {
                        return Err(AuthJwksCodecError::InvalidField(field));
                    }
                }
                let Some(Value::String(kid)) = key.remove("kid") else {
                    return Err(AuthJwksCodecError::InvalidField("kid"));
                };
                let Some(Value::String(x)) = key.remove("x") else {
                    return Err(AuthJwksCodecError::InvalidField("x"));
                };
                // Check length before allocation, then re-encode to reject unused trailing bits.
                if x.len() != 43 {
                    return Err(AuthJwksCodecError::InvalidField("x"));
                }
                let decoded = URL_SAFE_NO_PAD
                    .decode(&x)
                    .map_err(|_| AuthJwksCodecError::InvalidField("x"))?;
                if URL_SAFE_NO_PAD.encode(&decoded) != x {
                    return Err(AuthJwksCodecError::InvalidField("x"));
                }
                let public_key =
                    decoded.try_into().map_err(|_| AuthJwksCodecError::InvalidField("x"))?;
                AuthJwk::new(kid, public_key)
            })
            .collect::<Result<Vec<_>, _>>()?;
        Self::new(keys)
    }

    /// Encode public keys by ascending identifier with fixed key field order.
    ///
    /// # Errors
    ///
    /// Returns an error if JSON encoding fails. Validated bounds keep output below 4096 bytes.
    pub fn to_json(&self) -> Result<Vec<u8>, AuthJwksCodecError> {
        #[derive(Serialize)]
        struct Document<'a> {
            keys: Vec<Key<'a>>,
        }
        #[derive(Serialize)]
        struct Key<'a> {
            kty: &'static str,
            crv: &'static str,
            x: String,
            kid: &'a str,
            alg: &'static str,
            r#use: &'static str,
        }
        let keys = self
            .keys
            .iter()
            .map(|key| Key {
                kty: "OKP",
                crv: "Ed25519",
                x: URL_SAFE_NO_PAD.encode(key.public_key),
                kid: &key.kid,
                alg: "Ed25519",
                r#use: "sig",
            })
            .collect();
        serde_json::to_vec(&Document { keys }).map_err(|_| AuthJwksCodecError::InvalidJson)
    }
}
