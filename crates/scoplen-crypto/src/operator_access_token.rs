// SPDX-License-Identifier: Apache-2.0
//! D-111 Operator browser tokens with a signing purpose distinct from enrolled devices.

use std::{collections::BTreeMap, fmt};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use scoplen_model::validate_uuid_v7;
use serde::Serialize;
use serde_json::{Map, Value};
use thiserror::Error;
use uuid::Uuid;

use crate::{
    Ed25519SigningKey,
    device_access_token::{valid_kid, valid_scope},
    device_auth::validate_origin,
    dpop, ed25519_verify,
};

pub const MAX_OPERATOR_ACCESS_TOKEN_BYTES: usize = 4_096;
pub const OPERATOR_ACCESS_TOKEN_LIFETIME_SECONDS: u64 = 600;

#[derive(Serialize)]
struct SigningHeader<'a> {
    alg: &'static str,
    kid: &'a str,
    typ: &'static str,
}

#[derive(Serialize)]
struct SigningConfirmation<'a> {
    jkt: &'a str,
}

#[derive(Serialize)]
struct SigningPayload<'a> {
    aud: &'static str,
    cnf: SigningConfirmation<'a>,
    exp: u64,
    iat: u64,
    iss: &'a str,
    jti: String,
    scope: &'a str,
    sid: String,
    sub: String,
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum OperatorAccessTokenError {
    #[error("invalid operator access token signing context")]
    InvalidContext,
    #[error("invalid operator access token")]
    InvalidToken,
    #[error("operator access token signer failed")]
    SignerFailed,
}

/// A dedicated fallible Ed25519 signing boundary for the Operator keyring.
pub trait OperatorAccessTokenSigner {
    /// # Errors
    ///
    /// Rejects unavailable signing; no partial token may be returned.
    fn sign(&self, message: &[u8]) -> Result<[u8; 64], OperatorAccessTokenError>;
}

impl OperatorAccessTokenSigner for Ed25519SigningKey {
    fn sign(&self, message: &[u8]) -> Result<[u8; 64], OperatorAccessTokenError> {
        Ok(Ed25519SigningKey::sign(self, message))
    }
}

/// Identity and browser-family snapshot supplied from current verified issuer state.
#[derive(Clone, Eq, PartialEq)]
pub struct OperatorAccessTokenClaims {
    pub iss: String,
    pub sub: Uuid,
    pub sid: Uuid,
    pub jti: Uuid,
    pub cnf_jkt: String,
    pub scope: String,
    pub iat: u64,
    pub exp: u64,
}

impl fmt::Debug for OperatorAccessTokenClaims {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OperatorAccessTokenClaims([REDACTED])")
    }
}

impl OperatorAccessTokenClaims {
    /// # Errors
    ///
    /// Rejects a noncanonical issuer, identity, JKT, scope syntax, or 600-second lifetime.
    pub fn validate(&self) -> Result<(), OperatorAccessTokenError> {
        if validate_origin(&self.iss).is_err()
            || [self.sub, self.sid, self.jti].into_iter().any(|id| validate_uuid_v7(id).is_err())
            || dpop::decode_fixed_32(&self.cnf_jkt).is_err()
            || !valid_scope(&self.scope)
            || self.iat.checked_add(OPERATOR_ACCESS_TOKEN_LIFETIME_SECONDS) != Some(self.exp)
        {
            return Err(OperatorAccessTokenError::InvalidContext);
        }
        Ok(())
    }
}

/// A bounded compact JWS; parsing alone authenticates no principal.
#[derive(Clone, Eq, PartialEq)]
pub struct OperatorAccessToken(String);

impl fmt::Debug for OperatorAccessToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OperatorAccessToken([REDACTED])")
    }
}

impl OperatorAccessToken {
    /// # Errors
    ///
    /// Rejects oversized, malformed or noncanonical compact-JWS envelopes.
    pub fn parse(value: &str) -> Result<Self, OperatorAccessTokenError> {
        let (header, payload, signature) = split_compact(value)?;
        decode_segment(header)?;
        decode_segment(payload)?;
        if decode_segment(signature)?.len() != 64 {
            return Err(OperatorAccessTokenError::InvalidToken);
        }
        Ok(Self(value.to_owned()))
    }

    /// Sign the Operator profile using only its dedicated configured keyring.
    ///
    /// The caller supplies the current Operator, credential-bound family, scope ceiling and
    /// the JKT from verified browser `DPoP` evidence. No device identity is synthesized.
    ///
    /// # Errors
    ///
    /// Rejects invalid claims, unknown keys, oversized output, or failed/mismatched signing.
    pub fn sign(
        signer: &(impl OperatorAccessTokenSigner + ?Sized),
        signing_keys: &TrustedOperatorAccessTokenKeys,
        kid: &str,
        claims: &OperatorAccessTokenClaims,
    ) -> Result<Self, OperatorAccessTokenError> {
        claims.validate()?;
        if claims.iss != signing_keys.issuer || !valid_kid(kid) {
            return Err(OperatorAccessTokenError::InvalidContext);
        }
        let key = signing_keys.keys.get(kid).ok_or(OperatorAccessTokenError::InvalidContext)?;
        let header = SigningHeader { alg: "Ed25519", kid, typ: "spl-operator-access+jwt" };
        let payload = SigningPayload {
            aud: "spl-admin/1",
            cnf: SigningConfirmation { jkt: &claims.cnf_jkt },
            exp: claims.exp,
            iat: claims.iat,
            iss: &claims.iss,
            jti: claims.jti.to_string(),
            scope: &claims.scope,
            sid: claims.sid.to_string(),
            sub: claims.sub.to_string(),
        };
        let header =
            serde_json::to_vec(&header).map_err(|_| OperatorAccessTokenError::InvalidContext)?;
        let payload =
            serde_json::to_vec(&payload).map_err(|_| OperatorAccessTokenError::InvalidContext)?;
        let input =
            format!("{}.{}", URL_SAFE_NO_PAD.encode(header), URL_SAFE_NO_PAD.encode(payload));
        if input.len() + 87 > MAX_OPERATOR_ACCESS_TOKEN_BYTES {
            return Err(OperatorAccessTokenError::InvalidContext);
        }
        let signature =
            signer.sign(input.as_bytes()).map_err(|_| OperatorAccessTokenError::SignerFailed)?;
        ed25519_verify(key, input.as_bytes(), &signature)
            .map_err(|_| OperatorAccessTokenError::SignerFailed)?;
        Self::parse(&format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature)))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Verify original signed bytes against the trusted Operator keyring and current time.
    ///
    /// Current family/credential/revocation, exact route scope, `DPoP` and replay checks remain
    /// consumer responsibilities. Unknown syntactically valid scope tokens grant no authority.
    ///
    /// # Errors
    ///
    /// Rejects untrusted signatures, substituted profiles, malformed claims and expired tokens.
    pub fn verify(
        &self,
        trusted: &TrustedOperatorAccessTokenKeys,
        now: u64,
    ) -> Result<VerifiedOperatorAccessToken, OperatorAccessTokenError> {
        let (encoded_header, encoded_payload, encoded_signature) = split_compact(&self.0)?;
        let header = unique_object(&decode_segment(encoded_header)?)?;
        if header.len() != 3
            || header.get("alg").and_then(Value::as_str) != Some("Ed25519")
            || header.get("typ").and_then(Value::as_str) != Some("spl-operator-access+jwt")
        {
            return Err(OperatorAccessTokenError::InvalidToken);
        }
        let kid = text(&header, "kid")?;
        if !valid_kid(kid) {
            return Err(OperatorAccessTokenError::InvalidToken);
        }
        let key = trusted.keys.get(kid).ok_or(OperatorAccessTokenError::InvalidToken)?;
        let signature = decode_segment(encoded_signature)?;
        let input = format!("{encoded_header}.{encoded_payload}");
        ed25519_verify(key, input.as_bytes(), &signature)
            .map_err(|_| OperatorAccessTokenError::InvalidToken)?;
        let payload = unique_object(&decode_segment(encoded_payload)?)?;
        let cnf = payload
            .get("cnf")
            .and_then(Value::as_object)
            .ok_or(OperatorAccessTokenError::InvalidToken)?;
        if cnf.len() != 1
            || payload.get("aud").and_then(Value::as_str) != Some("spl-admin/1")
            || payload.contains_key("did")
            || payload.contains_key("org")
        {
            return Err(OperatorAccessTokenError::InvalidToken);
        }
        let claims = OperatorAccessTokenClaims {
            iss: text(&payload, "iss")?.to_owned(),
            sub: identifier(&payload, "sub")?,
            sid: identifier(&payload, "sid")?,
            jti: identifier(&payload, "jti")?,
            cnf_jkt: text(cnf, "jkt")?.to_owned(),
            scope: text(&payload, "scope")?.to_owned(),
            iat: payload
                .get("iat")
                .and_then(Value::as_u64)
                .ok_or(OperatorAccessTokenError::InvalidToken)?,
            exp: payload
                .get("exp")
                .and_then(Value::as_u64)
                .ok_or(OperatorAccessTokenError::InvalidToken)?,
        };
        if claims.iss != trusted.issuer
            || claims.validate().is_err()
            || now < claims.iat
            || now >= claims.exp
        {
            return Err(OperatorAccessTokenError::InvalidToken);
        }
        Ok(VerifiedOperatorAccessToken { claims })
    }
}

/// Explicit trust for Operator signing only; device keyrings are a different type.
pub struct TrustedOperatorAccessTokenKeys {
    issuer: String,
    keys: BTreeMap<String, [u8; 32]>,
}

impl fmt::Debug for TrustedOperatorAccessTokenKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TrustedOperatorAccessTokenKeys([CONFIGURED])")
    }
}

impl TrustedOperatorAccessTokenKeys {
    /// # Errors
    ///
    /// Rejects noncanonical HTTPS issuers.
    pub fn new(issuer: impl Into<String>) -> Result<Self, OperatorAccessTokenError> {
        let issuer = issuer.into();
        validate_origin(&issuer).map_err(|_| OperatorAccessTokenError::InvalidContext)?;
        Ok(Self { issuer, keys: BTreeMap::new() })
    }

    /// # Errors
    ///
    /// Rejects invalid or duplicate key ids and invalid Ed25519 public keys.
    pub fn insert(&mut self, kid: &str, public_key: &[u8]) -> Result<(), OperatorAccessTokenError> {
        if !valid_kid(kid) || self.keys.contains_key(kid) {
            return Err(OperatorAccessTokenError::InvalidContext);
        }
        let key: [u8; 32] =
            public_key.try_into().map_err(|_| OperatorAccessTokenError::InvalidContext)?;
        ed25519_dalek::VerifyingKey::from_bytes(&key)
            .map_err(|_| OperatorAccessTokenError::InvalidContext)?;
        self.keys.insert(kid.to_owned(), key);
        Ok(())
    }
}

pub struct VerifiedOperatorAccessToken {
    claims: OperatorAccessTokenClaims,
}

impl fmt::Debug for VerifiedOperatorAccessToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("VerifiedOperatorAccessToken([STATELESS; NOT AUTHORIZED])")
    }
}

impl VerifiedOperatorAccessToken {
    #[must_use]
    pub fn claims(&self) -> &OperatorAccessTokenClaims {
        &self.claims
    }

    #[must_use]
    pub fn expires_at(&self) -> u64 {
        self.claims.exp
    }
}

fn split_compact(value: &str) -> Result<(&str, &str, &str), OperatorAccessTokenError> {
    if value.is_empty() || value.len() > MAX_OPERATOR_ACCESS_TOKEN_BYTES || !value.is_ascii() {
        return Err(OperatorAccessTokenError::InvalidToken);
    }
    let mut parts = value.split('.');
    let segments = (
        parts.next().ok_or(OperatorAccessTokenError::InvalidToken)?,
        parts.next().ok_or(OperatorAccessTokenError::InvalidToken)?,
        parts.next().ok_or(OperatorAccessTokenError::InvalidToken)?,
    );
    if parts.next().is_some()
        || [segments.0, segments.1, segments.2].into_iter().any(|part| {
            part.is_empty()
                || !part.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
    {
        return Err(OperatorAccessTokenError::InvalidToken);
    }
    Ok(segments)
}

fn decode_segment(value: &str) -> Result<Vec<u8>, OperatorAccessTokenError> {
    dpop::decode_segment(value).map_err(|_| OperatorAccessTokenError::InvalidToken)
}

fn unique_object(bytes: &[u8]) -> Result<Map<String, Value>, OperatorAccessTokenError> {
    dpop::parse_unique_json(bytes)
        .map_err(|_| OperatorAccessTokenError::InvalidToken)?
        .as_object()
        .cloned()
        .ok_or(OperatorAccessTokenError::InvalidToken)
}

fn text<'a>(
    object: &'a Map<String, Value>,
    key: &str,
) -> Result<&'a str, OperatorAccessTokenError> {
    object.get(key).and_then(Value::as_str).ok_or(OperatorAccessTokenError::InvalidToken)
}

fn identifier(object: &Map<String, Value>, key: &str) -> Result<Uuid, OperatorAccessTokenError> {
    let value = text(object, key)?;
    let id = Uuid::parse_str(value).map_err(|_| OperatorAccessTokenError::InvalidToken)?;
    if id.to_string() != value || validate_uuid_v7(id).is_err() {
        return Err(OperatorAccessTokenError::InvalidToken);
    }
    Ok(id)
}
