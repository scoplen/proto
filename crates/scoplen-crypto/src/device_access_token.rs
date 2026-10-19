// SPDX-License-Identifier: Apache-2.0
//! Bounded enrolled-device access tokens with a dedicated signing purpose.

use std::{collections::BTreeMap, fmt};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use scoplen_model::validate_uuid_v7;
use serde::Serialize;
use serde_json::{Map, Value};
use thiserror::Error;
use uuid::Uuid;

use crate::{Ed25519SigningKey, device_auth::validate_origin, dpop, ed25519_verify};

pub const MAX_DEVICE_ACCESS_TOKEN_BYTES: usize = 4_096;
pub const DEVICE_ACCESS_TOKEN_LIFETIME_SECONDS: u64 = 600;

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
struct SigningOrganization {
    id: String,
    sso_authenticated_at: Option<u64>,
}

#[derive(Serialize)]
struct SigningPayload<'a> {
    aud: &'static str,
    cnf: SigningConfirmation<'a>,
    did: String,
    exp: u64,
    iat: u64,
    iss: &'a str,
    jti: String,
    org: Vec<SigningOrganization>,
    scope: &'a str,
    sub: String,
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum DeviceAccessTokenError {
    #[error("invalid device access token signing context")]
    InvalidContext,
    #[error("invalid device access token")]
    InvalidToken,
    #[error("device access token signer failed")]
    SignerFailed,
}

/// A fallible Ed25519 signer backed by software or a configured signing service.
pub trait DeviceAccessTokenSigner {
    /// Sign the original two encoded JWS segments and their separating dot.
    ///
    /// # Errors
    ///
    /// Return an error if signing is unavailable; no partial token is issued.
    fn sign(&self, message: &[u8]) -> Result<[u8; 64], DeviceAccessTokenError>;
}

impl DeviceAccessTokenSigner for Ed25519SigningKey {
    fn sign(&self, message: &[u8]) -> Result<[u8; 64], DeviceAccessTokenError> {
        Ok(Ed25519SigningKey::sign(self, message))
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct DeviceOrganizationSnapshot {
    pub id: Uuid,
    pub sso_authenticated_at: Option<u64>,
}

impl fmt::Debug for DeviceOrganizationSnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DeviceOrganizationSnapshot([REDACTED])")
    }
}

/// Complete identity, membership, and scope snapshot supplied from verified issuer state.
#[derive(Clone, Eq, PartialEq)]
pub struct DeviceAccessTokenClaims {
    pub iss: String,
    pub sub: Uuid,
    pub did: Uuid,
    pub jti: Uuid,
    pub cnf_jkt: String,
    pub org: Vec<DeviceOrganizationSnapshot>,
    pub scope: String,
    pub iat: u64,
    pub exp: u64,
}

impl fmt::Debug for DeviceAccessTokenClaims {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DeviceAccessTokenClaims([REDACTED])")
    }
}

impl DeviceAccessTokenClaims {
    /// Validate the complete signed claim profile, before issuance or after verification.
    ///
    /// # Errors
    ///
    /// Rejects invalid identifiers, device binding, membership, scope, or lifetime.
    pub fn validate(&self) -> Result<(), DeviceAccessTokenError> {
        if validate_origin(&self.iss).is_err()
            || [self.sub, self.did, self.jti].into_iter().any(|id| validate_uuid_v7(id).is_err())
            || dpop::decode_fixed_32(&self.cnf_jkt).is_err()
            || !valid_scope(&self.scope)
            || self.iat.checked_add(DEVICE_ACCESS_TOKEN_LIFETIME_SECONDS) != Some(self.exp)
        {
            return Err(DeviceAccessTokenError::InvalidContext);
        }
        let mut previous = None;
        for entry in &self.org {
            if validate_uuid_v7(entry.id).is_err()
                || previous.is_some_and(|id| id >= entry.id)
                || entry.sso_authenticated_at.is_some_and(|at| at > self.iat)
            {
                return Err(DeviceAccessTokenError::InvalidContext);
            }
            previous = Some(entry.id);
        }
        Ok(())
    }
}

/// A syntactically bounded compact JWS. Parsing alone does not authenticate it.
#[derive(Clone, Eq, PartialEq)]
pub struct DeviceAccessToken(String);

impl fmt::Debug for DeviceAccessToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DeviceAccessToken([REDACTED])")
    }
}

impl DeviceAccessToken {
    /// Parse the canonical compact envelope without trusting any claim.
    ///
    /// # Errors
    ///
    /// Rejects oversized, non-ASCII, malformed, or noncanonical segments.
    pub fn parse(value: &str) -> Result<Self, DeviceAccessTokenError> {
        let (header, payload, signature) = split_compact(value)?;
        decode_segment(header)?;
        decode_segment(payload)?;
        if decode_segment(signature)?.len() != 64 {
            return Err(DeviceAccessTokenError::InvalidToken);
        }
        Ok(Self(value.to_owned()))
    }

    /// Sign trusted claims with a dedicated access-token key.
    ///
    /// The device public key must be taken from its verified certificate. The caller must supply
    /// current memberships, permitted scopes, and a fresh `jti` from trusted server state.
    ///
    /// # Errors
    ///
    /// Rejects an invalid snapshot or key, oversized output, and failed or mismatched signing.
    pub fn sign(
        signer: &(impl DeviceAccessTokenSigner + ?Sized),
        signing_keys: &TrustedDeviceAccessTokenKeys,
        kid: &str,
        device_signing_public_key_sec1: &[u8],
        claims: &DeviceAccessTokenClaims,
    ) -> Result<Self, DeviceAccessTokenError> {
        claims.validate()?;
        if claims.iss != signing_keys.issuer
            || !valid_kid(kid)
            || dpop::dpop_jwk_thumbprint(device_signing_public_key_sec1).ok().as_deref()
                != Some(&claims.cnf_jkt)
        {
            return Err(DeviceAccessTokenError::InvalidContext);
        }
        let signing_public_key =
            signing_keys.keys.get(kid).ok_or(DeviceAccessTokenError::InvalidContext)?;
        let org = claims
            .org
            .iter()
            .map(|entry| SigningOrganization {
                id: entry.id.to_string(),
                sso_authenticated_at: entry.sso_authenticated_at,
            })
            .collect();
        let header = SigningHeader { alg: "Ed25519", kid, typ: "spl-device-access+jwt" };
        let payload = SigningPayload {
            aud: "spl-api/1",
            cnf: SigningConfirmation { jkt: &claims.cnf_jkt },
            did: claims.did.to_string(),
            exp: claims.exp,
            iat: claims.iat,
            iss: &claims.iss,
            jti: claims.jti.to_string(),
            org,
            scope: &claims.scope,
            sub: claims.sub.to_string(),
        };
        let header =
            serde_json::to_vec(&header).map_err(|_| DeviceAccessTokenError::InvalidContext)?;
        let payload =
            serde_json::to_vec(&payload).map_err(|_| DeviceAccessTokenError::InvalidContext)?;
        let input =
            format!("{}.{}", URL_SAFE_NO_PAD.encode(header), URL_SAFE_NO_PAD.encode(payload));
        if input.len() + 87 > MAX_DEVICE_ACCESS_TOKEN_BYTES {
            return Err(DeviceAccessTokenError::InvalidContext);
        }
        let signature =
            signer.sign(input.as_bytes()).map_err(|_| DeviceAccessTokenError::SignerFailed)?;
        ed25519_verify(signing_public_key, input.as_bytes(), &signature)
            .map_err(|_| DeviceAccessTokenError::SignerFailed)?;
        Self::parse(&format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature)))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Verify the signed profile using only the dedicated configured keyring and trusted time.
    ///
    /// The result is identity evidence; route authorization, current state, `DPoP`, and replay
    /// checks remain consumer responsibilities.
    ///
    /// # Errors
    ///
    /// Rejects any untrusted key, signature, profile, claim, or time.
    pub fn verify(
        &self,
        trusted: &TrustedDeviceAccessTokenKeys,
        now: u64,
    ) -> Result<VerifiedDeviceAccessToken, DeviceAccessTokenError> {
        let (encoded_header, encoded_payload, encoded_signature) = split_compact(&self.0)?;
        let header = unique_object(&decode_segment(encoded_header)?)?;
        if header.len() != 3
            || header.get("alg").and_then(Value::as_str) != Some("Ed25519")
            || header.get("typ").and_then(Value::as_str) != Some("spl-device-access+jwt")
        {
            return Err(DeviceAccessTokenError::InvalidToken);
        }
        let kid = text(&header, "kid")?;
        if !valid_kid(kid) {
            return Err(DeviceAccessTokenError::InvalidToken);
        }
        let key = trusted.keys.get(kid).ok_or(DeviceAccessTokenError::InvalidToken)?;
        let signature = decode_segment(encoded_signature)?;
        if signature.len() != 64 {
            return Err(DeviceAccessTokenError::InvalidToken);
        }
        let input = format!("{encoded_header}.{encoded_payload}");
        ed25519_verify(key, input.as_bytes(), &signature)
            .map_err(|_| DeviceAccessTokenError::InvalidToken)?;
        let payload = unique_object(&decode_segment(encoded_payload)?)?;
        let cnf = payload
            .get("cnf")
            .and_then(Value::as_object)
            .ok_or(DeviceAccessTokenError::InvalidToken)?;
        if cnf.len() != 1 || payload.get("aud").and_then(Value::as_str) != Some("spl-api/1") {
            return Err(DeviceAccessTokenError::InvalidToken);
        }
        let org = payload
            .get("org")
            .and_then(Value::as_array)
            .ok_or(DeviceAccessTokenError::InvalidToken)?;
        let org = org
            .iter()
            .map(|value| {
                let object = value.as_object().ok_or(DeviceAccessTokenError::InvalidToken)?;
                if object.len() != 2 {
                    return Err(DeviceAccessTokenError::InvalidToken);
                }
                let sso = match object.get("sso_authenticated_at") {
                    Some(Value::Null) => None,
                    Some(value) => {
                        Some(value.as_u64().ok_or(DeviceAccessTokenError::InvalidToken)?)
                    }
                    None => return Err(DeviceAccessTokenError::InvalidToken),
                };
                Ok(DeviceOrganizationSnapshot {
                    id: identifier(object, "id")?,
                    sso_authenticated_at: sso,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let claims = DeviceAccessTokenClaims {
            iss: text(&payload, "iss")?.to_owned(),
            sub: identifier(&payload, "sub")?,
            did: identifier(&payload, "did")?,
            jti: identifier(&payload, "jti")?,
            cnf_jkt: text(cnf, "jkt")?.to_owned(),
            org,
            scope: text(&payload, "scope")?.to_owned(),
            iat: payload
                .get("iat")
                .and_then(Value::as_u64)
                .ok_or(DeviceAccessTokenError::InvalidToken)?,
            exp: payload
                .get("exp")
                .and_then(Value::as_u64)
                .ok_or(DeviceAccessTokenError::InvalidToken)?,
        };
        if claims.iss != trusted.issuer
            || claims.validate().is_err()
            || now < claims.iat
            || now >= claims.exp
        {
            return Err(DeviceAccessTokenError::InvalidToken);
        }
        Ok(VerifiedDeviceAccessToken { claims })
    }
}

/// Configured access-token signing keys, isolated from other signed-object purposes.
pub struct TrustedDeviceAccessTokenKeys {
    issuer: String,
    keys: BTreeMap<String, [u8; 32]>,
}

impl fmt::Debug for TrustedDeviceAccessTokenKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TrustedDeviceAccessTokenKeys([CONFIGURED])")
    }
}

impl TrustedDeviceAccessTokenKeys {
    /// # Errors
    ///
    /// Rejects a noncanonical HTTPS issuer.
    pub fn new(issuer: impl Into<String>) -> Result<Self, DeviceAccessTokenError> {
        let issuer = issuer.into();
        validate_origin(&issuer).map_err(|_| DeviceAccessTokenError::InvalidContext)?;
        Ok(Self { issuer, keys: BTreeMap::new() })
    }

    /// # Errors
    ///
    /// Rejects an invalid or duplicate key identifier or invalid Ed25519 public key.
    pub fn insert(&mut self, kid: &str, public_key: &[u8]) -> Result<(), DeviceAccessTokenError> {
        if !valid_kid(kid) || self.keys.contains_key(kid) {
            return Err(DeviceAccessTokenError::InvalidContext);
        }
        let key: [u8; 32] =
            public_key.try_into().map_err(|_| DeviceAccessTokenError::InvalidContext)?;
        ed25519_dalek::VerifyingKey::from_bytes(&key)
            .map_err(|_| DeviceAccessTokenError::InvalidContext)?;
        self.keys.insert(kid.to_owned(), key);
        Ok(())
    }
}

pub struct VerifiedDeviceAccessToken {
    claims: DeviceAccessTokenClaims,
}

impl fmt::Debug for VerifiedDeviceAccessToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("VerifiedDeviceAccessToken([STATELESS; NOT AUTHORIZED])")
    }
}

impl VerifiedDeviceAccessToken {
    #[must_use]
    pub fn claims(&self) -> &DeviceAccessTokenClaims {
        &self.claims
    }

    #[must_use]
    pub fn expires_at(&self) -> u64 {
        self.claims.exp
    }
}

fn split_compact(value: &str) -> Result<(&str, &str, &str), DeviceAccessTokenError> {
    if value.is_empty() || value.len() > MAX_DEVICE_ACCESS_TOKEN_BYTES || !value.is_ascii() {
        return Err(DeviceAccessTokenError::InvalidToken);
    }
    let mut parts = value.split('.');
    let segments = (
        parts.next().ok_or(DeviceAccessTokenError::InvalidToken)?,
        parts.next().ok_or(DeviceAccessTokenError::InvalidToken)?,
        parts.next().ok_or(DeviceAccessTokenError::InvalidToken)?,
    );
    if parts.next().is_some()
        || [segments.0, segments.1, segments.2].into_iter().any(|part| {
            part.is_empty()
                || !part.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
    {
        return Err(DeviceAccessTokenError::InvalidToken);
    }
    Ok(segments)
}

fn decode_segment(value: &str) -> Result<Vec<u8>, DeviceAccessTokenError> {
    dpop::decode_segment(value).map_err(|_| DeviceAccessTokenError::InvalidToken)
}

fn unique_object(bytes: &[u8]) -> Result<Map<String, Value>, DeviceAccessTokenError> {
    dpop::parse_unique_json(bytes)
        .map_err(|_| DeviceAccessTokenError::InvalidToken)?
        .as_object()
        .cloned()
        .ok_or(DeviceAccessTokenError::InvalidToken)
}

fn text<'a>(object: &'a Map<String, Value>, key: &str) -> Result<&'a str, DeviceAccessTokenError> {
    object.get(key).and_then(Value::as_str).ok_or(DeviceAccessTokenError::InvalidToken)
}

fn identifier(object: &Map<String, Value>, key: &str) -> Result<Uuid, DeviceAccessTokenError> {
    let value = text(object, key)?;
    let id = Uuid::parse_str(value).map_err(|_| DeviceAccessTokenError::InvalidToken)?;
    if id.to_string() != value || validate_uuid_v7(id).is_err() {
        return Err(DeviceAccessTokenError::InvalidToken);
    }
    Ok(id)
}

fn valid_kid(kid: &str) -> bool {
    !kid.is_empty()
        && kid.len() <= 128
        && kid.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
}

fn valid_scope(scope: &str) -> bool {
    if scope.is_empty() || scope.len() > 512 || !scope.is_ascii() {
        return false;
    }
    let tokens: Vec<_> = scope.split(' ').collect();
    if tokens.is_empty() || tokens.len() > 32 {
        return false;
    }
    let mut previous = None;
    for token in tokens {
        if token.is_empty()
            || token.len() > 64
            || !token
                .bytes()
                .all(|b| b == b'!' || (b'#'..=b'[').contains(&b) || (b']'..=b'~').contains(&b))
            || previous.is_some_and(|old| old >= token)
        {
            return false;
        }
        previous = Some(token);
    }
    true
}
