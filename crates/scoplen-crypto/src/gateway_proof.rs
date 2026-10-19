// SPDX-License-Identifier: Apache-2.0
//! Stateless raw-TLS application proof bound to one signed gateway ticket.

use std::fmt;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;
use thiserror::Error;

use crate::{
    DeviceSigner, GatewayTicket, TrustedGatewayTicketKeys, VerifiedGatewayTicket, dpop,
    p256_verify, random_bytes,
};

/// Maximum compact JWS length for one raw-TLS gateway possession proof.
pub const MAX_GATEWAY_PROOF_BYTES: usize = 8_192;

/// A gateway proof or its signing context is invalid.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum GatewayProofError {
    /// The ticket envelope or supplied device key is invalid for construction.
    #[error("invalid gateway proof signing context")]
    InvalidContext,
    /// The ticket, proof, signature, key binding, or time is invalid.
    #[error("invalid gateway proof")]
    InvalidProof,
    /// The selected device signer failed or returned a signature from another key.
    #[error("gateway proof signer failed")]
    SignerFailed,
    /// Operating-system randomness was unavailable.
    #[error("gateway proof identifier generation failed")]
    RandomnessFailed,
}

/// A bounded compact JWS. Parsing alone does not establish trust or possession.
#[derive(Clone, Eq, PartialEq)]
pub struct GatewayProof(String);

impl fmt::Debug for GatewayProof {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GatewayProof([REDACTED])")
    }
}

impl GatewayProof {
    /// Parse the bounded canonical compact-JWS envelope without trusting its contents.
    ///
    /// # Errors
    ///
    /// Rejects non-ASCII, malformed, padded, oversized, or noncanonical segments and signatures.
    pub fn parse(value: &str) -> Result<Self, GatewayProofError> {
        let (header, payload, signature) = compact_parts(value)?;
        let _ = decode(header)?;
        let _ = decode(payload)?;
        if decode(signature)?.len() != 64 {
            return Err(GatewayProofError::InvalidProof);
        }
        Ok(Self(value.to_owned()))
    }

    /// Sign a fresh raw-TLS proof for the exact ticket bytes with the device `DPoP` key.
    ///
    /// The ticket envelope is checked, but its issuer, claims, and lifetime are verified by the
    /// receiving edge. The public key must belong to the selected fallible device signer.
    ///
    /// # Errors
    ///
    /// Rejects invalid context, unavailable randomness, oversized output, and signer failures.
    pub fn sign(
        signer: &(impl DeviceSigner + ?Sized),
        public_key_sec1: &[u8],
        ticket: &GatewayTicket,
        iat: u64,
    ) -> Result<Self, GatewayProofError> {
        GatewayTicket::parse(ticket.as_str()).map_err(|_| GatewayProofError::InvalidContext)?;
        let jwk = dpop::PublicJwk::from_sec1(public_key_sec1)
            .map_err(|_| GatewayProofError::InvalidContext)?;
        let mut jti = [0_u8; 16];
        random_bytes(&mut jti).map_err(|_| GatewayProofError::RandomnessFailed)?;
        let header = json!({
            "alg": "ES256",
            "jwk": {"crv":"P-256", "kty":"EC", "x":jwk.x, "y":jwk.y},
            "typ": "spl-gw-proof+jwt"
        });
        let payload = json!({
            "ath": ticket_hash(ticket),
            "aud": "spl-gw/1",
            "iat": iat,
            "jti": URL_SAFE_NO_PAD.encode(jti)
        });
        let header = serde_json::to_vec(&header).map_err(|_| GatewayProofError::InvalidContext)?;
        let payload =
            serde_json::to_vec(&payload).map_err(|_| GatewayProofError::InvalidContext)?;
        let input =
            format!("{}.{}", URL_SAFE_NO_PAD.encode(header), URL_SAFE_NO_PAD.encode(payload));
        // A 64-byte signature is 86 base64url bytes, followed by one separator.
        if input.len() + 87 > MAX_GATEWAY_PROOF_BYTES {
            return Err(GatewayProofError::InvalidContext);
        }
        let signature =
            signer.sign(input.as_bytes()).map_err(|_| GatewayProofError::SignerFailed)?;
        p256_verify(public_key_sec1, input.as_bytes(), &signature)
            .map_err(|_| GatewayProofError::SignerFailed)?;
        Self::parse(&format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature)))
    }

    /// Return the exact proof for transport. Never log this value.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Verify the trusted ticket first, then this proof's signature and binding to it.
    ///
    /// The returned evidence is stateless. The edge still needs current authorization, exact SSH
    /// key use, and an atomic `(iss, ticket.jti)` replay claim before forwarding SSH bytes.
    ///
    /// # Errors
    ///
    /// Rejects an invalid ticket or proof without exposing their contents.
    pub fn verify(
        &self,
        ticket: &GatewayTicket,
        trusted: &TrustedGatewayTicketKeys,
        now: u64,
    ) -> Result<VerifiedGatewayProof, GatewayProofError> {
        let verified_ticket =
            ticket.verify(trusted, now).map_err(|_| GatewayProofError::InvalidProof)?;
        let (encoded_header, encoded_payload, encoded_signature) = compact_parts(&self.0)?;
        let header = unique_object(&decode(encoded_header)?)?;
        if header.get("typ").and_then(Value::as_str) != Some("spl-gw-proof+jwt")
            || header.get("alg").and_then(Value::as_str) != Some("ES256")
            || ["jku", "x5u", "x5c", "crit", "b64"]
                .into_iter()
                .any(|name| header.contains_key(name))
        {
            return Err(GatewayProofError::InvalidProof);
        }
        let jwk =
            dpop::PublicJwk::from_value(header.get("jwk").ok_or(GatewayProofError::InvalidProof)?)
                .map_err(|_| GatewayProofError::InvalidProof)?;
        let expected_jkt = fixed_hash(&verified_ticket.claims().cnf_jkt)?;
        let actual_jkt = fixed_hash(&jwk.thumbprint())?;
        if !bool::from(actual_jkt.ct_eq(&expected_jkt)) {
            return Err(GatewayProofError::InvalidProof);
        }
        let signature = decode(encoded_signature)?;
        if signature.len() != 64 {
            return Err(GatewayProofError::InvalidProof);
        }
        let signing_input = format!("{encoded_header}.{encoded_payload}");
        p256_verify(&jwk.sec1, signing_input.as_bytes(), &signature)
            .map_err(|_| GatewayProofError::InvalidProof)?;

        let payload = unique_object(&decode(encoded_payload)?)?;
        if payload.get("aud").and_then(Value::as_str) != Some("spl-gw/1")
            || ["htm", "htu", "nonce"].into_iter().any(|name| payload.contains_key(name))
        {
            return Err(GatewayProofError::InvalidProof);
        }
        let ath =
            payload.get("ath").and_then(Value::as_str).ok_or(GatewayProofError::InvalidProof)?;
        let actual_ath = fixed_hash(ath)?;
        let expected_ath: [u8; 32] = Sha256::digest(ticket.as_str().as_bytes()).into();
        if !bool::from(actual_ath.ct_eq(&expected_ath)) {
            return Err(GatewayProofError::InvalidProof);
        }
        let jti =
            payload.get("jti").and_then(Value::as_str).ok_or(GatewayProofError::InvalidProof)?;
        if decode(jti)?.len() != 16 {
            return Err(GatewayProofError::InvalidProof);
        }
        let iat =
            payload.get("iat").and_then(Value::as_u64).ok_or(GatewayProofError::InvalidProof)?;
        if iat < verified_ticket.claims().iat || iat > now {
            return Err(GatewayProofError::InvalidProof);
        }
        Ok(VerifiedGatewayProof { ticket: verified_ticket, jti: jti.to_owned(), iat })
    }
}

/// Trusted ticket and proof evidence only; authorization and replay remain consumer checks.
pub struct VerifiedGatewayProof {
    ticket: VerifiedGatewayTicket,
    jti: String,
    iat: u64,
}

impl fmt::Debug for VerifiedGatewayProof {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("VerifiedGatewayProof([STATELESS; REPLAY NOT CLAIMED])")
    }
}

impl VerifiedGatewayProof {
    #[must_use]
    pub fn ticket(&self) -> &VerifiedGatewayTicket {
        &self.ticket
    }

    #[must_use]
    pub fn proof_jti(&self) -> &str {
        &self.jti
    }

    #[must_use]
    pub const fn proof_issued_at(&self) -> u64 {
        self.iat
    }

    #[must_use]
    pub const fn expires_at(&self) -> u64 {
        self.ticket.expires_at()
    }
}

fn compact_parts(value: &str) -> Result<(&str, &str, &str), GatewayProofError> {
    if value.is_empty() || value.len() > MAX_GATEWAY_PROOF_BYTES || !value.is_ascii() {
        return Err(GatewayProofError::InvalidProof);
    }
    let mut parts = value.split('.');
    let segments = (
        parts.next().ok_or(GatewayProofError::InvalidProof)?,
        parts.next().ok_or(GatewayProofError::InvalidProof)?,
        parts.next().ok_or(GatewayProofError::InvalidProof)?,
    );
    if parts.next().is_some()
        || [segments.0, segments.1, segments.2].into_iter().any(|part| {
            part.is_empty()
                || !part.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
    {
        return Err(GatewayProofError::InvalidProof);
    }
    Ok(segments)
}

fn decode(value: &str) -> Result<Vec<u8>, GatewayProofError> {
    dpop::decode_segment(value).map_err(|_| GatewayProofError::InvalidProof)
}

fn fixed_hash(value: &str) -> Result<[u8; 32], GatewayProofError> {
    dpop::decode_fixed_32(value).map_err(|_| GatewayProofError::InvalidProof)
}

fn unique_object(bytes: &[u8]) -> Result<serde_json::Map<String, Value>, GatewayProofError> {
    dpop::parse_unique_json(bytes)
        .map_err(|_| GatewayProofError::InvalidProof)?
        .as_object()
        .cloned()
        .ok_or(GatewayProofError::InvalidProof)
}

fn ticket_hash(ticket: &GatewayTicket) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(ticket.as_str().as_bytes()))
}
