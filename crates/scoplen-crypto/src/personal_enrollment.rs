// SPDX-License-Identifier: Apache-2.0
//! D-101 first-device possession proof for Personal invitation enrollment.

use std::fmt;

use scoplen_model::validate_uuid_v7;
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use uuid::Uuid;

use crate::{DeviceSigner, PrimitiveError, device_auth::validate_origin, p256_verify};

const DOMAIN: &[u8] = b"spl-personal-enroll-v1";
const MAX_KEY_BUNDLE_BYTES: usize = 4 * 1_024 * 1_024;
const MAX_ARTIFACT_BYTES: usize = 65_536;

/// The exact decoded public keys and artifacts bound by an enrollment proof.
///
/// K-4 parsing, revision-1 and sole-wrap checks, K-2 certificate/account signature
/// verification, and the outer JSON body limit remain separate consumer checks.
#[derive(Clone, Copy)]
pub struct PersonalEnrollmentArtifacts<'a> {
    /// Raw Ed25519 account signing public key.
    pub account_signing_public_key: &'a [u8; 32],
    /// Raw X25519 account KEM public key.
    pub account_kem_public_key: &'a [u8; 32],
    /// Exact canonical K-4 key-bundle-update bytes, including its account signature.
    pub key_bundle_update: &'a [u8],
    /// Exact signed K-2 device-certificate bytes.
    pub device_certificate: &'a [u8],
    /// Opaque epoch-1 Personal vault key wrapped to the account root key.
    pub wrapped_personal_vault_key: &'a [u8],
}

impl fmt::Debug for PersonalEnrollmentArtifacts<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PersonalEnrollmentArtifacts([REDACTED])")
    }
}

/// Invalid public context or artifact bounds for the D-101 possession proof.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum PersonalEnrollmentError {
    /// The trusted deployment origin is not canonical HTTPS.
    #[error("Personal enrollment origin must be canonical HTTPS")]
    InvalidOrigin,
    /// An account or Personal vault identifier is not `UUIDv7`.
    #[error("Personal enrollment identifiers must be UUIDv7")]
    InvalidIdentifier,
    /// An artifact is empty or exceeds its existing K-2/K-4 size limit.
    #[error("Personal enrollment artifact length is invalid")]
    InvalidArtifact,
}

/// A bounded, domain-separated first-device possession-signature input.
///
/// This stores the invitation digest rather than its bearer token. Verification
/// proves possession only; it does not redeem an invitation or authenticate a
/// caller to another route.
#[derive(Clone, Eq, PartialEq)]
pub struct PersonalEnrollmentContext {
    input: Vec<u8>,
}

impl PersonalEnrollmentContext {
    /// Bind the trusted origin, decoded invitation token, ids, and exact artifacts.
    ///
    /// # Errors
    ///
    /// Rejects noncanonical origins, non-v7 identifiers, and empty or oversized
    /// artifacts. This does not parse or authenticate the supplied artifacts.
    pub fn new(
        origin: &str,
        invitation_token: &[u8; 32],
        account_id: Uuid,
        personal_vault_id: Uuid,
        artifacts: PersonalEnrollmentArtifacts<'_>,
    ) -> Result<Self, PersonalEnrollmentError> {
        validate_origin(origin).map_err(|_| PersonalEnrollmentError::InvalidOrigin)?;
        validate_uuid_v7(account_id).map_err(|_| PersonalEnrollmentError::InvalidIdentifier)?;
        validate_uuid_v7(personal_vault_id)
            .map_err(|_| PersonalEnrollmentError::InvalidIdentifier)?;
        for (bytes, limit) in [
            (artifacts.key_bundle_update, MAX_KEY_BUNDLE_BYTES),
            (artifacts.device_certificate, MAX_ARTIFACT_BYTES),
            (artifacts.wrapped_personal_vault_key, MAX_ARTIFACT_BYTES),
        ] {
            if bytes.is_empty() || bytes.len() > limit {
                return Err(PersonalEnrollmentError::InvalidArtifact);
            }
        }
        let origin_len =
            u16::try_from(origin.len()).map_err(|_| PersonalEnrollmentError::InvalidOrigin)?;
        let mut input = Vec::with_capacity(DOMAIN.len() + 2 + origin.len() + 224);
        input.extend_from_slice(DOMAIN);
        input.extend_from_slice(&origin_len.to_be_bytes());
        input.extend_from_slice(origin.as_bytes());
        input.extend_from_slice(&Sha256::digest(invitation_token));
        input.extend_from_slice(account_id.as_bytes());
        input.extend_from_slice(personal_vault_id.as_bytes());
        input.extend_from_slice(artifacts.account_signing_public_key);
        input.extend_from_slice(artifacts.account_kem_public_key);
        for bytes in [
            artifacts.key_bundle_update,
            artifacts.device_certificate,
            artifacts.wrapped_personal_vault_key,
        ] {
            input.extend_from_slice(&Sha256::digest(bytes));
        }
        Ok(Self { input })
    }

    /// Return the exact D-101 bytes; callers must not pre-hash them before signing.
    #[must_use]
    pub fn signature_input(&self) -> &[u8] {
        &self.input
    }

    /// Sign the complete input through the fallible device-key boundary.
    ///
    /// # Errors
    ///
    /// Propagates software or platform signer failures without a fallback key.
    pub fn sign(&self, signer: &dyn DeviceSigner) -> Result<[u8; 64], PrimitiveError> {
        signer.sign(self.signature_input())
    }

    /// Verify the fixed-width possession signature with the certified P-256 key.
    ///
    /// The caller first verifies the account-signed device certificate and binds
    /// its account and device ids to the enrollment and sole K-4 device wrap.
    ///
    /// # Errors
    ///
    /// Rejects malformed keys/signatures and any change to the signed context.
    pub fn verify(&self, certified_key: &[u8], signature: &[u8]) -> Result<(), PrimitiveError> {
        p256_verify(certified_key, self.signature_input(), signature)
    }
}

impl fmt::Debug for PersonalEnrollmentContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PersonalEnrollmentContext([REDACTED])")
    }
}
