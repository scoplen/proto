// SPDX-License-Identifier: Apache-2.0
//! D-128 deployment probe derivations, exact Account signatures and fresh Device proofs.

use std::fmt;

use hmac::{Hmac, Mac as _};
use p256::{PublicKey, elliptic_curve::sec1::ToSec1Point as _};
use scoplen_model::validate_uuid_v7;
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use uuid::Uuid;
use zeroize::Zeroize as _;

use crate::{
    DeviceSigner, Ed25519SigningKey, PrimitiveError, SecretBytes, ed25519_verify, p256_verify,
};

/// The independent, deployment-wide 32-byte D-128 probe secret.
///
/// Consumers generate and durably protect it once; loading this key neither initializes nor
/// rotates it. Copies held by this container are zeroized on drop and redacted in `Debug`.
pub struct AccountProbeKey(SecretBytes<32>);

impl AccountProbeKey {
    /// Load an existing probe key without deriving it from other Account or token material.
    ///
    /// # Errors
    /// Rejects any key length other than exactly 32 bytes.
    pub fn new(bytes: &[u8]) -> Result<Self, AccountRequestError> {
        Ok(Self(SecretBytes::from_slice(bytes).ok_or(AccountRequestError)?))
    }

    /// Stable public 16-byte salt for an unknown, inactive or retired canonical username.
    ///
    /// # Errors
    /// Rejects noncanonical origins or usernames without normalizing either value.
    pub fn synthetic_salt(
        &self,
        origin: &str,
        username: &str,
    ) -> Result<[u8; 16], AccountRequestError> {
        let full = self.derive(b"spl-account-synthetic-salt-v1", origin, username)?;
        let mut salt = [0; 16];
        salt.copy_from_slice(&full[..16]);
        Ok(salt)
    }

    /// Stable synthetic verifier used for the common password-denial path.
    ///
    /// # Errors
    /// Rejects noncanonical origins or usernames without normalizing either value.
    pub fn synthetic_verifier(
        &self,
        origin: &str,
        username: &str,
    ) -> Result<SecretBytes<32>, AccountRequestError> {
        self.derive(b"spl-account-synthetic-verifier-v1", origin, username)
    }

    /// Private keyed username identity for durable per-endpoint admission buckets.
    ///
    /// Endpoint/window selection and durable debt remain consumer responsibilities.
    /// # Errors
    /// Rejects noncanonical origins or usernames without normalizing either value.
    pub fn username_admission_identity(
        &self,
        origin: &str,
        username: &str,
    ) -> Result<SecretBytes<32>, AccountRequestError> {
        self.derive(b"spl-account-admission-username-v1", origin, username)
    }

    fn derive(
        &self,
        domain: &[u8],
        origin: &str,
        username: &str,
    ) -> Result<SecretBytes<32>, AccountRequestError> {
        crate::password_bootstrap::validate_identity(origin, username)
            .map_err(|_| AccountRequestError)?;
        let mut mac = Hmac::<Sha256>::new_from_slice(self.0.as_ref())
            .expect("HMAC-SHA256 accepts the fixed 32-byte probe key");
        mac.update(domain);
        for text in [origin, username] {
            let length = u16::try_from(text.len()).map_err(|_| AccountRequestError)?;
            mac.update(&length.to_be_bytes());
            mac.update(text.as_bytes());
        }
        let mut output = mac.finalize().into_bytes();
        let result = SecretBytes::from_slice(&output).expect("fixed HMAC-SHA256 output length");
        output.as_mut_slice().zeroize();
        Ok(result)
    }
}

impl fmt::Debug for AccountProbeKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AccountProbeKey([REDACTED])")
    }
}

/// The stable Account operation domain, independent of the fresh request intent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccountRequestKind {
    /// Initial Account, Personal vault and first Device creation.
    Register,
    /// One independently authenticated fresh Device admission.
    Admit,
}

impl AccountRequestKind {
    /// Exact native JSON spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Register => "register",
            Self::Admit => "admit",
        }
    }

    fn domain(self) -> &'static [u8] {
        match self {
            Self::Register => b"spl-account-register-v1",
            Self::Admit => b"spl-account-device-admit-v1",
        }
    }

    fn tag(self) -> u8 {
        match self {
            Self::Register => 1,
            Self::Admit => 2,
        }
    }
}

/// A fresh request either submits business state or confirms an exact historical receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccountRequestIntent {
    /// Only this intent may enter a new business mutation.
    Submit,
    /// An absent receipt leaves the original outcome unknown; never creates state.
    Confirm,
}

impl AccountRequestIntent {
    /// Exact native JSON spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Submit => "submit",
            Self::Confirm => "confirm",
        }
    }

    fn tag(self) -> u8 {
        match self {
            Self::Submit => 1,
            Self::Confirm => 2,
        }
    }
}

/// Redacted invalid signature-input context.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("invalid Account request context")]
pub struct AccountRequestError;

/// The complete domain-separated stable Account-signature input.
///
/// Its constructor bounds opaque bytes; the API codec separately verifies protected CBOR.
#[derive(Clone, Eq, PartialEq)]
pub struct AccountRequestSignatureInput(Vec<u8>);

impl AccountRequestSignatureInput {
    /// Prefix the exact retained protected bytes without parsing or reconstructing them.
    ///
    /// # Errors
    /// Rejects empty bytes or the corresponding complete protected-payload limit.
    pub fn new(kind: AccountRequestKind, payload: &[u8]) -> Result<Self, AccountRequestError> {
        let limit = match kind {
            AccountRequestKind::Register => 262_144,
            AccountRequestKind::Admit => 4_325_376,
        };
        if payload.is_empty() || payload.len() > limit {
            return Err(AccountRequestError);
        }
        let mut input = Vec::with_capacity(kind.domain().len() + payload.len());
        input.extend_from_slice(kind.domain());
        input.extend_from_slice(payload);
        Ok(Self(input))
    }

    /// Exact Ed25519 input, with no caller prehash or trailing NUL.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Sign through the Account root, in addition to certificate and K-4 signatures.
    #[must_use]
    pub fn sign(&self, signer: &Ed25519SigningKey) -> [u8; 64] {
        signer.sign(&self.0)
    }

    /// Verify against the trusted current root, or the original immutable receipt root.
    ///
    /// # Errors
    /// Propagates malformed keys or failed Ed25519 verification.
    pub fn verify(
        &self,
        public_key: &[u8; 32],
        signature: &[u8; 64],
    ) -> Result<(), PrimitiveError> {
        ed25519_verify(public_key, &self.0, signature)
    }

    /// Stable digest covers the exact Account signature and business bytes only.
    #[must_use]
    pub fn request_digest(&self, account_signature: &[u8; 64]) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(&self.0);
        hash.update(account_signature);
        hash.finalize().into()
    }
}

impl fmt::Debug for AccountRequestSignatureInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AccountRequestSignatureInput([REDACTED])")
    }
}

/// A fresh domain-separated Device proof binding stable bytes and explicit request intent.
#[derive(Clone, Eq, PartialEq)]
pub struct AccountRequestProof(Vec<u8>);

impl AccountRequestProof {
    /// Assemble the exact D-128 `proof_input` through a validated canonical context.
    ///
    /// # Errors
    /// Rejects noncanonical HTTPS origins or non-v7 identifiers.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        kind: AccountRequestKind,
        intent: AccountRequestIntent,
        origin: &str,
        attempt_id: &[u8; 32],
        nonce: &[u8; 32],
        operation_id: Uuid,
        device_id: Uuid,
        request_digest: &[u8; 32],
    ) -> Result<Self, AccountRequestError> {
        crate::validate_server_origin(origin).map_err(|_| AccountRequestError)?;
        validate_uuid_v7(operation_id).map_err(|_| AccountRequestError)?;
        validate_uuid_v7(device_id).map_err(|_| AccountRequestError)?;
        let length = u16::try_from(origin.len()).map_err(|_| AccountRequestError)?;
        let mut input = Vec::with_capacity(160 + origin.len());
        input.extend_from_slice(b"spl-account-request-proof-v1");
        input.extend_from_slice(&[kind.tag(), intent.tag()]);
        input.extend_from_slice(&length.to_be_bytes());
        input.extend_from_slice(origin.as_bytes());
        input.extend_from_slice(attempt_id);
        input.extend_from_slice(nonce);
        input.extend_from_slice(operation_id.as_bytes());
        input.extend_from_slice(device_id.as_bytes());
        input.extend_from_slice(request_digest);
        Ok(Self(input))
    }

    /// Original P-256/SHA-256 input; callers must not prehash it.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Sign with the independent fallible Device signer, without software fallback.
    ///
    /// # Errors
    /// Propagates signer errors unchanged.
    pub fn sign(&self, signer: &dyn DeviceSigner) -> Result<[u8; 64], PrimitiveError> {
        signer.sign(&self.0)
    }

    /// Verify possession of the signing key certified by the Account.
    ///
    /// This supplies no proof of the separate KEM private key or current authorization.
    /// # Errors
    /// Rejects malformed keys/signatures and changed proof bindings.
    pub fn verify(&self, certified_key: &[u8], signature: &[u8; 64]) -> Result<(), PrimitiveError> {
        p256_verify(certified_key, &self.0, signature)
    }
}

impl fmt::Debug for AccountRequestProof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AccountRequestProof([REDACTED])")
    }
}

/// Normalize accepted SEC1 P-256 points before cross-role freshness comparisons.
///
/// Preserve original signed certificate bytes separately.
/// # Errors
/// Rejects malformed or off-curve points through the existing P-256 implementation.
pub fn canonical_device_public_key(bytes: &[u8]) -> Result<[u8; 65], PrimitiveError> {
    let key = PublicKey::from_sec1_bytes(bytes).map_err(|_| PrimitiveError::InvalidKey)?;
    key.to_sec1_point(false).as_bytes().try_into().map_err(|_| PrimitiveError::InvalidKey)
}

/// Digest of an already validated exact complete bootstrap snapshot.
#[must_use]
pub fn account_bootstrap_digest(bytes: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"spl-account-bootstrap-v1");
    hash.update(bytes);
    hash.finalize().into()
}

/// One-way admission capability binding; the raw bearer is never retained in a receipt.
#[must_use]
pub fn account_capability_digest(token: &[u8; 32]) -> [u8; 32] {
    Sha256::digest(token).into()
}
