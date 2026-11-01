// SPDX-License-Identifier: Apache-2.0
//! D-136 separate team invitation password and context-bound verifier.

use std::fmt;

use scoplen_model::validate_uuid_v7;
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use uuid::Uuid;
use zeroize::{Zeroize as _, Zeroizing};

use crate::{SecretBytes, random_bytes, validate_server_origin};

const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const DOMAIN: &[u8] = b"spl-team-invitation-v1";

/// Input-free failures for the separate team invitation password profile.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum TeamInvitationError {
    /// The password is not exactly eight canonical uppercase Crockford symbols.
    #[error("invalid team invitation password")]
    InvalidPassword,
    /// The origin or either identifier is outside its canonical profile.
    #[error("invalid team invitation context")]
    InvalidContext,
    /// The operating system could not provide random bytes; no fallback is used.
    #[error("team invitation randomness unavailable")]
    Randomness,
}

/// An eight-symbol invitation password, zeroized on drop and redacted in `Debug`.
///
/// This authorizes only the fixed recipient's team invitation, never Account login or keys.
#[derive(Clone, Eq, PartialEq)]
pub struct TeamInvitationPassword(SecretBytes<8>);

impl TeamInvitationPassword {
    /// Parse exactly eight uppercase Crockford symbols without normalization or aliases.
    ///
    /// # Errors
    /// Rejects every other length or alphabet without retaining the input.
    pub fn parse(bytes: &[u8]) -> Result<Self, TeamInvitationError> {
        if bytes.len() != 8 || !bytes.iter().all(|byte| ALPHABET.contains(byte)) {
            return Err(TeamInvitationError::InvalidPassword);
        }
        SecretBytes::from_slice(bytes).map(Self).ok_or(TeamInvitationError::InvalidPassword)
    }

    /// Generate eight independent uniform symbols using the operating-system CSPRNG.
    ///
    /// # Errors
    /// Returns an input-free error if randomness is unavailable, without a fallback.
    pub fn generate() -> Result<Self, TeamInvitationError> {
        let mut bytes = Zeroizing::new([0; 8]);
        random_bytes(bytes.as_mut()).map_err(|_| TeamInvitationError::Randomness)?;
        for byte in bytes.iter_mut() {
            *byte = ALPHABET[usize::from(*byte & 31)];
        }
        Ok(Self(SecretBytes::new(*bytes)))
    }

    /// Borrow the password for its explicit transient transfer or encrypted pending operation.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 8] {
        self.0.as_bytes()
    }

    /// Derive the exact domain-separated verifier bound to one origin, team and invitation.
    ///
    /// The caller obtains the canonical origin and ids from its captured operation, not from
    /// untrusted response state. This does not establish current Account or team authority.
    ///
    /// # Errors
    /// Rejects a noncanonical HTTPS origin or a non-v7/RFC-variant identifier before hashing.
    pub fn verifier(
        &self,
        origin: &str,
        organization_id: &Uuid,
        invitation_id: &Uuid,
    ) -> Result<TeamInvitationVerifier, TeamInvitationError> {
        validate_server_origin(origin).map_err(|_| TeamInvitationError::InvalidContext)?;
        validate_uuid_v7(*organization_id).map_err(|_| TeamInvitationError::InvalidContext)?;
        validate_uuid_v7(*invitation_id).map_err(|_| TeamInvitationError::InvalidContext)?;
        let length =
            u16::try_from(origin.len()).map_err(|_| TeamInvitationError::InvalidContext)?;
        let mut hash = Sha256::new();
        hash.update(DOMAIN);
        hash.update(length.to_be_bytes());
        hash.update(origin.as_bytes());
        hash.update(organization_id.as_bytes());
        hash.update(invitation_id.as_bytes());
        hash.update(self.as_bytes());
        let mut digest: [u8; 32] = hash.finalize().into();
        let verifier = TeamInvitationVerifier::from_bytes(digest);
        digest.zeroize();
        Ok(verifier)
    }
}

impl fmt::Debug for TeamInvitationPassword {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TeamInvitationPassword([REDACTED])")
    }
}

/// A sensitive 32-byte invitation verifier with constant-time equality and zeroizing storage.
///
/// Loading a verifier neither authenticates an Account nor grants membership. The caller must
/// enforce the invitation's fixed recipient, current authorization, expiry and attempt limits.
#[derive(Clone, Eq, PartialEq)]
pub struct TeamInvitationVerifier(SecretBytes<32>);

impl TeamInvitationVerifier {
    /// Load the exact verifier bytes from a validated wire value or protected server storage.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(SecretBytes::new(bytes))
    }

    /// Borrow the verifier for its explicit wire encoding or durable protected storage.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }
}

impl fmt::Debug for TeamInvitationVerifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TeamInvitationVerifier([REDACTED])")
    }
}
