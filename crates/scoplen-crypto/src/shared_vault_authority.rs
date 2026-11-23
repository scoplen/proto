// SPDX-License-Identifier: Apache-2.0
//! D-171 deployment authority evidence for one Shared vault key wrap.

use ed25519_dalek::Signature;
use scoplen_model::validate_uuid_v7;
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use crate::shared_vault_wrap::verification_key;
use crate::{
    AccountKemKeyPair, Ed25519SigningKey, PrimitiveError, SharedVaultKeyWrap,
    SharedVaultWrapContext, SharedVaultWrapOperation, VaultKey,
};

const VERSION: u8 = 1;
const DOMAIN: &[u8] = b"spl-shared-vault-authority-v1";
const HEADER_SIZE: usize = 9;
const RECEIPT_SIZE: usize = HEADER_SIZE + 64;

/// Independently reviewed receipt context for the intended vault and recipient.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SharedVaultAuthorityContext {
    /// Authorized operation and exact author, recipient, team, vault and epoch.
    pub wrap: SharedVaultWrapContext,
    /// Fresh admission of the recipient to this vault.
    pub recipient_admission: Uuid,
    /// X25519 key from the independently reviewed author publication.
    pub author_kem_key: [u8; 32],
}

impl SharedVaultAuthorityContext {
    fn message(self, sequence: u64, digest: &[u8; 32]) -> Result<Vec<u8>, PrimitiveError> {
        validate_uuid_v7(self.recipient_admission).map_err(|_| PrimitiveError::InvalidEncoding)?;
        if sequence == 0
            || (self.wrap.operation == SharedVaultWrapOperation::Create
                && self.author_kem_key != self.wrap.recipient_kem_key)
        {
            return Err(PrimitiveError::InvalidEncoding);
        }
        let mut message = Vec::from(DOMAIN);
        message.push(VERSION);
        message.extend_from_slice(&sequence.to_be_bytes());
        message.extend_from_slice(self.recipient_admission.as_bytes());
        message.extend_from_slice(&self.wrap.encode()?);
        message.extend_from_slice(&self.author_kem_key);
        message.extend_from_slice(digest);
        Ok(message)
    }
}

/// A locally retained high-water receipt for one deployment, vault, admission and epoch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SharedVaultReceiptPin {
    /// Latest verified Organization audit sequence in this receipt scope.
    pub sequence: u64,
    /// Digest of the exact verified wrap.
    pub wrap_digest: [u8; 32],
}

/// A deployment audit signature attesting to one committed wrap.
#[derive(Clone, PartialEq, Eq)]
pub struct SharedVaultAuthorityReceipt {
    sequence: u64,
    signature: [u8; 64],
}

impl SharedVaultAuthorityReceipt {
    /// Sign the exact wrap and its authorized context for a mutation's audit event.
    ///
    /// The caller establishes current authority and stores the receipt, audit event
    /// and wrap in the same transaction before releasing any artifact.
    ///
    /// # Errors
    /// Rejects invalid context, sequence or author signature.
    pub fn issue(
        expected: &SharedVaultAuthorityContext,
        wrap: &SharedVaultKeyWrap,
        sequence: u64,
        audit_key: &Ed25519SigningKey,
    ) -> Result<Self, PrimitiveError> {
        wrap.verify(&expected.wrap)?;
        let digest = Sha256::digest(wrap.encode()).into();
        let signature = audit_key.sign(&expected.message(sequence, &digest)?);
        Ok(Self { sequence, signature })
    }

    /// Verify historical authority and the caller's local high-water mark before
    /// independently checking the author signature and opening the wrap.
    ///
    /// Pass an audit key already trusted for the deployment and the previously
    /// verified pin for this exact vault, admission and epoch, if one exists.
    ///
    /// # Errors
    /// Rejects substituted evidence, a stale receipt, an invalid wrap or a wrong recipient key.
    pub fn open(
        &self,
        expected: &SharedVaultAuthorityContext,
        wrap: &SharedVaultKeyWrap,
        trusted_audit_key: &[u8; 32],
        previous: Option<SharedVaultReceiptPin>,
        recipient: &AccountKemKeyPair,
    ) -> Result<(VaultKey, SharedVaultReceiptPin), PrimitiveError> {
        let pin = SharedVaultReceiptPin {
            sequence: self.sequence,
            wrap_digest: Sha256::digest(wrap.encode()).into(),
        };
        if previous.is_some_and(|old| {
            old.sequence > pin.sequence
                || (old.sequence == pin.sequence && old.wrap_digest != pin.wrap_digest)
        }) {
            return Err(PrimitiveError::InvalidSignature);
        }
        verification_key(trusted_audit_key)?
            .verify_strict(
                &expected.message(pin.sequence, &pin.wrap_digest)?,
                &Signature::from_bytes(&self.signature),
            )
            .map_err(|_| PrimitiveError::InvalidSignature)?;
        let key = wrap.open(&expected.wrap, recipient)?;
        Ok((key, pin))
    }

    /// Encode the version-one receipt.
    #[must_use]
    pub fn encode(&self) -> [u8; RECEIPT_SIZE] {
        let mut bytes = [0; RECEIPT_SIZE];
        bytes[0] = VERSION;
        bytes[1..HEADER_SIZE].copy_from_slice(&self.sequence.to_be_bytes());
        bytes[HEADER_SIZE..].copy_from_slice(&self.signature);
        bytes
    }

    /// Decode the envelope. The receipt is untrusted until verified.
    ///
    /// # Errors
    /// Rejects an unknown version, wrong size or zero sequence.
    pub fn decode(bytes: &[u8]) -> Result<Self, PrimitiveError> {
        if bytes.len() != RECEIPT_SIZE || bytes[0] != VERSION {
            return Err(PrimitiveError::InvalidEncoding);
        }
        let sequence = u64::from_be_bytes(
            bytes[1..HEADER_SIZE].try_into().map_err(|_| PrimitiveError::InvalidEncoding)?,
        );
        if sequence == 0 {
            return Err(PrimitiveError::InvalidEncoding);
        }
        let signature =
            bytes[HEADER_SIZE..].try_into().map_err(|_| PrimitiveError::InvalidEncoding)?;
        Ok(Self { sequence, signature })
    }
}
