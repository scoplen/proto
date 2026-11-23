// SPDX-License-Identifier: Apache-2.0
//! D-171 authenticated forms of the Shared vault epoch key.

use ed25519_dalek::{Signature, VerifyingKey};
use scoplen_model::validate_uuid_v7;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::AccountKemKeyPair;
use crate::{Ed25519SigningKey, PrimitiveError, VaultKey, hpke_open_account, hpke_seal_account};

const VERSION: u8 = 1;
const WRAP_DOMAIN: &[u8] = b"spl-shared-vault-wrap-v1";
const SIGNATURE_DOMAIN: &[u8] = b"spl-shared-vault-wrap-signature-v1";
const ENCAPSULATION_END: usize = 1 + 32;
const CIPHERTEXT_END: usize = ENCAPSULATION_END + 48;
const WRAP_SIZE: usize = CIPHERTEXT_END + 64;

/// The operation authorized to publish this wrap.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum SharedVaultWrapOperation {
    /// Create the vault and publish its first key to its creator.
    Create = 1,
    /// Admit a second Account to one served epoch.
    Admit = 2,
    /// Publish the next epoch to a current recipient.
    PublishEpoch = 3,
}

/// Account and Membership facts from a reviewed key publication.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SharedVaultWrapParty {
    /// Account whose keys the publication identifies.
    pub account: Uuid,
    /// Exact native Membership in the owning Organization.
    pub membership: Uuid,
    /// Positive Account key publication revision.
    pub revision: u64,
    /// Ed25519 public key from that publication.
    pub signing_key: [u8; 32],
}

/// Expected context reconstructed from authorized mutation or historical evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SharedVaultWrapContext {
    /// Authorized publication operation.
    pub operation: SharedVaultWrapOperation,
    /// Immutable owning Organization.
    pub organization: Uuid,
    /// Vault being created or administered.
    pub vault: Uuid,
    /// Positive epoch of the key being wrapped.
    pub epoch: u32,
    /// Publication of the authorized author.
    pub author: SharedVaultWrapParty,
    /// Publication of the authorized recipient.
    pub recipient: SharedVaultWrapParty,
    /// X25519 public key from the recipient publication.
    pub recipient_kem_key: [u8; 32],
}

impl SharedVaultWrapContext {
    pub(super) fn encode(self) -> Result<Vec<u8>, PrimitiveError> {
        for id in [
            self.organization,
            self.vault,
            self.author.account,
            self.author.membership,
            self.recipient.account,
            self.recipient.membership,
        ] {
            validate_uuid_v7(id).map_err(|_| PrimitiveError::InvalidEncoding)?;
        }
        let valid_operation = match self.operation {
            SharedVaultWrapOperation::Create => self.epoch == 1 && self.author == self.recipient,
            SharedVaultWrapOperation::Admit => {
                self.author.account != self.recipient.account
                    && self.author.membership != self.recipient.membership
            }
            SharedVaultWrapOperation::PublishEpoch => self.epoch > 1,
        };
        if self.epoch == 0
            || self.author.revision == 0
            || self.recipient.revision == 0
            || !valid_operation
        {
            return Err(PrimitiveError::InvalidEncoding);
        }
        let mut context = Vec::from(WRAP_DOMAIN);
        context.extend_from_slice(&[VERSION, self.operation as u8]);
        context.extend_from_slice(self.organization.as_bytes());
        context.extend_from_slice(self.vault.as_bytes());
        context.extend_from_slice(&self.epoch.to_be_bytes());
        for party in [self.author, self.recipient] {
            verification_key(&party.signing_key)?;
            context.extend_from_slice(party.account.as_bytes());
            context.extend_from_slice(party.membership.as_bytes());
            context.extend_from_slice(&party.revision.to_be_bytes());
            context.extend_from_slice(&party.signing_key);
        }
        context.extend_from_slice(&self.recipient_kem_key);
        Ok(context)
    }
}

/// One opaque K-2 wrap. Its context and authority are established separately.
#[derive(Clone, PartialEq, Eq)]
pub struct SharedVaultKeyWrap([u8; WRAP_SIZE]);

impl SharedVaultKeyWrap {
    /// Encrypt an epoch key to a reviewed recipient and sign the result.
    ///
    /// # Errors
    /// Returns an error for an invalid context, a mismatching signing key or an HPKE failure.
    pub fn seal(
        expected: &SharedVaultWrapContext,
        author: &Ed25519SigningKey,
        key: &VaultKey,
    ) -> Result<Self, PrimitiveError> {
        let context = expected.encode()?;
        if author.public_key() != expected.author.signing_key {
            return Err(PrimitiveError::InvalidKey);
        }
        let encrypted =
            hpke_seal_account(&expected.recipient_kem_key, &context, &context, key.as_ref())?;
        let mut bytes = [0; WRAP_SIZE];
        bytes[0] = VERSION;
        bytes[1..ENCAPSULATION_END].copy_from_slice(&encrypted.encapsulated_key);
        bytes[ENCAPSULATION_END..CIPHERTEXT_END].copy_from_slice(&encrypted.ciphertext);
        let signature = author.sign(&signature_input(&context, &bytes[1..CIPHERTEXT_END]));
        bytes[CIPHERTEXT_END..].copy_from_slice(&signature);
        Ok(Self(bytes))
    }

    /// Verify authorship and the exact expected context without opening the key.
    ///
    /// # Errors
    /// Returns an error for an invalid context, key or signature.
    pub fn verify(&self, expected: &SharedVaultWrapContext) -> Result<(), PrimitiveError> {
        self.verify_signature(&expected.author.signing_key, &expected.encode()?)
    }

    /// Verify authorship before opening the key with the intended recipient's private key.
    ///
    /// # Errors
    /// Returns an error if the context, signature, recipient key or HPKE authentication fails.
    pub fn open(
        &self,
        expected: &SharedVaultWrapContext,
        recipient: &AccountKemKeyPair,
    ) -> Result<VaultKey, PrimitiveError> {
        let context = expected.encode()?;
        self.verify_signature(&expected.author.signing_key, &context)?;
        if recipient.public_key() != expected.recipient_kem_key {
            return Err(PrimitiveError::InvalidKey);
        }
        let plaintext = Zeroizing::new(hpke_open_account(
            recipient,
            &self.0[1..ENCAPSULATION_END],
            &context,
            &context,
            &self.0[ENCAPSULATION_END..CIPHERTEXT_END],
        )?);
        VaultKey::from_slice(&plaintext).ok_or(PrimitiveError::InvalidEncoding)
    }

    /// Return the fixed-length version-one artifact.
    #[must_use]
    pub fn encode(&self) -> [u8; WRAP_SIZE] {
        self.0
    }

    /// Parse the envelope without trusting any of its contents.
    ///
    /// # Errors
    /// Returns an error for a wrong length or unknown version.
    pub fn decode(bytes: &[u8]) -> Result<Self, PrimitiveError> {
        let bytes: [u8; WRAP_SIZE] =
            bytes.try_into().map_err(|_| PrimitiveError::InvalidEncoding)?;
        if bytes[0] != VERSION {
            return Err(PrimitiveError::InvalidEncoding);
        }
        Ok(Self(bytes))
    }

    fn verify_signature(
        &self,
        public_key: &[u8; 32],
        context: &[u8],
    ) -> Result<(), PrimitiveError> {
        let signature = Signature::from_slice(&self.0[CIPHERTEXT_END..])
            .map_err(|_| PrimitiveError::InvalidSignature)?;
        verification_key(public_key)?
            .verify_strict(&signature_input(context, &self.0[1..CIPHERTEXT_END]), &signature)
            .map_err(|_| PrimitiveError::InvalidSignature)
    }
}

pub(super) fn verification_key(bytes: &[u8; 32]) -> Result<VerifyingKey, PrimitiveError> {
    let key = VerifyingKey::from_bytes(bytes).map_err(|_| PrimitiveError::InvalidKey)?;
    if key.is_weak() {
        return Err(PrimitiveError::InvalidKey);
    }
    Ok(key)
}

fn signature_input(context: &[u8], encrypted: &[u8]) -> Vec<u8> {
    let mut message = Vec::from(SIGNATURE_DOMAIN);
    message.extend_from_slice(context);
    message.extend_from_slice(encrypted);
    message
}
