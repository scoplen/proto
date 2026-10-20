// SPDX-License-Identifier: Apache-2.0
//! Versioned account hierarchy artifacts carried as opaque K-4 bytes.

use ed25519_dalek::VerifyingKey;
use scoplen_model::validate_uuid_v7;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{
    AccountKemKeyPair, AccountRootKey, DeviceKemKeyPair, Ed25519SigningKey, PrimitiveError,
    SecretBytes, VaultKey, XChaChaNonce, hkdf_sha256, hpke_open_device, hpke_seal_device,
    random_nonce, xchacha20poly1305_open, xchacha20poly1305_seal,
};

const VERSION: u8 = 1;
const DEVICE_ARK_DOMAIN: &[u8] = b"spl-device-ark-v1";
const ACCOUNT_SIGNING_DOMAIN: &[u8] = b"spl-account-signing-key-v1";
const ACCOUNT_KEM_DOMAIN: &[u8] = b"spl-account-kem-key-v1";
const PERSONAL_VAULT_DOMAIN: &[u8] = b"spl-personal-vault-key-v1";
const AEAD_ARTIFACT_LEN: usize = 1 + 24 + 48;
const DEVICE_ARK_ARTIFACT_LEN: usize = 1 + 65 + 48;

fn valid_id(id: Uuid) -> Result<(), PrimitiveError> {
    validate_uuid_v7(id).map_err(|_| PrimitiveError::InvalidEncoding)
}

fn account_context(domain: &[u8], account_id: Uuid, public_key: &[u8]) -> Vec<u8> {
    let mut context = Vec::with_capacity(domain.len() + 1 + 16 + public_key.len());
    context.extend_from_slice(domain);
    context.push(VERSION);
    context.extend_from_slice(account_id.as_bytes());
    context.extend_from_slice(public_key);
    context
}

fn derive_account_key(
    ark: &AccountRootKey,
    account_id: Uuid,
    info: &[u8],
) -> Result<SecretBytes<32>, PrimitiveError> {
    let bytes = Zeroizing::new(hkdf_sha256(ark.as_ref(), Some(account_id.as_bytes()), info, 32)?);
    SecretBytes::from_slice(&bytes).ok_or(PrimitiveError::InvalidKey)
}

#[derive(Clone, PartialEq, Eq)]
struct AeadArtifact {
    nonce: XChaChaNonce,
    ciphertext: [u8; 48],
}

impl AeadArtifact {
    fn seal(
        key: &SecretBytes<32>,
        plaintext: &[u8; 32],
        aad: &[u8],
    ) -> Result<Self, PrimitiveError> {
        let nonce = random_nonce()?;
        let ciphertext = xchacha20poly1305_seal(key, &nonce, plaintext, aad)?;
        Ok(Self {
            nonce,
            ciphertext: ciphertext.try_into().map_err(|_| PrimitiveError::InvalidEncoding)?,
        })
    }

    fn open(&self, key: &SecretBytes<32>, aad: &[u8]) -> Result<SecretBytes<32>, PrimitiveError> {
        let plaintext =
            Zeroizing::new(xchacha20poly1305_open(key, &self.nonce, &self.ciphertext, aad)?);
        SecretBytes::from_slice(&plaintext).ok_or(PrimitiveError::InvalidEncoding)
    }

    fn encode(&self) -> [u8; AEAD_ARTIFACT_LEN] {
        let mut bytes = [0; AEAD_ARTIFACT_LEN];
        bytes[0] = VERSION;
        bytes[1..25].copy_from_slice(self.nonce.as_ref());
        bytes[25..].copy_from_slice(&self.ciphertext);
        bytes
    }

    fn decode(bytes: &[u8]) -> Result<Self, PrimitiveError> {
        if bytes.len() != AEAD_ARTIFACT_LEN || bytes[0] != VERSION {
            return Err(PrimitiveError::InvalidEncoding);
        }
        Ok(Self {
            nonce: XChaChaNonce::from_slice(&bytes[1..25])
                .ok_or(PrimitiveError::InvalidEncoding)?,
            ciphertext: bytes[25..].try_into().map_err(|_| PrimitiveError::InvalidEncoding)?,
        })
    }
}

/// A versioned P-256 HPKE wrapping of one account root key to a certified device.
#[derive(Clone, PartialEq, Eq)]
pub struct DeviceArkWrap {
    encapsulated_key: [u8; 65],
    ciphertext: [u8; 48],
}

impl DeviceArkWrap {
    /// Seal the ARK to one device, binding the account, device, and recipient key.
    ///
    /// # Errors
    /// Returns an error for invalid ids or recipient keys, or if HPKE sealing fails.
    pub fn seal(
        account_id: Uuid,
        device_id: Uuid,
        recipient_public_key: &[u8],
        ark: &AccountRootKey,
    ) -> Result<Self, PrimitiveError> {
        valid_id(account_id)?;
        valid_id(device_id)?;
        valid_device_public_key(recipient_public_key)?;
        let context = device_ark_context(account_id, device_id, recipient_public_key);
        let wrapped = hpke_seal_device(recipient_public_key, &context, &context, ark.as_ref())?;
        Ok(Self {
            encapsulated_key: wrapped
                .encapsulated_key
                .try_into()
                .map_err(|_| PrimitiveError::InvalidEncoding)?,
            ciphertext: wrapped
                .ciphertext
                .try_into()
                .map_err(|_| PrimitiveError::InvalidEncoding)?,
        })
    }

    /// Open only with the named device's private key and the original account context.
    ///
    /// # Errors
    /// Returns an error for invalid ids, a mismatched context, or failed HPKE authentication.
    pub fn open(
        &self,
        account_id: Uuid,
        device_id: Uuid,
        recipient: &DeviceKemKeyPair,
    ) -> Result<AccountRootKey, PrimitiveError> {
        valid_id(account_id)?;
        valid_id(device_id)?;
        let context = device_ark_context(account_id, device_id, recipient.public_key());
        let plaintext = Zeroizing::new(hpke_open_device(
            recipient,
            &self.encapsulated_key,
            &context,
            &context,
            &self.ciphertext,
        )?);
        SecretBytes::from_slice(&plaintext).ok_or(PrimitiveError::InvalidEncoding)
    }

    /// Return the exact 114-byte K-2 artifact.
    #[must_use]
    pub fn encode(&self) -> [u8; DEVICE_ARK_ARTIFACT_LEN] {
        let mut bytes = [0; DEVICE_ARK_ARTIFACT_LEN];
        bytes[0] = VERSION;
        bytes[1..66].copy_from_slice(&self.encapsulated_key);
        bytes[66..].copy_from_slice(&self.ciphertext);
        bytes
    }

    /// Decode the exact version-1 layout and validate its encapsulated P-256 key.
    ///
    /// # Errors
    /// Returns an error for a wrong length, unknown version, or malformed public key.
    pub fn decode(bytes: &[u8]) -> Result<Self, PrimitiveError> {
        if bytes.len() != DEVICE_ARK_ARTIFACT_LEN || bytes[0] != VERSION {
            return Err(PrimitiveError::InvalidEncoding);
        }
        valid_device_public_key(&bytes[1..66])?;
        Ok(Self {
            encapsulated_key: bytes[1..66]
                .try_into()
                .map_err(|_| PrimitiveError::InvalidEncoding)?,
            ciphertext: bytes[66..].try_into().map_err(|_| PrimitiveError::InvalidEncoding)?,
        })
    }
}

fn valid_device_public_key(bytes: &[u8]) -> Result<(), PrimitiveError> {
    if bytes.len() != 65 || bytes[0] != 4 {
        return Err(PrimitiveError::InvalidKey);
    }
    p256::PublicKey::from_sec1_bytes(bytes).map_err(|_| PrimitiveError::InvalidKey)?;
    Ok(())
}

fn device_ark_context(account_id: Uuid, device_id: Uuid, recipient_key: &[u8]) -> Vec<u8> {
    let mut context = account_context(DEVICE_ARK_DOMAIN, account_id, &[]);
    context.extend_from_slice(device_id.as_bytes());
    context.extend_from_slice(recipient_key);
    context
}

/// A versioned ARK-encrypted Ed25519 account signing seed.
#[derive(Clone, PartialEq, Eq)]
pub struct AccountSigningKeyWrap(AeadArtifact);

impl AccountSigningKeyWrap {
    /// Seal a software account signing key under a purpose-specific ARK-derived key.
    ///
    /// # Errors
    /// Returns an error for an invalid account id or failed key derivation or encryption.
    pub fn seal(
        account_id: Uuid,
        ark: &AccountRootKey,
        signing: &Ed25519SigningKey,
    ) -> Result<Self, PrimitiveError> {
        valid_id(account_id)?;
        let context = account_context(ACCOUNT_SIGNING_DOMAIN, account_id, &signing.public_key());
        let key = derive_account_key(ark, account_id, ACCOUNT_SIGNING_DOMAIN)?;
        Ok(Self(AeadArtifact::seal(&key, signing.private_key_bytes().as_bytes(), &context)?))
    }

    /// Open and require the reconstructed signing public key to match the expected key.
    ///
    /// # Errors
    /// Returns an error for invalid context or public key, failed authentication, or a key mismatch.
    pub fn open(
        &self,
        account_id: Uuid,
        ark: &AccountRootKey,
        expected_public_key: &[u8; 32],
    ) -> Result<Ed25519SigningKey, PrimitiveError> {
        valid_id(account_id)?;
        VerifyingKey::from_bytes(expected_public_key).map_err(|_| PrimitiveError::InvalidKey)?;
        let context = account_context(ACCOUNT_SIGNING_DOMAIN, account_id, expected_public_key);
        let key = derive_account_key(ark, account_id, ACCOUNT_SIGNING_DOMAIN)?;
        let seed = self.0.open(&key, &context)?;
        let signing = Ed25519SigningKey::from_bytes(seed.as_ref())?;
        if signing.public_key() != *expected_public_key {
            return Err(PrimitiveError::InvalidKey);
        }
        Ok(signing)
    }

    /// Return the exact 73-byte K-2 artifact.
    #[must_use]
    pub fn encode(&self) -> [u8; AEAD_ARTIFACT_LEN] {
        self.0.encode()
    }

    /// Decode the exact version-1 layout.
    ///
    /// # Errors
    /// Returns an error for a wrong length or unknown version.
    pub fn decode(bytes: &[u8]) -> Result<Self, PrimitiveError> {
        Ok(Self(AeadArtifact::decode(bytes)?))
    }
}

/// A versioned ARK-encrypted X25519 account KEM private key.
#[derive(Clone, PartialEq, Eq)]
pub struct AccountKemKeyWrap(AeadArtifact);

impl AccountKemKeyWrap {
    /// Seal a software account KEM key under a distinct ARK-derived key.
    ///
    /// # Errors
    /// Returns an error for an invalid account id or failed key derivation or encryption.
    pub fn seal(
        account_id: Uuid,
        ark: &AccountRootKey,
        kem: &AccountKemKeyPair,
    ) -> Result<Self, PrimitiveError> {
        valid_id(account_id)?;
        let public_key: [u8; 32] =
            kem.public_key().try_into().map_err(|_| PrimitiveError::InvalidKey)?;
        let context = account_context(ACCOUNT_KEM_DOMAIN, account_id, &public_key);
        let key = derive_account_key(ark, account_id, ACCOUNT_KEM_DOMAIN)?;
        Ok(Self(AeadArtifact::seal(&key, kem.private_key_bytes().as_bytes(), &context)?))
    }

    /// Open and require the reconstructed KEM public key to match the expected key.
    ///
    /// # Errors
    /// Returns an error for invalid context, failed authentication, or a key mismatch.
    pub fn open(
        &self,
        account_id: Uuid,
        ark: &AccountRootKey,
        expected_public_key: &[u8; 32],
    ) -> Result<AccountKemKeyPair, PrimitiveError> {
        valid_id(account_id)?;
        let context = account_context(ACCOUNT_KEM_DOMAIN, account_id, expected_public_key);
        let key = derive_account_key(ark, account_id, ACCOUNT_KEM_DOMAIN)?;
        let private = self.0.open(&key, &context)?;
        let kem = AccountKemKeyPair::from_private_bytes(private.as_ref())?;
        if kem.public_key() != expected_public_key {
            return Err(PrimitiveError::InvalidKey);
        }
        Ok(kem)
    }

    /// Return the exact 73-byte K-2 artifact.
    #[must_use]
    pub fn encode(&self) -> [u8; AEAD_ARTIFACT_LEN] {
        self.0.encode()
    }

    /// Decode the exact version-1 layout.
    ///
    /// # Errors
    /// Returns an error for a wrong length or unknown version.
    pub fn decode(bytes: &[u8]) -> Result<Self, PrimitiveError> {
        Ok(Self(AeadArtifact::decode(bytes)?))
    }
}

/// A versioned Personal vault epoch key encrypted under the ARK.
#[derive(Clone, PartialEq, Eq)]
pub struct PersonalVaultKeyWrap(AeadArtifact);

impl PersonalVaultKeyWrap {
    /// Seal one Personal vault epoch under a vault-specific ARK-derived key.
    ///
    /// # Errors
    /// Returns an error for invalid ids or epoch, or failed key derivation or encryption.
    pub fn seal(
        account_id: Uuid,
        vault_id: Uuid,
        epoch: u32,
        ark: &AccountRootKey,
        vault_key: &VaultKey,
    ) -> Result<Self, PrimitiveError> {
        let (info, context) = personal_contexts(account_id, vault_id, epoch)?;
        let key = derive_account_key(ark, account_id, &info)?;
        Ok(Self(AeadArtifact::seal(&key, vault_key.as_bytes(), &context)?))
    }

    /// Open only for the original account, Personal vault, and positive epoch.
    ///
    /// # Errors
    /// Returns an error for invalid ids or epoch, or failed key derivation or authentication.
    pub fn open(
        &self,
        account_id: Uuid,
        vault_id: Uuid,
        epoch: u32,
        ark: &AccountRootKey,
    ) -> Result<VaultKey, PrimitiveError> {
        let (info, context) = personal_contexts(account_id, vault_id, epoch)?;
        let key = derive_account_key(ark, account_id, &info)?;
        self.0.open(&key, &context)
    }

    /// Return the exact 73-byte K-2 artifact.
    #[must_use]
    pub fn encode(&self) -> [u8; AEAD_ARTIFACT_LEN] {
        self.0.encode()
    }

    /// Decode the exact version-1 layout.
    ///
    /// # Errors
    /// Returns an error for a wrong length or unknown version.
    pub fn decode(bytes: &[u8]) -> Result<Self, PrimitiveError> {
        Ok(Self(AeadArtifact::decode(bytes)?))
    }
}

fn personal_contexts(
    account_id: Uuid,
    vault_id: Uuid,
    epoch: u32,
) -> Result<(Vec<u8>, Vec<u8>), PrimitiveError> {
    valid_id(account_id)?;
    valid_id(vault_id)?;
    if epoch == 0 {
        return Err(PrimitiveError::InvalidEncoding);
    }
    let mut info = Vec::with_capacity(PERSONAL_VAULT_DOMAIN.len() + 20);
    info.extend_from_slice(PERSONAL_VAULT_DOMAIN);
    info.extend_from_slice(vault_id.as_bytes());
    info.extend_from_slice(&epoch.to_be_bytes());
    let mut context = account_context(PERSONAL_VAULT_DOMAIN, account_id, &[]);
    context.extend_from_slice(vault_id.as_bytes());
    context.extend_from_slice(&epoch.to_be_bytes());
    Ok((info, context))
}
