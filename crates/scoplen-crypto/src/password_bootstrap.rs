// SPDX-License-Identifier: Apache-2.0
//! D-127 password bootstrap. This authenticates encrypted key material, not its freshness.

use std::fmt;

use argon2::{Algorithm, Argon2, Block, Params, Version};
use chacha20poly1305::{AeadInPlace, KeyInit, Tag, XChaCha20Poly1305, XNonce};
use ed25519_dalek::VerifyingKey;
use hkdf::Hkdf;
use hpke::{Deserializable, Kem, kem::X25519HkdfSha256};
use scoplen_model::validate_uuid_v7;
use sha2::{Digest, Sha256};
use thiserror::Error;
use unicode_normalization::UnicodeNormalization;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    AccountKemKeyWrap, AccountKeys, AccountRootKey, AccountSigningKeyWrap, SecretBytes, SecretVec,
    random_bytes, validate_server_origin,
};

/// The only D-127 profile: Unicode 17 NFC and Argon2id v19, 64 MiB, three passes, four lanes.
pub const PASSWORD_BOOTSTRAP_PROFILE: u8 = 1;
/// Exact version-1 password-protected ARK artifact length.
pub const PASSWORD_ARK_WRAP_BYTES: usize = 73;

const VERSION: u8 = 1;
const RAW_PASSWORD_BYTES: usize = 2048;
const PASSWORD_BYTES: usize = 512;
const MIN_PASSWORD_SCALARS: usize = 15;
const MAX_PASSWORD_SCALARS: usize = 128;
const KDF_DOMAIN: &[u8] = b"spl-password-kdf-v1";
const AUTH_DOMAIN: &[u8] = b"spl-password-auth-v1";
const KEK_DOMAIN: &[u8] = b"spl-password-kek-v1";
const ARK_DOMAIN: &[u8] = b"spl-password-ark-v1";

// A dependency upgrade must preserve the profile's tables or deliberately introduce a new profile.
const _: () = assert!(
    unicode_normalization::UNICODE_VERSION.0 == 17
        && unicode_normalization::UNICODE_VERSION.1 == 0
        && unicode_normalization::UNICODE_VERSION.2 == 0
);

/// Input-free errors for password derivation and encrypted bootstrap opening.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum PasswordBootstrapError {
    /// The original password is too large, invalid UTF-8, or outside the NFC scalar/byte limits.
    #[error("invalid account password encoding or length")]
    InvalidPassword,
    /// Origin, username, salt, ids, generation, or public roots are malformed.
    #[error("invalid password bootstrap context")]
    InvalidContext,
    /// An unsupported KDF profile was supplied.
    #[error("unsupported password bootstrap profile")]
    UnsupportedProfile,
    /// An artifact has an unknown version or an incorrect length.
    #[error("invalid password bootstrap artifact")]
    InvalidEncoding,
    /// Randomness, bounded allocation, or fixed-profile derivation failed; there is no fallback.
    #[error("password bootstrap cryptographic resource failure")]
    Resource,
    /// A wrong password, changed context, tag, or reconstructed root failed authentication.
    #[error("password bootstrap authentication failed")]
    Authentication,
}

/// Normalize an owned, strict UTF-8 password with the fixed Unicode 17 NFC profile.
///
/// The original and collected output buffers are zeroized on all return paths. The maintained
/// normalizer's private iterator scratch and library/compiler/OS copies are not guaranteed erased.
///
/// # Errors
/// Returns an input-free error for malformed UTF-8, more than 2,048 original bytes, or NFC output
/// outside 15..=128 scalars and 512 bytes. Recoverable allocation failure aborts normalization.
pub fn normalize_account_password(
    password: SecretVec,
) -> Result<SecretVec, PasswordBootstrapError> {
    let mut normalized = Zeroizing::new(Vec::new());
    normalize_into(&password, &mut normalized)?;
    drop(password);
    Ok(SecretVec::new(std::mem::take(&mut *normalized)))
}

fn normalize_into(
    password: &SecretVec,
    normalized: &mut Zeroizing<Vec<u8>>,
) -> Result<(), PasswordBootstrapError> {
    let result = (|| {
        if password.len() > RAW_PASSWORD_BYTES {
            return Err(PasswordBootstrapError::InvalidPassword);
        }
        let text = std::str::from_utf8(password.as_bytes())
            .map_err(|_| PasswordBootstrapError::InvalidPassword)?;
        normalized
            .try_reserve_exact(PASSWORD_BYTES)
            .map_err(|_| PasswordBootstrapError::Resource)?;
        let mut count = 0;
        let mut encoded = Zeroizing::new([0; 4]);
        for scalar in text.nfc() {
            count += 1;
            if count > MAX_PASSWORD_SCALARS || normalized.len() + scalar.len_utf8() > PASSWORD_BYTES
            {
                return Err(PasswordBootstrapError::InvalidPassword);
            }
            normalized.extend_from_slice(scalar.encode_utf8(&mut *encoded).as_bytes());
            encoded.zeroize();
        }
        if count < MIN_PASSWORD_SCALARS {
            return Err(PasswordBootstrapError::InvalidPassword);
        }
        Ok(())
    })();
    if result.is_err() {
        normalized.zeroize();
    }
    result
}

/// Validated stored public inputs to the fixed password KDF.
#[derive(Clone, PartialEq, Eq)]
pub struct PasswordKdfContext {
    origin: String,
    username: String,
    salt: [u8; 16],
}

impl PasswordKdfContext {
    /// Validate stored context without allocating or executing Argon2.
    ///
    /// # Errors
    /// Rejects a noncanonical HTTPS origin or username, unknown profile, and non-16-byte salt.
    pub fn new(
        origin: &str,
        username: &str,
        profile: u8,
        salt: &[u8],
    ) -> Result<Self, PasswordBootstrapError> {
        if profile != PASSWORD_BOOTSTRAP_PROFILE {
            return Err(PasswordBootstrapError::UnsupportedProfile);
        }
        validate_identity(origin, username)?;
        let salt = salt.try_into().map_err(|_| PasswordBootstrapError::InvalidContext)?;
        Ok(Self { origin: origin.into(), username: username.into(), salt })
    }

    /// Trusted expected origin, preserved exactly.
    #[must_use]
    pub fn origin(&self) -> &str {
        &self.origin
    }

    /// Canonical deployment-local username, preserved exactly.
    #[must_use]
    pub fn username(&self) -> &str {
        &self.username
    }

    /// Stored public 16-byte salt.
    #[must_use]
    pub const fn salt(&self) -> &[u8; 16] {
        &self.salt
    }

    /// The supported single-byte profile identifier.
    #[must_use]
    pub const fn profile(&self) -> u8 {
        PASSWORD_BOOTSTRAP_PROFILE
    }

    /// Exact `C` bytes used as the HKDF extract salt and in both expand labels.
    #[must_use]
    pub fn derivation_context(&self) -> Vec<u8> {
        let mut bytes = KDF_DOMAIN.to_vec();
        bytes.push(PASSWORD_BOOTSTRAP_PROFILE);
        append_identity(&mut bytes, self);
        bytes.extend_from_slice(&self.salt);
        bytes
    }

    /// Derive authentication and wrapping secrets from an owned password and validated inputs.
    ///
    /// # Errors
    /// Rejects an invalid password or resource failure. The profile cannot be weakened or retried.
    pub fn derive(&self, password: SecretVec) -> Result<PasswordSecrets, PasswordBootstrapError> {
        let normalized = normalize_account_password(password)?;
        let material = password_material(&normalized, &self.salt)?;
        expand_secrets(self, &material)
    }
}

impl fmt::Debug for PasswordKdfContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PasswordKdfContext { metadata: [REDACTED] }")
    }
}

fn validate_identity(origin: &str, username: &str) -> Result<(), PasswordBootstrapError> {
    validate_server_origin(origin).map_err(|_| PasswordBootstrapError::InvalidContext)?;
    if !(3..=64).contains(&username.len())
        || (!username.as_bytes()[0].is_ascii_lowercase()
            && !username.as_bytes()[0].is_ascii_digit())
        || !username.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
    {
        return Err(PasswordBootstrapError::InvalidContext);
    }
    Ok(())
}

fn append_identity(bytes: &mut Vec<u8>, context: &PasswordKdfContext) {
    for text in [&context.origin, &context.username] {
        bytes.extend_from_slice(
            &u16::try_from(text.len()).expect("validated LP16 length").to_be_bytes(),
        );
        bytes.extend_from_slice(text.as_bytes());
    }
}

struct PasswordWorkspace(Zeroizing<Vec<Block>>);

impl PasswordWorkspace {
    fn new() -> Result<Self, PasswordBootstrapError> {
        let mut memory = Zeroizing::new(Vec::new());
        memory
            .try_reserve_exact(password_params().block_count())
            .map_err(|_| PasswordBootstrapError::Resource)?;
        memory.resize(password_params().block_count(), Block::new());
        Ok(Self(memory))
    }

    fn derive(
        &mut self,
        password: &[u8],
        salt: &[u8],
        output: &mut [u8],
    ) -> Result<(), PasswordBootstrapError> {
        let result = Argon2::new(Algorithm::Argon2id, Version::V0x13, password_params())
            .hash_password_into_with_memory(password, salt, output, self.0.as_mut_slice());
        // Keep the allocation alive only until the caller returns, but erase before examining errors.
        for block in &mut *self.0 {
            block.zeroize();
        }
        if result.is_err() {
            output.zeroize();
        }
        result.map_err(|_| PasswordBootstrapError::Resource)
    }
}

fn password_params() -> Params {
    Params::new(65_536, 3, 4, Some(32)).expect("fixed D-127 Argon2id parameters")
}

fn password_material(
    password: &SecretVec,
    salt: &[u8; 16],
) -> Result<SecretBytes<32>, PasswordBootstrapError> {
    let mut output = Zeroizing::new([0; 32]);
    PasswordWorkspace::new()?.derive(password.as_bytes(), salt, output.as_mut_slice())?;
    Ok(SecretBytes::new(*output))
}

fn expand_secrets(
    context: &PasswordKdfContext,
    material: &SecretBytes<32>,
) -> Result<PasswordSecrets, PasswordBootstrapError> {
    let bytes = context.derivation_context();
    let (mut prk, hkdf) = Hkdf::<Sha256>::extract(Some(&bytes), material.as_ref());
    prk.as_mut_slice().zeroize();
    let mut auth = Zeroizing::new([0; 32]);
    let mut kek = Zeroizing::new([0; 32]);
    for (domain, output) in [(AUTH_DOMAIN, &mut *auth), (KEK_DOMAIN, &mut *kek)] {
        let mut info = domain.to_vec();
        info.extend_from_slice(&bytes);
        hkdf.expand(&info, output).map_err(|_| PasswordBootstrapError::Resource)?;
    }
    Ok(PasswordSecrets {
        context: context.clone(),
        auth_secret: SecretBytes::new(*auth),
        kek: SecretBytes::new(*kek),
    })
}

/// Transient password-equivalent authentication material and a private bootstrap KEK.
///
/// This is not a PAKE. The authentication secret must only cross D128's reviewed native TLS boundary.
/// Upstream Argon2/HKDF/normalizer scratch and compiler or OS copies may outlive owned buffers.
pub struct PasswordSecrets {
    context: PasswordKdfContext,
    auth_secret: SecretBytes<32>,
    kek: SecretBytes<32>,
}

impl PasswordSecrets {
    /// Create a new credential, generating its salt internally from the OS CSPRNG.
    ///
    /// # Errors
    /// Rejects invalid context/password, randomness failure, or fixed-profile resource failure.
    pub fn create(
        origin: &str,
        username: &str,
        password: SecretVec,
    ) -> Result<Self, PasswordBootstrapError> {
        validate_identity(origin, username)?;
        let mut salt = [0; 16];
        random_bytes(&mut salt).map_err(|_| PasswordBootstrapError::Resource)?;
        PasswordKdfContext::new(origin, username, PASSWORD_BOOTSTRAP_PROFILE, &salt)?
            .derive(password)
    }

    /// Validated public inputs that must accompany the credential.
    #[must_use]
    pub const fn context(&self) -> &PasswordKdfContext {
        &self.context
    }

    /// Borrow the transient raw authentication secret; never persist or log it.
    #[must_use]
    pub const fn auth_secret(&self) -> &SecretBytes<32> {
        &self.auth_secret
    }

    /// Compute the only server-side password verifier, SHA-256 of the raw authentication secret.
    #[must_use]
    pub fn verifier(&self) -> PasswordVerifier {
        PasswordVerifier(hash_auth_secret(self.auth_secret.as_ref()))
    }

    /// Open the ARK and both D108 Account artifacts, requiring both reconstructed public roots.
    ///
    /// # Errors
    /// Returns the same authentication error for password, AEAD/context, and private-root failure.
    /// This does not prove the credential generation is current or authorize device admission.
    pub fn open_bootstrap(
        &self,
        context: &PasswordBootstrapContext,
        envelope: &PasswordArkWrap,
        signing: &AccountSigningKeyWrap,
        kem: &AccountKemKeyWrap,
    ) -> Result<PasswordBootstrap, PasswordBootstrapError> {
        let ark = envelope.open(self, context)?;
        let signing = signing
            .open(context.account_id, &ark, &context.signing_public_key)
            .map_err(|_| PasswordBootstrapError::Authentication)?;
        let kem = kem
            .open(context.account_id, &ark, &context.kem_public_key)
            .map_err(|_| PasswordBootstrapError::Authentication)?;
        Ok(PasswordBootstrap { ark, keys: AccountKeys { signing, kem } })
    }
}

impl fmt::Debug for PasswordSecrets {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PasswordSecrets { secrets: [REDACTED] }")
    }
}

fn hash_auth_secret(bytes: &[u8]) -> SecretBytes<32> {
    let mut digest = Sha256::digest(bytes);
    let result = SecretBytes::from_slice(digest.as_slice()).expect("SHA-256 output length");
    digest.as_mut_slice().zeroize();
    result
}

/// Exactly 32 secret-bearing verifier bytes suitable for server persistence, with redacted Debug.
#[derive(PartialEq, Eq)]
pub struct PasswordVerifier(SecretBytes<32>);

impl PasswordVerifier {
    /// Read an exact-length stored verifier.
    ///
    /// # Errors
    /// Rejects any length other than 32 bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PasswordBootstrapError> {
        Ok(Self(SecretBytes::from_slice(bytes).ok_or(PasswordBootstrapError::InvalidEncoding)?))
    }

    /// Borrow the raw digest for protected persistence, never logs or frontend IPC.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }

    /// Hash an owned transient `AuthSecret` and compare its digest in constant time.
    ///
    /// # Errors
    /// Returns a uniform authentication error for a wrong length or a different secret.
    pub fn verify(&self, presented: SecretVec) -> Result<(), PasswordBootstrapError> {
        let authenticated =
            presented.len() == 32 && self.0 == hash_auth_secret(presented.as_bytes());
        drop(presented);
        if !authenticated {
            return Err(PasswordBootstrapError::Authentication);
        }
        Ok(())
    }
}

impl fmt::Debug for PasswordVerifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PasswordVerifier { digest: [REDACTED] }")
    }
}

/// Complete, validated public metadata authenticated by a password ARK envelope.
#[derive(Clone, PartialEq, Eq)]
pub struct PasswordBootstrapContext {
    kdf: PasswordKdfContext,
    account_id: Uuid,
    personal_vault_id: Uuid,
    signing_public_key: [u8; 32],
    kem_public_key: [u8; 32],
    generation: u64,
}

impl PasswordBootstrapContext {
    /// Validate ids, generation, and the two exact-width public roots before any KDF allocation.
    ///
    /// # Errors
    /// Rejects invalid `UUIDv7` ids, zero generation, or malformed Ed25519/HPKE public encodings.
    pub fn new(
        kdf: PasswordKdfContext,
        account_id: Uuid,
        personal_vault_id: Uuid,
        signing_public_key: &[u8],
        kem_public_key: &[u8],
        generation: u64,
    ) -> Result<Self, PasswordBootstrapError> {
        validate_uuid_v7(account_id).map_err(|_| PasswordBootstrapError::InvalidContext)?;
        validate_uuid_v7(personal_vault_id).map_err(|_| PasswordBootstrapError::InvalidContext)?;
        if generation == 0 {
            return Err(PasswordBootstrapError::InvalidContext);
        }
        let signing_public_key =
            signing_public_key.try_into().map_err(|_| PasswordBootstrapError::InvalidContext)?;
        VerifyingKey::from_bytes(&signing_public_key)
            .map_err(|_| PasswordBootstrapError::InvalidContext)?;
        <X25519HkdfSha256 as Kem>::PublicKey::from_bytes(kem_public_key)
            .map_err(|_| PasswordBootstrapError::InvalidContext)?;
        let kem_public_key =
            kem_public_key.try_into().map_err(|_| PasswordBootstrapError::InvalidContext)?;
        Ok(Self {
            kdf,
            account_id,
            personal_vault_id,
            signing_public_key,
            kem_public_key,
            generation,
        })
    }

    /// Exact public `AAD` bytes. No serialization or normalization is applied to the metadata.
    #[must_use]
    pub fn aad(&self) -> Vec<u8> {
        let mut bytes = ARK_DOMAIN.to_vec();
        bytes.push(VERSION);
        append_identity(&mut bytes, &self.kdf);
        bytes.extend_from_slice(self.account_id.as_bytes());
        bytes.extend_from_slice(self.personal_vault_id.as_bytes());
        bytes.extend_from_slice(&self.signing_public_key);
        bytes.extend_from_slice(&self.kem_public_key);
        bytes.extend_from_slice(&self.generation.to_be_bytes());
        bytes.push(PASSWORD_BOOTSTRAP_PROFILE);
        bytes.extend_from_slice(&self.kdf.salt);
        bytes
    }

    /// Parse all three artifacts before deriving, then return only a fully authenticated bootstrap.
    ///
    /// # Errors
    /// Rejects malformed artifacts before Argon2, and otherwise returns derivation or uniform
    /// authentication failure. Trusted freshness and device admission remain caller obligations.
    pub fn derive_and_open(
        &self,
        password: SecretVec,
        envelope: &[u8],
        signing: &[u8],
        kem: &[u8],
    ) -> Result<PasswordBootstrap, PasswordBootstrapError> {
        let envelope = PasswordArkWrap::decode(envelope)?;
        let signing = AccountSigningKeyWrap::decode(signing)
            .map_err(|_| PasswordBootstrapError::InvalidEncoding)?;
        let kem =
            AccountKemKeyWrap::decode(kem).map_err(|_| PasswordBootstrapError::InvalidEncoding)?;
        self.kdf.derive(password)?.open_bootstrap(self, &envelope, &signing, &kem)
    }
}

impl fmt::Debug for PasswordBootstrapContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PasswordBootstrapContext { metadata: [REDACTED] }")
    }
}

/// A tag-authenticated ARK with both Account roots reconstructed from D108 artifacts.
///
/// This type proves neither freshness nor account login/device admission authority.
#[derive(Debug)]
pub struct PasswordBootstrap {
    ark: AccountRootKey,
    keys: AccountKeys,
}

impl PasswordBootstrap {
    /// Borrow the existing random ARK after both Account root checks succeeded.
    #[must_use]
    pub const fn ark(&self) -> &AccountRootKey {
        &self.ark
    }

    /// Borrow the private Account keys with public roots equal to the authenticated context.
    #[must_use]
    pub const fn keys(&self) -> &AccountKeys {
        &self.keys
    }

    /// Transfer the authenticated ARK and Account keys into protected caller-owned storage.
    #[must_use]
    pub fn into_parts(self) -> (AccountRootKey, AccountKeys) {
        (self.ark, self.keys)
    }
}

/// The exact version + 24-byte nonce + 32-byte ARK ciphertext + 16-byte tag artifact.
#[derive(Clone, PartialEq, Eq)]
pub struct PasswordArkWrap {
    nonce: [u8; 24],
    ciphertext: [u8; 32],
    tag: [u8; 16],
}

impl PasswordArkWrap {
    /// Wrap an existing random ARK with an internally generated fresh OS-CSPRNG nonce.
    ///
    /// # Errors
    /// Rejects mismatched derived context, randomness failure, or encryption failure.
    pub fn seal(
        secrets: &PasswordSecrets,
        context: &PasswordBootstrapContext,
        ark: &AccountRootKey,
    ) -> Result<Self, PasswordBootstrapError> {
        let mut nonce = [0; 24];
        random_bytes(&mut nonce).map_err(|_| PasswordBootstrapError::Resource)?;
        Self::seal_with_nonce(secrets, context, ark, nonce)
    }

    fn seal_with_nonce(
        secrets: &PasswordSecrets,
        context: &PasswordBootstrapContext,
        ark: &AccountRootKey,
        nonce: [u8; 24],
    ) -> Result<Self, PasswordBootstrapError> {
        require_context(secrets, context)?;
        let mut buffer = Zeroizing::new(*ark.as_bytes());
        let tag = XChaCha20Poly1305::new(secrets.kek.as_bytes().into())
            .encrypt_in_place_detached(XNonce::from_slice(&nonce), &context.aad(), &mut *buffer)
            .map_err(|_| PasswordBootstrapError::Resource)?;
        Ok(Self { nonce, ciphertext: *buffer, tag: tag.into() })
    }

    /// Authenticate the password envelope before exposing its ARK.
    ///
    /// # Errors
    /// Returns a uniform authentication error for a wrong password, context, nonce, or tag.
    /// Call `PasswordSecrets::open_bootstrap` before treating the Account bootstrap as verified.
    pub fn open(
        &self,
        secrets: &PasswordSecrets,
        context: &PasswordBootstrapContext,
    ) -> Result<AccountRootKey, PasswordBootstrapError> {
        require_context(secrets, context)?;
        let mut buffer = Zeroizing::new(self.ciphertext);
        XChaCha20Poly1305::new(secrets.kek.as_bytes().into())
            .decrypt_in_place_detached(
                XNonce::from_slice(&self.nonce),
                &context.aad(),
                &mut *buffer,
                Tag::from_slice(&self.tag),
            )
            .map_err(|_| PasswordBootstrapError::Authentication)?;
        Ok(SecretBytes::new(*buffer))
    }

    /// Encode exactly 73 bytes, without embedding the separately authenticated metadata.
    #[must_use]
    pub fn encode(&self) -> [u8; PASSWORD_ARK_WRAP_BYTES] {
        let mut bytes = [0; PASSWORD_ARK_WRAP_BYTES];
        bytes[0] = VERSION;
        bytes[1..25].copy_from_slice(&self.nonce);
        bytes[25..57].copy_from_slice(&self.ciphertext);
        bytes[57..].copy_from_slice(&self.tag);
        bytes
    }

    /// Decode an exact version-1 artifact before expensive password work.
    ///
    /// # Errors
    /// Rejects every other length or version, including surplus data.
    pub fn decode(bytes: &[u8]) -> Result<Self, PasswordBootstrapError> {
        if bytes.len() != PASSWORD_ARK_WRAP_BYTES || bytes[0] != VERSION {
            return Err(PasswordBootstrapError::InvalidEncoding);
        }
        Ok(Self {
            nonce: bytes[1..25].try_into().map_err(|_| PasswordBootstrapError::InvalidEncoding)?,
            ciphertext: bytes[25..57]
                .try_into()
                .map_err(|_| PasswordBootstrapError::InvalidEncoding)?,
            tag: bytes[57..].try_into().map_err(|_| PasswordBootstrapError::InvalidEncoding)?,
        })
    }
}

impl fmt::Debug for PasswordArkWrap {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PasswordArkWrap { artifact: [REDACTED] }")
    }
}

fn require_context(
    secrets: &PasswordSecrets,
    context: &PasswordBootstrapContext,
) -> Result<(), PasswordBootstrapError> {
    if secrets.context != context.kdf {
        return Err(PasswordBootstrapError::Authentication);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use scoplen_test_vectors::VectorDocument;
    use serde_json::Value;

    fn hex(text: &str) -> Vec<u8> {
        text.as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| {
                u8::from_str_radix(std::str::from_utf8(pair).expect("hex UTF-8"), 16).expect("hex")
            })
            .collect()
    }

    #[test]
    fn independent_intermediates_and_workspace_cleanup_match_profile_one() {
        let vectors =
            VectorDocument::parse_str(include_str!("../../../vectors/password-bootstrap.json"))
                .expect("vectors");
        let vector = vectors
            .vectors
            .iter()
            .find(|value| value.kind == "crypto.password-bootstrap")
            .expect("known answer");
        let input: Value = serde_json::from_str(&vector.input).expect("input");
        let expected: Value = serde_json::from_str(&vector.expected).expect("answer");
        let context = PasswordKdfContext::new(
            input["origin"].as_str().expect("origin"),
            input["username"].as_str().expect("username"),
            1,
            &hex(input["salt"].as_str().expect("salt")),
        )
        .expect("context");
        let password = normalize_account_password(SecretVec::new(hex(input["password_hex"]
            .as_str()
            .expect("password"))))
        .expect("normalized");
        let mut workspace = PasswordWorkspace::new().expect("fixed workspace");
        assert_eq!(workspace.0.len(), 65_536);
        let mut material = Zeroizing::new([0; 32]);
        workspace
            .derive(password.as_bytes(), &context.salt, material.as_mut_slice())
            .expect("Argon2id");
        assert_eq!(material.as_slice(), hex(expected["material"].as_str().expect("M")));
        assert!(workspace.0.iter().all(|block| block.as_ref().iter().all(|word| *word == 0)));
        for block in &mut *workspace.0 {
            block.as_mut().fill(u64::MAX);
        }
        assert_eq!(
            workspace.derive(password.as_bytes(), &[], material.as_mut_slice()),
            Err(PasswordBootstrapError::Resource)
        );
        assert_eq!(*material, [0; 32]);
        assert!(workspace.0.iter().all(|block| block.as_ref().iter().all(|word| *word == 0)));
        drop(workspace);

        material.copy_from_slice(&hex(expected["material"].as_str().expect("M")));

        let (mut prk, _) =
            Hkdf::<Sha256>::extract(Some(&context.derivation_context()), material.as_slice());
        assert_eq!(prk.as_slice(), hex(expected["prk"].as_str().expect("PRK")));
        prk.as_mut_slice().zeroize();
        assert!(prk.as_slice().iter().all(|byte| *byte == 0));
        let material = SecretBytes::new(*material);
        let secrets = expand_secrets(&context, &material).expect("HKDF");
        assert_eq!(
            secrets.auth_secret.as_ref(),
            hex(expected["auth_secret"].as_str().expect("AuthSecret"))
        );
        assert_eq!(secrets.kek.as_ref(), hex(expected["kek"].as_str().expect("KEK")));
        assert_ne!(secrets.auth_secret, secrets.kek);
        let bootstrap = PasswordBootstrapContext::new(
            context.clone(),
            Uuid::parse_str(input["account_id"].as_str().expect("id")).expect("UUID"),
            Uuid::parse_str(input["personal_vault_id"].as_str().expect("vault")).expect("UUID"),
            &hex(input["signing_public_key"].as_str().expect("signing")),
            &hex(input["kem_public_key"].as_str().expect("KEM")),
            input["generation"].as_str().expect("generation").parse().expect("u64 generation"),
        )
        .expect("bootstrap");
        let ark = SecretBytes::new([4; 32]);
        let nonce = hex(input["nonce"].as_str().expect("nonce")).try_into().expect("nonce width");
        let envelope = PasswordArkWrap::seal_with_nonce(&secrets, &bootstrap, &ark, nonce)
            .expect("fixture seal");
        assert_eq!(
            envelope.encode().as_slice(),
            hex(expected["envelope"].as_str().expect("envelope"))
        );

        for changed in [
            PasswordKdfContext::new(
                "https://other.example.com",
                context.username(),
                1,
                context.salt(),
            )
            .expect("origin"),
            PasswordKdfContext::new(context.origin(), "alice.changed", 1, context.salt())
                .expect("username"),
            PasswordKdfContext::new(context.origin(), context.username(), 1, &[3; 16])
                .expect("salt"),
        ] {
            let changed = expand_secrets(&changed, &material).expect("separate HKDF context");
            assert_ne!(secrets.auth_secret, changed.auth_secret);
            assert_ne!(secrets.kek, changed.kek);
        }
    }

    #[test]
    fn partial_normalization_and_owned_secret_storage_are_cleared() {
        for input in [b"short".to_vec(), vec![b'a'; 129], vec![0xff; 2049]] {
            let mut output = Zeroizing::new(Vec::new());
            assert!(normalize_into(&SecretVec::new(input), &mut output).is_err());
            assert!(output.is_empty());
        }
        let mut secret = SecretBytes::new([0x55; 32]);
        secret.zeroize();
        assert_eq!(secret.as_bytes(), &[0; 32]);
        let mut raw = SecretVec::new(vec![0x55; 128]);
        raw.zeroize();
        assert!(raw.is_empty());
    }
}
