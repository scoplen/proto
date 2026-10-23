// SPDX-License-Identifier: Apache-2.0
//! D-114 authenticated pairing messages and exact acceptance bindings.

use std::{collections::BTreeMap, fmt};

use scoplen_model::{
    cbor::{self, Value},
    validate_uuid_v7,
};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use uuid::Uuid;

use crate::{
    DeviceCertificate, DeviceSigner, PairingContext, PairingError, PairingRole, PairingSession,
    PrimitiveError, SecretVec, p256_verify, validate_server_origin,
};

/// Maximum complete new-device frame, including nonce and tag.
pub const MAX_PAIRING_NEW_DEVICE_FRAME_BYTES: usize = 131_072;
/// Maximum complete handoff frame, permitting every existing inner artifact bound.
pub const MAX_PAIRING_HANDOFF_FRAME_BYTES: usize = 4_456_448;
const FRAME_OVERHEAD: usize = 40;
const MAX_ARTIFACT: usize = 65_536;
const MAX_KEYS: usize = 4_194_304;

/// Invalid public context, canonical message, artifact bound or channel.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum PairingApplicationError {
    /// An origin, UUID or role does not match the fixed ceremony.
    #[error("invalid pairing application context")]
    InvalidContext,
    /// Noncanonical encoding, unknown/missing fields or invalid metadata.
    #[error("invalid pairing application message")]
    InvalidMessage,
    /// An empty or oversized artifact, frame or plaintext.
    #[error("pairing application size limit exceeded")]
    InvalidLength,
    /// The authenticated channel rejected the exchange.
    #[error("pairing channel failed: {0}")]
    Channel(#[from] PairingError),
}

/// Origin and all three identifiers fixed before the application exchange.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PairingApplicationContext {
    origin: String,
    pairing: PairingContext,
}

impl PairingApplicationContext {
    /// Bind the canonical origin to an already validated `CPace` context.
    ///
    /// # Errors
    /// Rejects a noncanonical HTTPS origin.
    pub fn new(origin: &str, pairing: PairingContext) -> Result<Self, PairingApplicationError> {
        validate_server_origin(origin).map_err(|_| PairingApplicationError::InvalidContext)?;
        Ok(Self { origin: origin.to_owned(), pairing })
    }

    /// Borrow the exact canonical HTTPS origin.
    #[must_use]
    pub fn origin(&self) -> &str {
        &self.origin
    }

    /// Return the fixed `CPace` session and ordered devices.
    #[must_use]
    pub const fn pairing(&self) -> PairingContext {
        self.pairing
    }

    fn entries(&self) -> Vec<(Value, Value)> {
        vec![
            entry("origin", Value::Text(self.origin.clone())),
            entry("pairing_id", id_value(self.pairing.pairing_id())),
            entry("initiator_device_id", id_value(self.pairing.initiator_device_id())),
            entry("responder_device_id", id_value(self.pairing.responder_device_id())),
        ]
    }

    fn take(fields: &mut Fields) -> Result<Self, PairingApplicationError> {
        let origin = fields.text("origin")?;
        let pairing = PairingContext::new(
            fields.id("pairing_id")?,
            fields.id("initiator_device_id")?,
            fields.id("responder_device_id")?,
        )
        .map_err(|_| PairingApplicationError::InvalidContext)?;
        Self::new(&origin, pairing)
    }

    fn session(
        &self,
        session: &PairingSession,
        role: PairingRole,
    ) -> Result<(), PairingApplicationError> {
        if session.context() != self.pairing || session.role() != role {
            return Err(PairingApplicationError::InvalidContext);
        }
        Ok(())
    }
}

/// Public new-device material encrypted after both `CPace` confirmations.
#[derive(Eq, PartialEq)]
pub struct PairingNewDevice {
    /// Exact expected ceremony.
    pub context: PairingApplicationContext,
    /// Valid uncompressed SEC1 P-256 signing key.
    pub signing_public_key: Vec<u8>,
    /// Valid uncompressed SEC1 P-256 KEM key.
    pub kem_public_key: Vec<u8>,
    /// Claimed device name, for explicit old-device confirmation.
    pub display_name: String,
    /// Claimed platform, for explicit old-device confirmation.
    pub platform: String,
    /// Claimed creation time in Unix milliseconds.
    pub created_at: u64,
}

impl PairingNewDevice {
    /// Validate keys and the resulting exact certificate size, then encode canonical CBOR.
    ///
    /// # Errors
    /// Rejects invalid keys/NFC, certificate metadata overflow and total overflow.
    pub fn encode(&self) -> Result<SecretVec, PairingApplicationError> {
        self.validate()?;
        let mut entries = self.context.entries();
        entries.extend([
            entry("signing_public_key", Value::Bytes(self.signing_public_key.clone())),
            entry("kem_public_key", Value::Bytes(self.kem_public_key.clone())),
            entry("display_name", Value::Text(self.display_name.clone())),
            entry("platform", Value::Text(self.platform.clone())),
            entry("created_at", Value::UInt(self.created_at)),
        ]);
        encode(entries, MAX_PAIRING_NEW_DEVICE_FRAME_BYTES - FRAME_OVERHEAD)
    }

    /// Decode the exact canonical map. Callers compare its context before use.
    ///
    /// # Errors
    /// Rejects malformed, unknown, duplicate, trailing, oversized or invalid fields.
    pub fn decode(bytes: &[u8]) -> Result<Self, PairingApplicationError> {
        let mut f = Fields::decode(bytes, MAX_PAIRING_NEW_DEVICE_FRAME_BYTES - FRAME_OVERHEAD)?;
        let value = Self {
            context: PairingApplicationContext::take(&mut f)?,
            signing_public_key: f.bytes("signing_public_key")?,
            kem_public_key: f.bytes("kem_public_key")?,
            display_name: f.text("display_name")?,
            platform: f.text("platform")?,
            created_at: f.uint("created_at")?,
        };
        f.finish()?;
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), PairingApplicationError> {
        for key in [&self.signing_public_key, &self.kem_public_key] {
            if key.len() != 65
                || key.first() != Some(&4)
                || p256::PublicKey::from_sec1_bytes(key).is_err()
            {
                return Err(PairingApplicationError::InvalidMessage);
            }
        }
        if self.display_name.len() > MAX_ARTIFACT || self.platform.len() > MAX_ARTIFACT {
            return Err(PairingApplicationError::InvalidLength);
        }
        // The account UUID and signature have fixed widths; their values cannot change this bound.
        let certificate = DeviceCertificate {
            device_id: self.context.pairing.responder_device_id(),
            account_id: self.context.pairing.initiator_device_id(),
            signing_public_key: self.signing_public_key.clone(),
            kem_public_key: self.kem_public_key.clone(),
            display_name: self.display_name.clone(),
            platform: self.platform.clone(),
            created_at: self.created_at,
            signature: [0; 64],
        }
        .encode()
        .map_err(invalid)?;
        bound(&certificate, MAX_ARTIFACT)
    }

    /// Encrypt slot 5 using the confirmed responder session and fixed context.
    ///
    /// # Errors
    /// Rejects context/role mismatch, invalid material or an unconfirmed channel.
    pub fn seal(&self, session: &PairingSession) -> Result<Vec<u8>, PairingApplicationError> {
        self.context.session(session, PairingRole::Responder)?;
        Ok(session.seal_frame(self.encode()?.as_bytes())?)
    }

    /// Authenticate slot 5 and compare all context fields before returning material.
    ///
    /// # Errors
    /// Rejects context, role, frame, bounds, nonce or plaintext validation failures.
    pub fn open(
        expected: &PairingApplicationContext,
        session: &PairingSession,
        frame: &[u8],
    ) -> Result<Self, PairingApplicationError> {
        expected.session(session, PairingRole::Initiator)?;
        frame_bound(frame, MAX_PAIRING_NEW_DEVICE_FRAME_BYTES)?;
        let plaintext = SecretVec::new(session.open_frame(PairingRole::Responder, frame)?);
        let value = Self::decode(plaintext.as_bytes())?;
        if &value.context != expected {
            return Err(PairingApplicationError::InvalidContext);
        }
        Ok(value)
    }
}

/// Exact public/ciphertext fields whose digest establishes the durable key anchor.
#[derive(Clone, Copy)]
pub struct PairingKeyProjection<'a> {
    /// Positive K-4 account-key revision.
    pub revision: u64,
    /// Exact device ARK wrap (opaque K-4 bytes).
    pub wrapped_ark: &'a [u8],
    /// Exact encrypted account signing key.
    pub account_signing_key: &'a [u8],
    /// Exact encrypted account KEM key.
    pub account_kem_key: &'a [u8],
    /// Exact recovery blob; does not imply possession of a recovery key.
    pub recovery_blob: &'a [u8],
}

/// Hash the exact five-field projection, excluding independent signed statements.
///
/// # Errors
/// Rejects revision zero and empty/oversized K-4 artifacts. The caller verifies K-2 values.
pub fn pairing_key_anchor(
    p: PairingKeyProjection<'_>,
) -> Result<[u8; 32], PairingApplicationError> {
    if p.revision == 0 {
        return Err(PairingApplicationError::InvalidMessage);
    }
    for bytes in [p.wrapped_ark, p.account_signing_key, p.account_kem_key, p.recovery_blob] {
        bound(bytes, MAX_ARTIFACT)?;
    }
    let bytes = encode(
        vec![
            entry("revision", Value::UInt(p.revision)),
            entry("wrapped_ark", Value::Bytes(p.wrapped_ark.to_vec())),
            entry("account_signing_key", Value::Bytes(p.account_signing_key.to_vec())),
            entry("account_kem_key", Value::Bytes(p.account_kem_key.to_vec())),
            entry("recovery_blob", Value::Bytes(p.recovery_blob.to_vec())),
        ],
        MAX_KEYS,
    )?;
    Ok(digest(b"spl-pairing-key-anchor-v1", bytes.as_bytes()))
}

/// Authenticated old-account handoff, containing no plaintext recovery key.
#[derive(Eq, PartialEq)]
pub struct PairingHandoff {
    /// Exact expected ceremony.
    pub context: PairingApplicationContext,
    /// Existing account identifier.
    pub account_id: Uuid,
    /// Existing Personal vault identifier.
    pub personal_vault_id: Uuid,
    /// Authenticated existing Ed25519 public root.
    pub account_signing_public_key: [u8; 32],
    /// Authenticated existing X25519 public root.
    pub account_kem_public_key: [u8; 32],
    /// Exact new-device signed certificate.
    pub device_certificate: Vec<u8>,
    /// Initial target revision floor.
    pub revision: u64,
    /// SHA-256 of the exact full signed K-4 update.
    pub key_bundle_update_hash: [u8; 32],
    /// Authenticated five-field key projection digest.
    pub key_anchor: [u8; 32],
    /// Exact 114-byte new-device ARK wrap.
    pub wrapped_ark: Vec<u8>,
    /// Exact 73-byte account signing key artifact.
    pub account_signing_key: Vec<u8>,
    /// Exact 73-byte account KEM artifact.
    pub account_kem_key: Vec<u8>,
    /// Opaque recovery blob, without the human recovery key.
    pub recovery_blob: Vec<u8>,
    /// Exact canonical K-4 Personal vault-keys response.
    pub personal_vault_keys: Vec<u8>,
}

impl PairingHandoff {
    /// Borrow the statement-independent projection.
    #[must_use]
    pub fn projection(&self) -> PairingKeyProjection<'_> {
        PairingKeyProjection {
            revision: self.revision,
            wrapped_ark: &self.wrapped_ark,
            account_signing_key: &self.account_signing_key,
            account_kem_key: &self.account_kem_key,
            recovery_blob: &self.recovery_blob,
        }
    }

    /// Validate the bounded map, certificate/account binding and projection; encode exact CBOR.
    ///
    /// This does not open artifacts or prove equality of reconstructed private keys. Consumers
    /// compare the expected new-device metadata, trusted roots and all opened Personal epochs.
    ///
    /// # Errors
    /// Rejects invalid identifiers/certificates/artifacts/anchor and inner or total overflow.
    pub fn encode(&self) -> Result<SecretVec, PairingApplicationError> {
        self.validate()?;
        let mut entries = self.context.entries();
        entries.extend([
            entry("account_id", id_value(self.account_id)),
            entry("personal_vault_id", id_value(self.personal_vault_id)),
            entry(
                "account_signing_public_key",
                Value::Bytes(self.account_signing_public_key.to_vec()),
            ),
            entry("account_kem_public_key", Value::Bytes(self.account_kem_public_key.to_vec())),
            entry("device_certificate", Value::Bytes(self.device_certificate.clone())),
            entry("revision", Value::UInt(self.revision)),
            entry("key_bundle_update_hash", Value::Bytes(self.key_bundle_update_hash.to_vec())),
            entry("key_anchor", Value::Bytes(self.key_anchor.to_vec())),
            entry("wrapped_ark", Value::Bytes(self.wrapped_ark.clone())),
            entry("account_signing_key", Value::Bytes(self.account_signing_key.clone())),
            entry("account_kem_key", Value::Bytes(self.account_kem_key.clone())),
            entry("recovery_blob", Value::Bytes(self.recovery_blob.clone())),
            entry("personal_vault_keys", Value::Bytes(self.personal_vault_keys.clone())),
        ]);
        encode(entries, MAX_PAIRING_HANDOFF_FRAME_BYTES - FRAME_OVERHEAD)
    }

    /// Decode the exact map and validate its public bindings. It is trusted only after `CPace`.
    ///
    /// # Errors
    /// Rejects noncanonical/duplicate/unknown/trailing data and every invalid inner field.
    pub fn decode(bytes: &[u8]) -> Result<Self, PairingApplicationError> {
        let mut f = Fields::decode(bytes, MAX_PAIRING_HANDOFF_FRAME_BYTES - FRAME_OVERHEAD)?;
        let value = Self {
            context: PairingApplicationContext::take(&mut f)?,
            account_id: f.id("account_id")?,
            personal_vault_id: f.id("personal_vault_id")?,
            account_signing_public_key: f.fixed("account_signing_public_key")?,
            account_kem_public_key: f.fixed("account_kem_public_key")?,
            device_certificate: f.bytes("device_certificate")?,
            revision: f.uint("revision")?,
            key_bundle_update_hash: f.fixed("key_bundle_update_hash")?,
            key_anchor: f.fixed("key_anchor")?,
            wrapped_ark: f.bytes("wrapped_ark")?,
            account_signing_key: f.bytes("account_signing_key")?,
            account_kem_key: f.bytes("account_kem_key")?,
            recovery_blob: f.bytes("recovery_blob")?,
            personal_vault_keys: f.bytes("personal_vault_keys")?,
        };
        f.finish()?;
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), PairingApplicationError> {
        for id in [self.account_id, self.personal_vault_id] {
            validate_uuid_v7(id).map_err(|_| PairingApplicationError::InvalidContext)?;
        }
        for (bytes, max) in [
            (&self.device_certificate, MAX_ARTIFACT),
            (&self.recovery_blob, MAX_ARTIFACT),
            (&self.personal_vault_keys, MAX_KEYS),
        ] {
            bound(bytes, max)?;
        }
        if self.wrapped_ark.len() != 114
            || self.account_signing_key.len() != 73
            || self.account_kem_key.len() != 73
        {
            return Err(PairingApplicationError::InvalidLength);
        }
        crate::DeviceArkWrap::decode(&self.wrapped_ark).map_err(invalid)?;
        crate::AccountSigningKeyWrap::decode(&self.account_signing_key).map_err(invalid)?;
        crate::AccountKemKeyWrap::decode(&self.account_kem_key).map_err(invalid)?;
        let cert = DeviceCertificate::decode(&self.device_certificate).map_err(invalid)?;
        cert.verify(&self.account_signing_public_key).map_err(invalid)?;
        if cert.device_id != self.context.pairing.responder_device_id()
            || cert.account_id != self.account_id
            || pairing_key_anchor(self.projection())? != self.key_anchor
        {
            return Err(PairingApplicationError::InvalidMessage);
        }
        cbor::decode(&self.personal_vault_keys).map_err(invalid)?;
        Ok(())
    }

    /// Encrypt slot 6 through the confirmed initiator channel.
    ///
    /// # Errors
    /// Rejects context/role mismatch, invalid material or an unconfirmed channel.
    pub fn seal(&self, session: &PairingSession) -> Result<Vec<u8>, PairingApplicationError> {
        self.context.session(session, PairingRole::Initiator)?;
        Ok(session.seal_frame(self.encode()?.as_bytes())?)
    }

    /// Authenticate slot 6 and compare every fixed context field before exposing the handoff.
    ///
    /// # Errors
    /// Rejects context, role, frame, bounds, nonce or public binding failures.
    pub fn open(
        expected: &PairingApplicationContext,
        session: &PairingSession,
        frame: &[u8],
    ) -> Result<Self, PairingApplicationError> {
        expected.session(session, PairingRole::Responder)?;
        frame_bound(frame, MAX_PAIRING_HANDOFF_FRAME_BYTES)?;
        let plaintext = SecretVec::new(session.open_frame(PairingRole::Initiator, frame)?);
        let value = Self::decode(plaintext.as_bytes())?;
        if &value.context != expected {
            return Err(PairingApplicationError::InvalidContext);
        }
        Ok(value)
    }
}

/// Domain-separated new-device acceptance input, safe to retain with an exact signature.
#[derive(Clone, Eq, PartialEq)]
pub struct PairingCompletionContext {
    input: Vec<u8>,
}

impl PairingCompletionContext {
    /// Bind exact stored relay/certificate/update bytes for the old device or server.
    ///
    /// # Errors
    /// Rejects invalid account id and existing artifact/frame bounds.
    pub fn new(
        context: &PairingApplicationContext,
        account_id: Uuid,
        handoff_frame: &[u8],
        certificate: &[u8],
        update: &[u8],
    ) -> Result<Self, PairingApplicationError> {
        bound(update, MAX_KEYS)?;
        Self::from_update_hash(
            context,
            account_id,
            handoff_frame,
            certificate,
            &Sha256::digest(update).into(),
        )
    }

    /// Bind the update hash obtained inside the authenticated handoff on the new device.
    ///
    /// This hash must come from that verified handoff, never an unauthenticated server field.
    /// The caller durably saves identity plus the exact resulting signature before slot 7.
    ///
    /// # Errors
    /// Rejects invalid account id and existing artifact/frame bounds.
    pub fn from_update_hash(
        context: &PairingApplicationContext,
        account_id: Uuid,
        handoff_frame: &[u8],
        certificate: &[u8],
        update_hash: &[u8; 32],
    ) -> Result<Self, PairingApplicationError> {
        validate_uuid_v7(account_id).map_err(|_| PairingApplicationError::InvalidContext)?;
        frame_bound(handoff_frame, MAX_PAIRING_HANDOFF_FRAME_BYTES)?;
        bound(certificate, MAX_ARTIFACT)?;
        let mut input = b"spl-pairing-complete-v1".to_vec();
        input.extend_from_slice(
            &u16::try_from(context.origin.len()).map_err(invalid)?.to_be_bytes(),
        );
        input.extend_from_slice(context.origin.as_bytes());
        for id in [
            context.pairing.pairing_id(),
            context.pairing.initiator_device_id(),
            context.pairing.responder_device_id(),
            account_id,
        ] {
            input.extend_from_slice(id.as_bytes());
        }
        input.extend_from_slice(&Sha256::digest(handoff_frame));
        input.extend_from_slice(&Sha256::digest(certificate));
        input.extend_from_slice(update_hash);
        Ok(Self { input })
    }

    /// Borrow the exact message, without caller pre-hashing.
    #[must_use]
    pub fn signature_input(&self) -> &[u8] {
        &self.input
    }

    /// Sign through the fallible certified device-key boundary.
    ///
    /// # Errors
    /// Propagates signer failures with no replacement key.
    pub fn sign(&self, signer: &dyn DeviceSigner) -> Result<[u8; 64], PrimitiveError> {
        signer.sign(&self.input)
    }

    /// Verify possession of the authenticated new-device P-256 signing key.
    ///
    /// # Errors
    /// Rejects malformed or substituted keys, input or signatures.
    pub fn verify(&self, certified_key: &[u8], signature: &[u8]) -> Result<(), PrimitiveError> {
        p256_verify(certified_key, &self.input, signature)
    }
}

/// Exact approval replay fingerprint. Syntax/authentication of inner artifacts is separate.
///
/// # Errors
/// Rejects empty/oversized certificate/update or a signature other than 64 bytes.
pub fn pairing_approval_fingerprint(
    certificate: &[u8],
    update: &[u8],
    signature: &[u8],
) -> Result<[u8; 32], PairingApplicationError> {
    bound(certificate, MAX_ARTIFACT)?;
    bound(update, MAX_KEYS)?;
    if signature.len() != 64 {
        return Err(PairingApplicationError::InvalidLength);
    }
    let bytes = encode(
        vec![
            entry("device_certificate", Value::Bytes(certificate.to_vec())),
            entry("key_bundle_update", Value::Bytes(update.to_vec())),
            entry("new_device_signature", Value::Bytes(signature.to_vec())),
        ],
        MAX_KEYS + MAX_ARTIFACT + 256,
    )?;
    Ok(digest(b"spl-pairing-approval-v1", bytes.as_bytes()))
}

macro_rules! redacted {
    ($($ty:ty),+ $(,)?) => { $(impl fmt::Debug for $ty {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str(concat!(stringify!($ty), "([REDACTED])")) }
    })+ };
}
redacted!(PairingNewDevice, PairingHandoff, PairingKeyProjection<'_>, PairingCompletionContext);

fn entry(key: &str, value: Value) -> (Value, Value) {
    (Value::Text(key.to_owned()), value)
}
fn id_value(id: Uuid) -> Value {
    Value::Bytes(id.as_bytes().to_vec())
}
fn invalid<T>(_: T) -> PairingApplicationError {
    PairingApplicationError::InvalidMessage
}
fn bound(bytes: &[u8], max: usize) -> Result<(), PairingApplicationError> {
    if bytes.is_empty() || bytes.len() > max {
        return Err(PairingApplicationError::InvalidLength);
    }
    Ok(())
}
fn frame_bound(bytes: &[u8], max: usize) -> Result<(), PairingApplicationError> {
    bound(bytes, max)?;
    if bytes.len() <= FRAME_OVERHEAD {
        return Err(PairingApplicationError::InvalidLength);
    }
    Ok(())
}
fn encode(entries: Vec<(Value, Value)>, max: usize) -> Result<SecretVec, PairingApplicationError> {
    let value = SecretVec::new(cbor::encode(&Value::Map(entries)).map_err(invalid)?);
    bound(value.as_bytes(), max)?;
    Ok(value)
}
fn digest(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(bytes);
    hash.finalize().into()
}

struct Fields(BTreeMap<String, Value>);
impl Fields {
    fn decode(bytes: &[u8], max: usize) -> Result<Self, PairingApplicationError> {
        bound(bytes, max)?;
        let Value::Map(entries) = cbor::decode(bytes).map_err(invalid)? else {
            return Err(PairingApplicationError::InvalidMessage);
        };
        let mut fields = BTreeMap::new();
        for (key, value) in entries {
            let Value::Text(key) = key else {
                return Err(PairingApplicationError::InvalidMessage);
            };
            if fields.insert(key, value).is_some() {
                return Err(PairingApplicationError::InvalidMessage);
            }
        }
        Ok(Self(fields))
    }
    fn take(&mut self, key: &str) -> Result<Value, PairingApplicationError> {
        self.0.remove(key).ok_or(PairingApplicationError::InvalidMessage)
    }
    fn bytes(&mut self, key: &str) -> Result<Vec<u8>, PairingApplicationError> {
        let Value::Bytes(bytes) = self.take(key)? else {
            return Err(PairingApplicationError::InvalidMessage);
        };
        Ok(bytes)
    }
    fn fixed<const N: usize>(&mut self, key: &str) -> Result<[u8; N], PairingApplicationError> {
        self.bytes(key)?.try_into().map_err(invalid)
    }
    fn id(&mut self, key: &str) -> Result<Uuid, PairingApplicationError> {
        let id = Uuid::from_bytes(self.fixed(key)?);
        validate_uuid_v7(id).map_err(|_| PairingApplicationError::InvalidContext)?;
        Ok(id)
    }
    fn text(&mut self, key: &str) -> Result<String, PairingApplicationError> {
        let Value::Text(text) = self.take(key)? else {
            return Err(PairingApplicationError::InvalidMessage);
        };
        Ok(text)
    }
    fn uint(&mut self, key: &str) -> Result<u64, PairingApplicationError> {
        let Value::UInt(value) = self.take(key)? else {
            return Err(PairingApplicationError::InvalidMessage);
        };
        Ok(value)
    }
    fn finish(self) -> Result<(), PairingApplicationError> {
        if !self.0.is_empty() {
            return Err(PairingApplicationError::InvalidMessage);
        }
        Ok(())
    }
}
