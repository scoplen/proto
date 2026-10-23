// SPDX-License-Identifier: Apache-2.0
//! D-114 public pairing locators and secret-bearing native QR payloads.

use std::fmt;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use scoplen_model::validate_uuid_v7;
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq;
use thiserror::Error;
use uuid::Uuid;

use crate::{PairingCode, SecretVec, validate_server_origin};

const QR_PREFIX: &str = "splpair2:";
const MAX_QR_BYTES: usize = 4_096;
const LINK_SEPARATOR: &str = "/pair#id=";

/// Invalid pairing locator, QR, or authenticated public-key binding.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum PairingQrError {
    /// The text is not the exact canonical D-114 representation.
    #[error("invalid pairing locator or QR payload")]
    InvalidPayload,
    /// A P-256 key is malformed or compressed.
    #[error("invalid device public key")]
    InvalidPublicKey,
    /// Authenticated keys do not match the out-of-band QR digest.
    #[error("device keys do not match the QR pairing payload")]
    KeyMismatch,
}

/// Public session locator; contains no password or capability.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PairingLink {
    origin: String,
    pairing_id: Uuid,
}

impl PairingLink {
    /// Construct a locator for a canonical HTTPS origin and `UUIDv7` session.
    ///
    /// # Errors
    /// Rejects a noncanonical origin or non-v7 id.
    pub fn new(origin: &str, pairing_id: Uuid) -> Result<Self, PairingQrError> {
        validate_server_origin(origin).map_err(|_| PairingQrError::InvalidPayload)?;
        validate_uuid_v7(pairing_id).map_err(|_| PairingQrError::InvalidPayload)?;
        Ok(Self { origin: origin.to_owned(), pairing_id })
    }

    /// Parse the exact public link without making a request.
    ///
    /// # Errors
    /// Rejects queries, extra fragments, alternate UUID spellings and other paths.
    pub fn decode(value: &str) -> Result<Self, PairingQrError> {
        if value.len() > 2_048 + LINK_SEPARATOR.len() + 36 {
            return Err(PairingQrError::InvalidPayload);
        }
        let (origin, id) =
            value.split_once(LINK_SEPARATOR).ok_or(PairingQrError::InvalidPayload)?;
        Self::new(origin, canonical_id(id)?)
    }

    /// Format the public link, suitable for an explicit Copy action.
    #[must_use]
    pub fn encode(&self) -> String {
        format!("{}{LINK_SEPARATOR}{}", self.origin, self.pairing_id)
    }

    /// Return the canonical trusted origin to compare with the selected account.
    #[must_use]
    pub fn origin(&self) -> &str {
        &self.origin
    }

    /// Return the public session id.
    #[must_use]
    pub const fn pairing_id(&self) -> Uuid {
        self.pairing_id
    }
}

/// Secret-bearing QR for one native scan. Never upload, log, or open as a URL.
pub struct PairingQrPayload {
    link: PairingLink,
    public_key_hash: [u8; 32],
    code: PairingCode,
}

impl PairingQrPayload {
    /// Bind origin, session, fresh secret and both new-device public keys.
    ///
    /// # Errors
    /// Rejects invalid origins, ids, or non-uncompressed P-256 keys.
    pub fn new(
        origin: &str,
        pairing_id: Uuid,
        kem_public_key: &[u8],
        signing_public_key: &[u8],
        code: PairingCode,
    ) -> Result<Self, PairingQrError> {
        Ok(Self {
            link: PairingLink::new(origin, pairing_id)?,
            public_key_hash: hash_public_keys(kem_public_key, signing_public_key)?,
            code,
        })
    }

    /// Parse only canonical `QRv2` text. The borrowed input remains caller-owned.
    ///
    /// # Errors
    /// Rejects `QRv1`, unknown versions, extra fields, encodings or invalid codes.
    pub fn decode(value: &str) -> Result<Self, PairingQrError> {
        if value.len() > MAX_QR_BYTES || !value.is_ascii() {
            return Err(PairingQrError::InvalidPayload);
        }
        let mut fields =
            value.strip_prefix(QR_PREFIX).ok_or(PairingQrError::InvalidPayload)?.split(':');
        let origin_text = fields.next().ok_or(PairingQrError::InvalidPayload)?;
        if origin_text.len() > 2_731 {
            return Err(PairingQrError::InvalidPayload);
        }
        let origin =
            URL_SAFE_NO_PAD.decode(origin_text).map_err(|_| PairingQrError::InvalidPayload)?;
        if URL_SAFE_NO_PAD.encode(&origin) != origin_text {
            return Err(PairingQrError::InvalidPayload);
        }
        let origin = std::str::from_utf8(&origin).map_err(|_| PairingQrError::InvalidPayload)?;
        let id = canonical_id(fields.next().ok_or(PairingQrError::InvalidPayload)?)?;
        let hash = fields.next().ok_or(PairingQrError::InvalidPayload)?;
        if hash.len() != 64
            || !hash.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(PairingQrError::InvalidPayload);
        }
        let mut public_key_hash = [0; 32];
        for (byte, pair) in public_key_hash.iter_mut().zip(hash.as_bytes().as_chunks::<2>().0) {
            let text = std::str::from_utf8(pair).map_err(|_| PairingQrError::InvalidPayload)?;
            *byte = u8::from_str_radix(text, 16).map_err(|_| PairingQrError::InvalidPayload)?;
        }
        let code = PairingCode::from_ascii(
            fields.next().ok_or(PairingQrError::InvalidPayload)?.as_bytes(),
        )
        .map_err(|_| PairingQrError::InvalidPayload)?;
        if fields.next().is_some() {
            return Err(PairingQrError::InvalidPayload);
        }
        Ok(Self { link: PairingLink::new(origin, id)?, public_key_hash, code })
    }

    /// Encode into a zeroizing container for the dedicated transient native UI.
    #[must_use]
    pub fn encode(&self) -> SecretVec {
        use std::fmt::Write as _;
        let mut prefix = format!(
            "{QR_PREFIX}{}:{}:",
            URL_SAFE_NO_PAD.encode(self.link.origin()),
            self.pairing_id()
        );
        for byte in self.public_key_hash {
            write!(&mut prefix, "{byte:02x}").expect("writing to String cannot fail");
        }
        prefix.push(':');
        let mut bytes = prefix.into_bytes();
        bytes.reserve(8);
        bytes.extend_from_slice(self.code.as_ascii());
        SecretVec::new(bytes)
    }

    /// Borrow the public locator independently of the QR secret.
    #[must_use]
    pub fn link(&self) -> &PairingLink {
        &self.link
    }

    /// Return the public session id.
    #[must_use]
    pub const fn pairing_id(&self) -> Uuid {
        self.link.pairing_id
    }

    /// Borrow the secret for the one `CPace` interaction.
    #[must_use]
    pub fn code(&self) -> &PairingCode {
        &self.code
    }

    /// Constant-time compare authenticated public keys with the QR digest.
    ///
    /// # Errors
    /// Rejects malformed or substituted keys.
    pub fn verify_public_keys(&self, kem: &[u8], signing: &[u8]) -> Result<(), PairingQrError> {
        let digest = hash_public_keys(kem, signing)?;
        if bool::from(self.public_key_hash.ct_eq(&digest)) {
            Ok(())
        } else {
            Err(PairingQrError::KeyMismatch)
        }
    }
}

impl fmt::Debug for PairingQrPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PairingQrPayload([REDACTED])")
    }
}

fn canonical_id(text: &str) -> Result<Uuid, PairingQrError> {
    let id = Uuid::parse_str(text).map_err(|_| PairingQrError::InvalidPayload)?;
    if id.to_string() != text || validate_uuid_v7(id).is_err() {
        return Err(PairingQrError::InvalidPayload);
    }
    Ok(id)
}

fn hash_public_keys(kem: &[u8], signing: &[u8]) -> Result<[u8; 32], PairingQrError> {
    for key in [kem, signing] {
        if key.len() != 65 || key.first() != Some(&4) {
            return Err(PairingQrError::InvalidPublicKey);
        }
        p256::PublicKey::from_sec1_bytes(key).map_err(|_| PairingQrError::InvalidPublicKey)?;
    }
    let mut hasher = Sha256::new();
    hasher.update(kem);
    hasher.update(signing);
    Ok(hasher.finalize().into())
}
