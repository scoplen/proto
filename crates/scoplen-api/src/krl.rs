// SPDX-License-Identifier: Apache-2.0
//! D-141 bounded, unsigned local Ed25519 user-CA OpenSSH KRL snapshots.
//!
//! Parsing validates the frozen binary subset and its expected public CA. It establishes no
//! authenticated origin, tenant ownership, current authority, freshness, or Host installation.
//! Empty snapshots carry no CA section; the caller must retain the authenticated request binding.

use std::fmt;

use ssh_key::{Algorithm, PublicKey};
use thiserror::Error;

/// Maximum complete raw HTTP response, checked before parsing or allocation.
pub const MAX_USER_CA_KRL_BYTES: usize = 4 * 1024 * 1024;
/// Maximum revoked serial count, checked before allocating the decoded list.
pub const MAX_USER_CA_KRL_SERIALS: usize = 100_000;
/// Exact success media type; a KRL is never wrapped in a JSON Resource.
pub const USER_CA_KRL_CONTENT_TYPE: &str = "application/octet-stream";

const MAGIC: &[u8; 8] = b"SSHKRL\n\0";
const HEADER_BYTES: usize = 44;
const CA_BLOB_BYTES: usize = 51;
const NONEMPTY_FIXED_BYTES: usize = 113;

/// Content-free failures for the explicitly supported KRL profile.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum KrlCodecError {
    /// The complete input exceeds the HTTP response budget.
    #[error("KRL exceeds the complete response byte limit")]
    InputTooLarge,
    /// The serial count exceeds the fixed per-CA bound.
    #[error("KRL exceeds the serial count limit")]
    TooManySerials,
    /// The expected CA is not the canonical raw Ed25519 OpenSSH public key.
    #[error("invalid expected KRL CA")]
    InvalidCa,
    /// Magic, format, version, flags, reserved or comment violates the fixed profile.
    #[error("invalid KRL header")]
    InvalidHeader,
    /// The body has unsupported sections, invalid lengths, truncation or trailing bytes.
    #[error("invalid KRL binary profile")]
    InvalidFormat,
    /// A serial is zero, duplicated or out of ascending order.
    #[error("invalid KRL serial list")]
    InvalidSerials,
    /// The embedded CA differs from the captured expected public CA.
    #[error("KRL CA differs from the expected CA")]
    CaMismatch,
    /// Media type, cache prevention or request-id metadata is absent or invalid.
    #[error("invalid KRL HTTP metadata")]
    HttpMetadata,
}

/// One canonical D-141 snapshot, bound to the caller's captured expected public CA.
///
/// Construction rejects unsorted or repeated serials; it never sorts or deduplicates input.
/// Fields are immutable so encoding cannot silently repair a malformed snapshot. The CA field
/// is retained even for the header-only empty encoding and does not itself establish trust.
#[derive(Clone, Eq, PartialEq)]
pub struct UserCaKrl {
    ca_public_key: String,
    ca_blob: [u8; CA_BLOB_BYTES],
    version: u64,
    generated_at_seconds: u64,
    revoked_serials: Vec<u64>,
}

impl fmt::Debug for UserCaKrl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UserCaKrl")
            .field("version", &self.version)
            .field("generated_at_seconds", &self.generated_at_seconds)
            .field("revoked_serial_count", &self.revoked_serials.len())
            .finish_non_exhaustive()
    }
}

impl UserCaKrl {
    /// Construct a snapshot using a canonical raw Ed25519 CA and ascending distinct serials.
    ///
    /// # Errors
    /// Rejects an invalid CA, zero version, more than 100,000 serials, or zero/duplicate/
    /// descending serials. Cardinality and serial validity are checked before copying the list.
    pub fn new(
        expected_ca_public_key: &str,
        version: u64,
        generated_at_seconds: u64,
        revoked_serials: &[u64],
    ) -> Result<Self, KrlCodecError> {
        if version == 0 {
            return Err(KrlCodecError::InvalidHeader);
        }
        validate_serials(revoked_serials)?;
        let ca_blob = parse_ca(expected_ca_public_key)?;
        Ok(Self {
            ca_public_key: expected_ca_public_key.into(),
            ca_blob,
            version,
            generated_at_seconds,
            revoked_serials: revoked_serials.to_vec(),
        })
    }

    /// Captured expected canonical public CA; absent from an empty snapshot's wire bytes.
    #[must_use]
    pub fn ca_public_key(&self) -> &str {
        &self.ca_public_key
    }

    /// Positive per-CA persisted KRL version, never a floating-point JSON number.
    #[must_use]
    pub const fn version(&self) -> u64 {
        self.version
    }

    /// Persisted generation time in Unix seconds; encoding never substitutes the current time.
    #[must_use]
    pub const fn generated_at_seconds(&self) -> u64 {
        self.generated_at_seconds
    }

    /// Ascending distinct positive revoked certificate serials.
    #[must_use]
    pub fn revoked_serials(&self) -> &[u64] {
        &self.revoked_serials
    }

    /// Encode exactly the supported unsigned v1 subset in network byte order.
    ///
    /// # Errors
    /// Returns an error if the complete encoding cannot fit the fixed byte budget.
    pub fn to_bytes(&self) -> Result<Vec<u8>, KrlCodecError> {
        let len = if self.revoked_serials.is_empty() {
            HEADER_BYTES
        } else {
            NONEMPTY_FIXED_BYTES + 8 * self.revoked_serials.len()
        };
        if len > MAX_USER_CA_KRL_BYTES {
            return Err(KrlCodecError::InputTooLarge);
        }
        let mut bytes = Vec::with_capacity(len);
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&1_u32.to_be_bytes());
        bytes.extend_from_slice(&self.version.to_be_bytes());
        bytes.extend_from_slice(&self.generated_at_seconds.to_be_bytes());
        bytes.extend_from_slice(&0_u64.to_be_bytes());
        bytes.extend_from_slice(&[0; 8]); // Empty reserved and comment SSH strings.
        if !self.revoked_serials.is_empty() {
            bytes.push(1);
            put_len(&mut bytes, len - HEADER_BYTES - 5)?;
            put_len(&mut bytes, CA_BLOB_BYTES)?;
            bytes.extend_from_slice(&self.ca_blob);
            bytes.extend_from_slice(&0_u32.to_be_bytes());
            bytes.push(0x20);
            put_len(&mut bytes, 8 * self.revoked_serials.len())?;
            for serial in &self.revoked_serials {
                bytes.extend_from_slice(&serial.to_be_bytes());
            }
        }
        Ok(bytes)
    }

    /// Decode the exact subset, comparing a nonempty snapshot to its captured expected CA.
    ///
    /// The expected CA must itself be canonical even when the snapshot is empty. Supplying a
    /// key does not authenticate it. Transport status, identity and request provenance remain
    /// consumer duties.
    ///
    /// # Errors
    /// Rejects oversize input before parsing/allocation, invalid headers or CA, unsupported or
    /// duplicate sections, malformed lengths, trailing bytes, and invalid/over-cap serial lists.
    pub fn from_bytes(input: &[u8], expected_ca_public_key: &str) -> Result<Self, KrlCodecError> {
        if input.len() > MAX_USER_CA_KRL_BYTES {
            return Err(KrlCodecError::InputTooLarge);
        }
        let mut remaining = input;
        if take(&mut remaining, MAGIC.len())? != MAGIC || read_u32(&mut remaining)? != 1 {
            return Err(KrlCodecError::InvalidHeader);
        }
        let version = read_u64(&mut remaining)?;
        let generated_at_seconds = read_u64(&mut remaining)?;
        if version == 0
            || read_u64(&mut remaining)? != 0
            || !read_string(&mut remaining)?.is_empty()
            || !read_string(&mut remaining)?.is_empty()
        {
            return Err(KrlCodecError::InvalidHeader);
        }
        let ca_blob = parse_ca(expected_ca_public_key)?;
        let serials = if remaining.is_empty() {
            &[][..]
        } else {
            if take(&mut remaining, 1)? != [1] {
                return Err(KrlCodecError::InvalidFormat);
            }
            let mut section = read_string(&mut remaining)?;
            if !remaining.is_empty() {
                return Err(KrlCodecError::InvalidFormat);
            }
            let embedded_ca = read_string(&mut section)?;
            if embedded_ca.len() != CA_BLOB_BYTES {
                return Err(KrlCodecError::InvalidCa);
            }
            if embedded_ca != ca_blob {
                return Err(KrlCodecError::CaMismatch);
            }
            if !read_string(&mut section)?.is_empty() || take(&mut section, 1)? != [0x20] {
                return Err(KrlCodecError::InvalidFormat);
            }
            let serials = read_string(&mut section)?;
            if !section.is_empty() || serials.is_empty() || serials.len() % 8 != 0 {
                return Err(KrlCodecError::InvalidFormat);
            }
            if serials.len() / 8 > MAX_USER_CA_KRL_SERIALS {
                return Err(KrlCodecError::TooManySerials);
            }
            serials
        };
        // Validate every serial before allocating the owned list.
        let mut last = 0;
        for chunk in serials.as_chunks::<8>().0 {
            let serial = u64::from_be_bytes(*chunk);
            if serial <= last {
                return Err(KrlCodecError::InvalidSerials);
            }
            last = serial;
        }
        let revoked_serials =
            serials.as_chunks::<8>().0.iter().map(|chunk| u64::from_be_bytes(*chunk)).collect();
        Ok(Self {
            ca_public_key: expected_ca_public_key.into(),
            ca_blob,
            version,
            generated_at_seconds,
            revoked_serials,
        })
    }

    /// Decode a complete success body with the exact required HTTP response metadata.
    ///
    /// # Errors
    /// Rejects missing/incorrect media type, cache prevention or request id, or invalid bytes.
    /// The caller separately verifies status, current authentication and captured provenance.
    pub fn from_http_bytes(
        input: &[u8],
        expected_ca_public_key: &str,
        content_type: Option<&str>,
        cache_control: Option<&str>,
        pragma: Option<&str>,
        request_id: Option<&str>,
    ) -> Result<Self, KrlCodecError> {
        if content_type != Some(USER_CA_KRL_CONTENT_TYPE)
            || cache_control != Some("no-store")
            || pragma != Some("no-cache")
            || request_id.is_none_or(str::is_empty)
        {
            return Err(KrlCodecError::HttpMetadata);
        }
        Self::from_bytes(input, expected_ca_public_key)
    }
}

fn parse_ca(public_key: &str) -> Result<[u8; CA_BLOB_BYTES], KrlCodecError> {
    if public_key.len() != 80 || !public_key.starts_with("ssh-ed25519 ") {
        return Err(KrlCodecError::InvalidCa);
    }
    let key = PublicKey::from_openssh(public_key).map_err(|_| KrlCodecError::InvalidCa)?;
    if key.algorithm() != Algorithm::Ed25519
        || key.to_openssh().map_err(|_| KrlCodecError::InvalidCa)? != public_key
    {
        return Err(KrlCodecError::InvalidCa);
    }
    key.to_bytes()
        .map_err(|_| KrlCodecError::InvalidCa)?
        .try_into()
        .map_err(|_| KrlCodecError::InvalidCa)
}

fn validate_serials(serials: &[u64]) -> Result<(), KrlCodecError> {
    if serials.len() > MAX_USER_CA_KRL_SERIALS {
        return Err(KrlCodecError::TooManySerials);
    }
    if serials.first() == Some(&0) || serials.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(KrlCodecError::InvalidSerials);
    }
    Ok(())
}

fn put_len(bytes: &mut Vec<u8>, len: usize) -> Result<(), KrlCodecError> {
    let len = u32::try_from(len).map_err(|_| KrlCodecError::InvalidFormat)?;
    bytes.extend_from_slice(&len.to_be_bytes());
    Ok(())
}

fn take<'a>(input: &mut &'a [u8], count: usize) -> Result<&'a [u8], KrlCodecError> {
    let (head, tail) = input.split_at_checked(count).ok_or(KrlCodecError::InvalidFormat)?;
    *input = tail;
    Ok(head)
}

fn read_u32(input: &mut &[u8]) -> Result<u32, KrlCodecError> {
    let bytes = take(input, 4)?.try_into().map_err(|_| KrlCodecError::InvalidFormat)?;
    Ok(u32::from_be_bytes(bytes))
}

fn read_u64(input: &mut &[u8]) -> Result<u64, KrlCodecError> {
    let bytes = take(input, 8)?.try_into().map_err(|_| KrlCodecError::InvalidFormat)?;
    Ok(u64::from_be_bytes(bytes))
}

fn read_string<'a>(input: &mut &'a [u8]) -> Result<&'a [u8], KrlCodecError> {
    let len = usize::try_from(read_u32(input)?).map_err(|_| KrlCodecError::InvalidFormat)?;
    take(input, len)
}
