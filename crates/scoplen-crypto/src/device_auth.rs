// SPDX-License-Identifier: Apache-2.0
//! Validated K-3 device-authentication signature context.

use std::net::{Ipv4Addr, Ipv6Addr};

use http::Uri;
use scoplen_model::validate_uuid_v7;
use thiserror::Error;
use uuid::Uuid;

const AUTH_DOMAIN: &[u8] = b"spl-auth-v1";
const MAX_ORIGIN_BYTES: usize = 2_048;

/// Invalid K-3 device-authentication signature context.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum DeviceAuthError {
    /// The origin is not the canonical HTTPS origin required by K-3.
    #[error("device authentication origin must be canonical HTTPS")]
    InvalidOrigin,
    /// The challenge nonce is not exactly 32 bytes of lowercase hexadecimal.
    #[error("device authentication nonce must be 32 bytes of lowercase hexadecimal")]
    InvalidNonce,
    /// The device identifier is not a `UUIDv7`.
    #[error("device authentication device id must be UUIDv7")]
    InvalidDeviceId,
}

/// A validated origin, challenge, and device identifier for the K-3 signature.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeviceAuthContext {
    origin: String,
    nonce: [u8; 32],
    device_id: Uuid,
}

impl DeviceAuthContext {
    /// Validate the exact origin, canonical nonce, and device identifier.
    ///
    /// # Errors
    ///
    /// Rejects a noncanonical HTTPS origin, malformed nonce, or non-v7 device identifier.
    pub fn new(origin: &str, nonce_hex: &str, device_id: Uuid) -> Result<Self, DeviceAuthError> {
        validate_origin(origin)?;
        validate_uuid_v7(device_id).map_err(|_| DeviceAuthError::InvalidDeviceId)?;
        let nonce = decode_nonce(nonce_hex)?;
        Ok(Self { origin: origin.to_owned(), nonce, device_id })
    }

    /// Return `spl-auth-v1 || UTF-8 origin || raw nonce || raw UUIDv7`.
    #[must_use]
    pub fn signature_input(&self) -> Vec<u8> {
        let mut input = Vec::with_capacity(AUTH_DOMAIN.len() + self.origin.len() + 32 + 16);
        input.extend_from_slice(AUTH_DOMAIN);
        input.extend_from_slice(self.origin.as_bytes());
        input.extend_from_slice(&self.nonce);
        input.extend_from_slice(self.device_id.as_bytes());
        input
    }
}

fn decode_nonce(value: &str) -> Result<[u8; 32], DeviceAuthError> {
    if value.len() != 64
        || !value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(DeviceAuthError::InvalidNonce);
    }
    let mut nonce = [0_u8; 32];
    for (index, byte) in nonce.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| DeviceAuthError::InvalidNonce)?;
    }
    Ok(nonce)
}

pub(crate) fn validate_origin(origin: &str) -> Result<(), DeviceAuthError> {
    if origin.is_empty() || origin.len() > MAX_ORIGIN_BYTES || !origin.is_ascii() {
        return Err(DeviceAuthError::InvalidOrigin);
    }
    let uri: Uri = origin.parse().map_err(|_| DeviceAuthError::InvalidOrigin)?;
    if uri.scheme_str() != Some("https") {
        return Err(DeviceAuthError::InvalidOrigin);
    }
    let authority = uri.authority().ok_or(DeviceAuthError::InvalidOrigin)?;
    if authority.as_str().contains('@') {
        return Err(DeviceAuthError::InvalidOrigin);
    }
    let host = authority.host();
    let canonical_host =
        if let Some(inner) = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
            let ip: Ipv6Addr = inner.parse().map_err(|_| DeviceAuthError::InvalidOrigin)?;
            format!("[{ip}]")
        } else if let Ok(ip) = host.parse::<Ipv4Addr>() {
            ip.to_string()
        } else {
            let final_label = host.rsplit('.').next().ok_or(DeviceAuthError::InvalidOrigin)?;
            let ambiguous_ip = final_label.bytes().all(|byte| byte.is_ascii_digit())
                || final_label.strip_prefix("0x").is_some_and(|digits| {
                    !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_hexdigit())
                });
            if ambiguous_ip {
                return Err(DeviceAuthError::InvalidOrigin);
            }
            validate_dns_name(host)?;
            host.to_owned()
        };
    let port = match authority.port_u16() {
        Some(0 | 443) => return Err(DeviceAuthError::InvalidOrigin),
        Some(port) => format!(":{port}"),
        None => String::new(),
    };
    if origin != format!("https://{canonical_host}{port}") {
        return Err(DeviceAuthError::InvalidOrigin);
    }
    Ok(())
}

fn validate_dns_name(host: &str) -> Result<(), DeviceAuthError> {
    if host.is_empty() || host.len() > 253 || !host.is_ascii() {
        return Err(DeviceAuthError::InvalidOrigin);
    }
    for label in host.split('.') {
        if label.is_empty()
            || label.len() > 63
            || !label
                .bytes()
                .next()
                .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
            || !label
                .bytes()
                .last()
                .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
            return Err(DeviceAuthError::InvalidOrigin);
        }
    }
    Ok(())
}
