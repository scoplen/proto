// SPDX-License-Identifier: Apache-2.0
//! Issuer-specific OIDC authorization response intake.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use scoplen_crypto::{SecretBytes, SecretVec};
use sha2::{Digest, Sha256};

use super::validate_issuer;

const MAX_QUERY_BYTES: usize = 8_192;
const MAX_CODE_BYTES: usize = 4_096;
const PATH_PREFIX: &str = "/api/v1/auth/enterprise/oidc/";
const PATH_SUFFIX: &str = "/callback";

/// Issuer identification pinned to the original attempt at discovery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IssuerIdentification {
    /// Require the RFC 9207 response parameter, including on denial.
    ResponseParameter,
    /// The registered URI is exclusive to this issuer. Reject an unsolicited parameter.
    ExclusiveCallback,
}

/// Authorization response content. Provider diagnostic strings are discarded.
#[derive(Debug, Eq, PartialEq)]
pub enum CallbackResult {
    /// An opaque, decoded authorization code for the one-time token request.
    Code(SecretVec),
    /// The provider returned a valid error response.
    Denied,
}

/// Callback intake. Only the correlation values are available before issuer verification.
#[derive(Debug, Eq, PartialEq)]
pub struct Callback<'a> {
    /// Original state bytes for the attempt lookup.
    pub state: SecretBytes<32>,
    /// Cookie bytes for comparison with the original browser binding.
    pub browser_binding: SecretBytes<32>,
    path: &'a str,
    returned_issuer: Option<SecretVec>,
    result: CallbackResult,
}

/// A content-free rejection suitable for one generic callback response.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("invalid identity callback")]
pub struct InvalidCallback;

/// Derive the registered path from the issuer's exact validated UTF-8 spelling.
///
/// # Errors
/// Rejects an issuer outside the Organization draft URL profile.
pub fn callback_path(issuer: &str) -> Result<String, InvalidCallback> {
    validate_issuer(issuer).map_err(|_| InvalidCallback)?;
    let hash = Sha256::digest(issuer.as_bytes());
    Ok(format!("{PATH_PREFIX}{hash:x}{PATH_SUFFIX}"))
}

/// Name the distinct D-169 activation cookie for a fresh state value.
#[must_use]
pub fn activation_cookie_name(state: &SecretBytes<32>) -> String {
    let digest = Sha256::digest(state.as_bytes());
    format!("__Host-spl-auth-activate-{digest:x}")
}

/// Select the activation cookie name from exactly one canonical state parameter.
/// The receiver still verifies the durable attempt's purpose, browser binding, and callback.
///
/// # Errors
/// Rejects oversized queries or a missing, ambiguous, or invalid state.
pub fn activation_cookie_name_from_query(query: &str) -> Result<String, InvalidCallback> {
    callback_state(query).map(|state| activation_cookie_name(&state))
}

/// Name the distinct D-170 member-link cookie for a fresh state value.
#[must_use]
pub fn member_link_cookie_name(state: &SecretBytes<32>) -> String {
    let digest = Sha256::digest(state.as_bytes());
    format!("__Host-spl-auth-link-{digest:x}")
}

/// Select the member-link cookie name from exactly one canonical state parameter.
/// The receiver still verifies the durable link purpose, browser binding, and callback.
///
/// # Errors
/// Rejects oversized queries or a missing, ambiguous, or invalid state.
pub fn member_link_cookie_name_from_query(query: &str) -> Result<String, InvalidCallback> {
    callback_state(query).map(|state| member_link_cookie_name(&state))
}

fn callback_state(query: &str) -> Result<SecretBytes<32>, InvalidCallback> {
    if query.len() > MAX_QUERY_BYTES {
        return Err(InvalidCallback);
    }
    let mut state = None;
    for pair in query.split('&') {
        let (name, value) = pair.split_once('=').ok_or(InvalidCallback)?;
        if decode_form(name)?.as_bytes() == b"state" {
            if state.is_some() {
                return Err(InvalidCallback);
            }
            state = Some(random_value(decode_form(value)?.as_bytes())?);
        }
    }
    state.ok_or(InvalidCallback)
}

impl<'a> Callback<'a> {
    /// Parse the raw request target and matching callback cookie values. The receiver
    /// verifies the trusted HTTPS origin and preserves cookie multiplicity.
    ///
    /// # Errors
    /// Rejects wrong route syntax, invalid correlation values, and malformed or oversized
    /// authorization responses. Verify the original attempt before calling [`Self::bind_issuer`].
    pub fn parse(
        method: &str,
        path: &'a str,
        query: &str,
        mut cookie_values: impl Iterator<Item = impl AsRef<str>>,
    ) -> Result<Self, InvalidCallback> {
        if method != "GET" || query.len() > MAX_QUERY_BYTES || !is_callback_path(path) {
            return Err(InvalidCallback);
        }
        let binding = cookie_values.next().ok_or(InvalidCallback)?;
        let browser_binding = random_value(binding.as_ref().as_bytes())?;
        if cookie_values.next().is_some() {
            return Err(InvalidCallback);
        }
        let mut state = None;
        let mut returned_issuer = None;
        let mut result = None;
        for pair in query.split('&') {
            let (name, value) = pair.split_once('=').ok_or(InvalidCallback)?;
            let name = decode_form(name)?;
            let value = decode_form(value)?;
            match name.as_bytes() {
                b"state" if state.is_none() => state = Some(random_value(value.as_bytes())?),
                b"iss" if returned_issuer.is_none() => returned_issuer = Some(value),
                b"code" if result.is_none() && value.len() <= MAX_CODE_BYTES => {
                    validate_oauth_value(&value)?;
                    result = Some(CallbackResult::Code(value));
                }
                b"error" if result.is_none() => {
                    validate_oauth_value(&value)?;
                    result = Some(CallbackResult::Denied);
                }
                b"state" | b"iss" | b"code" | b"error" | b"" => return Err(InvalidCallback),
                // OAuth extensions do not affect issuer selection or correlation.
                _ => {}
            }
        }
        Ok(Self {
            state: state.ok_or(InvalidCallback)?,
            browser_binding,
            path,
            returned_issuer,
            result: result.ok_or(InvalidCallback)?,
        })
    }

    /// Relate the callback path and issuer parameter to the original attempt before exposing
    /// its result. The receiver still enforces current authority and atomically claims the attempt
    /// before exchanging a code.
    ///
    /// # Errors
    /// Rejects an incorrect registered path and a missing, unsolicited or mismatched issuer.
    pub fn bind_issuer(
        self,
        issuer: &str,
        identification: IssuerIdentification,
    ) -> Result<CallbackResult, InvalidCallback> {
        if self.path != callback_path(issuer)? {
            return Err(InvalidCallback);
        }
        match (identification, self.returned_issuer) {
            (IssuerIdentification::ResponseParameter, Some(value))
                if value.as_bytes() == issuer.as_bytes() => {}
            (IssuerIdentification::ExclusiveCallback, None) => {}
            _ => return Err(InvalidCallback),
        }
        Ok(self.result)
    }
}

fn is_callback_path(path: &str) -> bool {
    path.strip_prefix(PATH_PREFIX).and_then(|path| path.strip_suffix(PATH_SUFFIX)).is_some_and(
        |hash| {
            hash.len() == 64
                && hash.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        },
    )
}

fn random_value(value: &[u8]) -> Result<SecretBytes<32>, InvalidCallback> {
    if value.len() != 43 {
        return Err(InvalidCallback);
    }
    let bytes = SecretVec::new(URL_SAFE_NO_PAD.decode(value).map_err(|_| InvalidCallback)?);
    SecretBytes::from_slice(bytes.as_bytes()).ok_or(InvalidCallback)
}

fn validate_oauth_value(value: &SecretVec) -> Result<(), InvalidCallback> {
    if value.is_empty() || !value.as_bytes().iter().all(|byte| (b' '..=b'~').contains(byte)) {
        return Err(InvalidCallback);
    }
    Ok(())
}

// The generic URL form parser replaces invalid UTF-8 and preserves broken escapes.
// The callback must compare only unambiguously decoded values.
fn decode_form(encoded: &str) -> Result<SecretVec, InvalidCallback> {
    let mut bytes = encoded.bytes();
    let mut decoded = Vec::with_capacity(encoded.len());
    while let Some(byte) = bytes.next() {
        let value = match byte {
            b'+' => b' ',
            b'%' => {
                let (Some(high), Some(low)) = (hex_value(bytes.next()), hex_value(bytes.next()))
                else {
                    drop(SecretVec::new(decoded));
                    return Err(InvalidCallback);
                };
                (high << 4) | low
            }
            _ => byte,
        };
        decoded.push(value);
    }
    let decoded = SecretVec::new(decoded);
    std::str::from_utf8(decoded.as_bytes()).map_err(|_| InvalidCallback)?;
    Ok(decoded)
}

fn hex_value(byte: Option<u8>) -> Option<u8> {
    match byte {
        Some(value @ b'0'..=b'9') => Some(value - b'0'),
        Some(value @ b'A'..=b'F') => Some(value - b'A' + 10),
        Some(value @ b'a'..=b'f') => Some(value - b'a' + 10),
        _ => None,
    }
}
