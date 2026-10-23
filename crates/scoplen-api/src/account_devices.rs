// SPDX-License-Identifier: Apache-2.0
//! D-113 bounded complete account device-statement snapshot.
//!
//! This codec checks transport syntax only. Consumers must bind the account and verify every
//! K-2 statement with their already trusted account key before deriving a device list.

use std::fmt;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use scoplen_model::validate_uuid_v7;
use serde::Serialize;
use serde_json::{Map, Value};
use thiserror::Error;
use uuid::Uuid;

use crate::request_wire;

/// Maximum decoded byte length of one certificate or revocation.
pub const MAX_ACCOUNT_DEVICE_ARTIFACT_BYTES: usize = 65_536;
/// Maximum combined decoded certificate and revocation bytes.
pub const MAX_ACCOUNT_DEVICE_DECODED_BYTES: usize = 4_194_304;
/// Maximum complete JSON body, including whitespace, escapes and ignored extensions.
pub const MAX_ACCOUNT_DEVICE_STATEMENTS_BYTES: usize = 6_291_456;

/// Redacted syntax and size errors; never includes identifiers, artifacts or raw responses.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AccountDeviceStatementsCodecError {
    /// The complete JSON body exceeds six MiB.
    #[error("account device statements exceed 6291456 bytes")]
    ResponseTooLarge,
    /// Combined decoded statement bytes exceed four MiB.
    #[error("account device statements exceed 4194304 decoded bytes")]
    DecodedTooLarge,
    /// Malformed JSON or a duplicate member name at any depth.
    #[error("invalid account device statements JSON")]
    InvalidJson,
    /// Missing, mistyped, unsorted or noncanonical required field.
    #[error("invalid account device statements field: {0}")]
    InvalidField(&'static str),
    /// Required HTTP cache prevention metadata is missing or incorrect.
    #[error("invalid account device statements HTTP metadata")]
    HttpMetadata,
    /// This read-only request contains forbidden input.
    #[error("invalid account devices request")]
    InvalidRequest,
}

/// Complete opaque signed-statement transport. The container has no independent signature.
#[derive(Clone, Eq, PartialEq)]
pub struct AccountDeviceStatements {
    /// Canonical lowercase `UUIDv7` account identifier on the wire.
    pub account_id: Uuid,
    /// All certificates, strictly ordered by their decoded raw bytes.
    pub certificates: Vec<Vec<u8>>,
    /// All revocations, strictly ordered by their decoded raw bytes.
    pub revocations: Vec<Vec<u8>>,
}

impl fmt::Debug for AccountDeviceStatements {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AccountDeviceStatements")
            .field("certificate_count", &self.certificates.len())
            .field("revocation_count", &self.revocations.len())
            .finish_non_exhaustive()
    }
}

impl AccountDeviceStatements {
    /// Construct a bounded snapshot without decoding or verifying K-2 statements.
    ///
    /// # Errors
    ///
    /// Rejects invalid identifiers, empty or oversized artifacts, invalid ordering or budgets.
    pub fn new(
        account_id: Uuid,
        certificates: Vec<Vec<u8>>,
        revocations: Vec<Vec<u8>>,
    ) -> Result<Self, AccountDeviceStatementsCodecError> {
        let snapshot = Self { account_id, certificates, revocations };
        snapshot.validate()?;
        Ok(snapshot)
    }

    /// Recheck all public mutable fields and the canonical encoded body budget.
    ///
    /// # Errors
    ///
    /// Rejects invalid identifiers, artifacts, ordering or aggregate/encoded budgets.
    pub fn validate(&self) -> Result<(), AccountDeviceStatementsCodecError> {
        validate_uuid_v7(self.account_id)
            .map_err(|_| AccountDeviceStatementsCodecError::InvalidField("account_id"))?;
        let mut decoded_bytes = 0;
        let mut encoded_bytes =
            br#"{"account_id":"","certificates":[],"revocations":[]}"#.len() + 36;
        for (name, artifacts) in
            [("certificates", &self.certificates), ("revocations", &self.revocations)]
        {
            if artifacts.windows(2).any(|pair| pair[0] >= pair[1]) {
                return Err(AccountDeviceStatementsCodecError::InvalidField(name));
            }
            encoded_bytes += artifacts.len().saturating_sub(1);
            for artifact in artifacts {
                if artifact.is_empty() || artifact.len() > MAX_ACCOUNT_DEVICE_ARTIFACT_BYTES {
                    return Err(AccountDeviceStatementsCodecError::InvalidField(name));
                }
                decoded_bytes += artifact.len();
                if decoded_bytes > MAX_ACCOUNT_DEVICE_DECODED_BYTES {
                    return Err(AccountDeviceStatementsCodecError::DecodedTooLarge);
                }
                // Unpadded base64url is ASCII and requires no JSON escaping.
                encoded_bytes += (artifact.len() * 4).div_ceil(3) + 2;
                if encoded_bytes > MAX_ACCOUNT_DEVICE_STATEMENTS_BYTES {
                    return Err(AccountDeviceStatementsCodecError::ResponseTooLarge);
                }
            }
        }
        Ok(())
    }

    /// Decode a complete response, ignoring extensions and rejecting duplicate names recursively.
    ///
    /// # Errors
    ///
    /// Rejects malformed, noncanonical, unsorted or oversized transport data.
    pub fn from_json(input: &[u8]) -> Result<Self, AccountDeviceStatementsCodecError> {
        if input.len() > MAX_ACCOUNT_DEVICE_STATEMENTS_BYTES {
            return Err(AccountDeviceStatementsCodecError::ResponseTooLarge);
        }
        let mut fields = request_wire::decode_unique_object(input)
            .map_err(|()| AccountDeviceStatementsCodecError::InvalidJson)?;
        let Some(Value::String(account_id_text)) = fields.remove("account_id") else {
            return Err(AccountDeviceStatementsCodecError::InvalidField("account_id"));
        };
        let account_id = Uuid::parse_str(&account_id_text)
            .map_err(|_| AccountDeviceStatementsCodecError::InvalidField("account_id"))?;
        if account_id.to_string() != account_id_text {
            return Err(AccountDeviceStatementsCodecError::InvalidField("account_id"));
        }
        let mut decoded_bytes = 0;
        let certificates = take_artifacts(&mut fields, "certificates", &mut decoded_bytes)?;
        let revocations = take_artifacts(&mut fields, "revocations", &mut decoded_bytes)?;
        Self::new(account_id, certificates, revocations)
    }

    /// Decode a response requiring exact `no-store` and `no-cache` headers.
    ///
    /// # Errors
    ///
    /// Rejects an invalid body or missing/incorrect HTTP metadata.
    pub fn from_http_json(
        input: &[u8],
        cache_control: Option<&str>,
        pragma: Option<&str>,
    ) -> Result<Self, AccountDeviceStatementsCodecError> {
        if cache_control != Some("no-store") || pragma != Some("no-cache") {
            return Err(AccountDeviceStatementsCodecError::HttpMetadata);
        }
        Self::from_json(input)
    }

    /// Encode in field order `account_id`, `certificates`, `revocations` without extra whitespace.
    ///
    /// # Errors
    ///
    /// Rejects invalid mutable fields or an exceeded body budget.
    pub fn to_json(&self) -> Result<Vec<u8>, AccountDeviceStatementsCodecError> {
        #[derive(Serialize)]
        struct Wire {
            account_id: String,
            certificates: Vec<String>,
            revocations: Vec<String>,
        }
        self.validate()?;
        let body = serde_json::to_vec(&Wire {
            account_id: self.account_id.to_string(),
            certificates: self
                .certificates
                .iter()
                .map(|item| URL_SAFE_NO_PAD.encode(item))
                .collect(),
            revocations: self.revocations.iter().map(|item| URL_SAFE_NO_PAD.encode(item)).collect(),
        })
        .map_err(|_| AccountDeviceStatementsCodecError::InvalidJson)?;
        if body.len() > MAX_ACCOUNT_DEVICE_STATEMENTS_BYTES {
            return Err(AccountDeviceStatementsCodecError::ResponseTooLarge);
        }
        Ok(body)
    }
}

/// Validate the input-free current-account device GET before protected collection access.
///
/// Authentication, current identity, origin, `DPoP` and scope are independent consumer checks.
///
/// # Errors
///
/// Rejects any query, nonempty body, `Idempotency-Key` or `If-Match`, including empty headers.
pub fn validate_account_devices_request(
    query: Option<&str>,
    body: &[u8],
    has_idempotency_key: bool,
    has_if_match: bool,
) -> Result<(), AccountDeviceStatementsCodecError> {
    if query.is_some() || !body.is_empty() || has_idempotency_key || has_if_match {
        return Err(AccountDeviceStatementsCodecError::InvalidRequest);
    }
    Ok(())
}

fn take_artifacts(
    fields: &mut Map<String, Value>,
    name: &'static str,
    decoded_bytes: &mut usize,
) -> Result<Vec<Vec<u8>>, AccountDeviceStatementsCodecError> {
    let Some(Value::Array(items)) = fields.remove(name) else {
        return Err(AccountDeviceStatementsCodecError::InvalidField(name));
    };
    items
        .into_iter()
        .map(|value| {
            let Value::String(encoded) = value else {
                return Err(AccountDeviceStatementsCodecError::InvalidField(name));
            };
            if encoded.is_empty()
                || encoded.len() > (MAX_ACCOUNT_DEVICE_ARTIFACT_BYTES * 4).div_ceil(3)
            {
                return Err(AccountDeviceStatementsCodecError::InvalidField(name));
            }
            let bytes = URL_SAFE_NO_PAD
                .decode(&encoded)
                .map_err(|_| AccountDeviceStatementsCodecError::InvalidField(name))?;
            if bytes.is_empty()
                || bytes.len() > MAX_ACCOUNT_DEVICE_ARTIFACT_BYTES
                || URL_SAFE_NO_PAD.encode(&bytes) != encoded
            {
                return Err(AccountDeviceStatementsCodecError::InvalidField(name));
            }
            *decoded_bytes += bytes.len();
            if *decoded_bytes > MAX_ACCOUNT_DEVICE_DECODED_BYTES {
                return Err(AccountDeviceStatementsCodecError::DecodedTooLarge);
            }
            Ok(bytes)
        })
        .collect()
}
