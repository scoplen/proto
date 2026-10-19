// SPDX-License-Identifier: Apache-2.0
//! Bounded current-account Resource response for K-3/K-5.

use std::fmt;

use scoplen_model::validate_uuid_v7;
use serde::Serialize;
use serde_json::{Map, Value};
use thiserror::Error;
use uuid::Uuid;

use crate::{
    certificate::{valid_strong_etag, valid_utc_timestamp},
    request_wire,
};

/// Maximum complete JSON body, including escapes, whitespace, and extensions.
pub const MAX_ACCOUNT_PROFILE_BYTES: usize = 4_096;
/// Maximum UTF-8 byte length of a present email address.
pub const MAX_ACCOUNT_EMAIL_BYTES: usize = 320;

/// Syntax error in a current-account Resource response.
///
/// Diagnostics never contain the address or raw response.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AccountProfileCodecError {
    /// The complete body exceeds 4,096 bytes.
    #[error("account profile exceeds 4096 bytes")]
    ResponseTooLarge,
    /// Malformed JSON or a duplicate name at any depth.
    #[error("invalid account profile JSON")]
    InvalidJson,
    /// Missing, mistyped, or invalid required field.
    #[error("invalid account profile field: {0}")]
    InvalidField(&'static str),
    /// Required HTTP metadata is missing or mismatched.
    #[error("invalid account profile HTTP metadata")]
    HttpMetadata,
}

/// The current account's public profile. The email is verified by the identity service, not this codec.
#[derive(Clone, Eq, PartialEq)]
pub struct AccountProfile {
    /// Canonical lowercase `UUIDv7` account identifier.
    pub id: Uuid,
    /// Strong HTTP entity tag including double quotes.
    pub etag: String,
    /// UTC creation timestamp.
    pub created_at: String,
    /// UTC update timestamp.
    pub updated_at: String,
    /// Present verified address, or no address. Encodes as required JSON null when absent.
    pub email: Option<String>,
}

impl fmt::Debug for AccountProfile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AccountProfile")
            .field("has_email", &self.email.is_some())
            .finish_non_exhaustive()
    }
}

impl AccountProfile {
    /// Construct a validated public profile.
    ///
    /// # Errors
    ///
    /// Rejects invalid metadata or address syntax.
    pub fn new(
        id: Uuid,
        etag: impl Into<String>,
        created_at: impl Into<String>,
        updated_at: impl Into<String>,
        email: Option<String>,
    ) -> Result<Self, AccountProfileCodecError> {
        let profile = Self {
            id,
            etag: etag.into(),
            created_at: created_at.into(),
            updated_at: updated_at.into(),
            email,
        };
        profile.validate()?;
        Ok(profile)
    }

    /// Recheck public mutable fields before use or encoding.
    ///
    /// # Errors
    ///
    /// Rejects invalid metadata or address syntax.
    pub fn validate(&self) -> Result<(), AccountProfileCodecError> {
        validate_uuid_v7(self.id).map_err(|_| AccountProfileCodecError::InvalidField("id"))?;
        if !valid_strong_etag(&self.etag) {
            return Err(AccountProfileCodecError::InvalidField("etag"));
        }
        if !valid_utc_timestamp(&self.created_at) {
            return Err(AccountProfileCodecError::InvalidField("created_at"));
        }
        if !valid_utc_timestamp(&self.updated_at) {
            return Err(AccountProfileCodecError::InvalidField("updated_at"));
        }
        if self.email.as_ref().is_some_and(|email| {
            email.is_empty()
                || email.len() > MAX_ACCOUNT_EMAIL_BYTES
                || email
                    .chars()
                    .any(|character| character.is_control() || character.is_whitespace())
        }) {
            return Err(AccountProfileCodecError::InvalidField("data.email"));
        }
        Ok(())
    }

    /// Decode a complete JSON Resource, ignoring extensions but rejecting duplicate names recursively.
    ///
    /// # Errors
    ///
    /// Rejects oversized, malformed, missing, or invalid fields.
    pub fn from_json(input: &[u8]) -> Result<Self, AccountProfileCodecError> {
        if input.len() > MAX_ACCOUNT_PROFILE_BYTES {
            return Err(AccountProfileCodecError::ResponseTooLarge);
        }
        let mut fields = request_wire::decode_unique_object(input)
            .map_err(|()| AccountProfileCodecError::InvalidJson)?;
        let id_text = take_string(&mut fields, "id")?;
        let id =
            Uuid::parse_str(&id_text).map_err(|_| AccountProfileCodecError::InvalidField("id"))?;
        if id.to_string() != id_text {
            return Err(AccountProfileCodecError::InvalidField("id"));
        }
        let etag = take_string(&mut fields, "etag")?;
        let created_at = take_string(&mut fields, "created_at")?;
        let updated_at = take_string(&mut fields, "updated_at")?;
        let Some(Value::Object(mut data)) = fields.remove("data") else {
            return Err(AccountProfileCodecError::InvalidField("data"));
        };
        let email = match data.remove("email") {
            Some(Value::Null) => None,
            Some(Value::String(email)) => Some(email),
            _ => return Err(AccountProfileCodecError::InvalidField("data.email")),
        };
        Self::new(id, etag, created_at, updated_at, email)
    }

    /// Decode a response with the exact `ETag` and cache-prevention headers.
    ///
    /// # Errors
    ///
    /// Rejects an invalid body or HTTP metadata.
    pub fn from_http_json(
        input: &[u8],
        etag_header: Option<&str>,
        cache_control: Option<&str>,
        pragma: Option<&str>,
    ) -> Result<Self, AccountProfileCodecError> {
        let profile = Self::from_json(input)?;
        if etag_header != Some(profile.etag.as_str())
            || cache_control != Some("no-store")
            || pragma != Some("no-cache")
        {
            return Err(AccountProfileCodecError::HttpMetadata);
        }
        Ok(profile)
    }

    /// Encode in fixed member order without insignificant whitespace.
    ///
    /// # Errors
    ///
    /// Rejects invalid mutable fields or a complete body above 4,096 bytes.
    pub fn to_json(&self) -> Result<Vec<u8>, AccountProfileCodecError> {
        #[derive(Serialize)]
        struct Data<'a> {
            email: Option<&'a str>,
        }
        #[derive(Serialize)]
        struct Wire<'a> {
            id: &'a str,
            etag: &'a str,
            created_at: &'a str,
            updated_at: &'a str,
            data: Data<'a>,
        }
        self.validate()?;
        let id = self.id.to_string();
        let body = serde_json::to_vec(&Wire {
            id: &id,
            etag: &self.etag,
            created_at: &self.created_at,
            updated_at: &self.updated_at,
            data: Data { email: self.email.as_deref() },
        })
        .map_err(|_| AccountProfileCodecError::InvalidJson)?;
        if body.len() > MAX_ACCOUNT_PROFILE_BYTES {
            return Err(AccountProfileCodecError::ResponseTooLarge);
        }
        Ok(body)
    }
}

fn take_string(
    fields: &mut Map<String, Value>,
    name: &'static str,
) -> Result<String, AccountProfileCodecError> {
    fields
        .remove(name)
        .and_then(|value| value.as_str().map(str::to_owned))
        .ok_or(AccountProfileCodecError::InvalidField(name))
}
