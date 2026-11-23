// SPDX-License-Identifier: Apache-2.0
//! D-166 wire types for the untested issuer held in one Organization's draft.

use std::fmt;

use serde::Serialize;
use uuid::Uuid;

pub mod callback;
pub mod reference;
pub mod test_login;

use crate::{
    certificate::valid_utc_timestamp,
    organization::{
        OrganizationCodecError as Error, OrganizationPreconditionError, encode, object,
        parse_organization_idempotency_key, parse_organization_if_match, take_object, take_string,
        take_uuid, valid_uuid, validate_cache_headers,
    },
};

/// Maximum bytes of the exact decoded issuer string.
pub const MAX_ISSUER_BYTES: usize = 2_048;
/// Maximum complete JSON request, including whitespace.
pub const MAX_CREATE_BYTES: usize = 4_096;
/// Maximum complete JSON Resource, including extensions.
pub const MAX_RESOURCE_BYTES: usize = 8_192;

/// Parsed syntax at the three canonical draft operations.
#[derive(Eq, PartialEq)]
pub enum DraftRequest<'a> {
    /// POST with a single wildcard and a validated request body.
    Create(Uuid, DraftCreate),
    /// Unconditional GET.
    Read,
    /// DELETE bound to the exact submitted strong validator.
    Cancel(Uuid, &'a str),
}

impl fmt::Debug for DraftRequest<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Create(_, _) => f.debug_struct("DraftCreateRequest").finish_non_exhaustive(),
            Self::Read => f.write_str("DraftReadRequest"),
            Self::Cancel(_, _) => f.debug_struct("DraftCancelRequest").finish_non_exhaustive(),
        }
    }
}

/// Public failure classification before checking protected state.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum DraftRequestError {
    /// Invalid query, headers or request body (400).
    #[error("invalid draft request")]
    Invalid,
    /// Complete POST body exceeds its byte bound (413).
    #[error("draft request exceeds its byte bound")]
    TooLarge,
    /// POST requires JSON (415).
    #[error("draft request requires JSON")]
    MediaType,
    /// A mutation lacks its required conditional header (428).
    #[error("draft request requires a precondition")]
    PreconditionRequired,
}

impl<'a> DraftRequest<'a> {
    /// Validate wire syntax after matching the exact route and before reading protected data.
    /// Pass individual header values before list joining and the raw query, including empty queries.
    /// Authentication, `DPoP`, trusted Origin and current authorization belong to the receiver.
    /// # Errors
    /// Rejects incorrect header multiplicity, method, query, body or JSON content type.
    pub fn from_http(
        method: &str,
        query: Option<&str>,
        headers: impl IntoIterator<Item = (&'a str, &'a str)>,
        body: &[u8],
    ) -> Result<Self, DraftRequestError> {
        use DraftRequestError::{Invalid, MediaType, PreconditionRequired, TooLarge};
        if query.is_some() {
            return Err(Invalid);
        }
        let (mut key, mut if_match, mut if_none_match, mut content_type) = (None, None, None, None);
        for (name, value) in headers {
            let field = if name.eq_ignore_ascii_case("Idempotency-Key") {
                &mut key
            } else if name.eq_ignore_ascii_case("If-Match") {
                &mut if_match
            } else if name.eq_ignore_ascii_case("If-None-Match") {
                &mut if_none_match
            } else if name.eq_ignore_ascii_case("Content-Type") {
                &mut content_type
            } else if ["If-Modified-Since", "If-Unmodified-Since", "If-Range"]
                .iter()
                .any(|k| name.eq_ignore_ascii_case(k))
            {
                return Err(Invalid);
            } else {
                continue;
            };
            if field.replace(value).is_some() {
                return Err(Invalid);
            }
        }
        let key_value =
            || parse_organization_idempotency_key(key.ok_or(Invalid)?).map_err(|_| Invalid);
        let condition = |e| match e {
            OrganizationPreconditionError::Required => PreconditionRequired,
            OrganizationPreconditionError::Invalid => Invalid,
        };
        match method {
            "POST" if if_match.is_none() => {
                require_empty_slot(if_none_match).map_err(condition)?;
                let key = key_value()?;
                if !matches!(
                    content_type,
                    Some("application/json" | "application/json; charset=utf-8")
                ) {
                    return Err(MediaType);
                }
                let create = DraftCreate::from_json(body)
                    .map_err(|e| if e == Error::TooLarge { TooLarge } else { Invalid })?;
                Ok(Self::Create(key, create))
            }
            "GET"
                if body.is_empty()
                    && key.is_none()
                    && if_match.is_none()
                    && if_none_match.is_none() =>
            {
                Ok(Self::Read)
            }
            "DELETE" if body.is_empty() && if_none_match.is_none() => {
                let tag = parse_organization_if_match(if_match).map_err(condition)?;
                Ok(Self::Cancel(key_value()?, tag))
            }
            _ => Err(Invalid),
        }
    }
}

/// Validate the syntax of an issuer without normalizing it or making a network request.
///
/// # Errors
/// Rejects an oversized issuer, missing HTTPS authority, credentials, query, fragment,
/// backslash, whitespace or control characters.
pub fn validate_issuer(issuer: &str) -> Result<(), Error> {
    let invalid = Error::InvalidField("issuer");
    if issuer.len() > MAX_ISSUER_BYTES
        || issuer.contains(['\\', '?', '#'])
        || issuer.chars().any(|c| c.is_control() || c.is_whitespace())
    {
        return Err(invalid);
    }
    let (scheme, rest) = issuer.split_once("://").ok_or(invalid.clone())?;
    let authority = rest.split('/').next().unwrap_or_default();
    if !scheme.eq_ignore_ascii_case("https") || authority.is_empty() || authority.contains('@') {
        return Err(invalid);
    }
    let url = url::Url::parse(issuer).map_err(|_| invalid.clone())?;
    if !url.has_host() || !url.username().is_empty() || url.password().is_some() {
        return Err(invalid);
    }
    Ok(())
}

/// Only the issuer may be submitted. Debug output omits its value.
#[derive(Clone, Eq, PartialEq)]
pub struct DraftCreate {
    /// Exact validated issuer, preserving the path and trailing slash.
    pub issuer: String,
}

impl fmt::Debug for DraftCreate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DraftCreate").finish_non_exhaustive()
    }
}

impl DraftCreate {
    /// Parse a bounded, duplicate-free request with no unknown fields.
    /// # Errors
    /// Rejects malformed JSON or an invalid issuer.
    pub fn from_json(bytes: &[u8]) -> Result<Self, Error> {
        let mut root = object(bytes, MAX_CREATE_BYTES)?;
        let mut data = take_object(&mut root, "data")?;
        let issuer = take_string(&mut data, "issuer")?;
        if !data.is_empty() || !root.is_empty() {
            return Err(Error::InvalidField("request members"));
        }
        validate_issuer(&issuer)?;
        Ok(Self { issuer })
    }

    /// Emit the canonical request used for original-writer confirmation.
    /// # Errors
    /// Rejects invalid mutable fields or complete body overflow.
    pub fn to_json(&self) -> Result<Vec<u8>, Error> {
        #[derive(Serialize)]
        struct Data<'a> {
            issuer: &'a str,
        }
        #[derive(Serialize)]
        struct Create<'a> {
            data: Data<'a>,
        }
        validate_issuer(&self.issuer)?;
        encode(&Create { data: Data { issuer: &self.issuer } }, MAX_CREATE_BYTES)
    }
}

/// One immutable generation. Its strong entity tag is derived from the generation.
#[derive(Clone, Eq, PartialEq)]
pub struct DraftResource {
    /// Server-allocated generation `UUIDv7`.
    pub id: Uuid,
    /// Owning Organization.
    pub organization_id: Uuid,
    /// Creation instant, also the last update instant.
    pub created_at: String,
    /// Exact issuer under consideration.
    pub issuer: String,
}

impl fmt::Debug for DraftResource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DraftResource").finish_non_exhaustive()
    }
}

impl DraftResource {
    /// The HTTP and JSON strong `ETag` for this generation.
    #[must_use]
    pub fn etag(&self) -> String {
        format!("\"{}\"", self.id)
    }

    fn validate(&self) -> Result<(), Error> {
        valid_uuid(self.id, "id")?;
        valid_uuid(self.organization_id, "organization_id")?;
        if !valid_utc_timestamp(&self.created_at) {
            return Err(Error::InvalidField("created_at"));
        }
        validate_issuer(&self.issuer)
    }

    /// Revalidate and serialize a Resource in the §2.9 field order.
    /// # Errors
    /// Rejects an invalid resource or encoded body overflow.
    pub fn to_json(&self) -> Result<Vec<u8>, Error> {
        #[derive(Serialize)]
        struct Data<'a> {
            organization_id: String,
            issuer: &'a str,
        }
        #[derive(Serialize)]
        struct Resource<'a> {
            id: String,
            etag: String,
            created_at: &'a str,
            updated_at: &'a str,
            data: Data<'a>,
        }
        self.validate()?;
        encode(
            &Resource {
                id: self.id.to_string(),
                etag: self.etag(),
                created_at: &self.created_at,
                updated_at: &self.created_at,
                data: Data {
                    organization_id: self.organization_id.to_string(),
                    issuer: &self.issuer,
                },
            },
            MAX_RESOURCE_BYTES,
        )
    }

    /// Read an individual response, checking the selected Organization and generation `ETag`.
    /// The transport checks status, content type, header multiplicity and `X-Request-ID`.
    /// # Errors
    /// Rejects malformed JSON, a mismatched binding or missing cache protection.
    pub fn from_http_json(
        bytes: &[u8],
        organization_id: Uuid,
        etag: Option<&str>,
        cache_control: Option<&str>,
        pragma: Option<&str>,
    ) -> Result<Self, Error> {
        validate_cache_headers(cache_control, pragma)?;
        let mut root = object(bytes, MAX_RESOURCE_BYTES)?;
        let mut data = take_object(&mut root, "data")?;
        let resource = Self {
            id: take_uuid(&mut root, "id")?,
            organization_id: take_uuid(&mut data, "organization_id")?,
            created_at: take_string(&mut root, "created_at")?,
            issuer: take_string(&mut data, "issuer")?,
        };
        resource.validate()?;
        if resource.organization_id != organization_id {
            return Err(Error::Context);
        }
        if take_string(&mut root, "updated_at")? != resource.created_at {
            return Err(Error::InvalidField("updated_at"));
        }
        let body_tag = take_string(&mut root, "etag")?;
        if body_tag != resource.etag() || etag != Some(body_tag.as_str()) {
            return Err(Error::HttpMetadata);
        }
        Ok(resource)
    }
}

/// Require a single wildcard for create. The router rejects repeated headers.
/// # Errors
/// Returns a missing or malformed precondition separately.
pub fn require_empty_slot(value: Option<&str>) -> Result<(), OrganizationPreconditionError> {
    match value {
        Some("*") => Ok(()),
        Some(_) => Err(OrganizationPreconditionError::Invalid),
        None => Err(OrganizationPreconditionError::Required),
    }
}
