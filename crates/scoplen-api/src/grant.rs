// SPDX-License-Identifier: Apache-2.0
//! D-147 named-Membership Host Grant wire contracts.
//! Parsing establishes syntax and request binding, not current tenant ownership or authority.

use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, value::RawValue};
use uuid::Uuid;

use crate::{
    audit::{format_audit_timestamp, parse_audit_timestamp},
    certificate::{valid_strong_etag, valid_utc_timestamp},
    organization::{
        OrganizationCodecError as Error, OrganizationListQuery, encode, object, parse_uuid,
        take_object, take_string, take_uuid, valid_uuid, validate_cache_headers,
    },
    request_wire::valid_remote_user,
};

/// Complete UTF-8 Grant request or Resource byte ceiling, including whitespace/extensions.
pub const MAX_GRANT_BYTES: usize = 4_096;
/// Complete UTF-8 Grant Page ceiling.
pub const MAX_GRANT_PAGE_BYTES: usize = 2_097_152;
/// Maximum number of Grants in one administration Page.
pub const MAX_GRANT_PAGE_ITEMS: usize = 500;
/// Last whole Unix second representable by the four-digit-year Grant timestamp profile.
pub const MAX_GRANT_TIMESTAMP_SECONDS: u64 = 253_402_300_799;

/// Complete desired fields; times are exact Unix seconds and encode as UTC text.
#[derive(Clone, Eq, PartialEq)]
pub struct GrantFields {
    /// Current Organization Membership, not a caller-proposed Account identity.
    pub membership: Uuid,
    /// Exactly one Organization Host; no `HostGroup` principal is authorized.
    pub host: Uuid,
    /// Exact SSH username, without trimming or normalization.
    pub remote_user: String,
    /// Inclusive whole-Unix-second start, including zero.
    pub valid_from: u64,
    /// Exclusive end, or explicit nonexpiring access.
    pub valid_until: Option<u64>,
}

impl fmt::Debug for GrantFields {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GrantFields").finish_non_exhaustive()
    }
}

impl GrantFields {
    /// Validate syntax only; current ownership, membership and policy are separate checks.
    /// # Errors
    /// Rejects invalid UUIDs, remote user, calendar bounds or nonpositive finite intervals.
    pub fn validate(&self) -> Result<(), Error> {
        valid_uuid(self.membership, "membership")?;
        valid_uuid(self.host, "host")?;
        if !valid_remote_user(&self.remote_user) {
            return Err(Error::InvalidField("remote_user"));
        }
        if self.valid_from > MAX_GRANT_TIMESTAMP_SECONDS
            || self
                .valid_until
                .is_some_and(|end| end > MAX_GRANT_TIMESTAMP_SECONDS || end <= self.valid_from)
        {
            return Err(Error::InvalidField("validity"));
        }
        Ok(())
    }

    fn from_value(fields: &mut Map<String, Value>, strict: bool) -> Result<Self, Error> {
        let result = Self {
            membership: take_uuid(fields, "membership")?,
            host: take_uuid(fields, "host")?,
            remote_user: take_string(fields, "remote_user")?,
            valid_from: parse_grant_timestamp(&take_string(fields, "valid_from")?)?,
            valid_until: match fields.remove("valid_until") {
                Some(Value::Null) => None,
                Some(Value::String(time)) => Some(parse_grant_timestamp(&time)?),
                _ => return Err(Error::InvalidField("valid_until")),
            },
        };
        if strict && !fields.is_empty() {
            return Err(Error::InvalidField("request members"));
        }
        result.validate()?;
        Ok(result)
    }

    fn wire(&self) -> Result<FieldsWire<'_>, Error> {
        self.validate()?;
        Ok(FieldsWire {
            membership: self.membership.to_string(),
            host: self.host.to_string(),
            remote_user: &self.remote_user,
            valid_from: format_grant_timestamp(self.valid_from)?,
            valid_until: self.valid_until.map(format_grant_timestamp).transpose()?,
        })
    }
}

#[derive(Serialize)]
struct FieldsWire<'a> {
    membership: String,
    host: String,
    remote_user: &'a str,
    valid_from: String,
    valid_until: Option<String>,
}

/// Parse exact whole-second Gregorian UTC in the initial Grant profile.
/// # Errors
/// Rejects offsets, fractions, leap seconds, invalid calendars and pre-epoch instants.
pub fn parse_grant_timestamp(text: &str) -> Result<u64, Error> {
    if text.len() != 20 {
        return Err(Error::InvalidField("timestamp"));
    }
    let milliseconds = parse_audit_timestamp(text).map_err(|_| Error::InvalidField("timestamp"))?;
    let seconds = u64::try_from(milliseconds.div_euclid(1_000))
        .map_err(|_| Error::InvalidField("timestamp"))?;
    if seconds > MAX_GRANT_TIMESTAMP_SECONDS {
        return Err(Error::InvalidField("timestamp"));
    }
    Ok(seconds)
}

/// Encode one exact whole Unix second, without aliases or fractional seconds.
/// # Errors
/// Rejects a time beyond year 9999.
pub fn format_grant_timestamp(seconds: u64) -> Result<String, Error> {
    if seconds > MAX_GRANT_TIMESTAMP_SECONDS {
        return Err(Error::InvalidField("timestamp"));
    }
    let milliseconds =
        i64::try_from(seconds * 1_000).map_err(|_| Error::InvalidField("timestamp"))?;
    format_audit_timestamp(milliseconds).map_err(|_| Error::InvalidField("timestamp"))
}

/// Exact POST body; its id and canonical fields bind the original create receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GrantCreateRequest {
    /// Fresh caller-generated Grant `UUIDv7`.
    pub id: Uuid,
    /// Complete desired values.
    pub fields: GrantFields,
}

impl GrantCreateRequest {
    /// Decode strict bounded Grant creation JSON.
    /// # Errors
    /// Rejects unknown/duplicate/missing fields, invalid values or byte overflow.
    pub fn from_json(input: &[u8]) -> Result<Self, Error> {
        let mut fields = object(input, MAX_GRANT_BYTES)?;
        let result = Self {
            id: take_uuid(&mut fields, "id")?,
            fields: GrantFields::from_value(&mut take_object(&mut fields, "data")?, true)?,
        };
        if !fields.is_empty() {
            return Err(Error::InvalidField("request members"));
        }
        Ok(result)
    }

    /// Encode the exact canonical create payload.
    /// # Errors
    /// Rejects invalid public fields or encoded overflow.
    pub fn to_json(&self) -> Result<Vec<u8>, Error> {
        #[derive(Serialize)]
        struct Wire<'a> {
            id: String,
            data: FieldsWire<'a>,
        }
        valid_uuid(self.id, "id")?;
        encode(&Wire { id: self.id.to_string(), data: self.fields.wire()? }, MAX_GRANT_BYTES)
    }
}

/// Exact PUT body, replacing all five desired fields.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GrantReplaceRequest {
    /// Complete replacement values.
    pub fields: GrantFields,
}

impl GrantReplaceRequest {
    /// Decode strict bounded complete replacement JSON.
    /// # Errors
    /// Rejects unknown/duplicate/missing fields, invalid values or byte overflow.
    pub fn from_json(input: &[u8]) -> Result<Self, Error> {
        let mut fields = object(input, MAX_GRANT_BYTES)?;
        let result =
            Self { fields: GrantFields::from_value(&mut take_object(&mut fields, "data")?, true)? };
        if !fields.is_empty() {
            return Err(Error::InvalidField("request members"));
        }
        Ok(result)
    }

    /// Encode one canonical full replacement.
    /// # Errors
    /// Rejects invalid public fields or encoded overflow.
    pub fn to_json(&self) -> Result<Vec<u8>, Error> {
        #[derive(Serialize)]
        struct Wire<'a> {
            data: FieldsWire<'a>,
        }
        encode(&Wire { data: self.fields.wire()? }, MAX_GRANT_BYTES)
    }
}

/// Server-owned Grant projection; historical create responses are not current authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GrantResource {
    /// Grant `UUIDv7`.
    pub id: Uuid,
    /// Strong validator for this stored projection.
    pub etag: String,
    /// Existing RFC 3339 UTC metadata profile.
    pub created_at: String,
    /// Existing RFC 3339 UTC metadata profile.
    pub updated_at: String,
    /// Complete desired Grant values.
    pub fields: GrantFields,
}

impl GrantResource {
    /// Validate known metadata and fields without inferring current authority.
    /// # Errors
    /// Rejects malformed metadata or invalid Grant fields.
    pub fn validate(&self) -> Result<(), Error> {
        valid_uuid(self.id, "id")?;
        if !valid_strong_etag(&self.etag)
            || !valid_utc_timestamp(&self.created_at)
            || !valid_utc_timestamp(&self.updated_at)
        {
            return Err(Error::InvalidField("metadata"));
        }
        self.fields.validate()
    }

    /// Bind a read response to its captured Grant id.
    /// # Errors
    /// Rejects invalid values or a response for another id.
    pub fn validate_for_id(&self, id: Uuid) -> Result<(), Error> {
        self.validate()?;
        valid_uuid(id, "requested id")?;
        if self.id != id {
            return Err(Error::Context);
        }
        Ok(())
    }

    /// Bind confirmed creation to the exact original id and desired values.
    /// # Errors
    /// Rejects invalid or mismatched captured input and response.
    pub fn validate_for_create(&self, request: &GrantCreateRequest) -> Result<(), Error> {
        request.to_json()?;
        self.validate_for_id(request.id)?;
        self.validate_for_fields(&request.fields)
    }

    /// Bind replacement confirmation to the exact captured complete desired fields.
    /// # Errors
    /// Rejects invalid fields or any mismatch.
    pub fn validate_for_fields(&self, fields: &GrantFields) -> Result<(), Error> {
        self.validate()?;
        fields.validate()?;
        if &self.fields != fields {
            return Err(Error::Context);
        }
        Ok(())
    }

    /// Decode a complete bounded Resource, ignoring response extensions.
    /// # Errors
    /// Rejects malformed/duplicate/missing known fields or original byte overflow.
    pub fn from_json(input: &[u8]) -> Result<Self, Error> {
        let mut fields = object(input, MAX_GRANT_BYTES)?;
        let result = Self {
            id: take_uuid(&mut fields, "id")?,
            etag: take_string(&mut fields, "etag")?,
            created_at: take_string(&mut fields, "created_at")?,
            updated_at: take_string(&mut fields, "updated_at")?,
            fields: GrantFields::from_value(&mut take_object(&mut fields, "data")?, false)?,
        };
        result.validate()?;
        Ok(result)
    }

    /// Decode a Resource with matching strong HTTP `ETag` and no-store metadata.
    /// # Errors
    /// Rejects invalid body, mismatched `ETag` or missing cache-prevention headers.
    pub fn from_http_json(
        input: &[u8],
        etag: Option<&str>,
        cache_control: Option<&str>,
        pragma: Option<&str>,
    ) -> Result<Self, Error> {
        validate_cache_headers(cache_control, pragma)?;
        let result = Self::from_json(input)?;
        if etag != Some(result.etag.as_str()) {
            return Err(Error::HttpMetadata);
        }
        Ok(result)
    }

    /// Encode the complete known Resource fields.
    /// # Errors
    /// Rejects invalid public fields or encoded overflow.
    pub fn to_json(&self) -> Result<Vec<u8>, Error> {
        #[derive(Serialize)]
        struct Wire<'a> {
            id: String,
            etag: &'a str,
            created_at: &'a str,
            updated_at: &'a str,
            data: FieldsWire<'a>,
        }
        self.validate()?;
        encode(
            &Wire {
                id: self.id.to_string(),
                etag: &self.etag,
                created_at: &self.created_at,
                updated_at: &self.updated_at,
                data: self.fields.wire()?,
            },
            MAX_GRANT_BYTES,
        )
    }
}

/// Current ascending Grant administration Page, including expired but not withdrawn rows.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GrantPage {
    /// Strictly ascending unique Resources.
    pub items: Vec<GrantResource>,
    /// Last returned id when a further page exists.
    pub next_cursor: Option<Uuid>,
}

impl GrantPage {
    /// Validate every Resource, count, ordering and continuation.
    /// # Errors
    /// Rejects invalid Resources, duplicates, excess count or inconsistent cursor.
    pub fn validate(&self) -> Result<(), Error> {
        if self.items.len() > MAX_GRANT_PAGE_ITEMS {
            return Err(Error::TooLarge);
        }
        let mut previous = None;
        for item in &self.items {
            item.validate()?;
            if previous.is_some_and(|id| item.id <= id) {
                return Err(Error::InvalidField("items"));
            }
            previous = Some(item.id);
        }
        if self.next_cursor.is_some() && self.next_cursor != previous {
            return Err(Error::InvalidField("next_cursor"));
        }
        Ok(())
    }

    /// Bind a Page to the captured count and cursor.
    /// # Errors
    /// Rejects invalid input or a Page outside the requested continuation/count.
    pub fn validate_for_query(&self, query: OrganizationListQuery) -> Result<(), Error> {
        self.validate()?;
        query.validate()?;
        if self.items.len() > usize::from(query.limit)
            || self.items.iter().any(|item| query.cursor.is_some_and(|id| item.id <= id))
        {
            return Err(Error::Context);
        }
        Ok(())
    }

    /// Decode a bounded Page while checking each original embedded Resource byte budget.
    /// # Errors
    /// Rejects malformed/duplicate/missing fields, oversized original items or invalid ordering.
    pub fn from_json(input: &[u8]) -> Result<Self, Error> {
        #[derive(Deserialize)]
        struct Wire {
            items: Vec<Box<RawValue>>,
            next_cursor: Option<String>,
        }
        let fields = object(input, MAX_GRANT_PAGE_BYTES)?;
        if !fields.contains_key("items") || !fields.contains_key("next_cursor") {
            return Err(Error::InvalidField("page"));
        }
        let raw: Wire = serde_json::from_slice(input).map_err(|_| Error::InvalidJson)?;
        if raw.items.len() > MAX_GRANT_PAGE_ITEMS {
            return Err(Error::TooLarge);
        }
        let result = Self {
            items: raw
                .items
                .iter()
                .map(|value| GrantResource::from_json(value.get().as_bytes()))
                .collect::<Result<_, _>>()?,
            next_cursor: raw.next_cursor.map(|id| parse_uuid(&id, "next_cursor")).transpose()?,
        };
        result.validate()?;
        Ok(result)
    }

    /// Decode a Page with the standard cache-prevention response headers.
    /// # Errors
    /// Rejects invalid headers, body, bounds or continuation.
    pub fn from_http_json(
        input: &[u8],
        cache_control: Option<&str>,
        pragma: Option<&str>,
    ) -> Result<Self, Error> {
        validate_cache_headers(cache_control, pragma)?;
        Self::from_json(input)
    }

    /// Encode one bounded complete Page.
    /// # Errors
    /// Rejects invalid fields or encoded item/Page overflow.
    pub fn to_json(&self) -> Result<Vec<u8>, Error> {
        #[derive(Serialize)]
        struct Wire {
            items: Vec<Box<RawValue>>,
            next_cursor: Option<String>,
        }
        self.validate()?;
        let items = self
            .items
            .iter()
            .map(|item| {
                let bytes = item.to_json()?;
                serde_json::from_slice::<Box<RawValue>>(&bytes).map_err(|_| Error::InvalidJson)
            })
            .collect::<Result<_, _>>()?;
        encode(
            &Wire { items, next_cursor: self.next_cursor.map(|id| id.to_string()) },
            MAX_GRANT_PAGE_BYTES,
        )
    }
}
