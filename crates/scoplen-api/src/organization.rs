// SPDX-License-Identifier: Apache-2.0
//! D-130 bounded team creation and current Account membership discovery.
//!
//! These codecs validate syntax and response bindings, not current membership or authority.

use std::{collections::BTreeSet, fmt};

use scoplen_model::validate_uuid_v7;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, value::RawValue};
use uuid::Uuid;

use crate::{
    certificate::{valid_strong_etag, valid_utc_timestamp},
    request_wire,
};

/// Complete UTF-8 creation request bound, including whitespace.
pub const MAX_ORGANIZATION_CREATE_BYTES: usize = 1_024;
/// Complete Resource bound, including extensions and whitespace inside a page item.
pub const MAX_ORGANIZATION_RESOURCE_BYTES: usize = 4_096;
/// Complete membership Page bound.
pub const MAX_ORGANIZATION_PAGE_BYTES: usize = 2_097_152;
/// Complete problem response bound.
pub const MAX_ORGANIZATION_PROBLEM_BYTES: usize = 4_096;
/// Maximum UTF-8 team-name bytes.
pub const MAX_ORGANIZATION_NAME_BYTES: usize = 128;
/// Maximum roles in the caller's membership projection.
pub const MAX_ORGANIZATION_ROLES: usize = 32;
/// Initial discovery page size.
pub const DEFAULT_ORGANIZATION_LIMIT: u16 = 50;
/// Maximum discovery page size.
pub const MAX_ORGANIZATION_LIMIT: u16 = 500;
/// Required receipt lifetime after a confirmed team creation.
pub const ORGANIZATION_CREATION_RECEIPT_SECONDS: u64 = 86_400;

/// Content-free syntax or binding error.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum OrganizationCodecError {
    /// The complete encoded input exceeds the endpoint's bound.
    #[error("organization message exceeds its byte bound")]
    TooLarge,
    /// Invalid JSON, UTF-8 or recursively duplicate names.
    #[error("invalid organization JSON")]
    InvalidJson,
    /// Missing, mistyped or invalid required value.
    #[error("invalid organization field: {0}")]
    InvalidField(&'static str),
    /// Required HTTP metadata is missing or mismatched.
    #[error("invalid organization HTTP metadata")]
    HttpMetadata,
    /// The response does not belong to the requested Account or continuation.
    #[error("organization response context mismatch")]
    Context,
}

/// The one accepted team-creation payload; Account and owner are never caller-selected.
#[derive(Clone, Eq, PartialEq)]
pub struct OrganizationCreateRequest {
    /// Display name, preserved without normalization.
    pub name: String,
}

impl fmt::Debug for OrganizationCreateRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OrganizationCreateRequest").finish_non_exhaustive()
    }
}

impl OrganizationCreateRequest {
    /// Construct a bounded creation payload.
    /// # Errors
    /// Rejects invalid name syntax.
    pub fn new(name: impl Into<String>) -> Result<Self, OrganizationCodecError> {
        let value = Self { name: name.into() };
        value.validate()?;
        Ok(value)
    }

    /// Recheck mutable public fields.
    /// # Errors
    /// Rejects invalid name syntax.
    pub fn validate(&self) -> Result<(), OrganizationCodecError> {
        validate_name(&self.name)
    }

    /// Parse the strict request, rejecting all extension fields.
    /// # Errors
    /// Rejects malformed, duplicate, unknown, oversized or invalid fields.
    pub fn from_json(input: &[u8]) -> Result<Self, OrganizationCodecError> {
        let mut fields = object(input, MAX_ORGANIZATION_CREATE_BYTES)?;
        let mut data = take_object(&mut fields, "data")?;
        let name = take_string(&mut data, "name")?;
        if !fields.is_empty() || !data.is_empty() {
            return Err(OrganizationCodecError::InvalidField("request members"));
        }
        Self::new(name)
    }

    /// Emit the canonical payload used to bind the Account's idempotency receipt.
    /// # Errors
    /// Rejects invalid mutable fields.
    pub fn to_json(&self) -> Result<Vec<u8>, OrganizationCodecError> {
        #[derive(Serialize)]
        struct Data<'a> {
            name: &'a str,
        }
        #[derive(Serialize)]
        struct Wire<'a> {
            data: Data<'a>,
        }
        self.validate()?;
        encode(&Wire { data: Data { name: &self.name } }, MAX_ORGANIZATION_CREATE_BYTES)
    }
}

/// The caller's own active Organization membership, never a member directory.
#[derive(Clone, Eq, PartialEq)]
pub struct OrganizationMembership {
    /// Membership `UUIDv7`.
    pub id: Uuid,
    /// Account `UUIDv7`, independently checked against the authenticated Account.
    pub account_id: Uuid,
    /// Distinct identifiers; unknown roles carry no implicit authority.
    pub roles: Vec<String>,
}

impl fmt::Debug for OrganizationMembership {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OrganizationMembership")
            .field("roles", &self.roles.len())
            .finish_non_exhaustive()
    }
}

impl OrganizationMembership {
    /// Recheck ids, role syntax, cardinality and uniqueness.
    /// # Errors
    /// Rejects invalid public fields.
    pub fn validate(&self) -> Result<(), OrganizationCodecError> {
        valid_uuid(self.id, "membership.id")?;
        valid_uuid(self.account_id, "membership.account_id")?;
        let mut unique = BTreeSet::new();
        if self.roles.is_empty()
            || self.roles.len() > MAX_ORGANIZATION_ROLES
            || self.roles.iter().any(|role| {
                role.is_empty()
                    || role.len() > 64
                    || !role.as_bytes()[0].is_ascii_lowercase()
                    || !role
                        .bytes()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_')
                    || !unique.insert(role)
            })
        {
            return Err(OrganizationCodecError::InvalidField("membership.roles"));
        }
        Ok(())
    }
}

/// Caller-specific Organization Resource, containing no inventory or private Account data.
#[derive(Clone, Eq, PartialEq)]
pub struct OrganizationResource {
    /// Organization `UUIDv7`.
    pub id: Uuid,
    /// Strong entity tag including quotes.
    pub etag: String,
    /// UTC creation timestamp.
    pub created_at: String,
    /// UTC update timestamp of the caller-specific projection.
    pub updated_at: String,
    /// Organization name.
    pub name: String,
    /// Only the current caller's membership.
    pub membership: OrganizationMembership,
}

impl fmt::Debug for OrganizationResource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OrganizationResource").finish_non_exhaustive()
    }
}

impl OrganizationResource {
    /// Recheck public fields before use or encoding.
    /// # Errors
    /// Rejects invalid ids, metadata, name or membership.
    pub fn validate(&self) -> Result<(), OrganizationCodecError> {
        valid_uuid(self.id, "id")?;
        if !valid_strong_etag(&self.etag) {
            return Err(OrganizationCodecError::InvalidField("etag"));
        }
        if !valid_utc_timestamp(&self.created_at) {
            return Err(OrganizationCodecError::InvalidField("created_at"));
        }
        if !valid_utc_timestamp(&self.updated_at) {
            return Err(OrganizationCodecError::InvalidField("updated_at"));
        }
        validate_name(&self.name)?;
        self.membership.validate()
    }

    /// Bind syntax-checked discovery to the authenticated Account.
    /// # Errors
    /// Rejects invalid fields or another Account's membership.
    pub fn validate_for_account(&self, account_id: Uuid) -> Result<(), OrganizationCodecError> {
        self.validate()?;
        if self.membership.account_id != account_id {
            return Err(OrganizationCodecError::Context);
        }
        Ok(())
    }

    /// Decode one bounded Resource, ignoring extensions after recursive duplicate checks.
    /// # Errors
    /// Rejects malformed, oversized or invalid required fields.
    pub fn from_json(input: &[u8]) -> Result<Self, OrganizationCodecError> {
        let mut fields = object(input, MAX_ORGANIZATION_RESOURCE_BYTES)?;
        let id = take_uuid(&mut fields, "id")?;
        let etag = take_string(&mut fields, "etag")?;
        let created_at = take_string(&mut fields, "created_at")?;
        let updated_at = take_string(&mut fields, "updated_at")?;
        let mut data = take_object(&mut fields, "data")?;
        let name = take_string(&mut data, "name")?;
        let mut membership = take_object(&mut data, "membership")?;
        let membership_id = take_uuid(&mut membership, "id")?;
        let account_id = take_uuid(&mut membership, "account_id")?;
        let Some(Value::Array(values)) = membership.remove("roles") else {
            return Err(OrganizationCodecError::InvalidField("membership.roles"));
        };
        let mut roles = values
            .into_iter()
            .map(|role| match role {
                Value::String(role) => Ok(role),
                _ => Err(OrganizationCodecError::InvalidField("membership.roles")),
            })
            .collect::<Result<Vec<_>, _>>()?;
        roles.sort_unstable();
        let value = Self {
            id,
            etag,
            created_at,
            updated_at,
            name,
            membership: OrganizationMembership { id: membership_id, account_id, roles },
        };
        value.validate()?;
        Ok(value)
    }

    /// Decode individual HTTP metadata and its Resource.
    /// HTTP status, content type and `X-Request-ID` are checked by the transport consumer.
    /// # Errors
    /// Rejects invalid body, `ETag` or cache prevention headers.
    pub fn from_http_json(
        input: &[u8],
        etag: Option<&str>,
        cache_control: Option<&str>,
        pragma: Option<&str>,
    ) -> Result<Self, OrganizationCodecError> {
        let value = Self::from_json(input)?;
        if etag != Some(value.etag.as_str()) {
            return Err(OrganizationCodecError::HttpMetadata);
        }
        validate_cache_headers(cache_control, pragma)?;
        Ok(value)
    }

    /// Canonical Resource encoding, with sorted roles and no extensions.
    /// # Errors
    /// Rejects invalid mutable fields or complete body overflow.
    pub fn to_json(&self) -> Result<Vec<u8>, OrganizationCodecError> {
        #[derive(Serialize)]
        struct Membership<'a> {
            id: String,
            account_id: String,
            roles: Vec<&'a str>,
        }
        #[derive(Serialize)]
        struct Data<'a> {
            name: &'a str,
            membership: Membership<'a>,
        }
        #[derive(Serialize)]
        struct Wire<'a> {
            id: String,
            etag: &'a str,
            created_at: &'a str,
            updated_at: &'a str,
            data: Data<'a>,
        }
        self.validate()?;
        let mut roles: Vec<_> = self.membership.roles.iter().map(String::as_str).collect();
        roles.sort_unstable();
        encode(
            &Wire {
                id: self.id.to_string(),
                etag: &self.etag,
                created_at: &self.created_at,
                updated_at: &self.updated_at,
                data: Data {
                    name: &self.name,
                    membership: Membership {
                        id: self.membership.id.to_string(),
                        account_id: self.membership.account_id.to_string(),
                        roles,
                    },
                },
            },
            MAX_ORGANIZATION_RESOURCE_BYTES,
        )
    }
}

/// Exact team-discovery query, with defaults materialized.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OrganizationListQuery {
    /// Requested item count, 1..500.
    pub limit: u16,
    /// Last previously returned Organization id, used only for ordering.
    pub cursor: Option<Uuid>,
}

impl Default for OrganizationListQuery {
    fn default() -> Self {
        Self { limit: DEFAULT_ORGANIZATION_LIMIT, cursor: None }
    }
}

impl OrganizationListQuery {
    /// Parse already URL-decoded pairs, rejecting duplicate and unknown names.
    /// # Errors
    /// Rejects invalid limit or cursor syntax.
    pub fn from_parameters<'a>(
        parameters: impl IntoIterator<Item = (&'a str, &'a str)>,
    ) -> Result<Self, OrganizationCodecError> {
        let mut value = Self::default();
        let (mut limit_seen, mut cursor_seen) = (false, false);
        for (name, text) in parameters {
            match name {
                "limit" if !limit_seen => {
                    limit_seen = true;
                    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
                        return Err(OrganizationCodecError::InvalidField("limit"));
                    }
                    value.limit =
                        text.parse().map_err(|_| OrganizationCodecError::InvalidField("limit"))?;
                }
                "cursor" if !cursor_seen => {
                    cursor_seen = true;
                    value.cursor = Some(parse_uuid(text, "cursor")?);
                }
                _ => return Err(OrganizationCodecError::InvalidField("query")),
            }
        }
        value.validate()?;
        Ok(value)
    }

    /// Recheck mutable query fields.
    /// # Errors
    /// Rejects invalid limit or cursor.
    pub fn validate(&self) -> Result<(), OrganizationCodecError> {
        if !(1..=MAX_ORGANIZATION_LIMIT).contains(&self.limit) {
            return Err(OrganizationCodecError::InvalidField("limit"));
        }
        if let Some(id) = self.cursor {
            valid_uuid(id, "cursor")?;
        }
        Ok(())
    }
}

/// Current Account's ascending team page; not a frozen inventory or authorization snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OrganizationPage {
    /// Caller-specific team Resources.
    pub items: Vec<OrganizationResource>,
    /// Last returned Organization id only when further eligible items exist.
    pub next_cursor: Option<Uuid>,
}

impl OrganizationPage {
    /// Validate page-wide ordering, count, resources and continuation.
    /// # Errors
    /// Rejects malformed Resources, duplicate/out-of-order ids or invalid continuation.
    pub fn validate(&self) -> Result<(), OrganizationCodecError> {
        if self.items.len() > usize::from(MAX_ORGANIZATION_LIMIT) {
            return Err(OrganizationCodecError::InvalidField("items"));
        }
        for item in &self.items {
            item.validate()?;
        }
        if !self.items.windows(2).all(|p| p[0].id < p[1].id) {
            return Err(OrganizationCodecError::InvalidField("items"));
        }
        if self.next_cursor.is_some() && self.next_cursor != self.items.last().map(|item| item.id) {
            return Err(OrganizationCodecError::InvalidField("next_cursor"));
        }
        Ok(())
    }

    /// Bind a complete page to the Account and original query before displaying it.
    /// # Errors
    /// Rejects another Account, an exceeded requested count or an invalid continuation range.
    pub fn validate_for_account(
        &self,
        account_id: Uuid,
        query: OrganizationListQuery,
    ) -> Result<(), OrganizationCodecError> {
        self.validate()?;
        query.validate()?;
        if self.items.len() > usize::from(query.limit)
            || self.items.iter().any(|item| {
                item.membership.account_id != account_id
                    || query.cursor.is_some_and(|cursor| item.id <= cursor)
            })
        {
            return Err(OrganizationCodecError::Context);
        }
        Ok(())
    }

    /// Decode the complete Page and each original Resource's encoded byte bound.
    /// # Errors
    /// Rejects oversized input, duplicate names or invalid required fields.
    pub fn from_json(input: &[u8]) -> Result<Self, OrganizationCodecError> {
        #[derive(Deserialize)]
        struct Wire {
            items: Vec<Box<RawValue>>,
            next_cursor: Option<String>,
        }
        let fields = object(input, MAX_ORGANIZATION_PAGE_BYTES)?;
        if !fields.contains_key("items") || !fields.contains_key("next_cursor") {
            return Err(OrganizationCodecError::InvalidField("page"));
        }
        let raw: Wire =
            serde_json::from_slice(input).map_err(|_| OrganizationCodecError::InvalidJson)?;
        if raw.items.len() > usize::from(MAX_ORGANIZATION_LIMIT) {
            return Err(OrganizationCodecError::InvalidField("items"));
        }
        let items = raw
            .items
            .iter()
            .map(|item| OrganizationResource::from_json(item.get().as_bytes()))
            .collect::<Result<Vec<_>, _>>()?;
        let next_cursor =
            raw.next_cursor.map(|text| parse_uuid(&text, "next_cursor")).transpose()?;
        let value = Self { items, next_cursor };
        value.validate()?;
        Ok(value)
    }

    /// Decode a no-store discovery Page.
    /// HTTP status, content type and `X-Request-ID` are checked by the transport consumer.
    /// # Errors
    /// Rejects invalid body or cache prevention metadata.
    pub fn from_http_json(
        input: &[u8],
        cache_control: Option<&str>,
        pragma: Option<&str>,
    ) -> Result<Self, OrganizationCodecError> {
        validate_cache_headers(cache_control, pragma)?;
        Self::from_json(input)
    }

    /// Canonical Page encoding after individual Resource validation.
    /// # Errors
    /// Rejects invalid mutable fields or a complete body overflow.
    pub fn to_json(&self) -> Result<Vec<u8>, OrganizationCodecError> {
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
                let text =
                    String::from_utf8(bytes).map_err(|_| OrganizationCodecError::InvalidJson)?;
                RawValue::from_string(text).map_err(|_| OrganizationCodecError::InvalidJson)
            })
            .collect::<Result<Vec<_>, _>>()?;
        encode(
            &Wire { items, next_cursor: self.next_cursor.map(|id| id.to_string()) },
            MAX_ORGANIZATION_PAGE_BYTES,
        )
    }
}

/// Parse the required exactly-one creation header value; header multiplicity is a router duty.
/// # Errors
/// Rejects any spelling other than canonical lowercase `UUIDv7`.
pub fn parse_organization_idempotency_key(value: &str) -> Result<Uuid, OrganizationCodecError> {
    parse_uuid(value, "Idempotency-Key")
}

/// Validate the mandatory no-store discovery response headers.
/// # Errors
/// Rejects missing or mismatched header values.
pub fn validate_cache_headers(
    cache_control: Option<&str>,
    pragma: Option<&str>,
) -> Result<(), OrganizationCodecError> {
    if cache_control != Some("no-store") || pragma != Some("no-cache") {
        return Err(OrganizationCodecError::HttpMetadata);
    }
    Ok(())
}

fn validate_name(name: &str) -> Result<(), OrganizationCodecError> {
    if name.is_empty()
        || name.len() > MAX_ORGANIZATION_NAME_BYTES
        || name.trim() != name
        || name.chars().any(char::is_control)
    {
        return Err(OrganizationCodecError::InvalidField("name"));
    }
    Ok(())
}
fn valid_uuid(id: Uuid, field: &'static str) -> Result<(), OrganizationCodecError> {
    validate_uuid_v7(id).map_err(|_| OrganizationCodecError::InvalidField(field))
}
fn parse_uuid(text: &str, field: &'static str) -> Result<Uuid, OrganizationCodecError> {
    let id = Uuid::parse_str(text).map_err(|_| OrganizationCodecError::InvalidField(field))?;
    if id.to_string() != text {
        return Err(OrganizationCodecError::InvalidField(field));
    }
    valid_uuid(id, field)?;
    Ok(id)
}
fn object(input: &[u8], bound: usize) -> Result<Map<String, Value>, OrganizationCodecError> {
    if input.len() > bound {
        return Err(OrganizationCodecError::TooLarge);
    }
    request_wire::decode_unique_object(input).map_err(|()| OrganizationCodecError::InvalidJson)
}
fn take_string(
    fields: &mut Map<String, Value>,
    name: &'static str,
) -> Result<String, OrganizationCodecError> {
    match fields.remove(name) {
        Some(Value::String(text)) => Ok(text),
        _ => Err(OrganizationCodecError::InvalidField(name)),
    }
}
fn take_uuid(
    fields: &mut Map<String, Value>,
    name: &'static str,
) -> Result<Uuid, OrganizationCodecError> {
    parse_uuid(&take_string(fields, name)?, name)
}
fn take_object(
    fields: &mut Map<String, Value>,
    name: &'static str,
) -> Result<Map<String, Value>, OrganizationCodecError> {
    match fields.remove(name) {
        Some(Value::Object(fields)) => Ok(fields),
        _ => Err(OrganizationCodecError::InvalidField(name)),
    }
}
fn encode(value: &impl Serialize, bound: usize) -> Result<Vec<u8>, OrganizationCodecError> {
    let bytes = serde_json::to_vec(value).map_err(|_| OrganizationCodecError::InvalidJson)?;
    if bytes.len() > bound {
        return Err(OrganizationCodecError::TooLarge);
    }
    Ok(bytes)
}
