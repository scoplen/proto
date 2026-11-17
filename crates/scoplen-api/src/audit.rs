// SPDX-License-Identifier: Apache-2.0
//! D-144 bounded immutable Organization audit projections, queries and verification results.
//! Parsing establishes syntax and request binding, never current authority or chain integrity.

use std::{fmt, str::FromStr};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use scoplen_model::validate_uuid_v7;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, value::RawValue};
use uuid::Uuid;

mod query;
pub mod reference;
mod verification;
pub use query::*;
pub use verification::*;

/// Complete encoded Event byte limit, including extensions and whitespace.
pub const MAX_AUDIT_EVENT_BYTES: usize = 2_048;
/// Complete encoded Page byte limit.
pub const MAX_AUDIT_PAGE_BYTES: usize = 1_048_576;
/// Complete encoded Verification Result byte limit.
pub const MAX_AUDIT_VERIFICATION_BYTES: usize = 4_096;
/// Complete RFC 9457 problem byte limit.
pub const MAX_AUDIT_PROBLEM_BYTES: usize = 4_096;

/// Content-free syntax, bound or context failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum AuditCodecError {
    /// A complete body, decoded query or range exceeds its bound.
    #[error("audit input exceeds its bound")]
    TooLarge,
    /// Invalid UTF-8/JSON, BOM or recursively duplicate names.
    #[error("invalid audit JSON")]
    InvalidJson,
    /// A required value is missing, malformed or internally inconsistent.
    #[error("invalid audit field: {0}")]
    InvalidField(&'static str),
    /// Response Organization, filters, cursor or range differ from the request.
    #[error("audit response context mismatch")]
    Context,
    /// Required response cache-prevention headers differ.
    #[error("invalid audit HTTP metadata")]
    HttpMetadata,
}

macro_rules! labels {
    ($name:ident, $doc:literal, {$($variant:ident => $text:literal),+ $(,)?}) => {
        #[doc = $doc]
        #[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
        pub enum $name { $(#[doc = concat!("`", $text, "`")] #[serde(rename = $text)] $variant),+ }
        impl $name {
            /// Canonical case-sensitive public label.
            #[must_use]
            pub const fn as_str(self) -> &'static str { match self { $(Self::$variant => $text),+ } }
        }
        impl FromStr for $name {
            type Err = AuditCodecError;
            fn from_str(text: &str) -> Result<Self, Self::Err> {
                match text { $($text => Ok(Self::$variant)),+, _ => Err(AuditCodecError::InvalidField(stringify!($name))) }
            }
        }
    }
}

labels!(AuditCategory, "Small public category labels; not the full OCSF schema.", {
    Authentication => "authentication", Authorization => "authorization",
    AccountChange => "account_change", Scoplen => "scoplen", Unknown => "unknown"
});
labels!(AuditOutcome, "Recorded outcome; absent historical outcomes may remain unknown.", {
    Success => "success", Failure => "failure", Unknown => "unknown"
});
labels!(AuditResourceKind, "Registered primary resource kinds; no current target lookup is implied.", {
    Organization => "organization", Invitation => "invitation", Membership => "membership",
    Host => "host", HostGroup => "host_group", AccessProfile => "access_profile", Route => "route",
    TrustRecord => "trust_record", Snippet => "snippet", GatewayNetwork => "gateway_network",
    Group => "group", Policy => "policy", Grant => "grant", CertificateAuthority => "certificate_authority",
    Certificate => "certificate"
});

/// Exact recorded primary resource, without a synthetic event UUID.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditResource {
    /// Registered primary target kind.
    pub kind: AuditResourceKind,
    /// Recorded target `UUIDv7`, even if the current object no longer exists.
    pub id: Uuid,
}
impl AuditResource {
    /// Validate mutable target identity.
    /// # Errors
    /// Rejects non-UUIDv7 identities.
    pub fn validate(&self) -> Result<(), AuditCodecError> {
        valid_uuid(self.id, "resource.id")
    }
}

/// Immutable safe projection; its JSON does not authenticate the original hashed bytes.
#[derive(Clone, Eq, PartialEq)]
pub struct AuditEvent {
    /// Owning Organization `UUIDv7`.
    pub organization_id: Uuid,
    /// One-based Organization-local sequence, encoded as an exact decimal string.
    pub sequence: u64,
    /// Stored creation time in normalized integer-millisecond UTC text.
    pub occurred_at: String,
    /// Registered category or unknown.
    pub category: AuditCategory,
    /// Safe original producer name, including unclassified names, or null.
    pub event_class: Option<String>,
    /// Recorded or explicitly classified committed-mutation outcome.
    pub outcome: AuditOutcome,
    /// Recorded actor Account; never guessed from another identity.
    pub actor_account_id: Option<Uuid>,
    /// Recorded Device actor, or null.
    pub actor_device_id: Option<Uuid>,
    /// Recorded browser-family actor, or null.
    pub actor_browser_family_id: Option<Uuid>,
    /// Known recorded primary target, or null.
    pub resource: Option<AuditResource>,
    /// Stored predecessor hash.
    pub previous_hash: [u8; 32],
    /// Stored event hash, not a hash of this projection.
    pub event_hash: [u8; 32],
}
impl fmt::Debug for AuditEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuditEvent").field("sequence", &self.sequence).finish_non_exhaustive()
    }
}

#[derive(Serialize, Deserialize)]
struct ResourceWire {
    kind: AuditResourceKind,
    id: String,
}
#[derive(Serialize, Deserialize)]
struct EventWire {
    organization_id: String,
    sequence: String,
    occurred_at: String,
    category: AuditCategory,
    event_class: Option<String>,
    outcome: AuditOutcome,
    actor_account_id: Option<String>,
    actor_device_id: Option<String>,
    actor_browser_family_id: Option<String>,
    resource: Option<ResourceWire>,
    previous_hash: String,
    event_hash: String,
}
const EVENT_FIELDS: &[&str] = &[
    "organization_id",
    "sequence",
    "occurred_at",
    "category",
    "event_class",
    "outcome",
    "actor_account_id",
    "actor_device_id",
    "actor_browser_family_id",
    "resource",
    "previous_hash",
    "event_hash",
];

impl AuditEvent {
    /// Validate all public fields without making a chain-integrity claim.
    /// # Errors
    /// Rejects invalid ids, sequence, timestamp, class or resource.
    pub fn validate(&self) -> Result<(), AuditCodecError> {
        valid_uuid(self.organization_id, "organization_id")?;
        if self.sequence == 0 {
            return Err(AuditCodecError::InvalidField("sequence"));
        }
        if parse_audit_timestamp(&self.occurred_at)? <= 0 {
            return Err(AuditCodecError::InvalidField("occurred_at"));
        }
        if let Some(class) = &self.event_class {
            validate_class(class)?;
        }
        for id in [self.actor_account_id, self.actor_device_id, self.actor_browser_family_id]
            .into_iter()
            .flatten()
        {
            valid_uuid(id, "actor")?;
        }
        if let Some(resource) = &self.resource {
            resource.validate()?;
        }
        Ok(())
    }
    /// Parse one complete bounded Event, ignoring extensions but rejecting duplicates recursively.
    /// # Errors
    /// Rejects malformed, missing, noncanonical or oversized fields.
    pub fn from_json(input: &[u8]) -> Result<Self, AuditCodecError> {
        require_fields(&object(input, MAX_AUDIT_EVENT_BYTES)?, EVENT_FIELDS)?;
        let wire: EventWire =
            serde_json::from_slice(input).map_err(|_| AuditCodecError::InvalidJson)?;
        let result = Self {
            organization_id: parse_uuid(&wire.organization_id, "organization_id")?,
            sequence: parse_decimal(&wire.sequence, false, "sequence")?,
            occurred_at: wire.occurred_at,
            category: wire.category,
            event_class: wire.event_class,
            outcome: wire.outcome,
            actor_account_id: optional_uuid(wire.actor_account_id)?,
            actor_device_id: optional_uuid(wire.actor_device_id)?,
            actor_browser_family_id: optional_uuid(wire.actor_browser_family_id)?,
            resource: wire
                .resource
                .map(|r| Ok(AuditResource { kind: r.kind, id: parse_uuid(&r.id, "resource.id")? }))
                .transpose()?,
            previous_hash: parse_hex(&wire.previous_hash)?,
            event_hash: parse_hex(&wire.event_hash)?,
        };
        result.validate()?;
        Ok(result)
    }
    /// Emit encoder-order JSON after revalidating mutable fields.
    /// # Errors
    /// Rejects invalid fields or a complete encoded item overflow.
    pub fn to_json(&self) -> Result<Vec<u8>, AuditCodecError> {
        self.validate()?;
        encode(
            &EventWire {
                organization_id: self.organization_id.to_string(),
                sequence: self.sequence.to_string(),
                occurred_at: self.occurred_at.clone(),
                category: self.category,
                event_class: self.event_class.clone(),
                outcome: self.outcome,
                actor_account_id: self.actor_account_id.map(|id| id.to_string()),
                actor_device_id: self.actor_device_id.map(|id| id.to_string()),
                actor_browser_family_id: self.actor_browser_family_id.map(|id| id.to_string()),
                resource: self
                    .resource
                    .as_ref()
                    .map(|r| ResourceWire { kind: r.kind, id: r.id.to_string() }),
                previous_hash: hex(&self.previous_hash),
                event_hash: hex(&self.event_hash),
            },
            MAX_AUDIT_EVENT_BYTES,
        )
    }
}

/// Strictly descending live audit Page.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditPage {
    /// Bounded immutable Event projections.
    pub items: Vec<AuditEvent>,
    /// Final returned sequence only when another matching row exists.
    pub next_cursor: Option<u64>,
}
impl AuditPage {
    /// Validate count, descending uniqueness, per-item syntax and continuation.
    /// # Errors
    /// Rejects invalid mutable page fields.
    pub fn validate(&self) -> Result<(), AuditCodecError> {
        if self.items.len() > 500 {
            return Err(AuditCodecError::InvalidField("items"));
        }
        for item in &self.items {
            item.validate()?;
        }
        if self.items.windows(2).any(|pair| {
            pair[0].sequence <= pair[1].sequence
                || pair[0].organization_id != pair[1].organization_id
        }) || self
            .next_cursor
            .is_some_and(|cursor| self.items.last().is_none_or(|item| item.sequence != cursor))
        {
            return Err(AuditCodecError::InvalidField("continuation"));
        }
        Ok(())
    }
    /// Bind a complete Page to its request before display or continuation.
    /// # Errors
    /// Rejects wrong tenant, filter, limit, cursor or malformed data.
    pub fn validate_for(
        &self,
        organization: Uuid,
        query: &AuditListQuery,
    ) -> Result<(), AuditCodecError> {
        self.validate()?;
        valid_uuid(organization, "organization_id")?;
        query.validate()?;
        if self.items.len() > usize::from(query.limit) {
            return Err(AuditCodecError::Context);
        }
        for item in &self.items {
            if item.organization_id != organization
                || query.cursor.is_some_and(|cursor| item.sequence >= cursor)
                || !query.filter.matches(item)?
            {
                return Err(AuditCodecError::Context);
            }
        }
        Ok(())
    }
    /// Decode and enforce each original encoded item's complete byte budget.
    /// # Errors
    /// Rejects malformed, oversized, missing or inconsistent page fields.
    pub fn from_json(input: &[u8]) -> Result<Self, AuditCodecError> {
        #[derive(Deserialize)]
        struct Wire {
            items: Vec<Box<RawValue>>,
            next_cursor: Option<String>,
        }
        require_fields(&object(input, MAX_AUDIT_PAGE_BYTES)?, &["items", "next_cursor"])?;
        let wire: Wire = serde_json::from_slice(input).map_err(|_| AuditCodecError::InvalidJson)?;
        if wire.items.len() > 500 {
            return Err(AuditCodecError::InvalidField("items"));
        }
        let result = Self {
            items: wire
                .items
                .iter()
                .map(|item| AuditEvent::from_json(item.get().as_bytes()))
                .collect::<Result<_, _>>()?,
            next_cursor: wire
                .next_cursor
                .map(|s| parse_decimal(&s, false, "next_cursor"))
                .transpose()?,
        };
        result.validate()?;
        Ok(result)
    }
    /// Decode a bounded response and bind it to its captured request.
    /// # Errors
    /// Rejects invalid syntax or request context.
    pub fn from_json_for(
        input: &[u8],
        organization: Uuid,
        query: &AuditListQuery,
    ) -> Result<Self, AuditCodecError> {
        let value = Self::from_json(input)?;
        value.validate_for(organization, query)?;
        Ok(value)
    }
    /// Emit canonical Page JSON with independently bounded items.
    /// # Errors
    /// Rejects invalid mutable fields or byte overflow.
    pub fn to_json(&self) -> Result<Vec<u8>, AuditCodecError> {
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
                let text =
                    String::from_utf8(item.to_json()?).map_err(|_| AuditCodecError::InvalidJson)?;
                RawValue::from_string(text).map_err(|_| AuditCodecError::InvalidJson)
            })
            .collect::<Result<_, _>>()?;
        encode(
            &Wire { items, next_cursor: self.next_cursor.map(|n| n.to_string()) },
            MAX_AUDIT_PAGE_BYTES,
        )
    }
}

/// Require the shared cache-prevention metadata; transport also checks status/type/request id.
/// # Errors
/// Rejects absent or mismatched header values.
pub fn validate_audit_cache_headers(
    cache_control: Option<&str>,
    pragma: Option<&str>,
) -> Result<(), AuditCodecError> {
    if cache_control != Some("no-store") || pragma != Some("no-cache") {
        return Err(AuditCodecError::HttpMetadata);
    }
    Ok(())
}

fn object(input: &[u8], bound: usize) -> Result<Map<String, Value>, AuditCodecError> {
    if input.len() > bound {
        return Err(AuditCodecError::TooLarge);
    }
    crate::request_wire::decode_unique_object(input).map_err(|()| AuditCodecError::InvalidJson)
}
fn require_fields(fields: &Map<String, Value>, names: &[&str]) -> Result<(), AuditCodecError> {
    if names.iter().any(|name| !fields.contains_key(*name)) {
        return Err(AuditCodecError::InvalidField("required fields"));
    }
    Ok(())
}
fn encode(value: &impl Serialize, bound: usize) -> Result<Vec<u8>, AuditCodecError> {
    let bytes = serde_json::to_vec(value).map_err(|_| AuditCodecError::InvalidJson)?;
    if bytes.len() > bound {
        return Err(AuditCodecError::TooLarge);
    }
    Ok(bytes)
}
fn valid_uuid(id: Uuid, field: &'static str) -> Result<(), AuditCodecError> {
    validate_uuid_v7(id).map_err(|_| AuditCodecError::InvalidField(field))
}
fn parse_uuid(text: &str, field: &'static str) -> Result<Uuid, AuditCodecError> {
    let id = Uuid::parse_str(text).map_err(|_| AuditCodecError::InvalidField(field))?;
    if id.to_string() != text {
        return Err(AuditCodecError::InvalidField(field));
    }
    valid_uuid(id, field)?;
    Ok(id)
}
fn optional_uuid(text: Option<String>) -> Result<Option<Uuid>, AuditCodecError> {
    text.map(|s| parse_uuid(&s, "actor")).transpose()
}
fn parse_decimal(text: &str, zero: bool, field: &'static str) -> Result<u64, AuditCodecError> {
    if text.is_empty()
        || (text.starts_with('0') && (text.len() != 1 || !zero))
        || !text.bytes().all(|c| c.is_ascii_digit())
    {
        return Err(AuditCodecError::InvalidField(field));
    }
    text.parse().map_err(|_| AuditCodecError::InvalidField(field))
}
fn validate_class(text: &str) -> Result<(), AuditCodecError> {
    if text.len() > 128
        || !text.contains('.')
        || text.split('.').any(|part| {
            part.is_empty()
                || !part.as_bytes()[0].is_ascii_lowercase()
                || !part.bytes().all(|c| {
                    c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'_' | b'-')
                })
        })
    {
        return Err(AuditCodecError::InvalidField("event_class"));
    }
    Ok(())
}
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(text, "{byte:02x}").expect("String writing is infallible");
    }
    text
}
fn parse_hex(text: &str) -> Result<[u8; 32], AuditCodecError> {
    if text.len() != 64 || !text.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)) {
        return Err(AuditCodecError::InvalidField("hash"));
    }
    let mut bytes = [0; 32];
    for (i, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[i * 2..i * 2 + 2], 16)
            .map_err(|_| AuditCodecError::InvalidField("hash"))?;
    }
    Ok(bytes)
}
