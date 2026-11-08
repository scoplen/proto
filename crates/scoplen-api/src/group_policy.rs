// SPDX-License-Identifier: Apache-2.0
//! D-137 local groups, persisted policies and the shared simple-rule generator.
//!
//! Codecs and policy inspection establish syntax, not current tenant ownership or authority.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    str::FromStr,
};

use cedar_policy::{EntityUid, Policy, PolicySet, Schema, ValidationMode, Validator};
use scoplen_model::ObjectType;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, value::RawValue};
use uuid::Uuid;

use crate::{
    certificate::{valid_strong_etag, valid_utc_timestamp},
    control_plane::CEDAR_SCHEMA,
    organization::{
        OrganizationCodecError as Error, OrganizationListQuery, encode, object, parse_uuid,
        take_object, take_string, take_uuid, valid_uuid, validate_cache_headers, validate_name,
    },
    request_wire::valid_remote_user,
};

/// Complete request or Resource JSON ceiling.
pub const MAX_GROUP_POLICY_BYTES: usize = 262_144;
/// Complete Page JSON ceiling, including extensions and whitespace.
pub const MAX_GROUP_POLICY_PAGE_BYTES: usize = 8_388_608;
/// Maximum current Membership ids in one group.
pub const MAX_GROUP_MEMBERS: usize = 4_096;
/// Maximum UTF-8 bytes of one persisted or generated Cedar policy.
pub const MAX_POLICY_SOURCE_BYTES: usize = 65_536;
/// Maximum selectors in a simple view rule, or in either connect selector list.
pub const MAX_SIMPLE_RULE_SELECTORS: usize = 64;

/// Complete writable local-group data; members are Membership ids, never Account ids.
#[derive(Clone, Eq, PartialEq)]
pub struct GroupFields {
    /// Bounded display name.
    pub name: String,
    /// Distinct current Membership ids; encoders sort them by UUID bytes.
    pub members: Vec<Uuid>,
}

impl fmt::Debug for GroupFields {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GroupFields").field("members", &self.members.len()).finish_non_exhaustive()
    }
}

impl GroupFields {
    /// Validate the name and distinct bounded Membership id set.
    /// # Errors
    /// Rejects invalid names, ids, duplicates or excess members.
    pub fn validate(&self) -> Result<(), Error> {
        validate_name(&self.name)?;
        validate_ids(&self.members, MAX_GROUP_MEMBERS, "members")
    }

    fn from_value(value: &mut Map<String, Value>, strict: bool) -> Result<Self, Error> {
        let result =
            Self { name: take_string(value, "name")?, members: take_ids(value, "members")? };
        if strict {
            reject_remaining(value)?;
        }
        result.validate()?;
        Ok(result)
    }

    fn wire(&self, source: Option<GroupSource>) -> GroupWire<'_> {
        let mut members = self.members.clone();
        members.sort_unstable();
        GroupWire {
            name: &self.name,
            members: members.iter().map(Uuid::to_string).collect(),
            source,
        }
    }
}

/// Server-owned group origin. `IdP` groups are read-only through the local-group route.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum GroupSource {
    /// Authored in this Organization.
    #[serde(rename = "local")]
    Local,
    /// Supplied by an identity provider.
    #[serde(rename = "IdP")]
    Idp,
}

impl GroupSource {
    fn parse(value: &str) -> Result<Self, Error> {
        match value {
            "local" => Ok(Self::Local),
            "IdP" => Ok(Self::Idp),
            _ => Err(invalid("source")),
        }
    }
}

#[derive(Serialize)]
struct GroupWire<'a> {
    name: &'a str,
    members: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    source: Option<GroupSource>,
}

/// Exact POST payload for a new local group.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GroupCreateRequest {
    /// Client-created group id.
    pub id: Uuid,
    /// Complete desired group fields.
    pub fields: GroupFields,
}

impl GroupCreateRequest {
    /// Decode strict bounded POST JSON.
    /// # Errors
    /// Rejects invalid ids, fields, duplicates, extensions or byte overflow.
    pub fn from_json(input: &[u8]) -> Result<Self, Error> {
        let mut fields = object(input, MAX_GROUP_POLICY_BYTES)?;
        let id = take_uuid(&mut fields, "id")?;
        let data = GroupFields::from_value(&mut take_object(&mut fields, "data")?, true)?;
        reject_remaining(&fields)?;
        Ok(Self { id, fields: data })
    }

    /// Encode the complete canonical desired payload.
    /// # Errors
    /// Rejects invalid mutable public fields or byte overflow.
    pub fn to_json(&self) -> Result<Vec<u8>, Error> {
        valid_uuid(self.id, "id")?;
        self.fields.validate()?;
        encode(
            &CreateWire { id: self.id.to_string(), data: self.fields.wire(None) },
            MAX_GROUP_POLICY_BYTES,
        )
    }
}

/// Exact PUT payload for the complete local-group replacement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GroupReplaceRequest {
    /// Complete desired group fields.
    pub fields: GroupFields,
}

impl GroupReplaceRequest {
    /// Decode strict bounded replacement JSON.
    /// # Errors
    /// Rejects malformed, duplicate, unknown or oversized fields.
    pub fn from_json(input: &[u8]) -> Result<Self, Error> {
        let mut fields = object(input, MAX_GROUP_POLICY_BYTES)?;
        let data = GroupFields::from_value(&mut take_object(&mut fields, "data")?, true)?;
        reject_remaining(&fields)?;
        Ok(Self { fields: data })
    }

    /// Encode the complete desired fields with sorted Membership ids.
    /// # Errors
    /// Rejects invalid mutable public fields or byte overflow.
    pub fn to_json(&self) -> Result<Vec<u8>, Error> {
        self.fields.validate()?;
        encode(&ReplaceWire { data: self.fields.wire(None) }, MAX_GROUP_POLICY_BYTES)
    }
}

/// Complete mutable persisted-policy fields.
#[derive(Clone, Eq, PartialEq)]
pub struct PolicyFields {
    /// Bounded display name.
    pub name: String,
    /// Exactly one non-template schema-valid Cedar policy in the initial profile.
    pub source: String,
    /// Whether current authorization loads this policy.
    pub enabled: bool,
}

impl fmt::Debug for PolicyFields {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PolicyFields").field("enabled", &self.enabled).finish_non_exhaustive()
    }
}

impl PolicyFields {
    /// Validate one strict-schema policy without consulting current durable references.
    /// # Errors
    /// Rejects invalid names, source, schema or time-dependent visibility rules.
    pub fn validate(&self) -> Result<(), Error> {
        validate_name(&self.name)?;
        parse_policy_source(&self.source)?;
        Ok(())
    }

    fn from_value(value: &mut Map<String, Value>, strict: bool) -> Result<Self, Error> {
        let result = Self {
            name: take_string(value, "name")?,
            source: take_string(value, "source")?,
            enabled: take_bool(value, "enabled")?,
        };
        if strict {
            reject_remaining(value)?;
        }
        result.validate()?;
        Ok(result)
    }

    fn wire(&self) -> PolicyWire<'_> {
        PolicyWire { name: &self.name, source: &self.source, enabled: self.enabled }
    }
}

#[derive(Serialize)]
struct PolicyWire<'a> {
    name: &'a str,
    source: &'a str,
    enabled: bool,
}

/// Exact POST payload for a new policy Resource.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyCreateRequest {
    /// Client-created policy id.
    pub id: Uuid,
    /// Complete desired policy fields.
    pub fields: PolicyFields,
}

impl PolicyCreateRequest {
    /// Decode one strict bounded policy creation request.
    /// # Errors
    /// Rejects invalid JSON, ids, source, profile, extensions or body overflow.
    pub fn from_json(input: &[u8]) -> Result<Self, Error> {
        let mut fields = object(input, MAX_GROUP_POLICY_BYTES)?;
        let id = take_uuid(&mut fields, "id")?;
        let data = PolicyFields::from_value(&mut take_object(&mut fields, "data")?, true)?;
        reject_remaining(&fields)?;
        Ok(Self { id, fields: data })
    }

    /// Encode the exact typed payload for its create receipt.
    /// # Errors
    /// Rejects invalid mutable fields or encoded overflow.
    pub fn to_json(&self) -> Result<Vec<u8>, Error> {
        valid_uuid(self.id, "id")?;
        self.fields.validate()?;
        encode(
            &CreateWire { id: self.id.to_string(), data: self.fields.wire() },
            MAX_GROUP_POLICY_BYTES,
        )
    }
}

/// Exact PUT payload for complete replacement of a persisted policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyReplaceRequest {
    /// Complete desired policy fields.
    pub fields: PolicyFields,
}

impl PolicyReplaceRequest {
    /// Decode one strict bounded replacement request.
    /// # Errors
    /// Rejects malformed, duplicate, unknown or oversized fields and invalid source.
    pub fn from_json(input: &[u8]) -> Result<Self, Error> {
        let mut fields = object(input, MAX_GROUP_POLICY_BYTES)?;
        let data = PolicyFields::from_value(&mut take_object(&mut fields, "data")?, true)?;
        reject_remaining(&fields)?;
        Ok(Self { fields: data })
    }

    /// Encode complete desired policy fields.
    /// # Errors
    /// Rejects invalid mutable fields or encoded overflow.
    pub fn to_json(&self) -> Result<Vec<u8>, Error> {
        self.fields.validate()?;
        encode(&ReplaceWire { data: self.fields.wire() }, MAX_GROUP_POLICY_BYTES)
    }
}

#[derive(Serialize)]
struct CreateWire<T> {
    id: String,
    data: T,
}
#[derive(Serialize)]
struct ReplaceWire<T> {
    data: T,
}
#[derive(Serialize)]
struct ResourceWire<'a, T> {
    id: String,
    etag: &'a str,
    created_at: &'a str,
    updated_at: &'a str,
    data: T,
}

/// Server-owned local or `IdP` group Resource.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GroupResource {
    /// Group identifier.
    pub id: Uuid,
    /// Strong entity tag for this Resource.
    pub etag: String,
    /// RFC 3339 UTC creation timestamp.
    pub created_at: String,
    /// RFC 3339 UTC update timestamp.
    pub updated_at: String,
    /// Complete current group fields.
    pub fields: GroupFields,
    /// Server-owned source.
    pub source: GroupSource,
}

impl GroupResource {
    /// Validate metadata and current fields, without granting mutation rights.
    /// # Errors
    /// Rejects invalid metadata, name, ids or member cardinality.
    pub fn validate(&self) -> Result<(), Error> {
        validate_metadata(self.id, &self.etag, &self.created_at, &self.updated_at)?;
        self.fields.validate()
    }

    /// Bind a decoded Resource to the exact requested group id.
    /// # Errors
    /// Rejects invalid fields or a foreign response id.
    pub fn validate_for_request(&self, id: Uuid) -> Result<(), Error> {
        self.validate()?;
        valid_uuid(id, "requested id")?;
        if self.id != id {
            return Err(Error::Context);
        }
        Ok(())
    }

    /// Decode a complete bounded Resource, ignoring response extensions.
    /// # Errors
    /// Rejects malformed, duplicate, missing or oversized known fields.
    pub fn from_json(input: &[u8]) -> Result<Self, Error> {
        let mut fields = object(input, MAX_GROUP_POLICY_BYTES)?;
        let mut data = take_object(&mut fields, "data")?;
        let source = GroupSource::parse(&take_string(&mut data, "source")?)?;
        let result = Self {
            id: take_uuid(&mut fields, "id")?,
            etag: take_string(&mut fields, "etag")?,
            created_at: take_string(&mut fields, "created_at")?,
            updated_at: take_string(&mut fields, "updated_at")?,
            fields: GroupFields::from_value(&mut data, false)?,
            source,
        };
        result.validate()?;
        Ok(result)
    }

    /// Decode the Resource and require matching strong HTTP `ETag` and no-store headers.
    /// # Errors
    /// Rejects invalid metadata, body or header values.
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

    /// Encode current fields and their server-owned source.
    /// # Errors
    /// Rejects invalid mutable fields or encoded overflow.
    pub fn to_json(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        encode(
            &ResourceWire {
                id: self.id.to_string(),
                etag: &self.etag,
                created_at: &self.created_at,
                updated_at: &self.updated_at,
                data: self.fields.wire(Some(self.source)),
            },
            MAX_GROUP_POLICY_BYTES,
        )
    }
}

/// Server-owned persisted custom-policy Resource.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyResource {
    /// Policy identifier.
    pub id: Uuid,
    /// Strong entity tag for this Resource.
    pub etag: String,
    /// RFC 3339 UTC creation timestamp.
    pub created_at: String,
    /// RFC 3339 UTC update timestamp.
    pub updated_at: String,
    /// Complete current policy fields.
    pub fields: PolicyFields,
}

impl PolicyResource {
    /// Validate metadata and the initial persisted-policy profile.
    /// # Errors
    /// Rejects invalid metadata, source, schema or unsupported visibility conditions.
    pub fn validate(&self) -> Result<(), Error> {
        validate_metadata(self.id, &self.etag, &self.created_at, &self.updated_at)?;
        self.fields.validate()
    }

    /// Bind a Resource to its captured id and check its explicit Organization literals.
    /// Remaining references require independent current ownership checks by the consumer.
    /// # Errors
    /// Rejects invalid values, foreign id or foreign explicit Organization references.
    pub fn validate_for_request(&self, organization: Uuid, id: Uuid) -> Result<(), Error> {
        self.validate()?;
        valid_uuid(id, "requested id")?;
        if self.id != id {
            return Err(Error::Context);
        }
        policy_references(&parse_policy_source(&self.fields.source)?, organization)?;
        Ok(())
    }

    /// Decode a bounded current policy Resource, ignoring response extensions.
    /// # Errors
    /// Rejects malformed, duplicate, oversized or invalid known fields and policy source.
    pub fn from_json(input: &[u8]) -> Result<Self, Error> {
        let mut fields = object(input, MAX_GROUP_POLICY_BYTES)?;
        let result = Self {
            id: take_uuid(&mut fields, "id")?,
            etag: take_string(&mut fields, "etag")?,
            created_at: take_string(&mut fields, "created_at")?,
            updated_at: take_string(&mut fields, "updated_at")?,
            fields: PolicyFields::from_value(&mut take_object(&mut fields, "data")?, false)?,
        };
        result.validate()?;
        Ok(result)
    }

    /// Decode the Resource and require its matching strong `ETag` and no-store metadata.
    /// # Errors
    /// Rejects invalid body or header metadata.
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

    /// Encode the complete current policy Resource.
    /// # Errors
    /// Rejects invalid mutable fields or encoded overflow.
    pub fn to_json(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        encode(
            &ResourceWire {
                id: self.id.to_string(),
                etag: &self.etag,
                created_at: &self.created_at,
                updated_at: &self.updated_at,
                data: self.fields.wire(),
            },
            MAX_GROUP_POLICY_BYTES,
        )
    }
}

/// Current ascending group administration page, not an Account directory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GroupPage {
    /// Authorized group Resources in strictly ascending UUID order.
    pub items: Vec<GroupResource>,
    /// Last returned id if another page exists.
    pub next_cursor: Option<Uuid>,
}

impl GroupPage {
    /// Validate count, ordering and continuation with every Resource.
    /// # Errors
    /// Rejects invalid Resources, duplicates, ordering or continuation.
    pub fn validate(&self) -> Result<(), Error> {
        for item in &self.items {
            item.validate()?;
        }
        validate_page(self.items.iter().map(|item| item.id), self.next_cursor)
    }

    /// Bind a page to the original count and cursor.
    /// # Errors
    /// Rejects invalid pages, excess items or ids not beyond the requested cursor.
    pub fn validate_for_query(&self, query: OrganizationListQuery) -> Result<(), Error> {
        self.validate()?;
        validate_query(self.items.iter().map(|item| item.id), query)
    }

    /// Decode a bounded Page and enforce each original embedded Resource's byte limit.
    /// # Errors
    /// Rejects malformed, duplicate, oversized or invalid pages and items.
    pub fn from_json(input: &[u8]) -> Result<Self, Error> {
        let (raw, next_cursor) = decode_page(input)?;
        let result = Self {
            items: raw
                .iter()
                .map(|item| GroupResource::from_json(item.get().as_bytes()))
                .collect::<Result<_, _>>()?,
            next_cursor,
        };
        result.validate()?;
        Ok(result)
    }

    /// Decode a Page with mandatory no-store response metadata.
    /// # Errors
    /// Rejects invalid body or cache headers.
    pub fn from_http_json(
        input: &[u8],
        cache_control: Option<&str>,
        pragma: Option<&str>,
    ) -> Result<Self, Error> {
        validate_cache_headers(cache_control, pragma)?;
        Self::from_json(input)
    }

    /// Encode a bounded Page, stopping before collecting an oversized set of items.
    /// # Errors
    /// Rejects invalid public fields or any encoded byte overflow.
    pub fn to_json(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        encode_page(self.items.iter().map(GroupResource::to_json), self.next_cursor)
    }
}

/// Current ascending persisted-policy administration page.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyPage {
    /// Authorized policy Resources in strictly ascending UUID order.
    pub items: Vec<PolicyResource>,
    /// Last returned id if another page exists.
    pub next_cursor: Option<Uuid>,
}

impl PolicyPage {
    /// Validate all Resources, count, ordering and continuation.
    /// # Errors
    /// Rejects invalid Resources, ids or continuation.
    pub fn validate(&self) -> Result<(), Error> {
        for item in &self.items {
            item.validate()?;
        }
        validate_page(self.items.iter().map(|item| item.id), self.next_cursor)
    }

    /// Bind a page to its captured continuation and requested count.
    /// # Errors
    /// Rejects invalid pages or response/query mismatch.
    pub fn validate_for_query(&self, query: OrganizationListQuery) -> Result<(), Error> {
        self.validate()?;
        validate_query(self.items.iter().map(|item| item.id), query)
    }

    /// Decode a bounded complete Page, including every original item's encoded byte budget.
    /// # Errors
    /// Rejects malformed, duplicate, oversized or invalid pages and source.
    pub fn from_json(input: &[u8]) -> Result<Self, Error> {
        let (raw, next_cursor) = decode_page(input)?;
        let result = Self {
            items: raw
                .iter()
                .map(|item| PolicyResource::from_json(item.get().as_bytes()))
                .collect::<Result<_, _>>()?,
            next_cursor,
        };
        result.validate()?;
        Ok(result)
    }

    /// Decode a complete no-store policy Page.
    /// # Errors
    /// Rejects invalid body or missing/mismatched cache headers.
    pub fn from_http_json(
        input: &[u8],
        cache_control: Option<&str>,
        pragma: Option<&str>,
    ) -> Result<Self, Error> {
        validate_cache_headers(cache_control, pragma)?;
        Self::from_json(input)
    }

    /// Encode one complete bounded Page, stopping before excess item accumulation.
    /// # Errors
    /// Rejects invalid fields or complete-body overflow.
    pub fn to_json(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        encode_page(self.items.iter().map(PolicyResource::to_json), self.next_cursor)
    }
}

/// Parse exactly one static, strict-schema policy under the initial visibility profile.
/// This does not establish current reference ownership, enabled state or author permission.
/// # Errors
/// Rejects empty/oversized source, templates, multiple policies, unknown actions, schema errors
/// or `context.now` in a policy whose parsed request environments can include `view_inventory`.
pub fn parse_policy_source(source: &str) -> Result<Policy, Error> {
    if source.is_empty() || source.len() > MAX_POLICY_SOURCE_BYTES {
        return Err(invalid("source"));
    }
    let policies = PolicySet::from_str(source).map_err(|_| invalid("source"))?;
    if policies.templates().next().is_some() || policies.policies().count() != 1 {
        return Err(invalid("source"));
    }
    let policy = policies.policies().next().ok_or(invalid("source"))?.clone();
    if !policy.is_static() {
        return Err(invalid("source"));
    }
    let schema = Schema::from_str(CEDAR_SCHEMA).map_err(|_| invalid("policy schema"))?;
    if !Validator::new(schema.clone())
        .validate(&policies, ValidationMode::Strict)
        .validation_passed()
    {
        return Err(invalid("source"));
    }
    if policy
        .get_valid_request_envs(&schema)
        .any(|env| env.action().id().unescaped() == "view_inventory")
        && references_context_attribute(&policy.to_json().map_err(|_| invalid("source"))?, "now")
    {
        return Err(invalid("time-dependent inventory visibility"));
    }
    Ok(policy)
}

/// Whether a validated policy can match `connect` and observes its source IP.
/// The initial local-user-CA consumer denies issuance if any enabled policy returns true.
/// Obtain `policy` from [`parse_policy_source`]; this inspection is not policy validation,
/// authorization, enabled-state checking or translation into certificate address constraints.
/// # Errors
/// Rejects failure to load the shared schema or inspect the parsed policy expression.
pub fn connect_policy_observes_source_ip(policy: &Policy) -> Result<bool, Error> {
    let schema = Schema::from_str(CEDAR_SCHEMA).map_err(|_| invalid("policy schema"))?;
    Ok(policy.get_valid_request_envs(&schema).any(|env| env.action().id().unescaped() == "connect")
        && references_context_attribute(
            &policy.to_json().map_err(|_| invalid("source"))?,
            "source_ip",
        ))
}

/// Inspect parsed entity locators for current same-Organization resolution by the consumer.
/// An explicit Organization literal must equal the captured owner; a literal is not required.
/// `Action` literals are schema-owned and omitted. No returned locator grants read or membership.
/// # Errors
/// Rejects noncanonical entity ids, unsupported entity kinds or a foreign Organization literal.
pub fn policy_references(policy: &Policy, organization: Uuid) -> Result<Vec<EntityUid>, Error> {
    valid_uuid(organization, "organization")?;
    let mut result = BTreeSet::new();
    for reference in policy.entity_literals() {
        let kind = reference.type_name().to_string();
        if kind == "Action" {
            continue;
        }
        if !matches!(
            kind.as_str(),
            "Account"
                | "Device"
                | "Membership"
                | "Group"
                | "Organization"
                | "Host"
                | "HostGroup"
                | "GatewayNetwork"
                | "AccessProfile"
                | "Route"
                | "TrustRecord"
                | "Snippet"
                | "AccessRequest"
                | "Session"
        ) {
            return Err(invalid("policy reference"));
        }
        let id = parse_uuid(reference.id().unescaped(), "policy reference")?;
        if kind == "Organization" && id != organization {
            return Err(Error::Context);
        }
        result.insert(reference);
    }
    Ok(result.into_iter().collect())
}

fn references_context_attribute(value: &Value, attribute: &str) -> bool {
    match value {
        Value::Object(fields) => {
            for operator in [".", "has"] {
                if let Some(Value::Object(access)) = fields.get(operator)
                    && access.get("left").is_some_and(|left| {
                        left.get("Var").and_then(Value::as_str) == Some("context")
                    })
                {
                    return access.get("attr").and_then(Value::as_str) == Some(attribute);
                }
            }
            // Whole-context observations include every field, for example record equality.
            fields.get("Var").and_then(Value::as_str) == Some("context")
                || fields.values().any(|value| references_context_attribute(value, attribute))
        }
        Value::Array(items) => {
            items.iter().any(|value| references_context_attribute(value, attribute))
        }
        _ => false,
    }
}

/// One named current subject under the captured Organization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SimpleRuleSubject {
    /// An exact Membership id.
    Membership(Uuid),
    /// One current local Group id.
    Group(Uuid),
}

/// Exact typed Organization inventory selector; UUIDs alone do not grant access.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct SimpleRuleSelector {
    /// One of the seven Organization K-1 types.
    pub object_type: ObjectType,
    /// Selected resource id.
    pub id: Uuid,
}

/// Exactly one independent view or connect rule.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SimpleRule {
    /// Explicit read access to the selected typed resources, without dependency grants.
    View {
        /// One through 64 distinct typed resources.
        resources: Vec<SimpleRuleSelector>,
    },
    /// SSH connection authority for an exact remote user; supplies no inventory read.
    Connect {
        /// Zero through 64 distinct Host ids.
        hosts: Vec<Uuid>,
        /// Zero through 64 distinct `HostGroup` ids.
        host_groups: Vec<Uuid>,
        /// Exact bounded remote SSH username.
        remote_user: String,
    },
}

/// Public input to the shared pure Cedar generator used by both consumers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SimpleRuleInput {
    /// Captured Organization owner.
    pub organization: Uuid,
    /// Exactly one current Membership or local Group subject.
    pub subject: SimpleRuleSubject,
    /// One separate view or connect permission.
    pub rule: SimpleRule,
}

impl SimpleRuleInput {
    /// Decode the exact bounded public generator input without resolving any selection.
    /// # Errors
    /// Rejects invalid/duplicate/unknown fields, ids, type numbers, selectors or remote user.
    pub fn from_json(input: &[u8]) -> Result<Self, Error> {
        let mut fields = object(input, MAX_GROUP_POLICY_BYTES)?;
        let organization = take_uuid(&mut fields, "organization")?;
        let subject = match (fields.remove("membership"), fields.remove("group")) {
            (Some(Value::String(id)), None) => {
                SimpleRuleSubject::Membership(parse_uuid(&id, "membership")?)
            }
            (None, Some(Value::String(id))) => SimpleRuleSubject::Group(parse_uuid(&id, "group")?),
            _ => return Err(invalid("subject")),
        };
        let rule = match (fields.remove("view"), fields.remove("connect")) {
            (Some(Value::Array(items)), None) => {
                let resources = items
                    .into_iter()
                    .map(|item| {
                        let Value::Object(mut item) = item else {
                            return Err(invalid("selector"));
                        };
                        let object_type = item
                            .remove("type")
                            .and_then(|value| value.as_u64())
                            .and_then(|value| ObjectType::from_wire(value).ok())
                            .ok_or(invalid("type"))?;
                        let id = take_uuid(&mut item, "id")?;
                        reject_remaining(&item)?;
                        Ok(SimpleRuleSelector { object_type, id })
                    })
                    .collect::<Result<_, Error>>()?;
                SimpleRule::View { resources }
            }
            (None, Some(Value::Object(mut data))) => {
                let hosts = take_ids(&mut data, "hosts")?;
                let host_groups = take_ids(&mut data, "host_groups")?;
                let remote_user = take_string(&mut data, "remote_user")?;
                reject_remaining(&data)?;
                SimpleRule::Connect { hosts, host_groups, remote_user }
            }
            _ => return Err(invalid("rule")),
        };
        reject_remaining(&fields)?;
        let result = Self { organization, subject, rule };
        result.validate()?;
        Ok(result)
    }

    /// Validate current input syntax, cardinality, uniqueness and known inventory types.
    /// # Errors
    /// Rejects invalid ids, selections, duplicates or remote username.
    pub fn validate(&self) -> Result<(), Error> {
        valid_uuid(self.organization, "organization")?;
        let (SimpleRuleSubject::Membership(id) | SimpleRuleSubject::Group(id)) = self.subject;
        valid_uuid(id, "subject")?;
        match &self.rule {
            SimpleRule::View { resources } => {
                if resources.is_empty() || resources.len() > MAX_SIMPLE_RULE_SELECTORS {
                    return Err(invalid("view"));
                }
                let mut distinct = BTreeSet::new();
                for selector in resources {
                    inventory_kind(selector.object_type)?;
                    valid_uuid(selector.id, "selector")?;
                    if !distinct.insert(*selector) {
                        return Err(invalid("duplicate selector"));
                    }
                }
            }
            SimpleRule::Connect { hosts, host_groups, remote_user } => {
                validate_ids(hosts, MAX_SIMPLE_RULE_SELECTORS, "hosts")?;
                validate_ids(host_groups, MAX_SIMPLE_RULE_SELECTORS, "host_groups")?;
                if (hosts.is_empty() && host_groups.is_empty()) || !valid_remote_user(remote_user) {
                    return Err(invalid("connect"));
                }
            }
        }
        Ok(())
    }

    /// Encode canonical input with sorted typed resources and UUID sets.
    /// # Errors
    /// Rejects invalid mutable public fields or encoded overflow.
    pub fn to_json(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        let mut fields = Map::new();
        fields.insert("organization".into(), Value::String(self.organization.to_string()));
        match self.subject {
            SimpleRuleSubject::Membership(id) => {
                fields.insert("membership".into(), Value::String(id.to_string()))
            }
            SimpleRuleSubject::Group(id) => {
                fields.insert("group".into(), Value::String(id.to_string()))
            }
        };
        match &self.rule {
            SimpleRule::View { resources } => {
                let mut resources = resources.clone();
                resources.sort_unstable();
                fields.insert("view".into(), Value::Array(resources.iter().map(|item| serde_json::json!({"type": item.object_type.to_wire(), "id": item.id.to_string()})).collect()));
            }
            SimpleRule::Connect { hosts, host_groups, remote_user } => {
                fields.insert("connect".into(), serde_json::json!({"hosts": sorted_ids(hosts), "host_groups": sorted_ids(host_groups), "remote_user": remote_user}));
            }
        }
        let mut fields = Value::Object(fields);
        fields.sort_all_objects();
        encode(&fields, MAX_GROUP_POLICY_BYTES)
    }

    /// Generate one bounded strict-schema permit without resolving or granting references.
    /// The caller previews it and persists it through the normal authorized policy operation.
    /// # Errors
    /// Rejects invalid input, source overflow or generated-policy validation failure.
    pub fn generate(&self) -> Result<String, Error> {
        self.validate()?;
        let subject = match self.subject {
            SimpleRuleSubject::Membership(id) => {
                format!("context.membership == Membership::\"{id}\"")
            }
            SimpleRuleSubject::Group(id) => {
                format!("context.membership.groups.contains(Group::\"{id}\")")
            }
        };
        let (action, target) = match &self.rule {
            SimpleRule::View { resources } => {
                let mut resources = resources.clone();
                resources.sort_unstable();
                let mut by_type = BTreeMap::<ObjectType, Vec<String>>::new();
                for item in resources {
                    by_type.entry(item.object_type).or_default().push(format!(
                        "{}::\"{}\"",
                        inventory_kind(item.object_type)?,
                        item.id
                    ));
                }
                let selectors = by_type
                    .into_iter()
                    .map(|(kind, ids)| {
                        Ok(format!(
                            "(resource is {} && [{}].contains(resource))",
                            inventory_kind(kind)?,
                            ids.join(", ")
                        ))
                    })
                    .collect::<Result<Vec<_>, Error>>()?;
                ("view_inventory", format!("({})", selectors.join(" || ")))
            }
            SimpleRule::Connect { hosts, host_groups, remote_user } => {
                let hosts = sorted_ids(hosts)
                    .iter()
                    .map(|id| format!("Host::\"{id}\""))
                    .collect::<Vec<_>>();
                let groups = sorted_ids(host_groups)
                    .iter()
                    .map(|id| format!("resource.host_groups.contains(HostGroup::\"{id}\")"))
                    .collect::<Vec<_>>();
                let mut selectors = Vec::new();
                if !hosts.is_empty() {
                    selectors.push(format!("[{}].contains(resource)", hosts.join(", ")));
                }
                selectors.extend(groups);
                let user =
                    serde_json::to_string(remote_user).map_err(|_| invalid("remote_user"))?;
                (
                    "connect",
                    format!("({}) && context.remote_user == {user}", selectors.join(" || ")),
                )
            }
        };
        let source = format!(
            "permit(principal is Account, action == Action::\"{action}\", resource)\nwhen {{\n    context.organization == Organization::\"{}\" &&\n    {subject} &&\n    {target}\n}};",
            self.organization
        );
        let policy = parse_policy_source(&source)?;
        policy_references(&policy, self.organization)?;
        Ok(source)
    }
}

fn inventory_kind(kind: ObjectType) -> Result<&'static str, Error> {
    match kind {
        ObjectType::HOST => Ok("Host"),
        ObjectType::ACCESS_PROFILE => Ok("AccessProfile"),
        ObjectType::ROUTE => Ok("Route"),
        ObjectType::HOST_GROUP => Ok("HostGroup"),
        ObjectType::TRUST_RECORD => Ok("TrustRecord"),
        ObjectType::SNIPPET => Ok("Snippet"),
        ObjectType::GATEWAY_NETWORK => Ok("GatewayNetwork"),
        _ => Err(invalid("inventory type")),
    }
}

fn invalid(field: &'static str) -> Error {
    Error::InvalidField(field)
}
fn reject_remaining(fields: &Map<String, Value>) -> Result<(), Error> {
    if fields.is_empty() { Ok(()) } else { Err(invalid("request members")) }
}
fn take_bool(fields: &mut Map<String, Value>, name: &'static str) -> Result<bool, Error> {
    match fields.remove(name) {
        Some(Value::Bool(value)) => Ok(value),
        _ => Err(invalid(name)),
    }
}
fn take_ids(fields: &mut Map<String, Value>, name: &'static str) -> Result<Vec<Uuid>, Error> {
    let Some(Value::Array(values)) = fields.remove(name) else {
        return Err(invalid(name));
    };
    values
        .into_iter()
        .map(|value| match value {
            Value::String(text) => parse_uuid(&text, name),
            _ => Err(invalid(name)),
        })
        .collect()
}
fn sorted_ids(ids: &[Uuid]) -> Vec<String> {
    let mut ids = ids.to_vec();
    ids.sort_unstable();
    ids.iter().map(Uuid::to_string).collect()
}
fn validate_ids(ids: &[Uuid], maximum: usize, name: &'static str) -> Result<(), Error> {
    if ids.len() > maximum {
        return Err(invalid(name));
    }
    let mut distinct = BTreeSet::new();
    for id in ids {
        valid_uuid(*id, name)?;
        if !distinct.insert(*id) {
            return Err(invalid(name));
        }
    }
    Ok(())
}
fn validate_metadata(
    id: Uuid,
    etag: &str,
    created_at: &str,
    updated_at: &str,
) -> Result<(), Error> {
    valid_uuid(id, "id")?;
    if !valid_strong_etag(etag)
        || !valid_utc_timestamp(created_at)
        || !valid_utc_timestamp(updated_at)
    {
        return Err(invalid("metadata"));
    }
    Ok(())
}
fn validate_page(ids: impl Iterator<Item = Uuid>, next: Option<Uuid>) -> Result<(), Error> {
    let mut previous = None;
    let mut count = 0usize;
    for id in ids {
        if previous.is_some_and(|previous| id <= previous) {
            return Err(invalid("items"));
        }
        previous = Some(id);
        count += 1;
    }
    if count > 500 || (next.is_some() && next != previous) {
        return Err(invalid("page"));
    }
    Ok(())
}
fn validate_query(
    ids: impl Iterator<Item = Uuid>,
    query: OrganizationListQuery,
) -> Result<(), Error> {
    query.validate()?;
    let mut count = 0usize;
    for id in ids {
        count += 1;
        if query.cursor.is_some_and(|cursor| id <= cursor) {
            return Err(Error::Context);
        }
    }
    if count > usize::from(query.limit) {
        return Err(Error::Context);
    }
    Ok(())
}
fn decode_page(input: &[u8]) -> Result<(Vec<Box<RawValue>>, Option<Uuid>), Error> {
    #[derive(Deserialize)]
    struct Wire {
        items: Vec<Box<RawValue>>,
        next_cursor: Option<String>,
    }
    let fields = object(input, MAX_GROUP_POLICY_PAGE_BYTES)?;
    if !fields.contains_key("items") || !fields.contains_key("next_cursor") {
        return Err(invalid("page"));
    }
    let wire: Wire = serde_json::from_slice(input).map_err(|_| Error::InvalidJson)?;
    if wire.items.len() > 500 {
        return Err(invalid("items"));
    }
    Ok((wire.items, wire.next_cursor.map(|text| parse_uuid(&text, "next_cursor")).transpose()?))
}
fn encode_page(
    items: impl Iterator<Item = Result<Vec<u8>, Error>>,
    next: Option<Uuid>,
) -> Result<Vec<u8>, Error> {
    #[derive(Serialize)]
    struct Wire {
        items: Vec<Box<RawValue>>,
        next_cursor: Option<String>,
    }
    let mut wire = Wire { items: Vec::new(), next_cursor: next.map(|id| id.to_string()) };
    let mut bytes = encode(&wire, MAX_GROUP_POLICY_PAGE_BYTES)?.len();
    for item in items {
        let item = item?;
        bytes = bytes
            .checked_add(item.len())
            .and_then(|size| size.checked_add(usize::from(!wire.items.is_empty())))
            .ok_or(Error::TooLarge)?;
        if bytes > MAX_GROUP_POLICY_PAGE_BYTES {
            return Err(Error::TooLarge);
        }
        wire.items.push(
            RawValue::from_string(String::from_utf8(item).map_err(|_| Error::InvalidJson)?)
                .map_err(|_| Error::InvalidJson)?,
        );
    }
    encode(&wire, MAX_GROUP_POLICY_PAGE_BYTES)
}
