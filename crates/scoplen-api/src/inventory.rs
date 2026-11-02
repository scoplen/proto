// SPDX-License-Identifier: Apache-2.0
//! D-137 typed, clock-free Organization inventory projections over the existing K-1 model.
//!
//! Syntax and model validation supply no ownership, reference-read or mutation authority.
//! Consumers bind every response to its captured origin/Organization and recheck references,
//! current authorization, server clocks, receipts and transactions at their own boundary.

use std::{collections::BTreeMap, fmt};

use scoplen_model::{
    FieldEntry, FieldPath, Hlc, MAX_MAP_ENTRIES, MapKey, ModelError, Object, ObjectType,
    cbor::Value as Cbor, validate_uuid_v7,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, value::RawValue};
use uuid::Uuid;

use crate::{
    certificate::{valid_strong_etag, valid_utc_timestamp},
    organization::{
        OrganizationCodecError as Error, OrganizationListQuery, validate_cache_headers,
    },
    request_wire,
};

/// Complete request or individual Resource budget, including whitespace and extensions.
pub const MAX_INVENTORY_RESOURCE_BYTES: usize = 2_097_152;
/// Complete directory Page budget, including each original Resource.
pub const MAX_INVENTORY_PAGE_BYTES: usize = 8_388_608;
/// Maximum live directory items, independently of its encoded byte budget.
pub const MAX_INVENTORY_PAGE_ITEMS: usize = 500;

/// The seven K-1 types supported by Organization authoring routes.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum InventoryType {
    /// Host address and metadata.
    Host,
    /// Host-bound Organization login using the source-bound certificate signer.
    AccessProfile,
    /// Jump, proxy, command or managed route without a Personal credential.
    Route,
    /// Named Host group and defaults.
    HostGroup,
    /// Host key or CA trust record.
    TrustRecord,
    /// Command template and transient variables.
    Snippet,
    /// Organization-managed gateway network metadata.
    GatewayNetwork,
}

impl InventoryType {
    /// Every allowed Organization inventory type, in K-1 registry order.
    pub const ALL: [Self; 7] = [
        Self::Host,
        Self::AccessProfile,
        Self::Route,
        Self::HostGroup,
        Self::TrustRecord,
        Self::Snippet,
        Self::GatewayNetwork,
    ];

    /// Exact collection path segment, without surrounding slashes.
    #[must_use]
    pub const fn segment(self) -> &'static str {
        match self {
            Self::Host => "hosts",
            Self::AccessProfile => "access-profiles",
            Self::Route => "routes",
            Self::HostGroup => "host-groups",
            Self::TrustRecord => "trust-records",
            Self::Snippet => "snippets",
            Self::GatewayNetwork => "gateway-networks",
        }
    }

    /// Parse one exact route segment.
    /// # Errors
    /// Rejects aliases and every non-Organization object type.
    pub fn from_segment(segment: &str) -> Result<Self, Error> {
        Self::ALL.into_iter().find(|kind| kind.segment() == segment).ok_or(invalid("type"))
    }

    /// Corresponding existing K-1 type number.
    #[must_use]
    pub const fn object_type(self) -> ObjectType {
        match self {
            Self::Host => ObjectType::HOST,
            Self::AccessProfile => ObjectType::ACCESS_PROFILE,
            Self::Route => ObjectType::ROUTE,
            Self::HostGroup => ObjectType::HOST_GROUP,
            Self::TrustRecord => ObjectType::TRUST_RECORD,
            Self::Snippet => ObjectType::SNIPPET,
            Self::GatewayNetwork => ObjectType::GATEWAY_NETWORK,
        }
    }

    /// Bind a K-1 object to one of the authoring collections.
    /// # Errors
    /// Rejects Credentials, Forwards, Personal-only and unknown types.
    pub fn from_object_type(kind: ObjectType) -> Result<Self, Error> {
        Self::ALL.into_iter().find(|value| value.object_type() == kind).ok_or(invalid("type"))
    }
}

/// Validated known fields in decomposed K-1 form, without consumer-authored clocks.
/// Empty maps and cleared K-1 entries have the same absent-field projection.
#[derive(Clone, Eq, PartialEq)]
pub struct InventoryFields {
    kind: InventoryType,
    values: BTreeMap<FieldPath, Cbor>,
}

/// A declared resource locator and its required K-1 type, without target read authority.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct InventoryReference {
    /// Expected same-Organization target type.
    pub kind: InventoryType,
    /// Opaque target object `UUIDv7`; callers must independently authorize dereferencing it.
    pub id: Uuid,
}

impl fmt::Debug for InventoryFields {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InventoryFields").field("kind", &self.kind).finish_non_exhaustive()
    }
}

impl InventoryFields {
    /// Decode strictly writable named fields, without the request's `data` envelope.
    /// # Errors
    /// Rejects unknown/read-only fields, nulls, invalid typed values and model overflow.
    pub fn from_json(kind: InventoryType, input: &[u8]) -> Result<Self, Error> {
        Self::parse(kind, object(input, MAX_INVENTORY_RESOURCE_BYTES)?, false)
    }

    /// K-1 type represented by these validated fields.
    #[must_use]
    pub const fn kind(&self) -> InventoryType {
        self.kind
    }

    /// Return only declared resource references, sorted and deduplicated by type/id.
    /// This performs no lookup, closure expansion or ownership/read authorization.
    /// Account/Device attribution and arbitrary UUID-looking text are excluded.
    /// # Errors
    /// Rejects invalid declared resource identifiers, including a malformed default route.
    pub fn references(&self) -> Result<Vec<InventoryReference>, Error> {
        let scalars: &[(u64, InventoryType)] = match self.kind {
            InventoryType::Host => &[(8, InventoryType::AccessProfile)],
            InventoryType::AccessProfile => &[(1, InventoryType::Host), (5, InventoryType::Route)],
            InventoryType::Route => &[(7, InventoryType::GatewayNetwork)],
            InventoryType::HostGroup => &[(2, InventoryType::HostGroup)],
            InventoryType::TrustRecord => &[(1, InventoryType::Host)],
            InventoryType::Snippet | InventoryType::GatewayNetwork => &[],
        };
        let mut result = Vec::new();
        for (field, kind) in scalars {
            if let Some(Cbor::Bytes(value)) = self.values.get(&FieldPath::Field(*field)) {
                result.push(InventoryReference { kind: *kind, id: uuid_from_bytes(value)? });
            }
        }
        if self.kind == InventoryType::Host {
            for path in self.values.keys() {
                if let FieldPath::MapEntry { field: 5, key: MapKey::Bytes(value) } = path {
                    result.push(InventoryReference {
                        kind: InventoryType::HostGroup,
                        id: uuid_from_bytes(value)?,
                    });
                }
            }
        }
        if self.kind == InventoryType::Route
            && let Some(Cbor::Array(values)) = self.values.get(&FieldPath::Field(3))
        {
            for value in values {
                let Cbor::Bytes(value) = value else {
                    return Err(invalid("hops"));
                };
                result.push(InventoryReference {
                    kind: InventoryType::AccessProfile,
                    id: uuid_from_bytes(value)?,
                });
            }
        }
        if self.kind == InventoryType::HostGroup {
            let path = FieldPath::MapEntry { field: 4, key: MapKey::Text("route".into()) };
            if let Some(Cbor::Text(route)) = self.values.get(&path)
                && route != "0"
            {
                result.push(InventoryReference {
                    kind: InventoryType::Route,
                    id: parse_uuid(route)?,
                });
            }
        }
        result.sort_unstable();
        result.dedup();
        Ok(result)
    }

    /// Encode known clock-free fields with canonical named-field and map ordering.
    /// # Errors
    /// Rejects invalid model state or encoded overflow.
    pub fn to_json(&self) -> Result<Vec<u8>, Error> {
        encode(&self.named_fields()?, MAX_INVENTORY_RESOURCE_BYTES)
    }

    /// Add authoritative `TrustRecord` attribution after accepting a strict write request.
    /// This does not authenticate the supplied committing Account/Device or time.
    /// # Errors
    /// Rejects another type, invalid attribution ids or a resulting model overflow.
    pub fn with_trust_attribution(
        mut self,
        accepted_at: u64,
        account: Uuid,
        device: Uuid,
    ) -> Result<Self, Error> {
        if self.kind != InventoryType::TrustRecord {
            return Err(invalid("attribution"));
        }
        uuid(account)?;
        uuid(device)?;
        for (field, value) in
            [(6, Cbor::UInt(accepted_at)), (7, uuid_value(device)), (8, uuid_value(account))]
        {
            self.values.insert(FieldPath::Field(field), value);
        }
        self.validate(true)?;
        Ok(self)
    }

    /// Author a complete schema-one K-1 value with the authenticated writer's server clock.
    /// `TrustRecord` attribution must already be server-assigned and name that same Device.
    /// # Errors
    /// Rejects malformed ids, missing attribution, a different writer or K-1 overflow.
    pub fn to_object(&self, id: Uuid, clock: Hlc, writer: Uuid) -> Result<Object, Error> {
        self.validate(true)?;
        if self.kind == InventoryType::TrustRecord
            && self.values.get(&FieldPath::Field(7)) != Some(&uuid_value(writer))
        {
            return Err(invalid("accepted_by_device"));
        }
        let object = self.model(id, clock, writer)?;
        object.encode().map_err(|error| model_error(&error))?;
        Ok(object)
    }

    /// Project an existing live K-1 object; cleared fields/entries are omitted.
    /// Unknown fields or schemas cannot silently become a complete editable replacement.
    /// # Errors
    /// Rejects deleted/unsupported objects or invalid typed known fields.
    pub fn from_object(object: &Object) -> Result<Self, Error> {
        object.encode().map_err(|error| model_error(&error))?;
        if object.schema != 1 || object.is_tombstoned() {
            return Err(invalid("object"));
        }
        let kind = InventoryType::from_object_type(object.object_type)?;
        for path in object.fields.keys() {
            if !definitions(kind).iter().any(|field| field.number == path.field_number()) {
                return Err(invalid("fields"));
            }
        }
        let value = Self {
            kind,
            values: object
                .fields
                .iter()
                .filter(|(_, entry)| entry.value != Cbor::Null)
                .map(|(path, entry)| (path.clone(), entry.value.clone()))
                .collect(),
        };
        // Reparse the named projection so K-1's broader extensible shapes never bypass this profile.
        Self::parse(kind, value.named_fields()?, true)
    }

    fn parse(
        kind: InventoryType,
        mut fields: Map<String, Value>,
        response: bool,
    ) -> Result<Self, Error> {
        let mut values = BTreeMap::new();
        for field in definitions(kind) {
            let Some(value) = fields.remove(field.name) else {
                continue;
            };
            if field.read_only && !response {
                return Err(invalid("read-only fields"));
            }
            match field.shape {
                Shape::TextMap | Shape::UuidSet | Shape::TextSet | Shape::Variables => {
                    parse_map(field, value, &mut values)?;
                }
                shape => {
                    values.insert(FieldPath::Field(field.number), parse_scalar(shape, value)?);
                }
            }
        }
        if !fields.is_empty() {
            return Err(invalid("fields"));
        }
        let value = Self { kind, values };
        value.validate(response)?;
        Ok(value)
    }

    fn validate(&self, response: bool) -> Result<(), Error> {
        let id = Uuid::from_u128(0x0000_0000_0000_7000_8000_0000_0000_0000);
        // Requests do not supply the committing clock. Reject impossible payloads here;
        // to_object checks the exact budget again with the authoritative clock and writer.
        let model = self.model(id, Hlc::from_wire(0).map_err(|_| invalid("clock"))?, id)?;
        model.encode().map_err(|error| model_error(&error))?;
        if !response
            && definitions(self.kind).iter().any(|field| {
                field.read_only && self.values.contains_key(&FieldPath::Field(field.number))
            })
        {
            return Err(invalid("read-only fields"));
        }
        if self.kind == InventoryType::TrustRecord {
            if response && (6..=8).any(|field| !self.values.contains_key(&FieldPath::Field(field)))
            {
                return Err(invalid("attribution"));
            }
            validate_trust(&model)?;
        }
        if self.kind == InventoryType::HostGroup {
            let path = FieldPath::MapEntry { field: 4, key: MapKey::Text("credential".into()) };
            if self.values.contains_key(&path) {
                return Err(invalid("defaults.credential"));
            }
        }
        self.references()?;
        Ok(())
    }

    fn model(&self, id: Uuid, clock: Hlc, writer: Uuid) -> Result<Object, Error> {
        uuid(id)?;
        uuid(writer)?;
        let mut object =
            Object::new(id, self.kind.object_type(), 1).map_err(|error| model_error(&error))?;
        object.fields = self
            .values
            .iter()
            .map(|(path, value)| {
                (path.clone(), FieldEntry { value: value.clone(), clock, origin: writer })
            })
            .collect();
        Ok(object)
    }

    fn named_fields(&self) -> Result<Map<String, Value>, Error> {
        let mut result = Map::new();
        for field in definitions(self.kind) {
            match field.shape {
                Shape::TextMap | Shape::UuidSet | Shape::TextSet | Shape::Variables => {
                    let mut entries = Map::new();
                    for (path, value) in &self.values {
                        if let FieldPath::MapEntry { field: number, key } = path
                            && *number == field.number
                        {
                            let key = match key {
                                MapKey::Text(text) => text.clone(),
                                MapKey::Bytes(bytes) => uuid_from_bytes(bytes)?.to_string(),
                            };
                            let value = if matches!(field.shape, Shape::Variables) {
                                encode_variable(value)?
                            } else {
                                encode_scalar(value, false)?
                            };
                            entries.insert(key, value);
                        }
                    }
                    if !entries.is_empty() {
                        entries.sort_keys();
                        result.insert(field.name.into(), Value::Object(entries));
                    }
                }
                shape => {
                    if let Some(value) = self.values.get(&FieldPath::Field(field.number)) {
                        result.insert(
                            field.name.into(),
                            encode_scalar(value, matches!(shape, Shape::DecimalU64))?,
                        );
                    }
                }
            }
        }
        result.sort_keys();
        Ok(result)
    }
}

/// Strict `POST /orgs/{org}/{type}` desired fields and caller-created immutable id.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InventoryCreateRequest {
    /// New object `UUIDv7`, also included in the canonical receipt binding.
    pub id: Uuid,
    /// Complete typed mutable desired state.
    pub fields: InventoryFields,
}

impl InventoryCreateRequest {
    /// Decode strict creation JSON for the captured route's type.
    /// # Errors
    /// Rejects duplicate, unknown, read-only or malformed fields and overflow.
    pub fn from_json(kind: InventoryType, input: &[u8]) -> Result<Self, Error> {
        let mut fields = object(input, MAX_INVENTORY_RESOURCE_BYTES)?;
        let id = take_uuid(&mut fields, "id")?;
        let data = write_data(&mut fields, kind)?;
        Ok(Self { id, fields: data })
    }

    /// Canonical complete creation payload for original-operation receipt binding.
    /// # Errors
    /// Rejects invalid public fields, attribution or overflow.
    pub fn to_json(&self) -> Result<Vec<u8>, Error> {
        #[derive(Serialize)]
        struct Wire {
            id: String,
            data: Value,
        }
        uuid(self.id)?;
        self.fields.validate(false)?;
        encode(
            &Wire { id: self.id.to_string(), data: data(&self.fields, false)? },
            MAX_INVENTORY_RESOURCE_BYTES,
        )
    }
}

/// Strict complete `PUT` replacement; optional fields absent here are removed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InventoryReplaceRequest {
    /// Complete typed mutable desired state, not field-clock patches.
    pub fields: InventoryFields,
}

impl InventoryReplaceRequest {
    /// Decode the exact replacement envelope for its captured type route.
    /// # Errors
    /// Rejects unknown, read-only, null or malformed fields and overflow.
    pub fn from_json(kind: InventoryType, input: &[u8]) -> Result<Self, Error> {
        let mut fields = object(input, MAX_INVENTORY_RESOURCE_BYTES)?;
        Ok(Self { fields: write_data(&mut fields, kind)? })
    }

    /// Canonical complete replacement with no immutable id, schema or writer metadata.
    /// # Errors
    /// Rejects attribution or overflow.
    pub fn to_json(&self) -> Result<Vec<u8>, Error> {
        #[derive(Serialize)]
        struct Wire {
            data: Value,
        }
        self.fields.validate(false)?;
        encode(&Wire { data: data(&self.fields, false)? }, MAX_INVENTORY_RESOURCE_BYTES)
    }
}

/// One complete authorized schema-one Resource. It contains no Organization ownership proof.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InventoryResource {
    /// Immutable object `UUIDv7`.
    pub id: Uuid,
    /// Strong current JSON entity tag.
    pub etag: String,
    /// UTC creation timestamp.
    pub created_at: String,
    /// UTC last content update timestamp.
    pub updated_at: String,
    /// Complete typed fields including server-owned `TrustRecord` attribution.
    pub fields: InventoryFields,
}

impl InventoryResource {
    /// Recheck syntax and complete current-profile model fields.
    /// # Errors
    /// Rejects malformed metadata, missing attribution or invalid model state.
    pub fn validate(&self) -> Result<(), Error> {
        uuid(self.id)?;
        if !valid_strong_etag(&self.etag) {
            return Err(invalid("etag"));
        }
        if !valid_utc_timestamp(&self.created_at) || !valid_utc_timestamp(&self.updated_at) {
            return Err(invalid("timestamp"));
        }
        self.fields.validate(true)
    }

    /// Bind a parsed individual response to its captured route and requested object id.
    /// # Errors
    /// Rejects another object or collection's response.
    pub fn validate_for_request(&self, kind: InventoryType, id: Uuid) -> Result<(), Error> {
        self.validate()?;
        uuid(id)?;
        if self.fields.kind != kind || self.id != id {
            return Err(Error::Context);
        }
        Ok(())
    }

    /// Parse the bounded Resource, ignoring envelope/data extensions after duplicate checks.
    /// Unknown model fields or future schemas cannot become writable replacements.
    /// # Errors
    /// Rejects invalid required data, duplicate names or overflow.
    pub fn from_json(kind: InventoryType, input: &[u8]) -> Result<Self, Error> {
        let mut fields = object(input, MAX_INVENTORY_RESOURCE_BYTES)?;
        let id = take_uuid(&mut fields, "id")?;
        let etag = take_text(&mut fields, "etag")?;
        let created_at = take_text(&mut fields, "created_at")?;
        let updated_at = take_text(&mut fields, "updated_at")?;
        let mut data = take_object(&mut fields, "data")?;
        if data.remove("schema").and_then(|value| value.as_u64()) != Some(1) {
            return Err(invalid("schema"));
        }
        let fields = InventoryFields::parse(kind, take_object(&mut data, "fields")?, true)?;
        let value = Self { id, etag, created_at, updated_at, fields };
        value.validate()?;
        Ok(value)
    }

    /// Parse an individual response with exact body/header `ETag` and cache prevention.
    /// Transport owns HTTP status/content type/request-id and source authority.
    /// # Errors
    /// Rejects invalid body, mismatched `ETag` or cache headers.
    pub fn from_http_json(
        kind: InventoryType,
        input: &[u8],
        etag: Option<&str>,
        cache_control: Option<&str>,
        pragma: Option<&str>,
    ) -> Result<Self, Error> {
        let value = Self::from_json(kind, input)?;
        if etag != Some(value.etag.as_str()) {
            return Err(Error::HttpMetadata);
        }
        validate_cache_headers(cache_control, pragma)?;
        Ok(value)
    }

    /// Encode standard Resource order with schema-one data and no response extensions.
    /// # Errors
    /// Rejects invalid public fields or complete body overflow.
    pub fn to_json(&self) -> Result<Vec<u8>, Error> {
        #[derive(Serialize)]
        struct Wire<'a> {
            id: String,
            etag: &'a str,
            created_at: &'a str,
            updated_at: &'a str,
            data: Value,
        }
        self.validate()?;
        encode(
            &Wire {
                id: self.id.to_string(),
                etag: &self.etag,
                created_at: &self.created_at,
                updated_at: &self.updated_at,
                data: data(&self.fields, true)?,
            },
            MAX_INVENTORY_RESOURCE_BYTES,
        )
    }
}

/// Live ascending directory, distinct from atomic revision-bound Organization sync.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InventoryPage {
    /// Collection captured from the original request, omitted from wire JSON.
    pub kind: InventoryType,
    /// Complete independently authorized Resources of this type.
    pub items: Vec<InventoryResource>,
    /// Last returned eligible id only when further eligible items exist.
    pub next_cursor: Option<Uuid>,
}

impl InventoryPage {
    /// Recheck collection binding, strict ordering and continuation.
    /// # Errors
    /// Rejects mixed types, duplicate/out-of-order ids, invalid Resources or continuation.
    pub fn validate(&self) -> Result<(), Error> {
        if self.items.len() > MAX_INVENTORY_PAGE_ITEMS {
            return Err(invalid("items"));
        }
        for item in &self.items {
            item.validate()?;
            if item.fields.kind != self.kind {
                return Err(Error::Context);
            }
        }
        if self.items.windows(2).any(|pair| pair[0].id >= pair[1].id) {
            return Err(invalid("items"));
        }
        if let Some(cursor) = self.next_cursor {
            uuid(cursor)?;
            if self.items.last().map(|item| item.id) != Some(cursor) {
                return Err(invalid("next_cursor"));
            }
        }
        Ok(())
    }

    /// Bind the live page to its captured collection and original continuation.
    /// # Errors
    /// Rejects foreign types, excess item count or earlier/repeated ids.
    pub fn validate_for_request(
        &self,
        kind: InventoryType,
        query: OrganizationListQuery,
    ) -> Result<(), Error> {
        self.validate()?;
        query.validate()?;
        if self.kind != kind
            || self.items.len() > usize::from(query.limit)
            || self.items.iter().any(|item| query.cursor.is_some_and(|cursor| item.id <= cursor))
        {
            return Err(Error::Context);
        }
        Ok(())
    }

    /// Parse the whole Page and each original Resource's own encoded byte limit.
    /// # Errors
    /// Rejects duplicate names, invalid metadata, ordering or either byte budget.
    pub fn from_json(kind: InventoryType, input: &[u8]) -> Result<Self, Error> {
        #[derive(Deserialize)]
        struct Wire {
            items: Vec<Box<RawValue>>,
            next_cursor: Option<String>,
        }
        let fields = object(input, MAX_INVENTORY_PAGE_BYTES)?;
        if !fields.contains_key("items") || !fields.contains_key("next_cursor") {
            return Err(invalid("page"));
        }
        let raw: Wire = serde_json::from_slice(input).map_err(|_| Error::InvalidJson)?;
        if raw.items.len() > MAX_INVENTORY_PAGE_ITEMS {
            return Err(invalid("items"));
        }
        let items = raw
            .items
            .iter()
            .map(|item| InventoryResource::from_json(kind, item.get().as_bytes()))
            .collect::<Result<Vec<_>, _>>()?;
        let next_cursor = raw.next_cursor.map(|text| parse_uuid(&text)).transpose()?;
        let value = Self { kind, items, next_cursor };
        value.validate()?;
        Ok(value)
    }

    /// Parse a no-store directory response.
    /// # Errors
    /// Rejects invalid body or cache metadata.
    pub fn from_http_json(
        kind: InventoryType,
        input: &[u8],
        cache_control: Option<&str>,
        pragma: Option<&str>,
    ) -> Result<Self, Error> {
        validate_cache_headers(cache_control, pragma)?;
        Self::from_json(kind, input)
    }

    /// Encode individually bounded Resources in standard page order.
    /// # Errors
    /// Rejects invalid public state or encoded page overflow.
    pub fn to_json(&self) -> Result<Vec<u8>, Error> {
        #[derive(Serialize)]
        struct Wire {
            items: Vec<Box<RawValue>>,
            next_cursor: Option<String>,
        }
        self.validate()?;
        let next_cursor = self.next_cursor.map(|id| id.to_string());
        let mut size = encode(
            &Wire { items: Vec::new(), next_cursor: next_cursor.clone() },
            MAX_INVENTORY_PAGE_BYTES,
        )?
        .len();
        let mut items = Vec::new();
        for item in &self.items {
            let encoded = item.to_json()?;
            size = size
                .checked_add(encoded.len())
                .and_then(|size| size.checked_add(usize::from(!items.is_empty())))
                .filter(|size| *size <= MAX_INVENTORY_PAGE_BYTES)
                .ok_or(Error::TooLarge)?;
            let text = String::from_utf8(encoded).map_err(|_| Error::InvalidJson)?;
            items.push(RawValue::from_string(text).map_err(|_| Error::InvalidJson)?);
        }
        encode(&Wire { items, next_cursor }, MAX_INVENTORY_PAGE_BYTES)
    }
}

#[derive(Clone, Copy)]
enum Shape {
    Text,
    Uuid,
    UInt(u64, u64),
    Bool,
    Route,
    Uuids,
    TextMap,
    UuidSet,
    TextSet,
    Variables,
    DecimalU64,
}

struct Definition {
    number: u64,
    name: &'static str,
    shape: Shape,
    read_only: bool,
}

const fn field(number: u64, name: &'static str, shape: Shape) -> Definition {
    Definition { number, name, shape, read_only: false }
}

const HOST_FIELDS: &[Definition] = &[
    field(1, "name", Shape::Text),
    field(2, "address", Shape::Text),
    field(3, "port", Shape::UInt(1, 65_535)),
    field(4, "tags", Shape::TextMap),
    field(5, "groups", Shape::UuidSet),
    field(6, "favorite", Shape::Bool),
    field(7, "notes", Shape::Text),
    field(8, "default_profile", Shape::Uuid),
    field(9, "ssh_options", Shape::TextMap),
    field(10, "mosh", Shape::TextMap),
];

const ACCESS_PROFILE_FIELDS: &[Definition] = &[
    field(1, "host", Shape::Uuid),
    field(2, "name", Shape::Text),
    field(3, "username", Shape::Text),
    field(5, "route", Shape::Route),
    field(6, "terminal_profile", Shape::Text),
    field(7, "startup_command", Shape::Text),
    field(9, "agent_forwarding", Shape::Bool),
];

const ROUTE_FIELDS: &[Definition] = &[
    field(1, "name", Shape::Text),
    field(2, "kind", Shape::UInt(1, 5)),
    field(3, "hops", Shape::Uuids),
    field(4, "proxy", Shape::Text),
    field(6, "command", Shape::Text),
    field(7, "gateway_network", Shape::Uuid),
    field(8, "proxy_username", Shape::Text),
];

const HOST_GROUP_FIELDS: &[Definition] = &[
    field(1, "name", Shape::Text),
    field(2, "parent", Shape::Uuid),
    field(3, "color", Shape::Text),
    field(4, "defaults", Shape::TextMap),
];

const TRUST_RECORD_FIELDS: &[Definition] = &[
    field(1, "host", Shape::Uuid),
    field(2, "pattern", Shape::Text),
    field(3, "key", Shape::Text),
    field(4, "fingerprint", Shape::Text),
    field(5, "provenance", Shape::UInt(1, 4)),
    Definition { number: 6, name: "accepted_at", shape: Shape::DecimalU64, read_only: true },
    Definition { number: 7, name: "accepted_by_device", shape: Shape::Uuid, read_only: true },
    Definition { number: 8, name: "accepted_by_account", shape: Shape::Uuid, read_only: true },
    field(9, "revoked", Shape::Bool),
    field(10, "ca", Shape::Bool),
];

const SNIPPET_FIELDS: &[Definition] = &[
    field(1, "name", Shape::Text),
    field(2, "template", Shape::Text),
    field(3, "variables", Shape::Variables),
    field(4, "tags", Shape::TextSet),
    field(5, "folder", Shape::Text),
];

const GATEWAY_NETWORK_FIELDS: &[Definition] =
    &[field(1, "name", Shape::Text), field(2, "description", Shape::Text)];

fn definitions(kind: InventoryType) -> &'static [Definition] {
    match kind {
        InventoryType::Host => HOST_FIELDS,
        InventoryType::AccessProfile => ACCESS_PROFILE_FIELDS,
        InventoryType::Route => ROUTE_FIELDS,
        InventoryType::HostGroup => HOST_GROUP_FIELDS,
        InventoryType::TrustRecord => TRUST_RECORD_FIELDS,
        InventoryType::Snippet => SNIPPET_FIELDS,
        InventoryType::GatewayNetwork => GATEWAY_NETWORK_FIELDS,
    }
}

fn parse_map(
    field: &Definition,
    value: Value,
    target: &mut BTreeMap<FieldPath, Cbor>,
) -> Result<(), Error> {
    let Value::Object(entries) = value else {
        return Err(invalid("map"));
    };
    if entries.len() > MAX_MAP_ENTRIES {
        return Err(invalid("map"));
    }
    for (key, value) in entries {
        let key = if matches!(field.shape, Shape::UuidSet) {
            MapKey::Bytes(parse_uuid(&key)?.into_bytes().to_vec())
        } else {
            MapKey::Text(key)
        };
        let value = match field.shape {
            Shape::TextMap => parse_scalar(Shape::Text, value)?,
            Shape::UuidSet | Shape::TextSet if value == Value::Bool(true) => Cbor::Bool(true),
            Shape::Variables => parse_variable(value)?,
            _ => return Err(invalid("map")),
        };
        target.insert(FieldPath::MapEntry { field: field.number, key }, value);
    }
    Ok(())
}

fn parse_scalar(shape: Shape, value: Value) -> Result<Cbor, Error> {
    match (shape, value) {
        (Shape::Text, Value::String(value)) => Ok(Cbor::Text(value)),
        (Shape::Uuid | Shape::Route, Value::String(value)) => Ok(uuid_value(parse_uuid(&value)?)),
        (Shape::Route, Value::Number(value)) if value.as_u64() == Some(0) => Ok(Cbor::UInt(0)),
        (Shape::UInt(min, max), Value::Number(value)) => value
            .as_u64()
            .filter(|v| (min..=max).contains(v))
            .map(Cbor::UInt)
            .ok_or(invalid("integer")),
        (Shape::DecimalU64, Value::String(text)) => text
            .parse::<u64>()
            .ok()
            .filter(|value| value.to_string() == text)
            .map(Cbor::UInt)
            .ok_or(invalid("accepted_at")),
        (Shape::Bool, Value::Bool(value)) => Ok(Cbor::Bool(value)),
        (Shape::Uuids, Value::Array(values)) => values
            .into_iter()
            .map(|value| parse_scalar(Shape::Uuid, value))
            .collect::<Result<Vec<_>, _>>()
            .map(Cbor::Array),
        _ => Err(invalid("field value")),
    }
}

fn parse_variable(value: Value) -> Result<Cbor, Error> {
    let Value::Object(mut fields) = value else {
        return Err(invalid("variable"));
    };
    let kind = fields
        .remove("kind")
        .and_then(|value| value.as_u64())
        .filter(|kind| (1..=4).contains(kind))
        .ok_or(invalid("variable.kind"))?;
    let default = fields.remove("default");
    let choices = fields.remove("choices");
    if !fields.is_empty() {
        return Err(invalid("variable"));
    }
    let mut result = vec![(Cbor::UInt(1), Cbor::UInt(kind))];
    let parsed_choices = if kind == 3 {
        let Some(Value::Array(values)) = choices else {
            return Err(invalid("variable.choices"));
        };
        if values.is_empty() || values.len() > MAX_MAP_ENTRIES {
            return Err(invalid("variable.choices"));
        }
        let values = values
            .into_iter()
            .map(|value| parse_scalar(Shape::Text, value))
            .collect::<Result<Vec<_>, _>>()?;
        let mut sorted = values
            .iter()
            .map(|value| match value {
                Cbor::Text(text) => Ok(text),
                _ => Err(invalid("variable.choices")),
            })
            .collect::<Result<Vec<_>, _>>()?;
        sorted.sort_unstable();
        if sorted.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(invalid("variable.choices"));
        }
        Some(values)
    } else {
        if choices.is_some() {
            return Err(invalid("variable.choices"));
        }
        None
    };
    if let Some(default) = default {
        let value = match (kind, default) {
            (1 | 3, Value::String(value)) => Cbor::Text(value),
            (2, Value::String(value)) => {
                let parsed = value.parse::<i64>().map_err(|_| invalid("variable.default"))?;
                if parsed.to_string() != value {
                    return Err(invalid("variable.default"));
                }
                if parsed < 0 {
                    Cbor::Int(i128::from(parsed))
                } else {
                    Cbor::UInt(parsed.unsigned_abs())
                }
            }
            _ => return Err(invalid("variable.default")),
        };
        if parsed_choices.as_ref().is_some_and(|choices| !choices.contains(&value)) {
            return Err(invalid("variable.default"));
        }
        result.push((Cbor::UInt(2), value));
    }
    if let Some(choices) = parsed_choices {
        result.push((Cbor::UInt(3), Cbor::Array(choices)));
    }
    Ok(Cbor::Map(result))
}

fn encode_scalar(value: &Cbor, decimal: bool) -> Result<Value, Error> {
    match value {
        Cbor::Text(value) => Ok(Value::String(value.clone())),
        Cbor::UInt(value) if decimal => Ok(Value::String(value.to_string())),
        Cbor::UInt(value) => Ok(Value::from(*value)),
        Cbor::Bool(value) => Ok(Value::Bool(*value)),
        Cbor::Bytes(value) => Ok(Value::String(uuid_from_bytes(value)?.to_string())),
        Cbor::Array(values) => values
            .iter()
            .map(|value| encode_scalar(value, false))
            .collect::<Result<Vec<_>, _>>()
            .map(Value::Array),
        _ => Err(invalid("field value")),
    }
}

fn encode_variable(value: &Cbor) -> Result<Value, Error> {
    let Cbor::Map(entries) = value else {
        return Err(invalid("variable"));
    };
    let kind = entries
        .iter()
        .find_map(|(key, value)| if key == &Cbor::UInt(1) { Some(value) } else { None });
    let mut result = Map::new();
    for (key, value) in entries {
        let (name, value) = match key {
            Cbor::UInt(1) => ("kind", encode_scalar(value, false)?),
            Cbor::UInt(2) if kind == Some(&Cbor::UInt(2)) => (
                "default",
                Value::String(match value {
                    Cbor::UInt(value) if *value <= i64::MAX.unsigned_abs() => value.to_string(),
                    Cbor::Int(value) if *value >= i128::from(i64::MIN) && *value < 0 => {
                        value.to_string()
                    }
                    _ => return Err(invalid("variable.default")),
                }),
            ),
            Cbor::UInt(2) => ("default", encode_scalar(value, false)?),
            Cbor::UInt(3) => ("choices", encode_scalar(value, false)?),
            _ => return Err(invalid("variable")),
        };
        if result.insert(name.into(), value).is_some() {
            return Err(invalid("variable"));
        }
    }
    // The request parser enforces kind/default/choices relationships and rejects unknown keys.
    parse_variable(Value::Object(result.clone()))?;
    result.sort_keys();
    Ok(Value::Object(result))
}

fn validate_trust(object: &Object) -> Result<(), Error> {
    let key = object
        .optional_text(3)
        .map_err(|_| invalid("key"))?
        .map(ssh_key::PublicKey::from_openssh)
        .transpose()
        .map_err(|_| invalid("key"))?;
    if let Some(fingerprint) = object.optional_text(4).map_err(|_| invalid("fingerprint"))? {
        let key = key.ok_or(invalid("fingerprint"))?;
        if key.fingerprint(ssh_key::HashAlg::Sha256).to_string() != fingerprint {
            return Err(invalid("fingerprint"));
        }
    }
    Ok(())
}

fn write_data(
    fields: &mut Map<String, Value>,
    kind: InventoryType,
) -> Result<InventoryFields, Error> {
    let mut data = take_object(fields, "data")?;
    let value = InventoryFields::parse(kind, take_object(&mut data, "fields")?, false)?;
    if !fields.is_empty() || !data.is_empty() {
        return Err(invalid("request members"));
    }
    Ok(value)
}

fn data(fields: &InventoryFields, response: bool) -> Result<Value, Error> {
    let mut result = Map::new();
    result.insert("fields".into(), Value::Object(fields.named_fields()?));
    if response {
        result.insert("schema".into(), Value::from(1));
    }
    Ok(Value::Object(result))
}

fn object(input: &[u8], max: usize) -> Result<Map<String, Value>, Error> {
    if input.len() > max {
        return Err(Error::TooLarge);
    }
    request_wire::decode_unique_object(input).map_err(|()| Error::InvalidJson)
}

fn encode(value: &impl Serialize, max: usize) -> Result<Vec<u8>, Error> {
    let encoded = serde_json::to_vec(value).map_err(|_| Error::InvalidJson)?;
    if encoded.len() > max {
        return Err(Error::TooLarge);
    }
    Ok(encoded)
}

fn take_object(
    fields: &mut Map<String, Value>,
    name: &'static str,
) -> Result<Map<String, Value>, Error> {
    match fields.remove(name) {
        Some(Value::Object(fields)) => Ok(fields),
        _ => Err(invalid(name)),
    }
}

fn take_text(fields: &mut Map<String, Value>, name: &'static str) -> Result<String, Error> {
    match fields.remove(name) {
        Some(Value::String(value)) => Ok(value),
        _ => Err(invalid(name)),
    }
}

fn take_uuid(fields: &mut Map<String, Value>, name: &'static str) -> Result<Uuid, Error> {
    parse_uuid(&take_text(fields, name)?)
}

fn parse_uuid(text: &str) -> Result<Uuid, Error> {
    let value = Uuid::parse_str(text).map_err(|_| invalid("uuid"))?;
    uuid(value)?;
    if value.to_string() != text {
        return Err(invalid("uuid"));
    }
    Ok(value)
}

fn uuid(value: Uuid) -> Result<(), Error> {
    validate_uuid_v7(value).map_err(|_| invalid("uuid"))
}
fn uuid_value(value: Uuid) -> Cbor {
    Cbor::Bytes(value.into_bytes().to_vec())
}
fn uuid_from_bytes(bytes: &[u8]) -> Result<Uuid, Error> {
    let value = Uuid::from_slice(bytes).map_err(|_| invalid("uuid"))?;
    uuid(value)?;
    Ok(value)
}
fn invalid(field: &'static str) -> Error {
    Error::InvalidField(field)
}
fn model_error(error: &ModelError) -> Error {
    if matches!(error, ModelError::ObjectLimit) { Error::TooLarge } else { invalid("fields") }
}
