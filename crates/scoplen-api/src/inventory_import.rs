// SPDX-License-Identifier: Apache-2.0
//! Bounded D-151 CSV/D-153 OpenSSH preparation and atomic Organization inventory batch wire.
//! Parsing supplies neither current authority nor receipt/commit evidence.

mod openssh;
pub mod reference;

pub use openssh::*;

use std::{collections::BTreeSet, fmt};

use serde::Serialize;
use serde_json::{Map, Value, json};
use uuid::Uuid;

use crate::{
    inventory::{InventoryCreateRequest, InventoryFields, InventoryType},
    organization::{
        OrganizationCodecError as Error, encode, object, take_string, take_uuid, valid_uuid,
        validate_cache_headers,
    },
};

/// Complete original CSV input bound, including an optional leading BOM.
pub const MAX_INVENTORY_CSV_BYTES: usize = 1_048_576;
/// Complete original JSON request bound, including whitespace.
pub const MAX_INVENTORY_IMPORT_REQUEST_BYTES: usize = 2_097_152;
/// Complete JSON result bound, including ignored response extensions.
pub const MAX_INVENTORY_IMPORT_RESULT_BYTES: usize = 32_768;
/// Maximum ordered Host/default-Login pairs in one atomic operation.
pub const MAX_INVENTORY_IMPORT_ROWS: usize = 100;
/// Original-operation confirmation window.
pub const INVENTORY_IMPORT_RECEIPT_SECONDS: u64 = 86_400;

const HEADER: [&str; 5] = ["name", "address", "port", "username", "login_name"];

/// Prepared nonsecret fields, without newly allocated object identities.
#[derive(Clone, Eq, PartialEq, Serialize)]
pub struct InventoryImportFields {
    /// Exact nonempty Host name.
    pub name: String,
    /// Exact nonempty Host address, with no DNS lookup.
    pub address: String,
    /// Direct SSH port, 1 through 65535.
    pub port: u16,
    /// Exact nonempty Login username.
    pub username: String,
    /// Optional nonempty Login display name; absence remains absence.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub login_name: Option<String>,
}

impl fmt::Debug for InventoryImportFields {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InventoryImportFields").finish_non_exhaustive()
    }
}

impl InventoryImportFields {
    /// Validate the same nonempty, NFC and K-1 limits for CSV and direct JSON rows.
    /// # Errors
    /// Rejects invalid text, empty present fields, port or complete typed objects.
    pub fn validate(&self) -> Result<(), Error> {
        for (name, value, kind, target) in [
            ("name", &self.name, InventoryType::Host, "name"),
            ("address", &self.address, InventoryType::Host, "address"),
            ("username", &self.username, InventoryType::AccessProfile, "username"),
        ] {
            validate_cell(name, value, kind, target)?;
        }
        if let Some(name) = &self.login_name {
            validate_cell("login_name", name, InventoryType::AccessProfile, "name")?;
        }
        if self.port == 0 {
            return Err(Error::InvalidField("port"));
        }
        Ok(())
    }

    fn from_value(fields: &mut Map<String, Value>) -> Result<Self, Error> {
        let port = fields
            .remove("port")
            .and_then(|value| value.as_u64())
            .and_then(|value| u16::try_from(value).ok())
            .ok_or(Error::InvalidField("port"))?;
        let login_name = fields
            .remove("login_name")
            .map(|value| value.as_str().map(str::to_owned).ok_or(Error::InvalidField("login_name")))
            .transpose()?;
        let result = Self {
            name: take_string(fields, "name")?,
            address: take_string(fields, "address")?,
            port,
            username: take_string(fields, "username")?,
            login_name,
        };
        if !fields.is_empty() {
            return Err(Error::InvalidField("row members"));
        }
        result.validate()?;
        Ok(result)
    }
}

fn validate_cell(
    field: &'static str,
    value: &str,
    kind: InventoryType,
    target: &str,
) -> Result<(), Error> {
    if value.is_empty() {
        return Err(Error::InvalidField(field));
    }
    // The existing K-1 codec supplies the text/NFC limit. Required companion fields
    // are supplied only to exercise that same public validator, never persisted.
    let mut fields = match kind {
        InventoryType::Host => json!({"name":"x","address":"x"}),
        _ => json!({"host":"00000000-0000-7000-8000-000000000000","username":"x"}),
    };
    fields[target] = json!(value);
    InventoryFields::from_json(kind, &serde_json::to_vec(&fields).map_err(|_| Error::InvalidJson)?)
        .map(drop)
        .map_err(|_| Error::InvalidField(field))
}

/// One ordered pair of new immutable object identities and reviewed fields.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InventoryImportRow {
    /// Newly allocated Host `UUIDv7`.
    pub host_id: Uuid,
    /// Newly allocated default `AccessProfile` `UUIDv7`.
    pub access_profile_id: Uuid,
    /// Complete initial Direct fields.
    pub fields: InventoryImportFields,
}

impl InventoryImportRow {
    /// Convert to existing typed creates in Host-then-Login order.
    /// # Errors
    /// Rejects invalid ids, fields, K-1 reference syntax or complete-object overflow.
    pub fn inventory_creates(
        &self,
    ) -> Result<(InventoryCreateRequest, InventoryCreateRequest), Error> {
        valid_uuid(self.host_id, "host_id")?;
        valid_uuid(self.access_profile_id, "access_profile_id")?;
        if self.host_id == self.access_profile_id {
            return Err(Error::InvalidField("object ids"));
        }
        self.fields.validate()?;
        let host = json!({"name":self.fields.name,"address":self.fields.address,"port":self.fields.port,"default_profile":self.access_profile_id.to_string()});
        let mut login =
            json!({"host":self.host_id.to_string(),"username":self.fields.username,"route":0});
        if let Some(name) = &self.fields.login_name {
            login["name"] = json!(name);
        }
        let create = |id, kind, fields| {
            Ok(InventoryCreateRequest {
                id,
                fields: InventoryFields::from_json(
                    kind,
                    &serde_json::to_vec(&fields).map_err(|_| Error::InvalidJson)?,
                )?,
            })
        };
        Ok((
            create(self.host_id, InventoryType::Host, host)?,
            create(self.access_profile_id, InventoryType::AccessProfile, login)?,
        ))
    }
}

#[derive(Serialize)]
struct RowWire<'a> {
    #[serde(serialize_with = "serialize_uuid")]
    host_id: Uuid,
    #[serde(serialize_with = "serialize_uuid")]
    access_profile_id: Uuid,
    #[serde(flatten)]
    fields: &'a InventoryImportFields,
}

/// One synchronous atomic creation intent. It has no job identity or polling state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InventoryImportRequest {
    /// Original reviewed order; never sorted or deduplicated by endpoint/name.
    pub rows: Vec<InventoryImportRow>,
}

impl InventoryImportRequest {
    /// Validate every pair and all 2*N distinct identities.
    /// # Errors
    /// Rejects empty/over-limit rows, repeated ids or invalid fields/objects.
    pub fn validate(&self) -> Result<(), Error> {
        if self.rows.is_empty() || self.rows.len() > MAX_INVENTORY_IMPORT_ROWS {
            return Err(Error::InvalidField("rows"));
        }
        let mut ids = BTreeSet::new();
        for row in &self.rows {
            row.inventory_creates()?;
            if !ids.insert(row.host_id) || !ids.insert(row.access_profile_id) {
                return Err(Error::InvalidField("object ids"));
            }
        }
        Ok(())
    }

    /// Decode the strict flat typed request, rejecting recursive duplicate names.
    /// # Errors
    /// Rejects unknown/null fields, integer aliases, invalid ids or complete overflow.
    pub fn from_json(input: &[u8]) -> Result<Self, Error> {
        let mut fields = object(input, MAX_INVENTORY_IMPORT_REQUEST_BYTES)?;
        let rows = fields
            .remove("rows")
            .and_then(|value| value.as_array().cloned())
            .ok_or(Error::InvalidField("rows"))?;
        if !fields.is_empty() || rows.is_empty() || rows.len() > MAX_INVENTORY_IMPORT_ROWS {
            return Err(Error::InvalidField("rows"));
        }
        let rows = rows
            .into_iter()
            .map(|value| {
                let mut fields = value.as_object().cloned().ok_or(Error::InvalidField("row"))?;
                Ok(InventoryImportRow {
                    host_id: take_uuid(&mut fields, "host_id")?,
                    access_profile_id: take_uuid(&mut fields, "access_profile_id")?,
                    fields: InventoryImportFields::from_value(&mut fields)?,
                })
            })
            .collect::<Result<_, Error>>()?;
        let result = Self { rows };
        result.validate()?;
        Ok(result)
    }

    /// Canonical typed rows for original-operation receipt binding.
    /// # Errors
    /// Rejects invalid mutable fields or complete encoded overflow.
    pub fn to_json(&self) -> Result<Vec<u8>, Error> {
        #[derive(Serialize)]
        struct Wire<'a> {
            rows: Vec<RowWire<'a>>,
        }
        self.validate()?;
        let rows = self
            .rows
            .iter()
            .map(|row| RowWire {
                host_id: row.host_id,
                access_profile_id: row.access_profile_id,
                fields: &row.fields,
            })
            .collect();
        encode(&Wire { rows }, MAX_INVENTORY_IMPORT_REQUEST_BYTES)
    }
}

/// Original Host/default-Login identities, without current Resource contents.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct InventoryImportPair {
    /// Original Host `UUIDv7`.
    #[serde(serialize_with = "serialize_uuid")]
    pub host_id: Uuid,
    /// Original default `AccessProfile` `UUIDv7`.
    #[serde(serialize_with = "serialize_uuid")]
    pub access_profile_id: Uuid,
}

fn serialize_uuid<S: serde::Serializer>(id: &Uuid, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&id.to_string())
}

/// Ordered confirmed identities. Syntax alone is not request-bound success evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InventoryImportResult {
    /// Exactly one pair for each submitted row, in the original order.
    pub items: Vec<InventoryImportPair>,
}

impl InventoryImportResult {
    /// Decode required result fields, ignoring only bounded response extensions.
    /// # Errors
    /// Rejects invalid ids/counts, duplicates, recursive duplicate names or overflow.
    pub fn from_json(input: &[u8]) -> Result<Self, Error> {
        let mut fields = object(input, MAX_INVENTORY_IMPORT_RESULT_BYTES)?;
        let items = fields
            .remove("items")
            .and_then(|value| value.as_array().cloned())
            .ok_or(Error::InvalidField("items"))?;
        let items = items
            .into_iter()
            .map(|value| {
                let mut fields = value.as_object().cloned().ok_or(Error::InvalidField("item"))?;
                Ok(InventoryImportPair {
                    host_id: take_uuid(&mut fields, "host_id")?,
                    access_profile_id: take_uuid(&mut fields, "access_profile_id")?,
                })
            })
            .collect::<Result<_, Error>>()?;
        let result = Self { items };
        result.validate()?;
        Ok(result)
    }

    /// Verify the original row count, order and every submitted identity.
    /// # Errors
    /// Rejects any different request/result pair or invalid mutable request/result.
    pub fn validate_for_request(&self, request: &InventoryImportRequest) -> Result<(), Error> {
        self.validate()?;
        request.validate()?;
        if self.items.len() != request.rows.len()
            || self.items.iter().zip(&request.rows).any(|(item, row)| {
                item.host_id != row.host_id || item.access_profile_id != row.access_profile_id
            })
        {
            return Err(Error::Context);
        }
        Ok(())
    }

    /// Validate cache metadata and bind a complete result to its retained request.
    /// # Errors
    /// Rejects missing headers, malformed/oversized results or mismatched identities.
    pub fn from_http_json(
        input: &[u8],
        cache_control: Option<&str>,
        pragma: Option<&str>,
        request: &InventoryImportRequest,
    ) -> Result<Self, Error> {
        validate_cache_headers(cache_control, pragma)?;
        let result = Self::from_json(input)?;
        result.validate_for_request(request)?;
        Ok(result)
    }

    /// Encode only the original ordered identities.
    /// # Errors
    /// Rejects invalid mutable identities/counts or complete overflow.
    pub fn to_json(&self) -> Result<Vec<u8>, Error> {
        #[derive(Serialize)]
        struct Wire<'a> {
            items: &'a [InventoryImportPair],
        }
        self.validate()?;
        encode(&Wire { items: &self.items }, MAX_INVENTORY_IMPORT_RESULT_BYTES)
    }

    fn validate(&self) -> Result<(), Error> {
        if self.items.is_empty() || self.items.len() > MAX_INVENTORY_IMPORT_ROWS {
            return Err(Error::InvalidField("items"));
        }
        let mut ids = BTreeSet::new();
        for item in &self.items {
            valid_uuid(item.host_id, "host_id")?;
            valid_uuid(item.access_profile_id, "access_profile_id")?;
            if !ids.insert(item.host_id) || !ids.insert(item.access_profile_id) {
                return Err(Error::InvalidField("object ids"));
            }
        }
        Ok(())
    }
}

/// Fixed source-free CSV failure class.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InventoryCsvErrorKind {
    /// Input is not valid UTF-8.
    InvalidUtf8,
    /// Invalid quote/record/cell framing.
    InvalidCsv,
    /// Parsed header differs from the exact ordered five-column profile.
    InvalidHeader,
    /// A known cell violates its typed field constraints.
    InvalidCell,
    /// No data records were supplied.
    EmptyInput,
    /// More than one hundred data records.
    TooManyRecords,
    /// Original raw input exceeds one MiB.
    TooLarge,
}

/// Content-free CSV diagnostics; record numbers count data records, never physical lines.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct InventoryCsvError {
    /// Fixed failure kind.
    pub kind: InventoryCsvErrorKind,
    /// Optional one-based data-record number.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub record: Option<usize>,
    /// Optional known column name, never an untrusted source label.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field: Option<&'static str>,
}

impl fmt::Display for InventoryCsvError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "inventory CSV {:?}", self.kind)
    }
}
impl std::error::Error for InventoryCsvError {}

impl InventoryCsvError {
    /// Serialize only the fixed diagnostic fields for the thin browser adapter.
    #[must_use]
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| "{\"kind\":\"invalid_cell\"}".into())
    }
}

/// Serialize the shared CSV preparation as a flat-field preview without allocated ids.
/// # Errors
/// Returns only the shared fixed CSV diagnostics.
pub fn inventory_csv_preview(input: &[u8]) -> Result<String, InventoryCsvError> {
    #[derive(Serialize)]
    struct Preview {
        rows: Vec<InventoryImportFields>,
    }
    let rows = parse_inventory_csv(input)?;
    serde_json::to_string(&Preview { rows })
        .map_err(|_| csv_error(InventoryCsvErrorKind::InvalidCell, None, None))
}

fn csv_error(
    kind: InventoryCsvErrorKind,
    record: Option<usize>,
    field: Option<&'static str>,
) -> InventoryCsvError {
    InventoryCsvError { kind, record, field }
}

/// Parse the sole bounded CSV profile, without allocating ids, normalizing or doing I/O.
/// # Errors
/// Returns only fixed kind/record/known-field diagnostics, never source contents.
pub fn parse_inventory_csv(input: &[u8]) -> Result<Vec<InventoryImportFields>, InventoryCsvError> {
    use InventoryCsvErrorKind as Kind;
    if input.len() > MAX_INVENTORY_CSV_BYTES {
        return Err(csv_error(Kind::TooLarge, None, None));
    }
    let text = std::str::from_utf8(input).map_err(|_| csv_error(Kind::InvalidUtf8, None, None))?;
    let input = text.strip_prefix('\u{feff}').unwrap_or(text).as_bytes();
    if input.is_empty() {
        return Err(csv_error(Kind::EmptyInput, None, None));
    }
    let mut rows = Vec::new();
    let mut header = false;
    let mut cells = Vec::new();
    let mut cell = Vec::new();
    // 0=start, 1=unquoted, 2=quoted, 3=closed quote.
    let mut state = 0;
    let mut index = 0;
    let record = |header, count| if header { Some(count + 1) } else { None };
    while index < input.len() {
        let byte = input[index];
        if state == 2 {
            if byte == b'"' {
                state = 3;
            } else {
                cell.push(byte);
            }
            index += 1;
            continue;
        }
        if state == 3 && byte == b'"' {
            cell.push(byte);
            state = 2;
            index += 1;
            continue;
        }
        if byte == b',' || matches!(byte, b'\n' | b'\r') {
            if byte == b'\r' {
                if input.get(index + 1) != Some(&b'\n') {
                    return Err(csv_error(Kind::InvalidCsv, record(header, rows.len()), None));
                }
                index += 1;
            }
            cells.push(
                String::from_utf8(std::mem::take(&mut cell))
                    .map_err(|_| csv_error(Kind::InvalidUtf8, None, None))?,
            );
            if cells.len() > HEADER.len() || (byte == b',' && cells.len() == HEADER.len()) {
                let kind = if header { Kind::InvalidCsv } else { Kind::InvalidHeader };
                return Err(csv_error(kind, record(header, rows.len()), None));
            }
            state = 0;
            if byte != b',' {
                csv_record(&mut header, &mut rows, std::mem::take(&mut cells))?;
            }
        } else if byte == b'"' && state == 0 {
            state = 2;
        } else if byte == b'"' || state == 3 {
            return Err(csv_error(Kind::InvalidCsv, record(header, rows.len()), None));
        } else {
            cell.push(byte);
            state = 1;
        }
        index += 1;
    }
    if state == 2 {
        return Err(csv_error(Kind::InvalidCsv, record(header, rows.len()), None));
    }
    if state != 0 || !cell.is_empty() || !cells.is_empty() {
        cells.push(String::from_utf8(cell).map_err(|_| csv_error(Kind::InvalidUtf8, None, None))?);
        csv_record(&mut header, &mut rows, cells)?;
    }
    if rows.is_empty() {
        return Err(csv_error(Kind::EmptyInput, None, None));
    }
    Ok(rows)
}

fn csv_record(
    header: &mut bool,
    rows: &mut Vec<InventoryImportFields>,
    cells: Vec<String>,
) -> Result<(), InventoryCsvError> {
    use InventoryCsvErrorKind as Kind;
    if !*header {
        if cells != HEADER {
            return Err(csv_error(Kind::InvalidHeader, None, None));
        }
        *header = true;
        return Ok(());
    }
    let record = Some(rows.len() + 1);
    if rows.len() == MAX_INVENTORY_IMPORT_ROWS {
        return Err(csv_error(Kind::TooManyRecords, record, None));
    }
    let [name, address, port, username, login_name]: [String; 5] =
        cells.try_into().map_err(|_| csv_error(Kind::InvalidCsv, record, None))?;
    let port = if port.is_empty() {
        22
    } else {
        if port.starts_with('0') || !port.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(csv_error(Kind::InvalidCell, record, Some("port")));
        }
        port.parse::<u16>()
            .ok()
            .filter(|port| *port != 0)
            .ok_or_else(|| csv_error(Kind::InvalidCell, record, Some("port")))?
    };
    let fields = InventoryImportFields {
        name,
        address,
        port,
        username,
        login_name: (!login_name.is_empty()).then_some(login_name),
    };
    let row = InventoryImportRow {
        host_id: Uuid::from_u128(0x0000_0000_0000_7000_8000_0000_0000_0000),
        access_profile_id: Uuid::from_u128(0x0000_0000_0000_7000_8000_0000_0000_0001),
        fields,
    };
    row.inventory_creates().map_err(|error| {
        let field = match error {
            Error::InvalidField(field) if HEADER.contains(&field) => Some(field),
            _ => None,
        };
        csv_error(Kind::InvalidCell, record, field)
    })?;
    rows.push(row.fields);
    Ok(())
}
