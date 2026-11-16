// SPDX-License-Identifier: Apache-2.0
//! D-142 named, streaming portable snapshots.
//!
//! This codec neither authenticates an archive nor authorizes an import. Entry callbacks are
//! tentative until [`read_archive`] succeeds, including its final EOF read. An age consumer must
//! additionally finish container authentication before publishing staged changes. References,
//! receipt identity, imported trust and destination ownership remain consumer responsibilities.

#![allow(clippy::missing_errors_doc, clippy::must_use_candidate)]

use std::{
    collections::BTreeMap,
    fmt,
    io::{Read, Write},
};
use uuid::Uuid;
use zeroize::Zeroize;

use crate::{FieldEntry, FieldPath, Hlc, Object, ObjectType, cbor::Value, validate_uuid_v7};

mod json;
mod mapping;

/// The exact initial portable JSON Schema, including all eleven registered object types.
pub const JSON_SCHEMA: &str = include_str!("schema.json");
/// Complete encoded entry budget, including adjacent separators and whitespace.
pub const MAX_ENTRY_BYTES: usize = 8 * 1024 * 1024;
/// Number of original object identities permitted in an archive.
pub const MAX_OBJECTS: usize = 100_000;
/// Separate bounds for document header and final framing.
pub const MAX_FRAMING_BYTES: usize = 64 * 1024;
/// JSON syntax nesting; arbitrary CBOR still has its own 128-level model limit.
pub const MAX_JSON_DEPTH: usize = 512;

/// A descriptive exporter kind, never evidence of authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceKind {
    /// An enrolled or account-free exporting device.
    Device,
    /// An Organization export produced through its authorized boundary.
    Organization,
}

/// Whether portable secret fields were included or explicitly omitted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecretMode {
    /// Secret-omitting JSON; missing fields have exact omission markers.
    Omitted,
    /// Secret-including JSON; native consumers require authenticated age transport.
    Included,
}

/// Non-authoritative archive metadata. Format and model version are fixed by this API.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Header {
    /// Unsigned Unix milliseconds, without conversion through floating point.
    pub exported_at: u64,
    /// Descriptive exporter kind.
    pub source_kind: SourceKind,
    /// Descriptive `UUIDv7` of the exporting device or Organization.
    pub source_id: Uuid,
    /// The archive-wide omission policy.
    pub secrets: SecretMode,
}

/// Completion metadata, returned only after strict JSON EOF.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Summary {
    /// Validated document metadata; member order is irrelevant during decoding.
    pub header: Header,
    /// Number of fully validated entries passed to the tentative callback.
    pub objects: usize,
}

/// Content-free parser, model, streaming and consumer errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum Error {
    /// Reader or writer failure; paths and underlying messages are not disclosed.
    #[error("The portable archive could not be read or written.")]
    Io,
    /// Invalid JSON, duplicate names, encoding or trailing content.
    #[error("The portable archive is not valid strict JSON.")]
    Json,
    /// Unknown or missing schema member, type, version or structure.
    #[error("The portable archive contains unsupported or incomplete data.")]
    Unsupported,
    /// Wrong scalar, UUID, base64url, CBOR representation or model value.
    #[error("A portable archive value does not satisfy the object model.")]
    Value,
    /// Encoded entry, framing, object count or JSON nesting budget exceeded.
    #[error("The portable archive exceeds a format limit.")]
    Limit,
    /// Repeated original object identity.
    #[error("The portable archive repeats an original object identifier.")]
    DuplicateId,
    /// Invalid or inconsistent secret omission state.
    #[error("The portable archive has inconsistent secret omission markers.")]
    SecretPolicy,
    /// A redacted shared Credential cannot become a complete replicated Object.
    #[error("The portable Credential needs its omitted secret before it can become an Object.")]
    MissingSecret,
    /// The caller refused a tentative entry or stopped writing the archive.
    #[error("Portable archive processing was stopped by its consumer.")]
    Consumer,
}

/// One current-state entry, with numeric K-1 paths for direct Rust consumption.
///
/// It may describe a redacted shared Credential and is therefore deliberately not an Object.
/// Debug output contains no field values or omission paths. Owned values are wiped on drop.
#[derive(Clone, Eq, PartialEq)]
pub struct Entry {
    id: Uuid,
    object_type: ObjectType,
    fields: BTreeMap<FieldPath, Value>,
    omitted_secrets: Vec<String>,
}

impl fmt::Debug for Entry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PortableEntry")
            .field("id", &self.id)
            .field("object_type", &self.object_type)
            .field("field_count", &self.fields.len())
            .field("omitted_secret_count", &self.omitted_secrets.len())
            .finish_non_exhaustive()
    }
}

impl Drop for Entry {
    fn drop(&mut self) {
        for value in self.fields.values_mut() {
            wipe_value(value);
        }
        for pointer in &mut self.omitted_secrets {
            pointer.zeroize();
        }
    }
}

impl Entry {
    /// Construct and validate a portable description, independently of archive-wide policy.
    pub fn from_fields(
        id: Uuid,
        object_type: ObjectType,
        fields: BTreeMap<FieldPath, Value>,
        omitted_secrets: Vec<String>,
    ) -> Result<Self, Error> {
        let entry = Self { id, object_type, fields, omitted_secrets };
        entry.validate(None)?;
        Ok(entry)
    }

    /// Project a complete model Object to current state; deleted objects produce `None`.
    /// Unknown fields, including cleared unknown fields, are rejected rather than discarded.
    pub fn from_object(object: &Object, secrets: SecretMode) -> Result<Option<Self>, Error> {
        let _encoded = zeroize::Zeroizing::new(object.encode().map_err(|_| Error::Value)?);
        if object.is_tombstoned() {
            return Ok(None);
        }
        mapping::check_supported(object)?;
        let mut entry = Self {
            id: object.id,
            object_type: object.object_type,
            fields: object
                .fields
                .iter()
                .filter(|(_, value)| !matches!(value.value, Value::Null))
                .map(|(path, value)| (path.clone(), value.value.clone()))
                .collect(),
            omitted_secrets: Vec::new(),
        };
        if secrets == SecretMode::Omitted {
            if object.object_type == ObjectType::CREDENTIAL {
                if let Some(mut value) = entry.fields.remove(&FieldPath::Field(4)) {
                    wipe_value(&mut value);
                    entry.omitted_secrets.push("/secret".into());
                }
            } else if object.object_type == ObjectType::SNIPPET {
                for (path, value) in &mut entry.fields {
                    let FieldPath::MapEntry { field: 3, key: crate::MapKey::Text(name) } = path
                    else {
                        continue;
                    };
                    let Value::Map(spec) = value else {
                        return Err(Error::Value);
                    };
                    if spec
                        .iter()
                        .any(|(key, value)| *key == Value::UInt(1) && *value == Value::UInt(4))
                        && let Some(index) = spec.iter().position(|(key, _)| *key == Value::UInt(2))
                    {
                        let (_, mut removed) = spec.remove(index);
                        wipe_value(&mut removed);
                        entry.omitted_secrets.push(format!(
                            "/variables/{}/default",
                            name.replace('~', "~0").replace('/', "~1")
                        ));
                    }
                }
            }
        }
        entry.omitted_secrets.sort();
        entry.validate(Some(secrets))?;
        Ok(Some(entry))
    }

    /// Original source identity; native import allocates a separate destination identity.
    pub const fn id(&self) -> Uuid {
        self.id
    }
    /// Known K-1 type of the entry; its schema is always one.
    pub const fn object_type(&self) -> ObjectType {
        self.object_type
    }
    /// Current scalar and decomposed-map values, with no replication clocks or clear markers.
    pub fn fields(&self) -> &BTreeMap<FieldPath, Value> {
        &self.fields
    }
    /// Exact omitted-secret pointers relative to the named `fields` object.
    pub fn omitted_secrets(&self) -> &[String] {
        &self.omitted_secrets
    }

    /// Construct a complete model value with caller-supplied destination identity and writer.
    /// References are unchanged: the consumer must remap known paths before publishing a copy.
    /// Redacted shared Credentials are refused; no placeholder secret is invented.
    pub fn to_object(&self, id: Uuid, clock: Hlc, origin: Uuid) -> Result<Object, Error> {
        self.validate(None)?;
        if self.omitted_secrets.iter().any(|pointer| pointer == "/secret") {
            return Err(Error::MissingSecret);
        }
        let object = self.model(id, clock, origin)?;
        let _encoded = zeroize::Zeroizing::new(object.encode().map_err(|_| Error::Value)?);
        Ok(object)
    }

    fn model(&self, id: Uuid, clock: Hlc, origin: Uuid) -> Result<Object, Error> {
        let mut object = Object::new(id, self.object_type, 1).map_err(|_| Error::Value)?;
        for (path, value) in &self.fields {
            object
                .insert(
                    path.clone(),
                    FieldEntry::new(value.clone(), clock, origin).map_err(|_| Error::Value)?,
                )
                .map_err(|_| Error::Value)?;
        }
        Ok(object)
    }

    fn validate(&self, mode: Option<SecretMode>) -> Result<(), Error> {
        validate_uuid_v7(self.id).map_err(|_| Error::Value)?;
        mapping::validate_omissions(self, mode)?;
        let mut model =
            self.model(self.id, Hlc::from_wire(0).map_err(|_| Error::Value)?, self.id)?;
        let result = model
            .validate_portable(self.omitted_secrets.iter().any(|pointer| pointer == "/secret"))
            .map_err(|_| Error::Value);
        for value in model.fields.values_mut() {
            wipe_value(&mut value.value);
        }
        result?;
        let _named = mapping::entry_json(self)?;
        Ok(())
    }
}

/// Read an archive one bounded entry at a time and visit entries in source order.
///
/// Callbacks may run before the header is complete. They are tentative until this function
/// returns `Ok`; callback, source, model or final-EOF failures require consumer rollback.
pub fn read_archive(
    reader: impl Read,
    on_entry: impl FnMut(Entry) -> Result<(), Error>,
) -> Result<Summary, Error> {
    json::read_archive(reader, on_entry)
}

/// Write a complete compact archive without collecting entries or the archive in memory.
/// A failure leaves a partial output; only the owner may publish it after successful return
/// and any enclosing age writer finalization. This function does not close the supplied writer.
pub fn write_archive(
    mut writer: impl Write,
    header: &Header,
    entries: impl IntoIterator<Item = Result<Entry, Error>>,
) -> Result<usize, Error> {
    json::write_archive(&mut writer, header, entries)
}

fn wipe_value(value: &mut Value) {
    match value {
        Value::Text(text) => text.zeroize(),
        Value::Bytes(bytes) => bytes.zeroize(),
        Value::Array(items) => {
            for item in items {
                wipe_value(item);
            }
        }
        Value::Map(items) => {
            for (key, item) in items {
                wipe_value(key);
                wipe_value(item);
            }
        }
        _ => {}
    }
}
