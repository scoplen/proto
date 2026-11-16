// SPDX-License-Identifier: Apache-2.0
//! Named schema projection; unknown K-1 fields are refused only at this transfer boundary.

use super::{Entry, Error, SecretMode, json::SensitiveJson};
use crate::{
    FieldPath, MapKey, Object, ObjectType,
    cbor::{self, Value},
    validate_uuid_v7,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Map, Value as Json};
use std::collections::BTreeMap;
use uuid::Uuid;

#[derive(Clone, Copy)]
enum Kind {
    Text,
    Uint,
    Bool,
    Bytes,
    Uuid,
    Route,
    Uuids,
    Any,
    Device,
    Variable,
    Session,
    TextMap,
    UuidBoolMap,
    TextBoolMap,
    DeviceMap,
    VariableMap,
    SessionMap,
}
use Kind::{
    Any, Bool, Bytes, Device, DeviceMap, Route, Session, SessionMap, Text, TextBoolMap, TextMap,
    Uint, Uuid as UuidKind, UuidBoolMap, Uuids, Variable, VariableMap,
};
type Spec = (u64, &'static str, Kind);

fn specs(kind: ObjectType) -> Result<&'static [Spec], Error> {
    Ok(match kind.to_wire() {
        1 => &[
            (1, "name", Text),
            (2, "address", Text),
            (3, "port", Uint),
            (4, "tags", TextMap),
            (5, "groups", UuidBoolMap),
            (6, "favorite", Bool),
            (7, "notes", Text),
            (8, "default_profile", UuidKind),
            (9, "ssh_options", TextMap),
            (10, "mosh", TextMap),
        ],
        2 => &[
            (1, "host", UuidKind),
            (2, "name", Text),
            (3, "username", Text),
            (4, "credential", UuidKind),
            (5, "route", Route),
            (6, "terminal_profile", Text),
            (7, "startup_command", Text),
            (8, "forwards", UuidBoolMap),
            (9, "agent_forwarding", Bool),
        ],
        3 => &[
            (1, "name", Text),
            (2, "kind", Uint),
            (3, "binding", Uint),
            (4, "secret", Bytes),
            (5, "devices", DeviceMap),
            (6, "public_key", Text),
            (7, "provider", TextMap),
            (8, "certificate_scope", UuidKind),
        ],
        4 => &[
            (1, "name", Text),
            (2, "kind", Uint),
            (3, "hops", Uuids),
            (4, "proxy", Text),
            (5, "proxy_credential", UuidKind),
            (6, "command", Text),
            (7, "gateway_network", UuidKind),
            (8, "proxy_username", Text),
        ],
        5 => &[
            (1, "name", Text),
            (2, "parent", UuidKind),
            (3, "color", Text),
            (4, "defaults", TextMap),
        ],
        6 => &[
            (1, "host", UuidKind),
            (2, "pattern", Text),
            (3, "key", Text),
            (4, "fingerprint", Text),
            (5, "provenance", Uint),
            (6, "accepted_at", Uint),
            (7, "accepted_by_device", UuidKind),
            (8, "accepted_by_account", UuidKind),
            (9, "revoked", Bool),
            (10, "ca", Bool),
        ],
        7 => &[
            (1, "name", Text),
            (2, "template", Text),
            (3, "variables", VariableMap),
            (4, "tags", TextBoolMap),
            (5, "folder", Text),
        ],
        8 => &[
            (1, "name", Text),
            (2, "kind", Uint),
            (3, "bind_address", Text),
            (4, "bind_port", Uint),
            (5, "target_host", Text),
            (6, "target_port", Uint),
            (7, "profile", UuidKind),
        ],
        9 => &[(1, "name", Text), (2, "layout", Bytes), (3, "sessions", SessionMap)],
        10 => &[(1, "key", Text), (2, "value", Any)],
        11 => &[(1, "name", Text), (2, "description", Text)],
        _ => return Err(Error::Unsupported),
    })
}

fn nested(kind: Kind) -> &'static [Spec] {
    match kind {
        Device => &[(1, "public_key", Text), (2, "label", Text)],
        Variable => &[(1, "kind", Uint), (2, "default", Any), (3, "choices", Any)],
        Session => &[
            (1, "profile", UuidKind),
            (2, "kind", Uint),
            (3, "forward", UuidKind),
            (4, "working_directory", Text),
        ],
        _ => &[],
    }
}

fn map_kind(kind: Kind) -> Option<(bool, Kind)> {
    Some(match kind {
        TextMap => (false, Text),
        UuidBoolMap => (true, Bool),
        TextBoolMap => (false, Bool),
        DeviceMap => (true, Device),
        VariableMap => (false, Variable),
        SessionMap => (true, Session),
        _ => return None,
    })
}

pub(super) fn check_supported(object: &Object) -> Result<(), Error> {
    let table = specs(object.object_type)?;
    for (path, entry) in &object.fields {
        let (_, _, kind) = table
            .iter()
            .find(|(number, _, _)| *number == path.field_number())
            .ok_or(Error::Unsupported)?;
        if matches!(entry.value, Value::Null) {
            continue;
        }
        let scalar = map_kind(*kind).map_or(*kind, |(_, value)| value);
        if matches!(scalar, Device | Variable | Session) {
            let _named = SensitiveJson(to_named(&entry.value, scalar)?);
        }
    }
    Ok(())
}

pub(super) fn entry_json(entry: &Entry) -> Result<SensitiveJson, Error> {
    let table = specs(entry.object_type)?;
    let mut fields = SensitiveJson(Json::Object(Map::new()));
    for (path, value) in &entry.fields {
        let (_, name, kind) = table
            .iter()
            .find(|(number, _, _)| *number == path.field_number())
            .ok_or(Error::Unsupported)?;
        if matches!(value, Value::Null) {
            return Err(Error::Value);
        }
        let Json::Object(target) = &mut fields.0 else { unreachable!() };
        match (path, map_kind(*kind)) {
            (FieldPath::Field(_), None) => {
                target.insert((*name).into(), to_named(value, *kind)?);
            }
            (FieldPath::MapEntry { key, .. }, Some((uuid, scalar))) => {
                let key = match (uuid, key) {
                    (true, MapKey::Bytes(bytes)) => uuid_text(bytes)?,
                    (false, MapKey::Text(text)) => text.clone(),
                    _ => return Err(Error::Value),
                };
                let Json::Object(map) =
                    target.entry((*name).to_string()).or_insert_with(|| Json::Object(Map::new()))
                else {
                    return Err(Error::Value);
                };
                if map.insert(key, to_named(value, scalar)?).is_some() {
                    return Err(Error::Value);
                }
            }
            _ => return Err(Error::Value),
        }
    }
    let mut root = Map::new();
    root.insert("type".into(), Json::String(entry.object_type.to_string()));
    root.insert("id".into(), Json::String(entry.id.to_string()));
    root.insert("schema".into(), Json::from(1));
    root.insert("fields".into(), fields.take());
    root.insert(
        "omitted_secrets".into(),
        Json::Array(entry.omitted_secrets.iter().cloned().map(Json::String).collect()),
    );
    Ok(SensitiveJson(Json::Object(root)))
}

pub(super) fn parse_entry(value: &Json) -> Result<Entry, Error> {
    let root = object(value)?;
    exact(root, &["type", "id", "schema", "fields", "omitted_secrets"])?;
    if uint(required(root, "schema")?)? != 1 {
        return Err(Error::Unsupported);
    }
    let name = text(required(root, "type")?)?;
    let kind = (1..=11)
        .filter_map(|number| ObjectType::from_wire(number).ok())
        .find(|kind| kind.to_string() == name)
        .ok_or(Error::Unsupported)?;
    let mut entry = Entry {
        id: uuid(text(required(root, "id")?)?)?,
        object_type: kind,
        fields: BTreeMap::new(),
        omitted_secrets: Vec::new(),
    };
    let table = specs(kind)?;
    for (name, value) in object(required(root, "fields")?)? {
        let (number, _, kind) =
            table.iter().find(|(_, candidate, _)| *candidate == name).ok_or(Error::Unsupported)?;
        if value.is_null() {
            return Err(Error::Value);
        }
        if let Some((uuid_key, scalar)) = map_kind(*kind) {
            for (key, value) in object(value)? {
                let key = if uuid_key {
                    MapKey::Bytes(uuid(key)?.as_bytes().to_vec())
                } else {
                    MapKey::Text(key.clone())
                };
                let path = FieldPath::map_entry(*number, key).map_err(|_| Error::Value)?;
                entry.fields.insert(path, from_named(value, scalar)?);
            }
        } else {
            entry.fields.insert(
                FieldPath::field(*number).map_err(|_| Error::Value)?,
                from_named(value, *kind)?,
            );
        }
    }
    for pointer in array(required(root, "omitted_secrets")?)? {
        entry.omitted_secrets.push(text(pointer)?.into());
    }
    entry.validate(None)?;
    Ok(entry)
}

fn to_named(value: &Value, kind: Kind) -> Result<Json, Error> {
    Ok(match (kind, value) {
        (Text, Value::Text(text)) => Json::String(text.clone()),
        (Uint, Value::UInt(number)) => Json::from(*number),
        (Bool, Value::Bool(value)) => Json::Bool(*value),
        (Bytes, Value::Bytes(bytes)) => Json::String(URL_SAFE_NO_PAD.encode(bytes)),
        (UuidKind | Route, Value::Bytes(bytes)) => Json::String(uuid_text(bytes)?),
        (Route, Value::UInt(0)) => Json::from(0),
        (Uuids, Value::Array(values)) => Json::Array(
            values.iter().map(|value| to_named(value, UuidKind)).collect::<Result<_, _>>()?,
        ),
        (Any, value) => to_any(value)?,
        (Device | Variable | Session, Value::Map(values)) => {
            let mut map = Map::new();
            for (key, value) in values {
                let Value::UInt(number) = key else {
                    return Err(Error::Unsupported);
                };
                let (_, name, scalar) = nested(kind)
                    .iter()
                    .find(|(candidate, _, _)| *candidate == *number)
                    .ok_or(Error::Unsupported)?;
                if map.insert((*name).into(), to_named(value, *scalar)?).is_some() {
                    return Err(Error::Value);
                }
            }
            Json::Object(map)
        }
        _ => return Err(Error::Value),
    })
}

fn from_named(value: &Json, kind: Kind) -> Result<Value, Error> {
    Ok(match kind {
        Text => Value::Text(text(value)?.into()),
        Uint => Value::UInt(uint(value)?),
        Bool => Value::Bool(value.as_bool().ok_or(Error::Value)?),
        Bytes => Value::Bytes(bytes(text(value)?)?),
        Route if value.as_u64() == Some(0) => Value::UInt(0),
        UuidKind | Route => Value::Bytes(uuid(text(value)?)?.as_bytes().to_vec()),
        Uuids => Value::Array(
            array(value)?
                .iter()
                .map(|value| from_named(value, UuidKind))
                .collect::<Result<_, _>>()?,
        ),
        Any => from_any(value)?,
        Device | Variable | Session => {
            let mut fields = Vec::new();
            for (name, value) in object(value)? {
                let (number, _, scalar) = nested(kind)
                    .iter()
                    .find(|(_, candidate, _)| *candidate == name)
                    .ok_or(Error::Unsupported)?;
                fields.push((Value::UInt(*number), from_named(value, *scalar)?));
            }
            Value::Map(fields)
        }
        _ => return Err(Error::Value),
    })
}

fn wrapper(name: &str, value: Json) -> Json {
    Json::Object(Map::from_iter([(name.into(), value)]))
}

fn to_any(value: &Value) -> Result<Json, Error> {
    Ok(match value {
        Value::Null => Json::Null,
        Value::Bool(value) => Json::Bool(*value),
        Value::Text(text) => Json::String(text.clone()),
        Value::UInt(number) => wrapper("uint", Json::String(number.to_string())),
        Value::Int(number) => wrapper("nint", Json::String(number.to_string())),
        Value::Bytes(bytes) => wrapper("bytes", Json::String(URL_SAFE_NO_PAD.encode(bytes))),
        Value::Array(values) => {
            wrapper("array", Json::Array(values.iter().map(to_any).collect::<Result<_, _>>()?))
        }
        Value::Map(values) => {
            let mut ordered = values
                .iter()
                .map(|(key, value)| {
                    Ok((
                        zeroize::Zeroizing::new(cbor::encode(key).map_err(|_| Error::Value)?),
                        key,
                        value,
                    ))
                })
                .collect::<Result<Vec<_>, Error>>()?;
            ordered.sort_by(|left, right| left.0.as_slice().cmp(right.0.as_slice()));
            if ordered.windows(2).any(|pair| pair[0].0.as_slice() == pair[1].0.as_slice()) {
                return Err(Error::Value);
            }
            wrapper(
                "map",
                Json::Array(
                    ordered
                        .iter()
                        .map(|(_, key, value)| Ok(Json::Array(vec![to_any(key)?, to_any(value)?])))
                        .collect::<Result<_, Error>>()?,
                ),
            )
        }
    })
}

fn from_any(value: &Json) -> Result<Value, Error> {
    Ok(match value {
        Json::Null => Value::Null,
        Json::Bool(value) => Value::Bool(*value),
        Json::String(value) => Value::Text(value.clone()),
        Json::Object(map) if map.len() == 1 => {
            let (kind, value) = map.iter().next().ok_or(Error::Value)?;
            match kind.as_str() {
                "uint" => {
                    let decimal = text(value)?;
                    let number: u64 = decimal.parse().map_err(|_| Error::Value)?;
                    if number.to_string() != decimal {
                        return Err(Error::Value);
                    }
                    Value::UInt(number)
                }
                "nint" => {
                    let decimal = text(value)?;
                    let number: i128 = decimal.parse().map_err(|_| Error::Value)?;
                    if !(-(1_i128 << 64)..=-1).contains(&number) || number.to_string() != decimal {
                        return Err(Error::Value);
                    }
                    Value::Int(number)
                }
                "bytes" => Value::Bytes(bytes(text(value)?)?),
                "array" => {
                    Value::Array(array(value)?.iter().map(from_any).collect::<Result<_, _>>()?)
                }
                "map" => {
                    let mut entries = Vec::new();
                    for pair in array(value)? {
                        let pair = array(pair)?;
                        if pair.len() != 2 {
                            return Err(Error::Value);
                        }
                        entries.push((from_any(&pair[0])?, from_any(&pair[1])?));
                    }
                    Value::Map(entries)
                }
                _ => return Err(Error::Unsupported),
            }
        }
        _ => return Err(Error::Value),
    })
}

pub(super) fn validate_omissions(entry: &Entry, mode: Option<SecretMode>) -> Result<(), Error> {
    if entry.omitted_secrets.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(Error::SecretPolicy);
    }
    let mut allowed = Vec::new();
    let mut has_secret = false;
    if entry.object_type == ObjectType::CREDENTIAL {
        has_secret = entry.fields.contains_key(&FieldPath::Field(4));
        let shared = entry.fields.get(&FieldPath::Field(3)) == Some(&Value::UInt(1));
        if shared && !has_secret {
            allowed.push("/secret".to_string());
        }
        if shared && !has_secret && entry.omitted_secrets != allowed {
            return Err(Error::SecretPolicy);
        }
    } else if entry.object_type == ObjectType::SNIPPET {
        for (path, value) in &entry.fields {
            let FieldPath::MapEntry { field: 3, key: MapKey::Text(name) } = path else {
                continue;
            };
            let Value::Map(fields) = value else {
                return Err(Error::Value);
            };
            if fields.iter().any(|(key, value)| *key == Value::UInt(1) && *value == Value::UInt(4))
            {
                if fields.iter().any(|(key, _)| *key == Value::UInt(2)) {
                    has_secret = true;
                } else {
                    allowed.push(format!(
                        "/variables/{}/default",
                        name.replace('~', "~0").replace('/', "~1")
                    ));
                }
            }
        }
    }
    if entry.omitted_secrets.iter().any(|pointer| !allowed.contains(pointer)) {
        return Err(Error::SecretPolicy);
    }
    if has_secret && !entry.omitted_secrets.is_empty() {
        return Err(Error::SecretPolicy);
    }
    if mode == Some(SecretMode::Omitted) && has_secret
        || mode == Some(SecretMode::Included) && !entry.omitted_secrets.is_empty()
    {
        return Err(Error::SecretPolicy);
    }
    Ok(())
}

pub(super) fn object(value: &Json) -> Result<&Map<String, Json>, Error> {
    value.as_object().ok_or(Error::Value)
}
pub(super) fn array(value: &Json) -> Result<&Vec<Json>, Error> {
    value.as_array().ok_or(Error::Value)
}
pub(super) fn text(value: &Json) -> Result<&str, Error> {
    value.as_str().ok_or(Error::Value)
}
pub(super) fn uint(value: &Json) -> Result<u64, Error> {
    value.as_u64().ok_or(Error::Value)
}
pub(super) fn required<'a>(map: &'a Map<String, Json>, name: &str) -> Result<&'a Json, Error> {
    map.get(name).ok_or(Error::Unsupported)
}
pub(super) fn exact(map: &Map<String, Json>, names: &[&str]) -> Result<(), Error> {
    if map.len() != names.len() || map.keys().any(|key| !names.contains(&key.as_str())) {
        Err(Error::Unsupported)
    } else {
        Ok(())
    }
}
pub(super) fn uuid(text: &str) -> Result<Uuid, Error> {
    let id = Uuid::parse_str(text).map_err(|_| Error::Value)?;
    validate_uuid_v7(id).map_err(|_| Error::Value)?;
    if id.to_string() != text {
        return Err(Error::Value);
    }
    Ok(id)
}
fn uuid_text(bytes: &[u8]) -> Result<String, Error> {
    let id = Uuid::from_slice(bytes).map_err(|_| Error::Value)?;
    validate_uuid_v7(id).map_err(|_| Error::Value)?;
    Ok(id.to_string())
}
fn bytes(text: &str) -> Result<Vec<u8>, Error> {
    let bytes = URL_SAFE_NO_PAD.decode(text).map_err(|_| Error::Value)?;
    if URL_SAFE_NO_PAD.encode(&bytes) != text {
        return Err(Error::Value);
    }
    Ok(bytes)
}
