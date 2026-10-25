// SPDX-License-Identifier: Apache-2.0
//! Shared input syntax for bounded K-5 JSON request codecs.

use std::fmt;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use scoplen_crypto::SecretVec;
use serde::{
    Deserialize, Deserializer,
    de::{self, MapAccess, SeqAccess, Visitor},
};
use serde_json::{Map, Number, Value};

pub(crate) fn valid_remote_user(value: &str) -> bool {
    !value.is_empty() && value.len() <= 255 && !value.chars().any(char::is_control)
}

pub(crate) fn valid_raw_ssh_public_key(value: &str) -> bool {
    if value.is_empty() || value.len() > 8_192 || !value.is_ascii() {
        return false;
    }
    let Some((algorithm, encoded_blob)) = value.split_once(' ') else {
        return false;
    };
    if !matches!(
        algorithm,
        "ssh-ed25519"
            | "ecdsa-sha2-nistp256"
            | "ecdsa-sha2-nistp384"
            | "ecdsa-sha2-nistp521"
            | "ssh-rsa"
            | "sk-ssh-ed25519@openssh.com"
            | "sk-ecdsa-sha2-nistp256@openssh.com"
    ) || encoded_blob.is_empty()
        || encoded_blob.contains(' ')
    {
        return false;
    }
    let Ok(blob) = STANDARD.decode(encoded_blob) else {
        return false;
    };
    if STANDARD.encode(&blob) != encoded_blob {
        return false;
    }
    let Ok(key) = ssh_key::PublicKey::from_bytes(&blob) else {
        return false;
    };
    key.to_openssh().is_ok_and(|canonical| canonical == value)
}

pub(crate) fn decode_unique_object(input: &[u8]) -> Result<Map<String, Value>, ()> {
    let value = serde_json::from_slice::<UniqueValue>(input).map_err(|_| ())?.into_inner();
    match value {
        Value::Object(fields) => Ok(fields),
        value => {
            clear_json_value(value);
            Err(())
        }
    }
}

struct UniqueValue(Value);

impl UniqueValue {
    fn into_inner(mut self) -> Value {
        std::mem::replace(&mut self.0, Value::Null)
    }
}

impl Drop for UniqueValue {
    fn drop(&mut self) {
        clear_json_value(std::mem::replace(&mut self.0, Value::Null));
    }
}

// Parsed authentication fields can contain secrets even when a later field or duplicate fails.
pub(crate) fn clear_json_value(value: Value) {
    match value {
        Value::String(value) => drop(SecretVec::new(value.into_bytes())),
        Value::Array(values) => {
            for value in values {
                clear_json_value(value);
            }
        }
        Value::Object(fields) => {
            for (key, value) in fields {
                drop(SecretVec::new(key.into_bytes()));
                clear_json_value(value);
            }
        }
        _ => {}
    }
}

impl<'de> Deserialize<'de> for UniqueValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(UniqueVisitor)
    }
}

struct UniqueVisitor;

impl<'de> Visitor<'de> for UniqueVisitor {
    type Value = UniqueValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value without duplicate keys")
    }
    fn visit_bool<E: de::Error>(self, value: bool) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::Bool(value)))
    }
    fn visit_i64<E: de::Error>(self, value: i64) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::Number(Number::from(value))))
    }
    fn visit_u64<E: de::Error>(self, value: u64) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::Number(Number::from(value))))
    }
    fn visit_f64<E: de::Error>(self, value: f64) -> Result<Self::Value, E> {
        Number::from_f64(value)
            .map(Value::Number)
            .map(UniqueValue)
            .ok_or_else(|| E::custom("invalid number"))
    }
    fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::String(value.to_owned())))
    }
    fn visit_string<E: de::Error>(self, value: String) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::String(value)))
    }
    fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::Null))
    }
    fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::Null))
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
        let mut guarded = UniqueValue(Value::Array(Vec::new()));
        let Value::Array(values) = &mut guarded.0 else {
            unreachable!();
        };
        while let Some(value) = sequence.next_element::<UniqueValue>()? {
            values.push(value.into_inner());
        }
        Ok(guarded)
    }
    fn visit_map<A: MapAccess<'de>>(self, mut access: A) -> Result<Self::Value, A::Error> {
        let mut guarded = UniqueValue(Value::Object(Map::new()));
        let Value::Object(values) = &mut guarded.0 else {
            unreachable!();
        };
        while let Some(key) = access.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(de::Error::custom("duplicate JSON key"));
            }
            let value: UniqueValue = access.next_value()?;
            values.insert(key, value.into_inner());
        }
        Ok(guarded)
    }
}
