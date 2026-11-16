// SPDX-License-Identifier: Apache-2.0
//! Bounded JSON framing and recursive duplicate-name rejection.

use super::{
    Entry, Error, Header, MAX_ENTRY_BYTES, MAX_FRAMING_BYTES, MAX_JSON_DEPTH, MAX_OBJECTS,
    SecretMode, SourceKind, Summary, mapping,
};
use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value};
use std::{
    collections::HashSet,
    fmt,
    io::{BufRead, BufReader, Read, Write},
};
use zeroize::{Zeroize, Zeroizing};

pub(super) struct SensitiveJson(pub Value);
impl SensitiveJson {
    pub fn take(&mut self) -> Value {
        std::mem::take(&mut self.0)
    }
}
impl Drop for SensitiveJson {
    fn drop(&mut self) {
        wipe_json(&mut self.0);
    }
}
fn wipe_json(value: &mut Value) {
    match value {
        Value::String(text) => text.zeroize(),
        Value::Array(items) => {
            for value in items {
                wipe_json(value);
            }
        }
        Value::Object(map) => {
            for (mut key, mut value) in std::mem::take(map) {
                key.zeroize();
                wipe_json(&mut value);
            }
        }
        _ => {}
    }
}

struct Seed(usize);
impl<'de> DeserializeSeed<'de> for Seed {
    type Value = SensitiveJson;
    fn deserialize<D: de::Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> Result<Self::Value, D::Error> {
        if self.0 > MAX_JSON_DEPTH {
            return Err(de::Error::custom("portable JSON depth limit"));
        }
        deserializer.deserialize_any(self)
    }
}
impl<'de> Visitor<'de> for Seed {
    type Value = SensitiveJson;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("strict portable JSON")
    }
    fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok(SensitiveJson(Value::Null))
    }
    fn visit_bool<E: de::Error>(self, value: bool) -> Result<Self::Value, E> {
        Ok(SensitiveJson(Value::Bool(value)))
    }
    fn visit_u64<E: de::Error>(self, value: u64) -> Result<Self::Value, E> {
        Ok(SensitiveJson(Value::from(value)))
    }
    fn visit_i64<E: de::Error>(self, _: i64) -> Result<Self::Value, E> {
        Err(E::custom("negative JSON number"))
    }
    fn visit_f64<E: de::Error>(self, _: f64) -> Result<Self::Value, E> {
        Err(E::custom("floating JSON number"))
    }
    fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
        if !crate::cbor::is_nfc(value) {
            return Err(E::custom("non-NFC JSON text"));
        }
        Ok(SensitiveJson(Value::String(value.into())))
    }
    fn visit_string<E: de::Error>(self, mut value: String) -> Result<Self::Value, E> {
        if !crate::cbor::is_nfc(&value) {
            value.zeroize();
            return Err(E::custom("non-NFC JSON text"));
        }
        Ok(SensitiveJson(Value::String(value)))
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
        let mut result = SensitiveJson(Value::Array(Vec::new()));
        while let Some(mut item) = sequence.next_element_seed(Seed(self.0 + 1))? {
            let Value::Array(items) = &mut result.0 else { unreachable!() };
            items.push(item.take());
        }
        Ok(result)
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut result = SensitiveJson(Value::Object(Map::new()));
        while let Some(mut key) = map.next_key::<String>()? {
            let Value::Object(items) = &mut result.0 else { unreachable!() };
            if !crate::cbor::is_nfc(&key) || items.contains_key(&key) {
                key.zeroize();
                return Err(de::Error::custom("duplicate or non-NFC JSON name"));
            }
            let mut item = map.next_value_seed(Seed(self.0 + 1))?;
            items.insert(key, item.take());
        }
        Ok(result)
    }
}

fn parse(bytes: &[u8]) -> Result<SensitiveJson, Error> {
    let mut decoder = serde_json::Deserializer::from_slice(bytes);
    decoder.disable_recursion_limit();
    let value = Seed(0).deserialize(&mut decoder).map_err(|_| Error::Json)?;
    decoder.end().map_err(|_| Error::Json)?;
    Ok(value)
}

struct Stream<R> {
    input: BufReader<R>,
    used: usize,
    limit: usize,
}
impl<R: Read> Stream<R> {
    fn new(reader: R) -> Self {
        Self { input: BufReader::with_capacity(8192, reader), used: 0, limit: MAX_FRAMING_BYTES }
    }
    fn reset(&mut self, limit: usize) {
        self.used = 0;
        self.limit = limit;
    }
    fn peek(&mut self) -> Result<Option<u8>, Error> {
        Ok(self.input.fill_buf().map_err(|_| Error::Io)?.first().copied())
    }
    fn take(&mut self) -> Result<u8, Error> {
        if self.used >= self.limit {
            return Err(Error::Limit);
        }
        let byte = self.peek()?.ok_or(Error::Json)?;
        self.input.consume(1);
        self.used += 1;
        Ok(byte)
    }
    fn spaces(&mut self) -> Result<(), Error> {
        while matches!(self.peek()?, Some(b' ' | b'\r' | b'\n' | b'\t')) {
            self.take()?;
        }
        Ok(())
    }
    fn expect(&mut self, byte: u8) -> Result<(), Error> {
        self.spaces()?;
        if self.take()? != byte {
            return Err(Error::Json);
        }
        Ok(())
    }
    fn value(&mut self) -> Result<Zeroizing<Vec<u8>>, Error> {
        self.spaces()?;
        let mut bytes = Zeroizing::new(Vec::new());
        let first = self.peek()?.ok_or(Error::Json)?;
        if first == b'{' || first == b'[' {
            let mut depth = 0_usize;
            let mut quoted = false;
            let mut escaped = false;
            loop {
                let byte = self.take()?;
                bytes.push(byte);
                if quoted {
                    if escaped {
                        escaped = false;
                    } else if byte == b'\\' {
                        escaped = true;
                    } else if byte == b'"' {
                        quoted = false;
                    }
                } else {
                    match byte {
                        b'"' => quoted = true,
                        b'{' | b'[' => {
                            depth += 1;
                            if depth > MAX_JSON_DEPTH {
                                return Err(Error::Limit);
                            }
                        }
                        b'}' | b']' => {
                            depth = depth.checked_sub(1).ok_or(Error::Json)?;
                            if depth == 0 {
                                break;
                            }
                        }
                        _ => {}
                    }
                }
            }
        } else if first == b'"' {
            bytes.push(self.take()?);
            let mut escaped = false;
            loop {
                let byte = self.take()?;
                bytes.push(byte);
                if escaped {
                    escaped = false;
                } else if byte == b'\\' {
                    escaped = true;
                } else if byte == b'"' {
                    break;
                }
            }
        } else {
            while let Some(byte) = self.peek()? {
                if matches!(byte, b' ' | b'\r' | b'\n' | b'\t' | b',' | b'}' | b']') {
                    break;
                }
                bytes.push(self.take()?);
            }
            if bytes.is_empty() {
                return Err(Error::Json);
            }
        }
        Ok(bytes)
    }
}

pub(super) fn read_archive(
    reader: impl Read,
    mut on_entry: impl FnMut(Entry) -> Result<(), Error>,
) -> Result<Summary, Error> {
    let mut stream = Stream::new(reader);
    stream.expect(b'{')?;
    let mut metadata = SensitiveJson(Value::Object(Map::new()));
    let mut members = HashSet::new();
    let mut ids = HashSet::new();
    let mut objects = 0;
    let mut requires_included = false;
    let mut requires_omitted = false;
    let mut first = true;
    let mut saw_objects = false;
    loop {
        stream.spaces()?;
        if stream.peek()? == Some(b'}') {
            stream.take()?;
            break;
        }
        if !first {
            stream.expect(b',')?;
        }
        first = false;
        let raw = stream.value()?;
        let key = parse(&raw)?;
        let key = mapping::text(&key.0)?;
        if !["format", "model_version", "exported_at", "source", "secrets", "objects"]
            .contains(&key)
        {
            return Err(Error::Unsupported);
        }
        if !members.insert(key.to_string()) {
            return Err(Error::Json);
        }
        stream.expect(b':')?;
        if key == "objects" {
            stream.expect(b'[')?;
            let mut first_entry = true;
            loop {
                stream.reset(MAX_ENTRY_BYTES);
                stream.spaces()?;
                if stream.peek()? == Some(b']') {
                    stream.limit = MAX_FRAMING_BYTES;
                    stream.take()?;
                    break;
                }
                if !first_entry {
                    stream.expect(b',')?;
                }
                first_entry = false;
                if objects >= MAX_OBJECTS {
                    return Err(Error::Limit);
                }
                let raw = stream.value()?;
                let value = parse(&raw)?;
                let entry = mapping::parse_entry(&value.0)?;
                if !ids.insert(entry.id) {
                    return Err(Error::DuplicateId);
                }
                requires_included |=
                    mapping::validate_omissions(&entry, Some(SecretMode::Omitted)).is_err();
                requires_omitted |=
                    mapping::validate_omissions(&entry, Some(SecretMode::Included)).is_err();
                on_entry(entry)?;
                objects += 1;
            }
            saw_objects = true;
        } else {
            let raw = stream.value()?;
            let mut value = parse(&raw)?;
            let Value::Object(fields) = &mut metadata.0 else { unreachable!() };
            fields.insert(key.to_string(), value.take());
        }
    }
    if !saw_objects || members.len() != 6 {
        return Err(Error::Unsupported);
    }
    stream.spaces()?;
    if stream.peek()?.is_some() {
        return Err(Error::Json);
    }
    let header = parse_header(&metadata.0)?;
    if header.secrets == SecretMode::Omitted && requires_included
        || header.secrets == SecretMode::Included && requires_omitted
    {
        return Err(Error::SecretPolicy);
    }
    Ok(Summary { header, objects })
}

fn parse_header(value: &Value) -> Result<Header, Error> {
    let fields = mapping::object(value)?;
    mapping::exact(fields, &["format", "model_version", "exported_at", "source", "secrets"])?;
    if mapping::text(mapping::required(fields, "format")?)? != "scoplen-export"
        || mapping::uint(mapping::required(fields, "model_version")?)? != 1
    {
        return Err(Error::Unsupported);
    }
    let source = mapping::object(mapping::required(fields, "source")?)?;
    mapping::exact(source, &["kind", "id"])?;
    Ok(Header {
        exported_at: mapping::uint(mapping::required(fields, "exported_at")?)?,
        source_kind: match mapping::text(mapping::required(source, "kind")?)? {
            "device" => SourceKind::Device,
            "organization" => SourceKind::Organization,
            _ => return Err(Error::Unsupported),
        },
        source_id: mapping::uuid(mapping::text(mapping::required(source, "id")?)?)?,
        secrets: match mapping::text(mapping::required(fields, "secrets")?)? {
            "omitted" => SecretMode::Omitted,
            "included" => SecretMode::Included,
            _ => return Err(Error::Unsupported),
        },
    })
}

pub(super) fn write_archive(
    writer: &mut impl Write,
    header: &Header,
    entries: impl IntoIterator<Item = Result<Entry, Error>>,
) -> Result<usize, Error> {
    crate::validate_uuid_v7(header.source_id).map_err(|_| Error::Value)?;
    let source = match header.source_kind {
        SourceKind::Device => "device",
        SourceKind::Organization => "organization",
    };
    let secrets = match header.secrets {
        SecretMode::Omitted => "omitted",
        SecretMode::Included => "included",
    };
    let prefix = format!(
        "{{\"format\":\"scoplen-export\",\"model_version\":1,\"exported_at\":{},\"source\":{{\"kind\":\"{source}\",\"id\":\"{}\"}},\"secrets\":\"{secrets}\",\"objects\":[",
        header.exported_at, header.source_id
    );
    writer.write_all(prefix.as_bytes()).map_err(|_| Error::Io)?;
    let mut ids = HashSet::new();
    let mut count = 0;
    for entry in entries {
        let entry = entry?;
        if count >= MAX_OBJECTS {
            return Err(Error::Limit);
        }
        if !ids.insert(entry.id) {
            return Err(Error::DuplicateId);
        }
        entry.validate(Some(header.secrets))?;
        let value = mapping::entry_json(&entry)?;
        let mut bounded = BoundedWriter { writer, remaining: MAX_ENTRY_BYTES };
        if count > 0 {
            bounded.write_all(b",").map_err(|_| Error::Io)?;
        }
        serde_json::to_writer(&mut bounded, &value.0).map_err(|_| Error::Io)?;
        count += 1;
    }
    writer.write_all(b"]}").map_err(|_| Error::Io)?;
    writer.flush().map_err(|_| Error::Io)?;
    Ok(count)
}

struct BoundedWriter<'a, W> {
    writer: &'a mut W,
    remaining: usize,
}
impl<W: Write> Write for BoundedWriter<'_, W> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > self.remaining {
            return Err(std::io::Error::from(std::io::ErrorKind::InvalidData));
        }
        let written = self.writer.write(bytes)?;
        self.remaining -= written;
        Ok(written)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.writer.flush()
    }
}
