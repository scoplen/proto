// SPDX-License-Identifier: Apache-2.0
//! D-142 behavior through the published model API and independent named JSON fixtures.

use scoplen_model::{
    FieldEntry, FieldPath, Hlc, MapKey, Object, ObjectType, Tombstone,
    cbor::Value,
    portable::{self, Entry, Error, Header, SecretMode, SourceKind},
};
use scoplen_test_vectors::{MODEL_PORTABLE, VectorDocument};
use std::{
    collections::BTreeMap,
    fmt::Write as _,
    io::{self, Read},
};
use uuid::Uuid;

fn id(n: u8) -> Uuid {
    Uuid::parse_str(&format!("01900000-0000-7000-8000-{n:012x}")).unwrap()
}
fn header(mode: SecretMode) -> Header {
    Header {
        exported_at: u64::MAX,
        source_kind: SourceKind::Device,
        source_id: id(30),
        secrets: mode,
    }
}
fn fixtures() -> VectorDocument {
    VectorDocument::from_bytes(MODEL_PORTABLE).unwrap()
}
fn decode(bytes: &[u8]) -> Result<(portable::Summary, Vec<Entry>), Error> {
    let mut entries = Vec::new();
    let summary = portable::read_archive(bytes, |entry| {
        entries.push(entry);
        Ok(())
    })?;
    Ok((summary, entries))
}
fn host() -> Object {
    let mut object = Object::new(id(1), ObjectType::HOST, 1).unwrap();
    set(&mut object, 1, Value::Text("Fixture host".into()));
    set(&mut object, 2, Value::Text("example.test".into()));
    object
}
fn set(object: &mut Object, field: u64, value: Value) {
    object
        .insert(
            FieldPath::field(field).unwrap(),
            FieldEntry::new(value, Hlc::at(1).unwrap(), id(30)).unwrap(),
        )
        .unwrap();
}

#[test]
fn independent_vectors_cover_all_eleven_types_omissions_and_strict_rejections() {
    for vector in fixtures().vectors {
        match vector.kind.as_str() {
            "model.portable.accept" => {
                let (summary, entries) = decode(vector.input.as_bytes())
                    .unwrap_or_else(|error| panic!("{}: {error}", vector.id));
                assert_eq!(summary.objects.to_string(), vector.expected, "{}", vector.id);
                let mut encoded = Vec::new();
                portable::write_archive(
                    &mut encoded,
                    &summary.header,
                    entries.iter().cloned().map(Ok),
                )
                .unwrap();
                let (_, again) = decode(&encoded).unwrap();
                assert_eq!(entries, again, "{}", vector.id);
                for entry in &entries {
                    if entry.omitted_secrets().iter().any(|p| p == "/secret") {
                        assert_eq!(
                            entry.to_object(id(100), Hlc::at(2).unwrap(), id(30)),
                            Err(Error::MissingSecret)
                        );
                    } else {
                        let model =
                            entry.to_object(entry.id(), Hlc::at(2).unwrap(), id(30)).unwrap();
                        model.encode().unwrap();
                    }
                }
            }
            "model.portable.reject" => {
                assert!(decode(vector.input.as_bytes()).is_err(), "{}", vector.id);
            }
            "model.portable.objects" => {
                let (_, entries) = decode(vector.input.as_bytes()).unwrap();
                let expected: Vec<String> = serde_json::from_str(&vector.expected).unwrap();
                assert_eq!(entries.len(), expected.len());
                for (entry, expected) in entries.iter().zip(expected) {
                    let object = entry.to_object(entry.id(), Hlc::at(1).unwrap(), id(30)).unwrap();
                    let mut actual = String::new();
                    for byte in object.encode().unwrap() {
                        write!(&mut actual, "{byte:02x}").unwrap();
                    }
                    assert_eq!(actual, expected, "{}", vector.id);
                }
            }
            _ => panic!("unexpected fixture kind"),
        }
    }
}

#[test]
fn public_json_schema_is_closed_and_names_every_registered_type() {
    let schema: serde_json::Value = serde_json::from_str(portable::JSON_SCHEMA).unwrap();
    assert_eq!(schema["additionalProperties"], false);
    for n in 1..=11 {
        let name = ObjectType::from_wire(n).unwrap().to_string();
        assert_eq!(schema["$defs"][&name]["properties"]["type"]["const"], name);
        assert_eq!(schema["$defs"][&name]["properties"]["fields"]["additionalProperties"], false);
    }
}

#[test]
fn live_projection_omits_clocks_tombstones_and_clears_without_inserting_defaults() {
    let mut object = host();
    set(&mut object, 7, Value::Null);
    for (key, value) in [("gone", Value::Null), ("live", Value::Text("value".into()))] {
        object
            .insert(
                FieldPath::map_entry(4, MapKey::Text(key.into())).unwrap(),
                FieldEntry::new(value, Hlc::at(1).unwrap(), id(30)).unwrap(),
            )
            .unwrap();
    }
    let entry = Entry::from_object(&object, SecretMode::Omitted).unwrap().unwrap();
    assert!(!entry.fields().contains_key(&FieldPath::Field(3)));
    assert!(!entry.fields().contains_key(&FieldPath::Field(7)));
    assert_eq!(entry.fields().len(), 3);
    let mut bytes = Vec::new();
    portable::write_archive(&mut bytes, &header(SecretMode::Omitted), [Ok(entry)]).unwrap();
    let json = String::from_utf8(bytes).unwrap();
    for absent in ["clock", "tombstone", "origin", "gone"] {
        assert!(!json.contains(absent));
    }
    object.set_tombstone(Some(Tombstone::new(Hlc::at(2).unwrap(), id(30)).unwrap()));
    assert!(Entry::from_object(&object, SecretMode::Omitted).unwrap().is_none());
    set(&mut object, 99, Value::Text("Future deleted field".into()));
    assert!(Entry::from_object(&object, SecretMode::Omitted).unwrap().is_none());
}

#[test]
fn portable_rejection_does_not_change_replication_unknown_field_preservation() {
    let mut object = host();
    set(&mut object, 99, Value::Null);
    assert_eq!(Object::decode(&object.encode().unwrap()).unwrap(), object);
    assert_eq!(Entry::from_object(&object, SecretMode::Omitted), Err(Error::Unsupported));
    object.fields.remove(&FieldPath::Field(99));
    let mut future = Object::new(id(2), ObjectType::from_wire(99).unwrap(), 2).unwrap();
    set(&mut future, 1, Value::Text("Future".into()));
    assert!(Object::decode(&future.encode().unwrap()).is_ok());
    assert_eq!(Entry::from_object(&future, SecretMode::Omitted), Err(Error::Unsupported));
}

#[test]
fn cleared_preference_value_stays_absent_while_nested_null_remains_a_value() {
    let mut preference = Object::new(id(10), ObjectType::PREFERENCE, 1).unwrap();
    set(&mut preference, 1, Value::Text("fixture.preference".into()));
    let missing = Entry::from_object(&preference, SecretMode::Omitted).unwrap().unwrap();
    set(&mut preference, 2, Value::Null);
    let cleared = Entry::from_object(&preference, SecretMode::Omitted).unwrap().unwrap();
    assert_eq!(missing, cleared);
    assert!(!cleared.fields().contains_key(&FieldPath::Field(2)));
    let mut encoded = Vec::new();
    portable::write_archive(&mut encoded, &header(SecretMode::Omitted), [Ok(cleared)]).unwrap();
    let (_, entries) = decode(&encoded).unwrap();
    let model = entries[0].to_object(id(11), Hlc::at(2).unwrap(), id(30)).unwrap();
    assert!(!model.fields.contains_key(&FieldPath::Field(2)));

    set(&mut preference, 2, Value::Array(vec![Value::Null]));
    let nested = Entry::from_object(&preference, SecretMode::Omitted).unwrap().unwrap();
    let mut encoded = Vec::new();
    portable::write_archive(&mut encoded, &header(SecretMode::Omitted), [Ok(nested.clone())])
        .unwrap();
    assert_eq!(decode(&encoded).unwrap().1, [nested]);
    let mut invalid: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
    invalid["objects"][0]["fields"]["value"] = serde_json::Value::Null;
    assert_eq!(decode(&serde_json::to_vec(&invalid).unwrap()), Err(Error::Value));
}

#[test]
fn secret_projection_redacts_password_and_snippet_defaults_with_exact_pointers() {
    let (summary, entries) = decode(fixtures().vectors[0].input.as_bytes()).unwrap();
    let mut projected = Vec::new();
    for entry in &entries {
        let object = entry.to_object(entry.id(), Hlc::at(1).unwrap(), id(30)).unwrap();
        projected.push(Entry::from_object(&object, SecretMode::Omitted).unwrap().unwrap());
    }
    let credential = projected.iter().find(|e| e.object_type() == ObjectType::CREDENTIAL).unwrap();
    assert_eq!(credential.omitted_secrets(), ["/secret"]);
    assert!(!credential.fields().contains_key(&FieldPath::Field(4)));
    let snippet = projected.iter().find(|e| e.object_type() == ObjectType::SNIPPET).unwrap();
    assert_eq!(snippet.omitted_secrets(), ["/variables/secret~1key~0/default"]);
    let mut out = Vec::new();
    let mut metadata = summary.header;
    metadata.secrets = SecretMode::Omitted;
    portable::write_archive(&mut out, &metadata, projected.into_iter().map(Ok)).unwrap();
    decode(&out).unwrap();
    assert!(!String::from_utf8(out).unwrap().contains("c3ludGhldGlj"));
}

struct SmallReads<'a> {
    input: &'a [u8],
    max_requested: usize,
}
impl Read for SmallReads<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        self.max_requested = self.max_requested.max(out.len());
        let n = 7.min(out.len()).min(self.input.len());
        out[..n].copy_from_slice(&self.input[..n]);
        self.input = &self.input[n..];
        Ok(n)
    }
}

#[test]
fn reader_streams_bounded_chunks_and_never_requires_a_whole_archive_buffer() {
    let fixture = &fixtures().vectors[0].input;
    let mut source = SmallReads { input: fixture.as_bytes(), max_requested: 0 };
    let mut count = 0;
    let result = portable::read_archive(&mut source, |_| {
        count += 1;
        Ok(())
    })
    .unwrap();
    assert_eq!(count, result.objects);
    assert!(source.max_requested <= 8192);
}

struct FailedEof<'a>(&'a [u8]);
impl Read for FailedEof<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.0.is_empty() {
            return Err(io::ErrorKind::InvalidData.into());
        }
        self.0.read(out)
    }
}

#[test]
fn entry_callbacks_are_tentative_until_authenticated_reader_eof() {
    let fixture = &fixtures().vectors[0].input;
    let mut staged = 0;
    let result = portable::read_archive(FailedEof(fixture.as_bytes()), |_| {
        staged += 1;
        Ok(())
    });
    assert!(staged > 0);
    assert_eq!(result, Err(Error::Io));
    let mut late: serde_json::Value = serde_json::from_str(fixture).unwrap();
    late["secrets"] = serde_json::json!("omitted");
    let objects = serde_json::to_string(&late["objects"]).unwrap();
    let raw = format!(
        "{{\"objects\":{objects},\"format\":\"scoplen-export\",\"model_version\":1,\"exported_at\":0,\"source\":{{\"kind\":\"device\",\"id\":\"{}\"}},\"secrets\":\"omitted\"}}",
        id(30)
    );
    assert_eq!(portable::read_archive(raw.as_bytes(), |_| Ok(())), Err(Error::SecretPolicy));
}

#[test]
fn oversized_entry_is_stopped_before_parsing_or_visiting_it() {
    let prefix = b"{\"objects\":[{\"fields\":{\"name\":\"";
    let source =
        prefix.as_slice().chain(io::repeat(b'x').take(portable::MAX_ENTRY_BYTES as u64 + 1));
    let mut visited = false;
    assert_eq!(
        portable::read_archive(source, |_| {
            visited = true;
            Ok(())
        }),
        Err(Error::Limit)
    );
    assert!(!visited);
}

#[test]
fn framing_budgets_do_not_leave_an_unbounded_whitespace_channel() {
    let mut oversized = vec![b' '; portable::MAX_FRAMING_BYTES + 1];
    oversized.extend_from_slice(b"{}");
    assert_eq!(portable::read_archive(oversized.as_slice(), |_| Ok(())), Err(Error::Limit));
    let mut empty = Vec::new();
    portable::write_archive(&mut empty, &header(SecretMode::Omitted), []).unwrap();
    empty.extend(std::iter::repeat_n(b' ', portable::MAX_FRAMING_BYTES + 1));
    assert_eq!(portable::read_archive(empty.as_slice(), |_| Ok(())), Err(Error::Limit));

    let mut split = Vec::new();
    portable::write_archive(&mut split, &header(SecretMode::Omitted), []).unwrap();
    split.truncate(split.len() - 2);
    split.extend(std::iter::repeat_n(b' ', portable::MAX_FRAMING_BYTES / 2));
    split.extend_from_slice(b"]}");
    split.extend(std::iter::repeat_n(b' ', portable::MAX_FRAMING_BYTES / 2));
    assert_eq!(portable::read_archive(split.as_slice(), |_| Ok(())), Err(Error::Limit));
}

#[test]
fn object_map_text_layout_and_arbitrary_value_depth_limits_remain_the_model_limits() {
    let mut object = host();
    set(&mut object, 7, Value::Text("x".repeat(scoplen_model::MAX_TEXT_BYTES)));
    assert!(Entry::from_object(&object, SecretMode::Omitted).is_ok());
    object.fields.get_mut(&FieldPath::Field(7)).unwrap().value =
        Value::Text("x".repeat(scoplen_model::MAX_TEXT_BYTES + 1));
    assert!(Entry::from_object(&object, SecretMode::Omitted).is_err());
}

#[test]
fn tagged_arrays_do_not_shrink_supported_cbor_depth() {
    let mut value = Value::Bool(true);
    for _ in 0..125 {
        value = Value::Array(vec![value]);
    }
    let fields = BTreeMap::from([
        (FieldPath::Field(1), Value::Text("deep".into())),
        (FieldPath::Field(2), value),
    ]);
    let entry = Entry::from_fields(id(10), ObjectType::PREFERENCE, fields, vec![]).unwrap();
    let mut bytes = Vec::new();
    portable::write_archive(&mut bytes, &header(SecretMode::Omitted), [Ok(entry)]).unwrap();
    decode(&bytes).unwrap();
}

#[test]
fn exact_entry_byte_boundary_counts_raw_json_before_parsing() {
    let entry = Entry::from_object(&host(), SecretMode::Omitted).unwrap().unwrap();
    let mut encoded = Vec::new();
    portable::write_archive(&mut encoded, &header(SecretMode::Omitted), [Ok(entry)]).unwrap();
    let start = encoded.windows(12).position(|window| window == b"\"objects\":[{").unwrap() + 11;
    let end = encoded.len() - 2;
    let padding = portable::MAX_ENTRY_BYTES - (end - start);
    let mut exact = Vec::with_capacity(encoded.len() + padding);
    exact.extend_from_slice(&encoded[..end - 1]);
    exact.extend(std::iter::repeat_n(b' ', padding));
    exact.extend_from_slice(&encoded[end - 1..]);
    assert_eq!(decode(&exact).unwrap().0.objects, 1);
    exact.insert(end - 1, b' ');
    assert_eq!(decode(&exact).unwrap_err(), Error::Limit);
}

#[test]
fn layout_and_complete_object_byte_budgets_are_not_replaced_by_json_budgets() {
    let mut workspace = Object::new(id(9), ObjectType::WORKSPACE, 1).unwrap();
    set(&mut workspace, 1, Value::Text("Fixture workspace".into()));
    set(&mut workspace, 2, Value::Bytes(vec![0; scoplen_model::MAX_WORKSPACE_LAYOUT_BYTES]));
    assert!(Entry::from_object(&workspace, SecretMode::Omitted).is_ok());
    workspace.fields.get_mut(&FieldPath::Field(2)).unwrap().value =
        Value::Bytes(vec![0; scoplen_model::MAX_WORKSPACE_LAYOUT_BYTES + 1]);
    assert!(Entry::from_object(&workspace, SecretMode::Omitted).is_err());
    let fields = BTreeMap::from([
        (FieldPath::Field(2), Value::UInt(1)),
        (FieldPath::Field(3), Value::UInt(1)),
        (FieldPath::Field(4), Value::Bytes(vec![0; scoplen_model::MAX_OBJECT_BYTES])),
    ]);
    assert!(Entry::from_fields(id(3), ObjectType::CREDENTIAL, fields, vec![]).is_err());
}

#[test]
fn map_entry_limits_and_natural_absent_secret_defaults_are_preserved() {
    let fields = BTreeMap::from([
        (FieldPath::Field(1), Value::Text("Fixture snippet".into())),
        (FieldPath::Field(2), Value::Text("{{secret}}".into())),
        (
            FieldPath::map_entry(3, MapKey::Text("secret".into())).unwrap(),
            Value::Map(vec![(Value::UInt(1), Value::UInt(4))]),
        ),
    ]);
    let entry = Entry::from_fields(id(7), ObjectType::SNIPPET, fields, vec![]).unwrap();
    let model = entry.to_object(id(8), Hlc::at(1).unwrap(), id(30)).unwrap();
    let projected = Entry::from_object(&model, SecretMode::Omitted).unwrap().unwrap();
    let no_omissions: &[String] = &[];
    assert_eq!(projected.omitted_secrets(), no_omissions);
    let mut fields = host()
        .fields
        .into_iter()
        .map(|(key, value)| (key, value.value))
        .collect::<BTreeMap<_, _>>();
    for n in 0..scoplen_model::MAX_MAP_ENTRIES {
        fields.insert(
            FieldPath::map_entry(4, MapKey::Text(n.to_string())).unwrap(),
            Value::Text("value".into()),
        );
    }
    assert!(Entry::from_fields(id(1), ObjectType::HOST, fields, vec![]).is_err());
}

#[test]
fn maximum_object_count_is_inclusive_for_streamed_read_and_write() {
    let entries = |count: usize| {
        (0..count).map(|n| {
            let mut bytes = id(1).into_bytes();
            bytes[10..].copy_from_slice(&(n as u64).to_be_bytes()[2..]);
            Entry::from_fields(
                Uuid::from_bytes(bytes),
                ObjectType::GATEWAY_NETWORK,
                BTreeMap::new(),
                vec![],
            )
        })
    };
    let mut encoded = Vec::new();
    assert_eq!(
        portable::write_archive(
            &mut encoded,
            &header(SecretMode::Omitted),
            entries(portable::MAX_OBJECTS)
        )
        .unwrap(),
        portable::MAX_OBJECTS
    );
    let mut count = 0;
    let summary = portable::read_archive(encoded.as_slice(), |_| {
        count += 1;
        Ok(())
    })
    .unwrap();
    assert_eq!(count, portable::MAX_OBJECTS);
    assert_eq!(summary.objects, count);
    assert_eq!(
        portable::write_archive(
            io::sink(),
            &header(SecretMode::Omitted),
            entries(portable::MAX_OBJECTS + 1)
        ),
        Err(Error::Limit)
    );
    encoded.truncate(encoded.len() - 2);
    encoded.extend_from_slice(b",{}");
    encoded.extend_from_slice(b"]}");
    assert_eq!(portable::read_archive(encoded.as_slice(), |_| Ok(())), Err(Error::Limit));
}

#[test]
fn no_secret_field_or_pointer_is_disclosed_by_entry_or_error_debug() {
    let entries = decode(fixtures().vectors[0].input.as_bytes()).unwrap().1;
    for entry in entries {
        let debug = format!("{entry:?}");
        for secret in ["synthetic", "secret/key", "Fixture host", "c3ludGhldGlj"] {
            assert!(!debug.contains(secret));
        }
    }
    for error in [Error::Json, Error::Value, Error::SecretPolicy, Error::MissingSecret] {
        assert!(!format!("{error:?}: {error}").contains("synthetic"));
    }
}

#[test]
fn duplicate_writer_ids_and_output_failures_are_reported_without_success() {
    struct Refuse;
    impl io::Write for Refuse {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::ErrorKind::Other.into())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let entry = Entry::from_object(&host(), SecretMode::Omitted).unwrap().unwrap();
    let mut out = Vec::new();
    assert_eq!(
        portable::write_archive(
            &mut out,
            &header(SecretMode::Omitted),
            [Ok(entry.clone()), Ok(entry)]
        ),
        Err(Error::DuplicateId)
    );
    assert_eq!(decode(&out).unwrap_err(), Error::Json);
    assert_eq!(portable::write_archive(Refuse, &header(SecretMode::Omitted), []), Err(Error::Io));
}

#[test]
fn consumer_refusal_stops_streaming_without_reporting_a_complete_archive() {
    let fixture = &fixtures().vectors[0].input;
    let mut visited = 0;
    assert_eq!(
        portable::read_archive(fixture.as_bytes(), |_| {
            visited += 1;
            Err(Error::Consumer)
        }),
        Err(Error::Consumer)
    );
    assert_eq!(visited, 1);
    let entry = Entry::from_object(&host(), SecretMode::Omitted).unwrap().unwrap();
    let mut out = Vec::new();
    assert_eq!(
        portable::write_archive(
            &mut out,
            &header(SecretMode::Omitted),
            [Ok(entry), Err(Error::Consumer)]
        ),
        Err(Error::Consumer)
    );
    assert!(decode(&out).is_err());
}

#[test]
fn malformed_utf8_and_excessive_json_nesting_are_rejected_before_entry_delivery() {
    let entry = Entry::from_object(&host(), SecretMode::Omitted).unwrap().unwrap();
    let mut encoded = Vec::new();
    portable::write_archive(&mut encoded, &header(SecretMode::Omitted), [Ok(entry)]).unwrap();
    let name = encoded.windows(7).position(|window| window == b"Fixture").unwrap();
    encoded[name] = 0xff;
    assert_eq!(decode(&encoded), Err(Error::Json));

    let mut nested = b"{\"objects\":[".to_vec();
    nested.extend(std::iter::repeat_n(b'[', portable::MAX_JSON_DEPTH + 1));
    let mut visited = false;
    assert_eq!(
        portable::read_archive(nested.as_slice(), |_| {
            visited = true;
            Ok(())
        }),
        Err(Error::Limit)
    );
    assert!(!visited);
}

proptest::proptest! {
    #[test]
    fn arbitrary_cbor_scalar_domains_round_trip_without_json_precision_loss(
        unsigned: u64,
        bytes in proptest::collection::vec(proptest::prelude::any::<u8>(),0..128),
        text in "[ -~]{0,64}",
        boolean: bool,
    ) {
        let value = Value::Array(vec![
            Value::UInt(unsigned),
            Value::Int(-1-i128::from(unsigned)),
            Value::Bytes(bytes.clone()),
            Value::Text(text),
            Value::Bool(boolean),
            Value::Null,
            Value::Map(vec![(Value::Array(vec![Value::Bytes(bytes)]),Value::Bool(boolean))]),
        ]);
        let fields = BTreeMap::from([(FieldPath::Field(1),Value::Text("property".into())),(FieldPath::Field(2),value)]);
        let entry = Entry::from_fields(id(10),ObjectType::PREFERENCE,fields,vec![]).unwrap();
        let mut encoded = Vec::new();
        portable::write_archive(&mut encoded,&header(SecretMode::Omitted),[Ok(entry.clone())]).unwrap();
        let (_,again)=decode(&encoded).unwrap();
        proptest::prop_assert_eq!(&again[0],&entry);
    }
}
