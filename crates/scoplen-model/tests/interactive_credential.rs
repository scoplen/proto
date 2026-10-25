// SPDX-License-Identifier: Apache-2.0
//! D-123 acceptance uses independently encoded bytes through the public object boundary.

use scoplen_model::{
    FieldEntry, FieldPath, Hlc, MapKey, ModelError, Object, cbor, merge, references,
};
use scoplen_test_vectors::VectorDocument;
use uuid::Uuid;

fn bytes(hex: &str) -> Vec<u8> {
    let (pairs, trailing) = hex.as_bytes().as_chunks::<2>();
    assert!(trailing.is_empty(), "vector hex must contain complete bytes");
    pairs
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn vectors() -> VectorDocument {
    VectorDocument::from_bytes(include_bytes!("../../../vectors/interactive-credential.json"))
        .expect("published D-123 vectors")
}

fn interactive() -> Object {
    let document = vectors();
    Object::decode(&bytes(&document.vectors[0].input)).expect("interactive descriptor")
}

#[test]
fn independent_objects_preserve_canonical_bytes_and_reject_saved_material() {
    let document = vectors();
    assert_eq!(document.vectors.len(), 10);
    for vector in document.vectors {
        let input = bytes(&vector.input);
        cbor::decode(&input).expect("negative cases are valid CBOR");
        if vector.kind == "model.object" {
            let object =
                Object::decode(&input).unwrap_or_else(|error| panic!("{}: {error}", vector.id));
            assert_eq!(object.required_uint(2).unwrap(), 8);
            assert_eq!(object.required_uint(3).unwrap(), 3);
            assert_eq!(object.encode().unwrap(), bytes(&vector.expected), "{}", vector.id);
            assert!(references(&object).is_empty(), "{}", vector.id);
        } else {
            assert_eq!(vector.kind, "model.object-invalid");
            assert_eq!(vector.expected, "invalid-fields");
            assert!(
                matches!(Object::decode(&input), Err(ModelError::InvalidFields { .. })),
                "{}",
                vector.id
            );
        }
    }
}

#[test]
fn converting_a_replicated_device_credential_requires_clearing_every_device_entry() {
    let descriptor = interactive();
    let origin = descriptor.field(1).unwrap().origin;
    let device = Uuid::parse_str("03000000-0000-7000-8000-000000000000").unwrap();
    let path = FieldPath::map_entry(5, MapKey::Bytes(device.as_bytes().to_vec())).unwrap();
    let mut original = descriptor.clone();
    original
        .insert(
            FieldPath::field(2).unwrap(),
            FieldEntry::new(cbor::Value::UInt(6), Hlc::at(1).unwrap(), origin).unwrap(),
        )
        .unwrap();
    original
        .insert(
            FieldPath::field(3).unwrap(),
            FieldEntry::new(cbor::Value::UInt(2), Hlc::at(1).unwrap(), origin).unwrap(),
        )
        .unwrap();
    original
        .insert(
            path.clone(),
            FieldEntry::new(
                cbor::Value::Map(vec![
                    (cbor::Value::UInt(1), cbor::Value::Text("ssh-ed25519 synthetic".into())),
                    (cbor::Value::UInt(2), cbor::Value::Text("test".into())),
                ]),
                Hlc::at(1).unwrap(),
                origin,
            )
            .unwrap(),
        )
        .unwrap();
    original.validate().expect("original device credential");

    let mut replacement = descriptor;
    for entry in replacement.fields.values_mut() {
        entry.clock = Hlc::at(2).unwrap();
    }
    let uncleared = merge(&original, &replacement).expect("field merge retains old bindings");
    assert!(
        uncleared.encode().is_err(),
        "uncleared device material cannot cross the object boundary"
    );
    replacement
        .insert(
            path.clone(),
            FieldEntry::new(cbor::Value::Null, Hlc::at(2).unwrap(), origin).unwrap(),
        )
        .unwrap();
    let converted = merge(&original, &replacement).expect("conversion clears old bindings");
    assert_eq!(converted.fields.get(&path).unwrap().value, cbor::Value::Null);
    assert_eq!(Object::decode(&converted.encode().unwrap()).unwrap(), converted);
}
