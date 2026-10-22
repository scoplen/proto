// SPDX-License-Identifier: Apache-2.0
//! K-1 object references exclude identity metadata and cleared map entries.

use std::collections::HashSet;

use scoplen_model::{
    FieldEntry, FieldPath, Hlc, MapKey, Object, ObjectType, Tombstone, cbor::Value, is_orphaned,
    references,
};
use uuid::Uuid;

fn id(seed: u8) -> Uuid {
    Uuid::parse_str(&format!("00000000-0000-7000-8000-{seed:012x}")).unwrap()
}

fn reference(seed: u8) -> Value {
    Value::Bytes(id(seed).as_bytes().to_vec())
}

fn field(object: &mut Object, path: FieldPath, value: Value) {
    object.insert(path, FieldEntry::new(value, Hlc::at(1).unwrap(), id(250)).unwrap()).unwrap();
}

fn scalar(object: &mut Object, number: u64, value: Value) {
    field(object, FieldPath::field(number).unwrap(), value);
}

fn member(object: &mut Object, number: u64, key: u8, value: Value) {
    field(
        object,
        FieldPath::map_entry(number, MapKey::Bytes(id(key).as_bytes().to_vec())).unwrap(),
        value,
    );
}

fn named(kind: ObjectType) -> Object {
    let mut object = Object::new(id(1), kind, 1).unwrap();
    scalar(&mut object, 1, Value::Text("Local inventory".into()));
    object
}

fn round_trip(object: &Object) -> Object {
    Object::decode(&object.encode().expect("valid K-1 object")).unwrap()
}

#[test]
fn host_default_profile_and_live_groups_are_object_references() {
    let mut host = named(ObjectType::HOST);
    scalar(&mut host, 2, Value::Text("example.com".into()));
    scalar(&mut host, 8, reference(4));
    member(&mut host, 5, 5, Value::Bool(true));
    member(&mut host, 5, 6, Value::Null);
    scalar(&mut host, 99, reference(99));
    let host = round_trip(&host);
    assert_eq!(references(&host), vec![id(4), id(5)]);
    assert!(is_orphaned(&host, &HashSet::from([id(4)])));
    assert!(!is_orphaned(&host, &HashSet::from([id(4), id(5)])));
}

#[test]
fn profile_forwards_and_group_parent_follow_the_documented_paths() {
    let mut profile = Object::new(id(1), ObjectType::ACCESS_PROFILE, 1).unwrap();
    scalar(&mut profile, 1, reference(2));
    scalar(&mut profile, 3, Value::Text("root".into()));
    scalar(&mut profile, 4, reference(3));
    scalar(&mut profile, 5, reference(4));
    member(&mut profile, 8, 5, Value::Bool(true));
    member(&mut profile, 8, 6, Value::Null);
    assert_eq!(references(&round_trip(&profile)), vec![id(2), id(3), id(4), id(5)]);
    scalar(&mut profile, 5, Value::UInt(0));
    assert_eq!(references(&round_trip(&profile)), vec![id(2), id(3), id(5)]);

    let mut group = named(ObjectType::HOST_GROUP);
    scalar(&mut group, 2, reference(2));
    assert_eq!(references(&round_trip(&group)), vec![id(2)]);
    scalar(&mut group, 2, Value::Null);
    assert_eq!(references(&round_trip(&group)), Vec::<Uuid>::new());
}

#[test]
fn workspace_session_maps_reference_only_profiles_and_forwards() {
    let mut workspace = named(ObjectType::WORKSPACE);
    member(
        &mut workspace,
        3,
        20,
        Value::Map(vec![
            (Value::UInt(1), reference(2)),
            (Value::UInt(2), Value::UInt(3)),
            (Value::UInt(3), reference(3)),
            (Value::UInt(4), Value::Text("/home".into())),
            (Value::UInt(99), reference(99)),
        ]),
    );
    member(
        &mut workspace,
        3,
        21,
        Value::Map(vec![(Value::UInt(1), reference(2)), (Value::UInt(2), Value::UInt(1))]),
    );
    member(&mut workspace, 3, 22, Value::Null);
    let mut workspace = round_trip(&workspace);
    assert_eq!(references(&workspace), vec![id(2), id(3)]);
    assert!(is_orphaned(&workspace, &HashSet::from([id(2)])));
    workspace.set_tombstone(Some(Tombstone::new(Hlc::at(2).unwrap(), id(250)).unwrap()));
    assert!(!is_orphaned(&workspace, &HashSet::new()));
}

#[test]
fn trust_provenance_and_credential_device_bindings_are_not_object_references() {
    let mut trust = Object::new(id(1), ObjectType::TRUST_RECORD, 1).unwrap();
    scalar(&mut trust, 1, reference(2));
    scalar(&mut trust, 3, Value::Text("ssh-ed25519 public-key".into()));
    scalar(&mut trust, 4, Value::Text("SHA256:fingerprint".into()));
    scalar(&mut trust, 7, reference(7));
    scalar(&mut trust, 8, reference(8));
    let trust = round_trip(&trust);
    assert_eq!(references(&trust), vec![id(2)]);
    assert!(!is_orphaned(&trust, &HashSet::from([id(2)])));

    let mut credential = named(ObjectType::CREDENTIAL);
    scalar(&mut credential, 2, Value::UInt(6));
    scalar(&mut credential, 3, Value::UInt(2));
    member(
        &mut credential,
        5,
        7,
        Value::Map(vec![
            (Value::UInt(1), Value::Text("ssh-ed25519 public-key".into())),
            (Value::UInt(2), Value::Text("This device".into())),
        ]),
    );
    assert_eq!(references(&round_trip(&credential)), Vec::<Uuid>::new());
}

#[test]
fn route_and_forward_references_preserve_existing_paths() {
    let mut route = named(ObjectType::ROUTE);
    scalar(&mut route, 2, Value::UInt(1));
    scalar(&mut route, 3, Value::Array(vec![reference(2), reference(3), reference(2)]));
    assert_eq!(references(&round_trip(&route)), vec![id(2), id(3)]);

    scalar(&mut route, 2, Value::UInt(2));
    scalar(&mut route, 3, Value::Null);
    scalar(&mut route, 4, Value::Text("proxy.example.com:1080".into()));
    scalar(&mut route, 5, reference(4));
    scalar(&mut route, 8, Value::Text("user".into()));
    assert_eq!(references(&round_trip(&route)), vec![id(4)]);

    scalar(&mut route, 2, Value::UInt(5));
    scalar(&mut route, 4, Value::Null);
    scalar(&mut route, 5, Value::Null);
    scalar(&mut route, 8, Value::Null);
    scalar(&mut route, 7, reference(5));
    assert_eq!(references(&round_trip(&route)), vec![id(5)]);

    let mut forward = named(ObjectType::FORWARD);
    scalar(&mut forward, 2, Value::UInt(1));
    scalar(&mut forward, 3, Value::Text("127.0.0.1".into()));
    scalar(&mut forward, 4, Value::UInt(8080));
    scalar(&mut forward, 5, Value::Text(id(99).to_string()));
    scalar(&mut forward, 6, Value::UInt(80));
    scalar(&mut forward, 7, reference(2));
    assert_eq!(references(&round_trip(&forward)), vec![id(2)]);
    scalar(&mut forward, 7, Value::Null);
    assert_eq!(references(&round_trip(&forward)), Vec::<Uuid>::new());
}
