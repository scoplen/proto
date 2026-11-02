// SPDX-License-Identifier: Apache-2.0
use std::{collections::BTreeMap, fmt::Write as _};

use scoplen_api::{
    inventory::{
        InventoryCreateRequest, InventoryFields, InventoryPage, InventoryReference,
        InventoryReplaceRequest, InventoryResource, InventoryType, MAX_INVENTORY_PAGE_BYTES,
        MAX_INVENTORY_RESOURCE_BYTES,
    },
    organization::{OrganizationCodecError as Error, OrganizationListQuery},
};
use scoplen_model::{
    FieldEntry, FieldPath, Hlc, MAX_OBJECT_BYTES, MAX_TEXT_BYTES, MapKey, Object, ObjectType,
    Tombstone, cbor::Value as Cbor,
};
use scoplen_test_vectors::VectorDocument;
use serde_json::{Value, json};
use uuid::Uuid;

const TIME: &str = "2026-11-01T00:00:00Z";

fn id(n: u16) -> Uuid {
    Uuid::parse_str(&format!("019bdad6-b800-7000-8000-{n:012}")).unwrap()
}

fn fields() -> InventoryFields {
    InventoryFields::from_json(
        InventoryType::Host,
        br#"{"name":"Host","address":"host.example.test"}"#,
    )
    .unwrap()
}

fn resource(n: u16) -> InventoryResource {
    InventoryResource {
        id: id(n),
        etag: "\"content-current\"".into(),
        created_at: TIME.into(),
        updated_at: TIME.into(),
        fields: fields(),
    }
}

fn process(kind: &str, route: &str, input: &[u8]) -> Result<Vec<u8>, Error> {
    let route = InventoryType::from_segment(route)?;
    match kind {
        "inventory.fields" => InventoryFields::from_json(route, input)?.to_json(),
        "inventory.create" => InventoryCreateRequest::from_json(route, input)?.to_json(),
        "inventory.replace" => InventoryReplaceRequest::from_json(route, input)?.to_json(),
        "inventory.resource" => InventoryResource::from_json(route, input)?.to_json(),
        "inventory.page" => InventoryPage::from_json(route, input)?.to_json(),
        _ => panic!("unknown inventory vector kind"),
    }
}

#[test]
fn independent_named_json_and_byte_budget_vectors_use_public_exports() {
    let document =
        VectorDocument::parse_str(include_str!("../../../vectors/organization-inventory.json"))
            .unwrap();
    let mut seen = 0;
    for vector in &document.vectors {
        if vector.kind == "inventory.model" {
            continue;
        }
        let input: Value = serde_json::from_str(&vector.input).unwrap();
        let route = input["type"].as_str().unwrap();
        if vector.kind == "inventory.bound" {
            let base = input["base"].as_str().unwrap();
            let size = usize::try_from(input["bytes"].as_u64().unwrap()).unwrap();
            let text = " ".repeat(size - base.len()) + base;
            let result = process(
                &format!("inventory.{}", input["kind"].as_str().unwrap()),
                route,
                text.as_bytes(),
            );
            assert_eq!(result.is_ok(), vector.expected == "accepted", "{}", vector.id);
        } else {
            let result = process(&vector.kind, route, input["json"].as_str().unwrap().as_bytes());
            if vector.expected == "rejected" {
                assert!(result.is_err(), "{}", vector.id);
            } else {
                assert_eq!(result.unwrap(), vector.expected.as_bytes(), "{}", vector.id);
            }
        }
        seen += 1;
    }
    assert!(seen >= 300);
}

#[test]
fn all_seven_independent_k1_answers_round_trip_with_actual_clocks_and_origins() {
    let document =
        VectorDocument::parse_str(include_str!("../../../vectors/organization-inventory.json"))
            .unwrap();
    let mut seen = 0;
    for vector in document.vectors.iter().filter(|vector| vector.kind == "inventory.model") {
        let input: Value = serde_json::from_str(&vector.input).unwrap();
        let kind = InventoryType::from_segment(input["type"].as_str().unwrap()).unwrap();
        let wire = json!({ "id": input["id"], "etag": "\"content\"", "created_at": TIME,
            "updated_at": TIME, "data": { "schema": 1, "fields": input["fields"] } });
        let resource =
            InventoryResource::from_json(kind, &serde_json::to_vec(&wire).unwrap()).unwrap();
        let writer = Uuid::parse_str(input["writer"].as_str().unwrap()).unwrap();
        let clock = Hlc::from_wire(input["clock"].as_str().unwrap().parse().unwrap()).unwrap();
        let object = resource.fields.to_object(resource.id, clock, writer).unwrap();
        let encoded = object.encode().unwrap();
        let mut hex = String::with_capacity(encoded.len() * 2);
        for byte in &encoded {
            write!(hex, "{byte:02x}").unwrap();
        }
        assert_eq!(hex, vector.expected, "{}", vector.id);
        assert_eq!(object.object_type, kind.object_type());
        assert_eq!(object.schema, 1);
        assert!(object.fields.values().all(|field| field.clock == clock && field.origin == writer));
        let decoded = Object::decode(&encoded).unwrap();
        assert_eq!(InventoryFields::from_object(&decoded).unwrap(), resource.fields);
        seen += 1;
    }
    assert_eq!(seen, 7);
}

#[test]
fn typed_references_follow_only_declared_resource_paths_and_preserve_target_types() {
    let cases = [
        (
            InventoryType::Host,
            json!({ "name": "Host", "address": id(99).to_string(),
            "default_profile": id(20).to_string(), "groups": { (id(30).to_string()): true } }),
            vec![(InventoryType::AccessProfile, 20), (InventoryType::HostGroup, 30)],
        ),
        (
            InventoryType::AccessProfile,
            json!({ "host": id(10).to_string(), "username": "deploy", "route": id(40).to_string() }),
            vec![(InventoryType::Host, 10), (InventoryType::Route, 40)],
        ),
        (
            InventoryType::Route,
            json!({ "name": "Jump", "kind": 1, "hops": [id(20).to_string(), id(21).to_string(), id(20).to_string()] }),
            vec![(InventoryType::AccessProfile, 20), (InventoryType::AccessProfile, 21)],
        ),
        (
            InventoryType::Route,
            json!({ "name": "Managed", "kind": 5, "gateway_network": id(70).to_string() }),
            vec![(InventoryType::GatewayNetwork, 70)],
        ),
        (
            InventoryType::HostGroup,
            json!({ "name": "Group", "parent": id(31).to_string(),
            "defaults": { "route": id(40).to_string(), "username": id(99).to_string() } }),
            vec![(InventoryType::Route, 40), (InventoryType::HostGroup, 31)],
        ),
        (
            InventoryType::TrustRecord,
            json!({ "host": id(10).to_string() }),
            vec![(InventoryType::Host, 10)],
        ),
        (
            InventoryType::Snippet,
            json!({ "name": "Snippet", "template": id(99).to_string(),
            "variables": { "id": { "kind": 1, "default": id(99).to_string() } } }),
            vec![],
        ),
        (
            InventoryType::GatewayNetwork,
            json!({ "name": "Network", "description": id(99).to_string() }),
            vec![],
        ),
    ];
    for (kind, fields, expected) in cases {
        let mut fields =
            InventoryFields::from_json(kind, &serde_json::to_vec(&fields).unwrap()).unwrap();
        if kind == InventoryType::TrustRecord {
            fields = fields.with_trust_attribution(1, id(91), id(90)).unwrap();
        }
        assert_eq!(
            fields.references().unwrap(),
            expected
                .into_iter()
                .map(|(kind, number)| InventoryReference { kind, id: id(number) })
                .collect::<Vec<_>>()
        );
        let object = fields.to_object(id(1), Hlc::from_wire(1).unwrap(), id(90)).unwrap();
        assert_eq!(
            InventoryFields::from_object(&object).unwrap().references(),
            fields.references()
        );
    }
    for (kind, value) in [
        (
            InventoryType::AccessProfile,
            json!({ "host": id(10).to_string(), "username": "deploy", "route": 0 }),
        ),
        (InventoryType::HostGroup, json!({ "name": "Group", "defaults": { "route": "0" } })),
    ] {
        let fields =
            InventoryFields::from_json(kind, &serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(
            fields
                .references()
                .unwrap()
                .iter()
                .all(|reference| reference.kind != InventoryType::Route)
        );
    }
    let value = json!({ "name": "Group", "defaults": { "route": "not-an-object-id" } });
    assert!(
        InventoryFields::from_json(InventoryType::HostGroup, &serde_json::to_vec(&value).unwrap())
            .is_err()
    );
}

#[test]
fn complete_replacement_omits_empty_maps_and_cleared_k1_values_without_changing_personal_bytes() {
    let kind = InventoryType::Host;
    let value = InventoryFields::from_json(
        kind,
        br#"{"name":"Host","address":"host.example.test","tags":{},"groups":{}}"#,
    )
    .unwrap();
    assert_eq!(value, fields());
    let mut object = value.to_object(id(10), Hlc::from_wire(1).unwrap(), id(90)).unwrap();
    let entry = FieldEntry::new(Cbor::Null, Hlc::from_wire(2).unwrap(), id(90)).unwrap();
    object.insert(FieldPath::Field(7), entry.clone()).unwrap();
    object
        .insert(FieldPath::MapEntry { field: 4, key: MapKey::Text("removed".into()) }, entry)
        .unwrap();
    assert_eq!(InventoryFields::from_object(&object).unwrap(), fields());
    for input in [
        br#"{"name":"Host","address":"host.example.test","notes":null}"#.as_slice(),
        br#"{"name":"Host","address":"host.example.test","tags":{"removed":null}}"#.as_slice(),
    ] {
        assert!(InventoryFields::from_json(kind, input).is_err());
    }
    let replacement = InventoryReplaceRequest { fields: value };
    assert_eq!(
        replacement.to_json().unwrap(),
        br#"{"data":{"fields":{"address":"host.example.test","name":"Host"}}}"#
    );
    assert!(!String::from_utf8(replacement.to_json().unwrap()).unwrap().contains("clock"));
}

#[test]
fn organization_restrictions_do_not_change_the_underlying_personal_model() {
    let clock = Hlc::from_wire(1).unwrap();
    let mut personal = Object::new(id(20), ObjectType::ACCESS_PROFILE, 1).unwrap();
    for (field, value) in [
        (1, Cbor::Bytes(id(10).into_bytes().to_vec())),
        (3, Cbor::Text("deploy".into())),
        (4, Cbor::Bytes(id(30).into_bytes().to_vec())),
    ] {
        personal
            .insert(FieldPath::Field(field), FieldEntry::new(value, clock, id(90)).unwrap())
            .unwrap();
    }
    let bytes = personal.encode().unwrap();
    assert_eq!(Object::decode(&bytes).unwrap(), personal);
    assert!(InventoryFields::from_object(&personal).is_err());
    for kind in [
        ObjectType::CREDENTIAL,
        ObjectType::FORWARD,
        ObjectType::WORKSPACE,
        ObjectType::PREFERENCE,
        ObjectType::from_wire(100).unwrap(),
    ] {
        assert!(InventoryType::from_object_type(kind).is_err());
    }
    for kind in InventoryType::ALL {
        assert_eq!(InventoryType::from_segment(kind.segment()), Ok(kind));
        assert_eq!(InventoryType::from_object_type(kind.object_type()), Ok(kind));
    }
}

#[test]
fn trust_attribution_is_response_only_and_binds_the_actual_committing_writer() {
    let trust = InventoryFields::from_json(
        InventoryType::TrustRecord,
        format!("{{\"host\":\"{}\"}}", id(10)).as_bytes(),
    )
    .unwrap();
    let clock = Hlc::from_wire(1).unwrap();
    assert!(trust.to_object(id(60), clock, id(90)).is_err());
    let attributed = trust.with_trust_attribution(u64::MAX, id(91), id(90)).unwrap();
    let object = attributed.to_object(id(60), clock, id(90)).unwrap();
    assert_eq!(object.required_uint(6).unwrap(), u64::MAX);
    assert_eq!(object.required_uuid(7).unwrap(), id(90));
    assert_eq!(object.required_uuid(8).unwrap(), id(91));
    assert!(attributed.to_object(id(60), clock, id(92)).is_err());
    assert!(InventoryCreateRequest { id: id(60), fields: attributed.clone() }.to_json().is_err());
    assert!(InventoryReplaceRequest { fields: attributed.clone() }.to_json().is_err());
    assert!(fields().with_trust_attribution(1, id(91), id(90)).is_err());
    let resource = InventoryResource { id: id(60), fields: attributed, ..resource(60) };
    let encoded = resource.to_json().unwrap();
    assert_eq!(
        InventoryResource::from_json(InventoryType::TrustRecord, &encoded).unwrap(),
        resource
    );
    assert!(
        String::from_utf8(encoded).unwrap().contains("\"accepted_at\":\"18446744073709551615\"")
    );
}

#[test]
fn resource_and_directory_bind_exact_original_http_and_continuation_context() {
    let kind = InventoryType::Host;
    let resource = resource(10);
    let encoded = resource.to_json().unwrap();
    assert_eq!(
        InventoryResource::from_http_json(
            kind,
            &encoded,
            Some(&resource.etag),
            Some("no-store"),
            Some("no-cache")
        )
        .unwrap(),
        resource
    );
    assert_eq!(
        InventoryResource::from_http_json(
            kind,
            &encoded,
            Some("\"wrong\""),
            Some("no-store"),
            Some("no-cache")
        ),
        Err(Error::HttpMetadata)
    );
    assert_eq!(
        InventoryResource::from_http_json(
            kind,
            &encoded,
            Some(&resource.etag),
            Some("public"),
            Some("no-cache")
        ),
        Err(Error::HttpMetadata)
    );
    assert_eq!(resource.validate_for_request(kind, id(11)), Err(Error::Context));
    assert_eq!(resource.validate_for_request(InventoryType::Route, id(10)), Err(Error::Context));
    let page = InventoryPage { kind, items: vec![resource], next_cursor: Some(id(10)) };
    let query = OrganizationListQuery { limit: 1, cursor: Some(id(9)) };
    assert_eq!(page.validate_for_request(kind, query), Ok(()));
    assert_eq!(
        page.validate_for_request(kind, OrganizationListQuery { cursor: Some(id(10)), ..query }),
        Err(Error::Context)
    );
    let encoded = page.to_json().unwrap();
    assert_eq!(
        InventoryPage::from_http_json(kind, &encoded, Some("no-store"), Some("no-cache")).unwrap(),
        page
    );
    assert!(InventoryPage::from_http_json(kind, &encoded, None, Some("no-cache")).is_err());
    let mut mixed = page;
    mixed.kind = InventoryType::Route;
    assert_eq!(mixed.to_json(), Err(Error::Context));
}

#[test]
fn page_checks_each_original_resource_before_discarding_extensions_or_whitespace() {
    let item = String::from_utf8(resource(10).to_json().unwrap()).unwrap();
    let padding = " ".repeat(MAX_INVENTORY_RESOURCE_BYTES + 1 - item.len());
    let original = format!("{{{padding}{}", &item[1..]);
    assert_eq!(original.len(), MAX_INVENTORY_RESOURCE_BYTES + 1);
    let page = format!("{{\"items\":[{original}],\"next_cursor\":null}}");
    assert!(page.len() < MAX_INVENTORY_PAGE_BYTES);
    assert_eq!(
        InventoryPage::from_json(InventoryType::Host, page.as_bytes()),
        Err(Error::TooLarge)
    );
    let value = json!({ "items": vec![serde_json::from_str::<Value>(&item).unwrap(); 501], "next_cursor": null });
    assert!(
        InventoryPage::from_json(InventoryType::Host, &serde_json::to_vec(&value).unwrap())
            .is_err()
    );
    let fields = InventoryFields::from_json(InventoryType::Host, &serde_json::to_vec(&json!({
        "name": "Host", "address": "x".repeat(MAX_TEXT_BYTES), "notes": "x".repeat(MAX_TEXT_BYTES)
    })).unwrap()).unwrap();
    let items = (1..=260)
        .map(|number| InventoryResource { fields: fields.clone(), ..resource(number) })
        .collect();
    let page = InventoryPage { kind: InventoryType::Host, items, next_cursor: None };
    assert_eq!(page.to_json(), Err(Error::TooLarge));
}

#[test]
fn unknown_or_deleted_model_content_cannot_turn_into_a_complete_editable_replacement() {
    let mut object = fields().to_object(id(10), Hlc::from_wire(1).unwrap(), id(90)).unwrap();
    let original = object.clone();
    object
        .insert(
            FieldPath::Field(99),
            FieldEntry::new(Cbor::Text("future".into()), Hlc::from_wire(1).unwrap(), id(90))
                .unwrap(),
        )
        .unwrap();
    assert!(InventoryFields::from_object(&object).is_err());
    object = original.clone();
    object.schema = 2;
    assert!(InventoryFields::from_object(&object).is_err());
    object = original;
    object.set_tombstone(Some(Tombstone::new(Hlc::from_wire(2).unwrap(), id(90)).unwrap()));
    assert!(InventoryFields::from_object(&object).is_err());
    assert!(fields().to_object(Uuid::nil(), Hlc::from_wire(1).unwrap(), id(90)).is_err());
    assert!(fields().to_object(id(10), Hlc::from_wire(1).unwrap(), Uuid::nil()).is_err());
}

#[test]
fn typed_text_map_and_encoded_k1_budgets_are_enforced_through_public_construction() {
    let mut value = json!({ "name": "Host", "address": "host.example.test", "notes": "x".repeat(MAX_TEXT_BYTES) });
    assert!(
        InventoryFields::from_json(InventoryType::Host, &serde_json::to_vec(&value).unwrap())
            .is_ok()
    );
    value["notes"] = Value::String("x".repeat(MAX_TEXT_BYTES + 1));
    assert!(
        InventoryFields::from_json(InventoryType::Host, &serde_json::to_vec(&value).unwrap())
            .is_err()
    );
    let entries = (0..4094)
        .map(|n| (format!("tag-{n:04}"), Value::String(String::new())))
        .collect::<serde_json::Map<_, _>>();
    value = json!({ "name": "Host", "address": "host.example.test", "tags": entries });
    assert!(
        InventoryFields::from_json(InventoryType::Host, &serde_json::to_vec(&value).unwrap())
            .is_ok()
    );
    value["tags"]["one-more"] = Value::String(String::new());
    assert!(
        InventoryFields::from_json(InventoryType::Host, &serde_json::to_vec(&value).unwrap())
            .is_err()
    );
    value["tags"] =
        json!((0..4097).map(|n| (format!("tag-{n:04}"), "")).collect::<BTreeMap<_, _>>());
    assert!(
        InventoryFields::from_json(InventoryType::Host, &serde_json::to_vec(&value).unwrap())
            .is_err()
    );
    let entries = (0..15)
        .map(|n| (format!("tag-{n}"), "x".repeat(MAX_TEXT_BYTES)))
        .collect::<BTreeMap<_, _>>();
    value = json!({ "name": "Host", "address": "host.example.test", "tags": entries, "notes": "" });
    let base =
        InventoryFields::from_json(InventoryType::Host, &serde_json::to_vec(&value).unwrap())
            .unwrap();
    let clock = Hlc::from_wire(u64::MAX).unwrap();
    let size = base.to_object(id(10), clock, id(90)).unwrap().encode().unwrap().len();
    value["notes"] = Value::String("x".repeat(MAX_OBJECT_BYTES - size - 2));
    let exact =
        InventoryFields::from_json(InventoryType::Host, &serde_json::to_vec(&value).unwrap())
            .unwrap();
    assert_eq!(
        exact.to_object(id(10), clock, id(90)).unwrap().encode().unwrap().len(),
        MAX_OBJECT_BYTES
    );
    value["notes"] = Value::String(format!("{}x", value["notes"].as_str().unwrap()));
    let fields =
        InventoryFields::from_json(InventoryType::Host, &serde_json::to_vec(&value).unwrap())
            .unwrap();
    assert_eq!(fields.to_object(id(10), clock, id(90)), Err(Error::TooLarge));
    let short_clock = Hlc::from_wire(0).unwrap();
    value["notes"] = Value::String(String::new());
    let base =
        InventoryFields::from_json(InventoryType::Host, &serde_json::to_vec(&value).unwrap())
            .unwrap();
    let size = base.to_object(id(10), short_clock, id(90)).unwrap().encode().unwrap().len();
    value["notes"] = Value::String("x".repeat(MAX_OBJECT_BYTES - size - 2));
    let short =
        InventoryFields::from_json(InventoryType::Host, &serde_json::to_vec(&value).unwrap())
            .unwrap();
    let object = short.to_object(id(10), short_clock, id(90)).unwrap();
    assert_eq!(object.encode().unwrap().len(), MAX_OBJECT_BYTES);
    assert_eq!(InventoryFields::from_object(&object).unwrap(), short);
    assert_eq!(short.to_object(id(10), clock, id(90)), Err(Error::TooLarge));
    value["notes"] = Value::String(format!("{}x", value["notes"].as_str().unwrap()));
    assert_eq!(
        InventoryFields::from_json(InventoryType::Host, &serde_json::to_vec(&value).unwrap()),
        Err(Error::TooLarge)
    );
}
