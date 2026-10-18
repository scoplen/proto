// SPDX-License-Identifier: Apache-2.0

use scoplen_api::sync::{
    MAX_SYNC_BATCH_BYTES, MAX_SYNC_BATCH_OBJECTS, MAX_SYNC_CONFLICT_BODY_BYTES,
    MAX_SYNC_CONFLICT_PAYLOAD_BYTES, MAX_SYNC_RETAINED_VERSIONS, SyncAckRequest, SyncAckResponse,
    SyncChange, SyncChangesQuery, SyncConflictEntry, SyncConflictProblem, SyncSnapshotResponse,
    SyncVersionsResponse, SyncWrite, SyncWriteAssignment, SyncWriteBatch, SyncWriteBatchResponse,
};
use scoplen_api::{ErrorCode, ProblemDetails};
use scoplen_model::cbor::{self, Value};
use serde_json::Value as JsonValue;
use uuid::Uuid;

fn id(last: u8) -> Uuid {
    Uuid::from_bytes([0, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, last])
}

fn numbered_id(number: u16) -> Uuid {
    let [high, low] = number.to_be_bytes();
    Uuid::from_bytes([0, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, high, low])
}

fn write(object: u8, base_seq: Option<u64>) -> SyncWrite {
    SyncWrite {
        object_id: id(object),
        base_seq,
        payload: vec![0xde, 0xad],
        tombstone: object.is_multiple_of(2),
    }
}

fn change(object: u8, seq: u64) -> SyncChange {
    SyncChange {
        object_id: id(object),
        seq,
        payload: vec![object, 0xbe],
        tombstone: object.is_multiple_of(2),
        signer_device_id: Some(id(object.saturating_add(10))),
    }
}

#[test]
fn published_sync_message_vectors_match_public_codecs() {
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../vectors/sync-messages.json");
    let document = scoplen_test_vectors::VectorDocument::from_path(path).expect("vectors");
    assert_eq!(document.vectors.len(), 8);
    for vector in &document.vectors {
        let expected = decode_hex(&vector.expected);
        match vector.kind.as_str() {
            "sync.writes.request" => {
                let source = write_batch_from_json(&vector.input);
                assert_eq!(source.to_cbor().expect("encode"), expected, "{}", vector.id);
                assert_eq!(SyncWriteBatch::from_cbor(&expected).expect("decode"), source);
            }
            "sync.writes.response" => {
                let source = write_response_from_json(&vector.input);
                assert_eq!(source.to_cbor().expect("encode"), expected, "{}", vector.id);
                assert_eq!(SyncWriteBatchResponse::from_cbor(&expected).expect("decode"), source);
            }
            "sync.writes.conflict" => {
                let source = conflict_from_json(&vector.input);
                assert_eq!(source.to_cbor().expect("encode"), expected, "{}", vector.id);
                assert_eq!(SyncConflictProblem::from_cbor(&expected).expect("decode"), source);
            }
            "sync.ack.request" => {
                let source = SyncAckRequest { cursor: json_number(&vector.input, "cursor") };
                assert_eq!(source.to_cbor().expect("encode"), expected, "{}", vector.id);
                assert_eq!(SyncAckRequest::from_cbor(&expected).expect("decode"), source);
            }
            "sync.ack.response" => {
                let source = SyncAckResponse { cursor: json_number(&vector.input, "cursor") };
                assert_eq!(source.to_cbor().expect("encode"), expected, "{}", vector.id);
                assert_eq!(SyncAckResponse::from_cbor(&expected).expect("decode"), source);
            }
            "sync.snapshot.response" => {
                let source = snapshot_from_json(&vector.input);
                assert_eq!(source.to_cbor().expect("encode"), expected, "{}", vector.id);
                assert_eq!(SyncSnapshotResponse::from_cbor(&expected).expect("decode"), source);
            }
            "sync.versions.response" => {
                let source = versions_from_json(&vector.input);
                assert_eq!(source.to_cbor().expect("encode"), expected, "{}", vector.id);
                assert_eq!(SyncVersionsResponse::from_cbor(&expected).expect("decode"), source);
            }
            other => panic!("unexpected vector kind {other}"),
        }
    }
}

#[test]
fn write_batches_enforce_limits_uniqueness_and_integer_keys() {
    assert!(SyncWriteBatch { writes: vec![] }.to_cbor().is_err());
    let mut duplicate = SyncWriteBatch { writes: vec![write(1, None), write(1, Some(2))] };
    assert!(duplicate.to_cbor().is_err());
    duplicate.writes[1].object_id = id(2);
    assert!(duplicate.to_cbor().is_ok());

    let too_many = SyncWriteBatch {
        writes: (0..=u16::try_from(MAX_SYNC_BATCH_OBJECTS).expect("batch limit fits u16"))
            .map(|object| SyncWrite {
                object_id: numbered_id(object),
                base_seq: Some(1),
                payload: vec![0xde, 0xad],
                tombstone: false,
            })
            .collect(),
    };
    assert_eq!(too_many.writes.len(), MAX_SYNC_BATCH_OBJECTS + 1);
    assert!(too_many.to_cbor().is_err());

    let oversized = SyncWriteBatch {
        writes: vec![SyncWrite {
            object_id: id(1),
            base_seq: None,
            payload: vec![0; MAX_SYNC_BATCH_BYTES],
            tombstone: false,
        }],
    };
    assert!(oversized.to_cbor().is_err());

    let mut fields = match cbor::decode(&write_batch().to_cbor().expect("encode")).expect("decode")
    {
        Value::Array(mut values) => {
            let Value::Map(fields) = values.remove(0) else { panic!("write map") };
            fields
        }
        _ => panic!("write array"),
    };
    fields.push((Value::UInt(9), Value::Null));
    let unknown = cbor::encode(&Value::Array(vec![Value::Map(fields)])).expect("unknown field");
    assert!(SyncWriteBatch::from_cbor(&unknown).is_err());

    let missing = cbor::encode(&Value::Array(vec![Value::Map(vec![
        (Value::UInt(1), Value::Bytes(id(1).into_bytes().to_vec())),
        (Value::UInt(2), Value::Null),
        (Value::UInt(3), Value::Bytes(vec![])),
    ])]))
    .expect("missing field");
    assert!(SyncWriteBatch::from_cbor(&missing).is_err());
    assert!(SyncWriteBatch::from_cbor(&[0x80]).is_err());
    assert!(SyncWriteBatch::from_cbor(&[0xa0]).is_err());
    assert!(
        SyncWriteBatch::from_cbor(&[
            0x81, 0xa4, 0x18, 0x01, 0x50, 0, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 1,
            0xf6, 0x03, 0x40, 0x04, 0xf4,
        ])
        .is_err()
    );
}

#[test]
fn assignment_response_matches_batch_and_rejects_bad_order() {
    let batch = write_batch();
    let response = SyncWriteBatchResponse {
        assignments: vec![
            SyncWriteAssignment { object_id: id(1), seq: 4 },
            SyncWriteAssignment { object_id: id(2), seq: 5 },
        ],
    };
    response.validate_for_batch(&batch).expect("matching response");

    let mut wrong = response.clone();
    wrong.assignments.reverse();
    assert!(wrong.validate_for_batch(&batch).is_err());
    wrong = response.clone();
    wrong.assignments[1].seq = 4;
    assert!(wrong.to_cbor().is_err());
    wrong = response.clone();
    wrong.assignments[1].object_id = wrong.assignments[0].object_id;
    assert!(wrong.to_cbor().is_err());

    let mut fields = match cbor::decode(&response.to_cbor().expect("encode")).expect("decode") {
        Value::Array(mut values) => {
            let Value::Map(fields) = values.remove(0) else { panic!("assignment map") };
            fields
        }
        _ => panic!("assignment array"),
    };
    fields.push((Value::UInt(3), Value::Null));
    let unknown = cbor::encode(&Value::Array(vec![Value::Map(fields)])).expect("unknown field");
    assert!(SyncWriteBatchResponse::from_cbor(&unknown).is_err());
    assert!(SyncWriteBatchResponse::from_cbor(&[0x80]).is_err());
    assert!(
        SyncWriteBatchResponse::from_cbor(&[
            0x81, 0xa2, 0x18, 0x01, 0x50, 0, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 1,
            0x02, 0x04,
        ])
        .is_err()
    );
}

#[test]
fn conflict_problem_validates_request_order_and_bounds() {
    let batch = SyncWriteBatch { writes: vec![write(1, None), write(2, None), write(3, None)] };
    let mut response = conflict_problem();
    response.conflicts[1].object_id = id(3);
    response.validate_for_batch(&batch).expect("ordered subset");
    response.conflicts.reverse();
    assert!(response.validate_for_batch(&batch).is_err());
    response.conflicts.reverse();
    response.conflicts[1].object_id = id(4);
    assert!(response.validate_for_batch(&batch).is_err());
    response.conflicts[1].object_id = id(1);
    assert!(response.to_cbor().is_err());

    let mut response = conflict_problem();
    response.conflicts.clear();
    assert!(response.to_cbor().is_err());
    response.conflicts = (0..=u16::try_from(MAX_SYNC_BATCH_OBJECTS).expect("count fits"))
        .map(|number| SyncConflictEntry { object_id: numbered_id(number), current: None })
        .collect();
    assert!(response.to_cbor().is_err());
    response.conflicts.pop();
    response.to_cbor().expect("500 conflicts allowed");

    let mut response = conflict_problem();
    response.conflicts[0].current.as_mut().expect("current").object_id = id(2);
    assert!(response.to_cbor().is_err());
    response.conflicts[0].current.as_mut().expect("current").object_id = id(1);
    response.conflicts[0].current.as_mut().expect("current").payload =
        vec![0; MAX_SYNC_CONFLICT_PAYLOAD_BYTES];
    response.to_cbor().expect("260 KiB payload allowed");
    response.conflicts[0].current.as_mut().expect("current").payload.push(0);
    assert!(response.to_cbor().is_err());

    let mut response = conflict_problem();
    response.problem.status = 400;
    assert!(response.to_cbor().is_err());
    response.problem.status = 409;
    response.problem.code = ErrorCode::new("sync.invalid_request").expect("code");
    assert!(response.to_cbor().is_err());
    response.problem.code = ErrorCode::new("sync.conflict").expect("code");
    response.problem.changed = true;
    assert!(response.to_cbor().is_err());
}

#[test]
fn conflict_decoder_rejects_incomplete_and_malformed_extensions() {
    let response = conflict_problem();
    let Value::Map(fields) = cbor::decode(&response.to_cbor().expect("encode")).expect("decode")
    else {
        panic!("problem map");
    };
    let mut missing = fields.clone();
    missing.retain(|(key, _)| key != &Value::Text("conflicts".into()));
    assert!(
        SyncConflictProblem::from_cbor(&cbor::encode(&Value::Map(missing)).expect("encode"))
            .is_err()
    );
    for replacement in [Value::Null, Value::Array(vec![])] {
        let mut wrong = fields.clone();
        replace_text_field(&mut wrong, "conflicts", replacement);
        assert!(
            SyncConflictProblem::from_cbor(&cbor::encode(&Value::Map(wrong)).expect("encode"))
                .is_err()
        );
    }

    let mut wrong = fields.clone();
    let Value::Array(entries) = text_field_mut(&mut wrong, "conflicts") else {
        panic!("conflicts array");
    };
    let Value::Map(first) = &mut entries[0] else { panic!("conflict entry") };
    first.retain(|(key, _)| key != &Value::Text("current".into()));
    assert!(
        SyncConflictProblem::from_cbor(&cbor::encode(&Value::Map(wrong)).expect("encode")).is_err()
    );

    let mut wrong = fields.clone();
    let Value::Array(entries) = text_field_mut(&mut wrong, "conflicts") else {
        panic!("conflicts array");
    };
    let Value::Map(first) = &mut entries[0] else { panic!("conflict entry") };
    replace_text_field(first, "object_id", Value::Text("invalid".into()));
    assert!(
        SyncConflictProblem::from_cbor(&cbor::encode(&Value::Map(wrong)).expect("encode")).is_err()
    );

    let mut wrong = fields.clone();
    let Value::Array(entries) = text_field_mut(&mut wrong, "conflicts") else {
        panic!("conflicts array");
    };
    let Value::Map(first) = &mut entries[0] else { panic!("conflict entry") };
    replace_text_field(first, "current", Value::Map(vec![]));
    assert!(
        SyncConflictProblem::from_cbor(&cbor::encode(&Value::Map(wrong)).expect("encode")).is_err()
    );

    let mut duplicate = fields.clone();
    let Value::Array(entries) = text_field_mut(&mut duplicate, "conflicts") else {
        panic!("conflicts array");
    };
    entries.push(entries[0].clone());
    assert!(
        SyncConflictProblem::from_cbor(&cbor::encode(&Value::Map(duplicate)).expect("encode"))
            .is_err()
    );

    let mut oversized = fields.clone();
    let Value::Array(entries) = text_field_mut(&mut oversized, "conflicts") else {
        panic!("conflicts array");
    };
    let Value::Map(first) = &mut entries[0] else { panic!("conflict entry") };
    let Value::Map(current) = text_field_mut(first, "current") else { panic!("current change") };
    for (key, value) in current {
        if key == &Value::UInt(3) {
            *value = Value::Bytes(vec![0; MAX_SYNC_CONFLICT_PAYLOAD_BYTES + 1]);
        }
    }
    assert!(
        SyncConflictProblem::from_cbor(&cbor::encode(&Value::Map(oversized)).expect("encode"))
            .is_err()
    );

    assert!(SyncConflictProblem::from_cbor(&[0xbf, 0xff]).is_err());
    assert!(SyncConflictProblem::from_cbor(&vec![0; MAX_SYNC_CONFLICT_BODY_BYTES + 1]).is_err());
}

#[test]
fn conflict_decoder_ignores_future_response_fields() {
    let response = conflict_problem();
    let Value::Map(mut fields) =
        cbor::decode(&response.to_cbor().expect("encode")).expect("decode")
    else {
        panic!("problem map");
    };
    let Value::Array(entries) = text_field_mut(&mut fields, "conflicts") else {
        panic!("conflicts array");
    };
    let Value::Map(first) = &mut entries[0] else { panic!("conflict entry") };
    first.push((Value::Text("future_entry".into()), Value::UInt(1)));
    let Value::Map(current) = text_field_mut(first, "current") else { panic!("current change") };
    current.push((Value::UInt(6), Value::Bool(true)));
    fields.push((Value::Text("future_problem".into()), Value::UInt(2)));
    let extended = cbor::encode(&Value::Map(fields)).expect("extended problem");
    assert_eq!(SyncConflictProblem::from_cbor(&extended).expect("decode extensions"), response);
}

#[test]
fn acknowledgements_use_canonical_text_maps_and_response_extensions() {
    let request = SyncAckRequest { cursor: u64::MAX };
    let encoded = request.to_cbor().expect("encode");
    assert_eq!(SyncAckRequest::from_cbor(&encoded).expect("decode"), request);
    let response = SyncAckResponse { cursor: 7 };
    let Value::Map(mut fields) =
        cbor::decode(&response.to_cbor().expect("encode")).expect("decode")
    else {
        panic!("ack map");
    };
    fields.push((Value::Text("future".into()), Value::UInt(1)));
    let extended = cbor::encode(&Value::Map(fields)).expect("extension");
    assert_eq!(SyncAckResponse::from_cbor(&extended).expect("decode"), response);

    assert!(SyncAckRequest::from_cbor(&cbor::encode(&Value::Map(vec![])).expect("empty")).is_err());
    assert!(SyncAckRequest::from_cbor(&[0x81]).is_err());
    let unknown = cbor::encode(&Value::Map(vec![
        (Value::Text("cursor".into()), Value::UInt(1)),
        (Value::Text("future".into()), Value::UInt(2)),
    ]))
    .expect("unknown");
    assert!(SyncAckRequest::from_cbor(&unknown).is_err());
    let wrong =
        cbor::encode(&Value::Map(vec![(Value::Text("cursor".into()), Value::Text("1".into()))]))
            .expect("wrong");
    assert!(SyncAckRequest::from_cbor(&wrong).is_err());
    assert!(
        SyncAckRequest::from_cbor(&[0xa1, 0x78, 0x06, b'c', b'u', b'r', b's', b'o', b'r', 0x07])
            .is_err()
    );
}

#[test]
fn snapshots_follow_change_page_rules_with_objects_key() {
    let page = snapshot();
    let query = SyncChangesQuery { after: 0, limit: 2 };
    page.validate_for_query(&query).expect("valid page");
    assert!(page.validate_for_query(&SyncChangesQuery { after: 2, limit: 2 }).is_err());
    let mut invalid = page.clone();
    invalid.objects.reverse();
    assert!(invalid.to_cbor().is_err());
    invalid = page.clone();
    invalid.objects[1].object_id = invalid.objects[0].object_id;
    assert!(invalid.to_cbor().is_err());
    invalid = page.clone();
    invalid.more = false;
    assert!(invalid.to_cbor().is_ok());
    invalid.next_cursor = 1;
    assert!(invalid.to_cbor().is_err());

    let Value::Map(mut fields) = cbor::decode(&page.to_cbor().expect("encode")).expect("decode")
    else {
        panic!("snapshot map");
    };
    fields.push((Value::Text("future".into()), Value::UInt(1)));
    let extended = cbor::encode(&Value::Map(fields)).expect("extension");
    assert_eq!(SyncSnapshotResponse::from_cbor(&extended).expect("decode"), page);
    let mut missing = cbor::decode(&page.to_cbor().expect("encode")).expect("decode");
    let Value::Map(ref mut fields) = missing else { panic!("snapshot map") };
    fields.retain(|(key, _)| key != &Value::Text("objects".into()));
    assert!(SyncSnapshotResponse::from_cbor(&cbor::encode(&missing).expect("encode")).is_err());
}

#[test]
fn versions_are_bounded_ascending_and_single_object() {
    let response = versions();
    response.validate_for_object(id(1)).expect("matching path");
    assert!(response.validate_for_object(id(2)).is_err());

    let mut invalid = response.clone();
    invalid.versions.reverse();
    assert!(invalid.to_cbor().is_err());
    invalid = response.clone();
    invalid.versions[1].object_id = id(2);
    assert!(invalid.to_cbor().is_err());
    invalid = response.clone();
    invalid.versions[1].seq = invalid.versions[0].seq;
    assert!(invalid.to_cbor().is_err());
    invalid.versions = vec![];
    assert!(invalid.to_cbor().is_err());

    let too_many = SyncVersionsResponse {
        versions: (1..=(MAX_SYNC_RETAINED_VERSIONS + 2) as u64)
            .map(|seq| SyncChange {
                object_id: id(1),
                seq,
                payload: vec![1],
                tombstone: false,
                signer_device_id: None,
            })
            .collect(),
    };
    assert!(too_many.to_cbor().is_err());
}

fn write_batch() -> SyncWriteBatch {
    SyncWriteBatch { writes: vec![write(1, None), write(2, Some(3))] }
}

fn snapshot() -> SyncSnapshotResponse {
    SyncSnapshotResponse { objects: vec![change(1, 2), change(2, 5)], next_cursor: 5, more: true }
}

fn versions() -> SyncVersionsResponse {
    SyncVersionsResponse { versions: vec![change(1, 2), change(1, 5)] }
}

fn conflict_problem() -> SyncConflictProblem {
    SyncConflictProblem {
        problem: ProblemDetails::new(
            ErrorCode::new("sync.conflict").expect("code"),
            409,
            "Write conflict",
            "The write batch was not applied; merge the current objects before retrying.",
            "request-1",
            false,
            true,
        )
        .expect("problem"),
        conflicts: vec![
            SyncConflictEntry { object_id: id(1), current: Some(change(1, 4)) },
            SyncConflictEntry { object_id: id(2), current: None },
        ],
    }
}

fn write_batch_from_json(input: &str) -> SyncWriteBatch {
    let source: JsonValue = serde_json::from_str(input).expect("write JSON");
    SyncWriteBatch {
        writes: source
            .as_array()
            .expect("write array")
            .iter()
            .map(|entry| SyncWrite {
                object_id: Uuid::parse_str(entry["object_id"].as_str().expect("id")).expect("UUID"),
                base_seq: entry["base_seq"].as_u64(),
                payload: decode_hex(entry["payload"].as_str().expect("payload")),
                tombstone: entry["tombstone"].as_bool().expect("tombstone"),
            })
            .collect(),
    }
}

fn write_response_from_json(input: &str) -> SyncWriteBatchResponse {
    let source: JsonValue = serde_json::from_str(input).expect("response JSON");
    SyncWriteBatchResponse {
        assignments: source
            .as_array()
            .expect("assignment array")
            .iter()
            .map(|entry| SyncWriteAssignment {
                object_id: Uuid::parse_str(entry["object_id"].as_str().expect("id")).expect("UUID"),
                seq: entry["seq"].as_u64().expect("seq"),
            })
            .collect(),
    }
}

fn snapshot_from_json(input: &str) -> SyncSnapshotResponse {
    let source: JsonValue = serde_json::from_str(input).expect("snapshot JSON");
    SyncSnapshotResponse {
        objects: source["objects"]
            .as_array()
            .expect("objects")
            .iter()
            .map(change_from_json)
            .collect(),
        next_cursor: source["next_cursor"].as_u64().expect("cursor"),
        more: source["more"].as_bool().expect("more"),
    }
}

fn versions_from_json(input: &str) -> SyncVersionsResponse {
    let source: JsonValue = serde_json::from_str(input).expect("versions JSON");
    SyncVersionsResponse {
        versions: source["versions"]
            .as_array()
            .expect("versions")
            .iter()
            .map(change_from_json)
            .collect(),
    }
}

fn conflict_from_json(input: &str) -> SyncConflictProblem {
    let source: JsonValue = serde_json::from_str(input).expect("conflict JSON");
    SyncConflictProblem {
        problem: serde_json::from_value(source["problem"].clone()).expect("problem"),
        conflicts: source["conflicts"]
            .as_array()
            .expect("conflicts")
            .iter()
            .map(|entry| SyncConflictEntry {
                object_id: Uuid::parse_str(entry["object_id"].as_str().expect("id")).expect("UUID"),
                current: entry["current"].as_object().map(|_| change_from_json(&entry["current"])),
            })
            .collect(),
    }
}

fn text_field_mut<'a>(fields: &'a mut [(Value, Value)], key: &str) -> &'a mut Value {
    &mut fields.iter_mut().find(|(field, _)| field == &Value::Text(key.into())).expect("field").1
}

fn replace_text_field(fields: &mut [(Value, Value)], key: &str, value: Value) {
    *text_field_mut(fields, key) = value;
}

fn change_from_json(entry: &JsonValue) -> SyncChange {
    SyncChange {
        object_id: Uuid::parse_str(entry["object_id"].as_str().expect("id")).expect("UUID"),
        seq: entry["seq"].as_u64().expect("seq"),
        payload: decode_hex(entry["payload"].as_str().expect("payload")),
        tombstone: entry["tombstone"].as_bool().expect("tombstone"),
        signer_device_id: entry["signer_device_id"]
            .as_str()
            .map(|id| Uuid::parse_str(id).expect("UUID")),
    }
}

fn json_number(input: &str, key: &str) -> u64 {
    serde_json::from_str::<JsonValue>(input).expect("JSON")[key].as_u64().expect("number")
}

fn decode_hex(input: &str) -> Vec<u8> {
    input
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let text = std::str::from_utf8(pair).expect("ASCII hex");
            u8::from_str_radix(text, 16).expect("hex byte")
        })
        .collect()
}
