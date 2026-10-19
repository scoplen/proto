// SPDX-License-Identifier: Apache-2.0

use scoplen_api::sync::{
    MAX_SYNC_READ_BODY_BYTES, MAX_SYNC_READ_ENVELOPE_BYTES, SyncChange, SyncChangesQuery,
    SyncChangesResponse, SyncReadLimits, SyncSnapshotResponse, SyncVersionsResponse,
};
use scoplen_model::cbor::{self, Value};
use uuid::Uuid;

fn id(last: u8) -> Uuid {
    Uuid::from_bytes([0, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, last])
}

fn change(payload_len: usize, signer: bool) -> SyncChange {
    SyncChange {
        object_id: id(1),
        seq: u64::MAX,
        payload: vec![0x41; payload_len],
        tombstone: false,
        signer_device_id: signer.then(|| id(2)),
    }
}

fn limits(envelope: usize, body: usize) -> SyncReadLimits {
    SyncReadLimits { max_envelope_bytes: envelope, max_body_bytes: body }
}

#[test]
fn published_read_limit_vectors_use_exact_response_bytes() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../vectors/sync-read-limits.json");
    let document = scoplen_test_vectors::VectorDocument::from_path(path).expect("vectors");
    assert_eq!(document.vectors.len(), 9);
    for vector in document.vectors {
        let input: serde_json::Value = serde_json::from_str(&vector.input).expect("profile");
        let number = |name: &str| {
            usize::try_from(input[name].as_u64().expect("unsigned limit")).expect("platform limit")
        };
        let selected = limits(number("max_envelope_bytes"), number("max_body_bytes"));
        let hex = input["cbor_hex"].as_str().expect("CBOR hex");
        assert!(hex.len().is_multiple_of(2));
        let wire: Vec<_> = hex
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| {
                u8::from_str_radix(std::str::from_utf8(pair).expect("ASCII"), 16).expect("hex byte")
            })
            .collect();
        let encoded = match vector.kind.as_str() {
            "sync.read.limits.changes" => {
                SyncChangesResponse::from_cbor_with_limits(&wire, selected)
                    .and_then(|response| response.to_cbor_with_limits(selected))
            }
            "sync.read.limits.snapshot" => {
                SyncSnapshotResponse::from_cbor_with_limits(&wire, selected)
                    .and_then(|response| response.to_cbor_with_limits(selected))
            }
            "sync.read.limits.versions" => {
                SyncVersionsResponse::from_cbor_with_limits(&wire, selected)
                    .and_then(|response| response.to_cbor_with_limits(selected))
            }
            other => panic!("unknown vector kind {other}"),
        };
        match vector.expected.as_str() {
            "accept" => assert_eq!(encoded.expect("accepted vector"), wire, "{}", vector.id),
            "reject" => assert!(encoded.is_err(), "{}", vector.id),
            other => panic!("unknown vector result {other}"),
        }
    }
}

#[test]
fn default_and_selected_limits_cover_all_three_responses() {
    assert_eq!(SyncReadLimits::default(), limits(260 * 1024, 266_295_039));
    assert_eq!(MAX_SYNC_READ_ENVELOPE_BYTES, 260 * 1024);
    assert_eq!(MAX_SYNC_READ_BODY_BYTES, 266_295_039);

    let larger = 260 * 1024 + 1;
    let entry = change(larger, true);
    let changes =
        SyncChangesResponse { changes: vec![entry.clone()], next_cursor: u64::MAX, more: false };
    let snapshot =
        SyncSnapshotResponse { objects: vec![entry.clone()], next_cursor: u64::MAX, more: false };
    let versions = SyncVersionsResponse { versions: vec![entry] };
    let raised = limits(larger, MAX_SYNC_READ_BODY_BYTES);

    assert!(changes.to_cbor().is_err());
    assert!(snapshot.to_cbor().is_err());
    assert!(versions.to_cbor().is_err());
    assert!(changes.validate_with_limits(raised).is_ok());
    assert!(snapshot.validate_with_limits(raised).is_ok());
    assert!(versions.validate_with_limits(raised).is_ok());

    for (wire, decode) in [
        (changes.to_cbor_with_limits(raised).expect("change page"), 0),
        (snapshot.to_cbor_with_limits(raised).expect("snapshot"), 1),
        (versions.to_cbor_with_limits(raised).expect("history"), 2),
    ] {
        let exact = limits(larger, wire.len());
        let short_body = limits(larger, wire.len() - 1);
        let short_payload = limits(larger - 1, wire.len());
        match decode {
            0 => {
                assert_eq!(changes.to_cbor_with_limits(exact).expect("exact"), wire);
                assert_eq!(
                    SyncChangesResponse::from_cbor_with_limits(&wire, exact).expect("exact"),
                    changes
                );
                assert!(changes.to_cbor_with_limits(short_body).is_err());
                assert!(SyncChangesResponse::from_cbor_with_limits(&wire, short_body).is_err());
                assert!(changes.to_cbor_with_limits(short_payload).is_err());
                assert!(SyncChangesResponse::from_cbor_with_limits(&wire, short_payload).is_err());
                assert!(SyncChangesResponse::from_cbor(&wire).is_err());
            }
            1 => {
                assert_eq!(snapshot.to_cbor_with_limits(exact).expect("exact"), wire);
                assert_eq!(
                    SyncSnapshotResponse::from_cbor_with_limits(&wire, exact).expect("exact"),
                    snapshot
                );
                assert!(snapshot.to_cbor_with_limits(short_body).is_err());
                assert!(SyncSnapshotResponse::from_cbor_with_limits(&wire, short_body).is_err());
                assert!(snapshot.to_cbor_with_limits(short_payload).is_err());
                assert!(SyncSnapshotResponse::from_cbor_with_limits(&wire, short_payload).is_err());
                assert!(SyncSnapshotResponse::from_cbor(&wire).is_err());
            }
            _ => {
                assert_eq!(versions.to_cbor_with_limits(exact).expect("exact"), wire);
                assert_eq!(
                    SyncVersionsResponse::from_cbor_with_limits(&wire, exact).expect("exact"),
                    versions
                );
                assert!(versions.to_cbor_with_limits(short_body).is_err());
                assert!(SyncVersionsResponse::from_cbor_with_limits(&wire, short_body).is_err());
                assert!(versions.to_cbor_with_limits(short_payload).is_err());
                assert!(SyncVersionsResponse::from_cbor_with_limits(&wire, short_payload).is_err());
                assert!(SyncVersionsResponse::from_cbor(&wire).is_err());
            }
        }
    }
}

#[test]
fn exact_encoded_sizes_cover_cbor_length_transitions() {
    for payload_len in [1, 23, 24, 255, 256, 65_535, 65_536] {
        for signer in [false, true] {
            let entry = change(payload_len, signer);
            let changes = SyncChangesResponse {
                changes: vec![entry.clone()],
                next_cursor: u64::MAX,
                more: false,
            };
            let snapshot = SyncSnapshotResponse {
                objects: vec![entry.clone()],
                next_cursor: u64::MAX,
                more: false,
            };
            let versions = SyncVersionsResponse { versions: vec![entry] };
            let generous = limits(payload_len, MAX_SYNC_READ_BODY_BYTES);
            let change_wire = changes.to_cbor_with_limits(generous).expect("change page");
            let snapshot_wire = snapshot.to_cbor_with_limits(generous).expect("snapshot");
            let version_wire = versions.to_cbor_with_limits(generous).expect("history");
            assert!(changes.to_cbor_with_limits(limits(payload_len, change_wire.len())).is_ok());
            assert!(snapshot.to_cbor_with_limits(limits(payload_len, snapshot_wire.len())).is_ok());
            assert!(versions.to_cbor_with_limits(limits(payload_len, version_wire.len())).is_ok());
            assert!(
                changes.to_cbor_with_limits(limits(payload_len, change_wire.len() - 1)).is_err()
            );
            assert!(
                snapshot.to_cbor_with_limits(limits(payload_len, snapshot_wire.len() - 1)).is_err()
            );
            assert!(
                versions.to_cbor_with_limits(limits(payload_len, version_wire.len() - 1)).is_err()
            );
        }
    }
}

#[test]
fn ignored_extensions_count_toward_complete_input_budget() {
    let entry = change(2, false);
    let changes =
        SyncChangesResponse { changes: vec![entry.clone()], next_cursor: u64::MAX, more: false };
    let snapshot =
        SyncSnapshotResponse { objects: vec![entry.clone()], next_cursor: u64::MAX, more: false };
    let versions = SyncVersionsResponse { versions: vec![entry] };
    let original = [
        changes.to_cbor().expect("changes"),
        snapshot.to_cbor().expect("snapshot"),
        versions.to_cbor().expect("versions"),
    ];
    for (index, wire) in original.iter().enumerate() {
        let Value::Map(mut fields) = cbor::decode(wire).expect("decode") else { panic!("map") };
        fields.push((Value::Text("future".into()), Value::Bytes(vec![1, 2, 3])));
        let extended = cbor::encode(&Value::Map(fields)).expect("extension");
        let exact = limits(2, extended.len());
        let short = limits(2, extended.len() - 1);
        assert!(extended.len() > wire.len());
        match index {
            0 => {
                assert_eq!(
                    SyncChangesResponse::from_cbor_with_limits(&extended, exact)
                        .expect("extension"),
                    changes
                );
                assert!(SyncChangesResponse::from_cbor_with_limits(&extended, short).is_err());
            }
            1 => {
                assert_eq!(
                    SyncSnapshotResponse::from_cbor_with_limits(&extended, exact)
                        .expect("extension"),
                    snapshot
                );
                assert!(SyncSnapshotResponse::from_cbor_with_limits(&extended, short).is_err());
            }
            _ => {
                assert_eq!(
                    SyncVersionsResponse::from_cbor_with_limits(&extended, exact)
                        .expect("extension"),
                    versions
                );
                assert!(SyncVersionsResponse::from_cbor_with_limits(&extended, short).is_err());
            }
        }
    }
}

#[test]
fn selected_limits_preserve_query_and_path_correlation() {
    let entry = change(3, true);
    let changes =
        SyncChangesResponse { changes: vec![entry.clone()], next_cursor: u64::MAX, more: false };
    let snapshot =
        SyncSnapshotResponse { objects: vec![entry.clone()], next_cursor: u64::MAX, more: false };
    let versions = SyncVersionsResponse { versions: vec![entry] };
    let selected = limits(3, MAX_SYNC_READ_BODY_BYTES);
    let query = SyncChangesQuery { after: u64::MAX - 1, limit: 1 };
    changes.validate_for_query_with_limits(&query, selected).expect("matching query");
    snapshot.validate_for_query_with_limits(&query, selected).expect("matching query");
    versions.validate_for_object_with_limits(id(1), selected).expect("matching path");
    assert!(
        changes
            .validate_for_query_with_limits(
                &SyncChangesQuery { after: u64::MAX, limit: 1 },
                selected
            )
            .is_err()
    );
    assert!(
        snapshot
            .validate_for_query_with_limits(
                &SyncChangesQuery { after: u64::MAX, limit: 1 },
                selected
            )
            .is_err()
    );
    assert!(versions.validate_for_object_with_limits(id(3), selected).is_err());
    let wire = versions.to_cbor_with_limits(selected).expect("history");
    assert!(
        SyncVersionsResponse::from_cbor_for_object_with_limits(&wire, id(3), selected).is_err()
    );
    assert_eq!(
        SyncVersionsResponse::from_cbor_for_object_with_limits(&wire, id(1), selected)
            .expect("path"),
        versions
    );
    assert!(
        changes
            .validate_for_query_with_limits(&query, limits(2, MAX_SYNC_READ_BODY_BYTES))
            .is_err()
    );
    assert!(
        snapshot
            .validate_for_query_with_limits(&query, limits(2, MAX_SYNC_READ_BODY_BYTES))
            .is_err()
    );
    assert!(
        versions
            .validate_for_object_with_limits(id(1), limits(2, MAX_SYNC_READ_BODY_BYTES))
            .is_err()
    );
}

#[test]
fn invalid_and_unrepresentable_limits_are_rejected_without_allocation() {
    assert!(limits(0, 1).validate().is_err());
    assert!(limits(1, 0).validate().is_err());
    assert!(limits(usize::MAX, usize::MAX).validate().is_err());
    #[cfg(target_pointer_width = "64")]
    {
        assert!(limits(u32::MAX as usize, 1).validate().is_ok());
        assert!(limits(u32::MAX as usize + 1, 1).validate().is_ok());
        let largest = (usize::MAX - 39) / 1_000 - 59;
        assert!(limits(largest, 1).validate().is_ok());
        assert!(limits(largest + 1, 1).validate().is_err());
    }
}
