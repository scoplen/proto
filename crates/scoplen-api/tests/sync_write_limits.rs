// SPDX-License-Identifier: Apache-2.0

use scoplen_api::{
    ErrorCode, ProblemDetails,
    sync::{
        MAX_SYNC_BATCH_BYTES, MAX_SYNC_BATCH_OBJECTS, MAX_SYNC_CONFLICT_BODY_BYTES,
        MAX_SYNC_CONFLICT_PAYLOAD_BYTES, SyncChange, SyncConflictEntry, SyncConflictProblem,
        SyncLimits, SyncWrite, SyncWriteAssignment, SyncWriteBatch, SyncWriteBatchResponse,
        SyncWriteLimits,
    },
};
use uuid::Uuid;

#[test]
fn published_limit_vectors_use_exact_wire_bytes_and_selected_profiles() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../vectors/sync-write-limits.json");
    let document = scoplen_test_vectors::VectorDocument::from_path(path).expect("vectors");
    assert_eq!(document.vectors.len(), 9);
    for vector in document.vectors {
        let input: serde_json::Value = serde_json::from_str(&vector.input).expect("input JSON");
        let number = |name: &str| {
            usize::try_from(input[name].as_u64().expect("unsigned limit")).expect("platform limit")
        };
        let limits = SyncWriteLimits {
            max_envelope_bytes: number("max_envelope_bytes"),
            max_batch_objects: number("max_batch_objects"),
            max_batch_bytes: number("max_batch_bytes"),
        };
        let hex = input["cbor_hex"].as_str().expect("CBOR hex");
        assert!(hex.len().is_multiple_of(2));
        let bytes: Vec<_> = hex
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| {
                u8::from_str_radix(std::str::from_utf8(pair).expect("ASCII"), 16).expect("hex byte")
            })
            .collect();
        let encoded = match vector.kind.as_str() {
            "sync.writes.limits.request" => SyncWriteBatch::from_cbor_with_limits(&bytes, limits)
                .and_then(|value| value.to_cbor_with_limits(limits)),
            "sync.writes.limits.response" => {
                SyncWriteBatchResponse::from_cbor_with_limits(&bytes, limits)
                    .and_then(|value| value.to_cbor_with_limits(limits))
            }
            "sync.writes.limits.conflict" => {
                SyncConflictProblem::from_cbor_with_limits(&bytes, limits)
                    .and_then(|value| value.to_cbor_with_limits(limits))
            }
            other => panic!("unknown vector kind {other}"),
        };
        match vector.expected.as_str() {
            "accept" => assert_eq!(encoded.expect("accepted vector"), bytes, "{}", vector.id),
            "reject" => assert!(encoded.is_err(), "{}", vector.id),
            other => panic!("unknown vector result {other}"),
        }
    }
}

fn id(number: u16) -> Uuid {
    let [high, low] = number.to_be_bytes();
    Uuid::from_bytes([0, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, high, low])
}

fn batch(count: u16, payload_bytes: usize) -> SyncWriteBatch {
    SyncWriteBatch {
        writes: (1..=count)
            .map(|number| SyncWrite {
                object_id: id(number),
                base_seq: Some(u64::from(number)),
                payload: vec![0x41; payload_bytes],
                tombstone: false,
            })
            .collect(),
    }
}

fn assignments(batch: &SyncWriteBatch) -> SyncWriteBatchResponse {
    SyncWriteBatchResponse {
        assignments: batch
            .writes
            .iter()
            .enumerate()
            .map(|(index, write)| SyncWriteAssignment {
                object_id: write.object_id,
                seq: u64::try_from(index).expect("index fits u64") + 1,
            })
            .collect(),
    }
}

fn conflicts(batch: &SyncWriteBatch) -> SyncConflictProblem {
    SyncConflictProblem {
        problem: ProblemDetails {
            problem_type: "about:blank".into(),
            title: "Write conflict".into(),
            status: 409,
            detail: "Merge and retry.".into(),
            instance: "limits-test".into(),
            code: ErrorCode::new("sync.conflict").expect("code"),
            changed: false,
            retryable: true,
        },
        conflicts: batch
            .writes
            .iter()
            .map(|write| SyncConflictEntry {
                object_id: write.object_id,
                current: Some(SyncChange {
                    object_id: write.object_id,
                    seq: 1,
                    payload: write.payload.clone(),
                    tombstone: false,
                    signer_device_id: Some(id(1)),
                }),
            })
            .collect(),
    }
}

#[test]
fn higher_count_limits_cover_requests_assignments_conflicts_and_binding() {
    let source = batch(501, 2);
    let limits = SyncWriteLimits { max_batch_objects: 501, ..SyncWriteLimits::default() };
    assert_eq!(MAX_SYNC_BATCH_OBJECTS, 500);
    assert!(source.to_cbor().is_err());
    let encoded = source.to_cbor_with_limits(limits).expect("raised count");
    assert!(SyncWriteBatch::from_cbor(&encoded).is_err());
    assert_eq!(SyncWriteBatch::from_cbor_with_limits(&encoded, limits).expect("decode"), source);

    let response = assignments(&source);
    assert!(response.to_cbor().is_err());
    let encoded = response.to_cbor_with_limits(limits).expect("assignments");
    let decoded = SyncWriteBatchResponse::from_cbor_with_limits(&encoded, limits).expect("decode");
    assert_eq!(decoded, response);
    assert!(SyncWriteBatchResponse::from_cbor(&encoded).is_err());
    decoded.validate_for_batch_with_limits(&source, limits).expect("bound response");
    let mut wrong = source.clone();
    wrong.writes.swap(0, 1);
    assert!(decoded.validate_for_batch_with_limits(&wrong, limits).is_err());

    let response = conflicts(&source);
    assert!(response.to_cbor().is_err());
    let encoded = response.to_cbor_with_limits(limits).expect("conflicts");
    let decoded = SyncConflictProblem::from_cbor_with_limits(&encoded, limits).expect("decode");
    assert_eq!(decoded, response);
    assert!(SyncConflictProblem::from_cbor(&encoded).is_err());
    decoded.validate_for_batch_with_limits(&source, limits).expect("bound conflict");
    assert!(decoded.validate_for_batch_with_limits(&wrong, limits).is_err());
    wrong = source.clone();
    wrong.writes[0].object_id = id(600);
    assert!(decoded.validate_for_batch_with_limits(&wrong, limits).is_err());
    let lower = SyncWriteLimits { max_batch_objects: 500, ..limits };
    assert!(decoded.validate_for_batch_with_limits(&source, lower).is_err());
}

#[test]
fn higher_payload_and_complete_body_limits_round_trip_without_default_fallback() {
    let payload = MAX_SYNC_CONFLICT_PAYLOAD_BYTES + 1;
    let source = batch(16, payload);
    let limits = SyncWriteLimits {
        max_envelope_bytes: payload,
        max_batch_bytes: 8 * 1024 * 1024,
        ..SyncWriteLimits::default()
    };
    let encoded = source.to_cbor_with_limits(limits).expect("raised body and payload");
    assert!(encoded.len() > MAX_SYNC_BATCH_BYTES);
    assert_eq!(SyncWriteBatch::from_cbor_with_limits(&encoded, limits).expect("decode"), source);
    assert!(source.validate().is_err());
    assert!(SyncWriteBatch::from_cbor(&encoded).is_err());
    let lower = SyncWriteLimits { max_envelope_bytes: payload - 1, ..limits };
    assert!(source.to_cbor_with_limits(lower).is_err());
    assert!(SyncWriteBatch::from_cbor_with_limits(&encoded, lower).is_err());
    let response = conflicts(&source);
    let encoded = response.to_cbor_with_limits(limits).expect("raised conflict payload");
    let decoded = SyncConflictProblem::from_cbor_with_limits(&encoded, limits).expect("decode");
    decoded.validate_for_batch_with_limits(&source, limits).expect("bound");
    assert!(response.to_cbor_with_limits(lower).is_err());
    assert!(SyncConflictProblem::from_cbor_with_limits(&encoded, lower).is_err());
    assert!(
        SyncConflictProblem::from_cbor_with_limits(
            &vec![0; MAX_SYNC_CONFLICT_BODY_BYTES + 1],
            limits,
        )
        .is_err()
    );
}

#[test]
fn exact_encoded_budget_tracks_cbor_length_and_base_integer_transitions() {
    for count in [1, 23, 24, 255, 256] {
        for payload in [0, 23, 24, 255, 256, 65_535, 65_536] {
            // Large payload transitions need one write, not hundreds of duplicate allocations.
            if count > 1 && payload > 256 {
                continue;
            }
            for base in [None, Some(23), Some(24), Some(255), Some(256), Some(u64::MAX)] {
                let mut source = batch(count, payload);
                for write in &mut source.writes {
                    write.base_seq = base;
                }
                let generous = SyncWriteLimits::default();
                let encoded = source.to_cbor_with_limits(generous).expect("encode");
                let exact = SyncWriteLimits { max_batch_bytes: encoded.len(), ..generous };
                source.validate_with_limits(exact).expect("exact budget");
                assert_eq!(source.to_cbor_with_limits(exact).expect("exact encode"), encoded);
                assert_eq!(
                    SyncWriteBatch::from_cbor_with_limits(&encoded, exact).expect("exact decode"),
                    source
                );
                let shorter = SyncWriteLimits { max_batch_bytes: encoded.len() - 1, ..exact };
                assert!(source.validate_with_limits(shorter).is_err());
                assert!(source.to_cbor_with_limits(shorter).is_err());
                assert!(SyncWriteBatch::from_cbor_with_limits(&encoded, shorter).is_err());
            }
        }
    }
}

#[test]
fn invalid_limits_and_assignment_body_overflow_fail_at_all_public_boundaries() {
    let source = batch(1, 1);
    let response = assignments(&source);
    let conflict = conflicts(&source);
    let normal = SyncWriteLimits::default();
    for limits in [
        SyncWriteLimits { max_envelope_bytes: 0, ..normal },
        SyncWriteLimits { max_batch_objects: 0, ..normal },
        SyncWriteLimits { max_batch_bytes: 0, ..normal },
        SyncWriteLimits { max_batch_objects: usize::MAX, ..normal },
    ] {
        assert!(limits.validate().is_err());
        assert!(source.to_cbor_with_limits(limits).is_err());
        assert!(SyncWriteBatch::from_cbor_with_limits(&[], limits).is_err());
        assert!(response.to_cbor_with_limits(limits).is_err());
        assert!(SyncWriteBatchResponse::from_cbor_with_limits(&[], limits).is_err());
        assert!(response.validate_for_batch_with_limits(&source, limits).is_err());
        assert!(conflict.to_cbor_with_limits(limits).is_err());
        assert!(SyncConflictProblem::from_cbor_with_limits(&[], limits).is_err());
        assert!(conflict.validate_for_batch_with_limits(&source, limits).is_err());
    }
    let body = vec![0; 9 + 29 + 1];
    let single = SyncWriteLimits { max_batch_objects: 1, ..normal };
    let error =
        SyncWriteBatchResponse::from_cbor_with_limits(&body, single).expect_err("body bound");
    assert!(error.to_string().contains("encoded-body limit"), "bound before malformed CBOR");
}

#[test]
fn selected_session_limits_convert_without_changing_the_session_wire() {
    let mut announced = SyncLimits {
        max_envelope_bytes: 524_288,
        max_batch_objects: 501,
        max_batch_bytes: 8_388_608,
        max_objects_per_vault: 100_000,
        max_shared_vaults_per_account: 1_000,
        max_members_per_shared_vault: 1_000,
        write_requests_per_second: 50,
        write_burst: 200,
    };
    let selected = SyncWriteLimits::try_from(&announced).expect("selected budget");
    assert_eq!(selected.max_envelope_bytes, 524_288);
    assert_eq!(selected.max_batch_objects, 501);
    assert_eq!(selected.max_batch_bytes, 8_388_608);
    announced.max_batch_objects = u64::MAX;
    assert!(SyncWriteLimits::try_from(&announced).is_err());
    announced.max_batch_objects = 501;
    announced.write_burst = 0;
    assert!(SyncWriteLimits::try_from(&announced).is_err());
}
