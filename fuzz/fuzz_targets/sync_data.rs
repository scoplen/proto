// SPDX-License-Identifier: Apache-2.0
#![no_main]

use libfuzzer_sys::fuzz_target;
use scoplen_api::ProblemDetails;
use scoplen_api::sync::{
    MAX_SYNC_BATCH_BYTES, MAX_SYNC_BATCH_OBJECTS, MAX_SYNC_CONFLICT_PAYLOAD_BYTES,
    MAX_SYNC_READ_BODY_BYTES, MAX_SYNC_READ_ENVELOPE_BYTES, SyncAckRequest, SyncAckResponse,
    SyncChangesQuery, SyncChangesResponse, SyncConflictProblem, SyncReadLimits,
    SyncSnapshotResponse, SyncVersionsResponse, SyncWriteBatch, SyncWriteBatchResponse,
    SyncWriteLimits,
};

macro_rules! round_trip {
    ($message:ty, $input:expr) => {
        if let Ok(message) = <$message>::from_cbor($input) {
            let encoded = message.clone().to_cbor().expect("validated sync message encodes");
            let decoded = <$message>::from_cbor(&encoded).expect("canonical sync message decodes");
            assert_eq!(decoded, message);
            assert_eq!(decoded.to_cbor().expect("canonical sync message encodes"), encoded);
        }
    };
}

macro_rules! round_trip_with_limits {
    ($message:ty, $input:expr, $limits:expr) => {
        if let Ok(message) = <$message>::from_cbor_with_limits($input, $limits) {
            let encoded = message
                .to_cbor_with_limits($limits)
                .expect("validated bounded sync message encodes");
            let decoded = <$message>::from_cbor_with_limits(&encoded, $limits)
                .expect("canonical bounded sync message decodes");
            assert_eq!(decoded, message);
            assert_eq!(
                decoded
                    .to_cbor_with_limits($limits)
                    .expect("canonical bounded sync message encodes"),
                encoded
            );
        }
    };
}

fn read_limits(profile: u8) -> SyncReadLimits {
    if profile & 1 == 0 {
        SyncReadLimits { max_envelope_bytes: 32, max_body_bytes: 256 }
    } else {
        SyncReadLimits {
            max_envelope_bytes: MAX_SYNC_READ_ENVELOPE_BYTES + 1,
            max_body_bytes: MAX_SYNC_READ_BODY_BYTES + 1,
        }
    }
}

fn write_limits(profile: u8) -> SyncWriteLimits {
    if profile & 1 == 0 {
        SyncWriteLimits { max_envelope_bytes: 32, max_batch_objects: 1, max_batch_bytes: 256 }
    } else {
        SyncWriteLimits {
            max_envelope_bytes: MAX_SYNC_CONFLICT_PAYLOAD_BYTES + 1,
            max_batch_objects: MAX_SYNC_BATCH_OBJECTS + 1,
            max_batch_bytes: MAX_SYNC_BATCH_BYTES + 1,
        }
    }
}

fuzz_target!(|bytes: &[u8]| {
    let Some((&selector, input)) = bytes.split_first() else {
        return;
    };
    match selector % 17 {
        0 => {
            if let Ok(text) = std::str::from_utf8(input)
                && let Ok(query) = SyncChangesQuery::from_query(text)
            {
                let canonical = query.to_query().expect("validated sync query formats");
                assert_eq!(SyncChangesQuery::from_query(&canonical), Ok(query));
                assert_eq!(
                    SyncChangesQuery::from_query(&canonical)
                        .expect("canonical query parses")
                        .to_query()
                        .expect("canonical query formats"),
                    canonical
                );
            }
        }
        1 => round_trip!(SyncChangesResponse, input),
        2 => round_trip!(SyncWriteBatch, input),
        3 => round_trip!(SyncWriteBatchResponse, input),
        4 => round_trip!(SyncConflictProblem, input),
        5 => round_trip!(SyncAckRequest, input),
        6 => round_trip!(SyncAckResponse, input),
        7 => round_trip!(SyncSnapshotResponse, input),
        8 => {
            round_trip!(SyncVersionsResponse, input);
            if let Ok(message) = SyncVersionsResponse::from_cbor(input) {
                let object_id = message.versions[0].object_id;
                assert_eq!(
                    SyncVersionsResponse::from_cbor_for_object(input, object_id),
                    Ok(message)
                );
            }
        }
        16 => round_trip!(ProblemDetails, input),
        9..=15 => {
            let profile = input.first().copied().unwrap_or_default();
            let input = input.get(1..).unwrap_or_default();
            match selector % 17 {
                9 => round_trip_with_limits!(SyncChangesResponse, input, read_limits(profile)),
                10 => round_trip_with_limits!(SyncWriteBatch, input, write_limits(profile)),
                11 => round_trip_with_limits!(SyncWriteBatchResponse, input, write_limits(profile)),
                12 => round_trip_with_limits!(SyncConflictProblem, input, write_limits(profile)),
                13 => round_trip_with_limits!(SyncSnapshotResponse, input, read_limits(profile)),
                14 => round_trip_with_limits!(SyncVersionsResponse, input, read_limits(profile)),
                15 => {
                    let limits = read_limits(profile);
                    if let Ok(message) = SyncVersionsResponse::from_cbor_with_limits(input, limits)
                    {
                        let object_id = message.versions[0].object_id;
                        assert_eq!(
                            SyncVersionsResponse::from_cbor_for_object_with_limits(
                                input, object_id, limits
                            ),
                            Ok(message)
                        );
                    }
                }
                _ => unreachable!(),
            }
        }
        _ => unreachable!(),
    }
});
