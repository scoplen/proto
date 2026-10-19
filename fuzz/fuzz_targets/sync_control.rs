// SPDX-License-Identifier: Apache-2.0
#![no_main]

use libfuzzer_sys::fuzz_target;
use scoplen_api::sync::{
    MAX_SYNC_SESSION_RESPONSE_BYTES, SyncAccountKeyBundle, SyncAccountKeyBundlePutResponse,
    SyncAccountKeyBundleUpdate, SyncAddVaultMemberRequest, SyncAddVaultMemberResponse,
    SyncCreateVaultRequest, SyncCreateVaultResponse, SyncPublishVaultEpochRequest,
    SyncPublishVaultEpochResponse, SyncRemoveVaultMemberResponse, SyncRetireVaultEpochResponse,
    SyncSessionRequest, SyncSessionResponse, SyncVaultKeysResponse,
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

fuzz_target!(|bytes: &[u8]| {
    let Some((&selector, input)) = bytes.split_first() else {
        return;
    };
    match selector % 15 {
        0 => round_trip!(SyncSessionRequest, input),
        1 => round_trip!(SyncSessionResponse, input),
        2 => {
            let profile = input.first().copied().unwrap_or_default();
            let input = input.get(1..).unwrap_or_default();
            let body_limit =
                if profile & 1 == 0 { 64 } else { MAX_SYNC_SESSION_RESPONSE_BYTES + 1 };
            if let Ok(message) = SyncSessionResponse::from_cbor_with_body_limit(input, body_limit) {
                let encoded = message
                    .to_cbor_with_body_limit(body_limit)
                    .expect("validated bounded session encodes");
                let decoded = SyncSessionResponse::from_cbor_with_body_limit(&encoded, body_limit)
                    .expect("canonical bounded session decodes");
                assert_eq!(decoded, message);
                assert_eq!(
                    decoded
                        .to_cbor_with_body_limit(body_limit)
                        .expect("canonical bounded session encodes"),
                    encoded
                );
            }
        }
        3 => round_trip!(SyncCreateVaultRequest, input),
        4 => round_trip!(SyncCreateVaultResponse, input),
        5 => round_trip!(SyncVaultKeysResponse, input),
        6 => round_trip!(SyncPublishVaultEpochRequest, input),
        7 => round_trip!(SyncPublishVaultEpochResponse, input),
        8 => round_trip!(SyncRetireVaultEpochResponse, input),
        9 => round_trip!(SyncAddVaultMemberRequest, input),
        10 => round_trip!(SyncAddVaultMemberResponse, input),
        11 => round_trip!(SyncRemoveVaultMemberResponse, input),
        12 => round_trip!(SyncAccountKeyBundle, input),
        13 => round_trip!(SyncAccountKeyBundleUpdate, input),
        14 => round_trip!(SyncAccountKeyBundlePutResponse, input),
        _ => unreachable!(),
    }
});
