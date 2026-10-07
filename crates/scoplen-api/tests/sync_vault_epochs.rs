// SPDX-License-Identifier: Apache-2.0

use scoplen_api::sync::{
    MAX_SYNC_VAULT_EPOCH_BODY_BYTES, MAX_SYNC_VAULT_EPOCH_WRAPS, SyncPublishVaultEpochRequest,
    SyncPublishVaultEpochResponse, SyncRetireVaultEpochResponse, SyncVaultEpochWrap,
};
use scoplen_model::cbor::{self, Value};
use serde_json::Value as JsonValue;
use uuid::Uuid;

fn account(last: u8) -> Uuid {
    Uuid::from_bytes([0, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, last])
}

fn request() -> SyncPublishVaultEpochRequest {
    SyncPublishVaultEpochRequest {
        epoch: 2,
        wrapped_keys: vec![
            SyncVaultEpochWrap { account_id: account(1), wrapped_vault_key: vec![1, 2] },
            SyncVaultEpochWrap { account_id: account(2), wrapped_vault_key: vec![3, 4] },
        ],
    }
}

#[test]
fn shared_vault_epoch_codecs_round_trip_and_accept_response_extensions() {
    let source = request();
    let encoded = source.to_cbor().expect("encode request");
    assert_eq!(SyncPublishVaultEpochRequest::from_cbor(&encoded).expect("decode request"), source);

    let response = SyncPublishVaultEpochResponse { epoch: 2 };
    let encoded = response.to_cbor().expect("encode response");
    let Value::Map(mut fields) = cbor::decode(&encoded).expect("response map") else {
        panic!("response must be a map");
    };
    fields.push((Value::Text("future".into()), Value::UInt(1)));
    let extended = cbor::encode(&Value::Map(fields)).expect("response extension");
    assert_eq!(
        SyncPublishVaultEpochResponse::from_cbor(&extended).expect("extension decode"),
        response
    );

    let retired = SyncRetireVaultEpochResponse { epoch: 1 };
    let encoded = retired.to_cbor().expect("encode retirement response");
    assert_eq!(
        SyncRetireVaultEpochResponse::from_cbor(&encoded).expect("decode retirement response"),
        retired
    );
}

#[test]
fn shared_vault_epoch_codecs_reject_invalid_order_fields_and_bounds() {
    let mut invalid = request();
    invalid.wrapped_keys.swap(0, 1);
    assert!(invalid.to_cbor().is_err(), "unsorted accounts");
    invalid = request();
    invalid.wrapped_keys[1].account_id = invalid.wrapped_keys[0].account_id;
    assert!(invalid.to_cbor().is_err(), "duplicate accounts");
    invalid = request();
    invalid.epoch = 0;
    assert!(invalid.to_cbor().is_err(), "zero epoch");
    invalid = request();
    invalid.wrapped_keys.clear();
    assert!(invalid.to_cbor().is_err(), "empty wraps");
    invalid = request();
    invalid.wrapped_keys[0].wrapped_vault_key.clear();
    assert!(invalid.to_cbor().is_err(), "empty key wrap");
    invalid = SyncPublishVaultEpochRequest {
        epoch: 2,
        wrapped_keys: (0..=MAX_SYNC_VAULT_EPOCH_WRAPS)
            .map(|index| SyncVaultEpochWrap {
                account_id: Uuid::from_bytes([
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0x70,
                    0,
                    0x80,
                    0,
                    0,
                    0,
                    0,
                    0,
                    u8::try_from(index / 256).expect("bounded high byte"),
                    u8::try_from(index % 256).expect("bounded low byte"),
                ]),
                wrapped_vault_key: vec![1],
            })
            .collect(),
    };
    assert!(invalid.to_cbor().is_err(), "too many wraps");
    assert!(
        SyncPublishVaultEpochRequest::from_cbor(&vec![0; MAX_SYNC_VAULT_EPOCH_BODY_BYTES + 1])
            .is_err(),
        "oversized request"
    );
    assert!(
        SyncRetireVaultEpochResponse { epoch: 0 }.to_cbor().is_err(),
        "retirement response must reject zero epoch"
    );

    let encoded = request().to_cbor().expect("encode request");
    let Value::Map(mut fields) = cbor::decode(&encoded).expect("request map") else {
        panic!("request must be a map");
    };
    fields.push((Value::Text("future".into()), Value::UInt(1)));
    assert!(
        SyncPublishVaultEpochRequest::from_cbor(
            &cbor::encode(&Value::Map(fields)).expect("unknown")
        )
        .is_err(),
        "unknown request field"
    );
}

#[test]
fn published_shared_vault_epoch_vectors_match_public_codecs() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../vectors/sync-vault-epochs.json");
    let document = scoplen_test_vectors::VectorDocument::from_path(path).expect("vectors");
    assert_eq!(document.vectors.len(), 3);
    for vector in &document.vectors {
        let expected = decode_hex(&vector.expected);
        match vector.kind.as_str() {
            "sync.vaults.epochs.publish.request" => {
                let input: JsonValue = serde_json::from_str(&vector.input).expect("request JSON");
                let source = SyncPublishVaultEpochRequest {
                    epoch: input["epoch"].as_u64().expect("epoch"),
                    wrapped_keys: input["wrapped_keys"]
                        .as_array()
                        .expect("wrapped keys")
                        .iter()
                        .map(|entry| SyncVaultEpochWrap {
                            account_id: Uuid::parse_str(
                                entry["account_id"].as_str().expect("account id"),
                            )
                            .expect("account UUID"),
                            wrapped_vault_key: decode_hex(
                                entry["wrapped_vault_key"].as_str().expect("wrapped key"),
                            ),
                        })
                        .collect(),
                };
                assert_eq!(source.to_cbor().expect("encode"), expected, "{}", vector.id);
                assert_eq!(
                    SyncPublishVaultEpochRequest::from_cbor(&expected).expect("decode"),
                    source
                );
            }
            "sync.vaults.epochs.publish.response" => {
                let source = SyncPublishVaultEpochResponse { epoch: 2 };
                assert_eq!(source.to_cbor().expect("encode"), expected, "{}", vector.id);
                assert_eq!(
                    SyncPublishVaultEpochResponse::from_cbor(&expected).expect("decode"),
                    source
                );
            }
            "sync.vaults.epochs.retire.response" => {
                let source = SyncRetireVaultEpochResponse { epoch: 1 };
                assert_eq!(source.to_cbor().expect("encode"), expected, "{}", vector.id);
                assert_eq!(
                    SyncRetireVaultEpochResponse::from_cbor(&expected).expect("decode"),
                    source
                );
            }
            other => panic!("unexpected vector kind {other}"),
        }
    }
}

fn decode_hex(input: &str) -> Vec<u8> {
    input
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair).expect("ASCII hex");
            u8::from_str_radix(text, 16).expect("hex byte")
        })
        .collect()
}
