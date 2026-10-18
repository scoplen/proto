// SPDX-License-Identifier: Apache-2.0

use scoplen_api::sync::{
    MAX_SYNC_VAULT_MEMBER_BODY_BYTES, MAX_SYNC_VAULT_MEMBER_EPOCHS, SyncAddVaultMemberRequest,
    SyncAddVaultMemberResponse, SyncRemoveVaultMemberResponse, SyncVaultKey,
};
use scoplen_model::cbor::{self, Value};
use serde_json::Value as JsonValue;
use uuid::Uuid;

fn account(last: u8) -> Uuid {
    Uuid::from_bytes([0, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, last])
}

fn request() -> SyncAddVaultMemberRequest {
    SyncAddVaultMemberRequest {
        account_id: account(3),
        wrapped_keys: vec![
            SyncVaultKey { epoch: 1, wrapped_vault_key: vec![1, 2] },
            SyncVaultKey { epoch: 2, wrapped_vault_key: vec![3, 4] },
        ],
    }
}

#[test]
fn shared_vault_member_codecs_round_trip_and_accept_response_extensions() {
    let source = request();
    let encoded = source.to_cbor().expect("encode request");
    assert_eq!(SyncAddVaultMemberRequest::from_cbor(&encoded).expect("decode request"), source);
    let response = SyncAddVaultMemberResponse { account_id: account(3) };
    let encoded = response.to_cbor().expect("encode response");
    let Value::Map(mut fields) = cbor::decode(&encoded).expect("response map") else {
        panic!("response must be a map");
    };
    fields.push((Value::Text("future".into()), Value::UInt(1)));
    let extended = cbor::encode(&Value::Map(fields)).expect("extension");
    assert_eq!(
        SyncAddVaultMemberResponse::from_cbor(&extended).expect("decode extension"),
        response
    );

    let removal = SyncRemoveVaultMemberResponse { account_id: account(3), rotation_pending: true };
    let encoded = removal.to_cbor().expect("encode removal response");
    let Value::Map(mut fields) = cbor::decode(&encoded).expect("removal response map") else {
        panic!("removal response must be a map");
    };
    fields.push((Value::Text("future".into()), Value::UInt(1)));
    let extended = cbor::encode(&Value::Map(fields)).expect("removal extension");
    assert_eq!(
        SyncRemoveVaultMemberResponse::from_cbor(&extended).expect("decode removal extension"),
        removal
    );
}

#[test]
fn shared_vault_member_codecs_reject_invalid_order_fields_and_bounds() {
    let mut invalid = request();
    invalid.wrapped_keys.swap(0, 1);
    assert!(invalid.to_cbor().is_err(), "unsorted epochs");
    invalid = request();
    invalid.wrapped_keys[1].epoch = 1;
    assert!(invalid.to_cbor().is_err(), "duplicate epochs");
    invalid = request();
    invalid.wrapped_keys.clear();
    assert!(invalid.to_cbor().is_err(), "empty wraps");
    invalid = request();
    invalid.account_id = Uuid::nil();
    assert!(invalid.to_cbor().is_err(), "invalid account");
    let invalid_removal =
        SyncRemoveVaultMemberResponse { account_id: account(3), rotation_pending: false };
    assert!(invalid_removal.to_cbor().is_err(), "false rotation marker");
    invalid = SyncAddVaultMemberRequest {
        account_id: account(3),
        wrapped_keys: (1..=MAX_SYNC_VAULT_MEMBER_EPOCHS as u64 + 1)
            .map(|epoch| SyncVaultKey { epoch, wrapped_vault_key: vec![1] })
            .collect(),
    };
    assert!(invalid.to_cbor().is_err(), "too many epochs");
    assert!(
        SyncAddVaultMemberRequest::from_cbor(&vec![0; MAX_SYNC_VAULT_MEMBER_BODY_BYTES + 1])
            .is_err(),
        "oversized body"
    );
    let encoded = request().to_cbor().expect("encode request");
    let Value::Map(mut fields) = cbor::decode(&encoded).expect("request map") else {
        panic!("request must be a map");
    };
    fields.push((Value::Text("future".into()), Value::UInt(1)));
    assert!(
        SyncAddVaultMemberRequest::from_cbor(&cbor::encode(&Value::Map(fields)).expect("unknown"))
            .is_err(),
        "unknown request field"
    );
}

#[test]
fn removal_response_rejects_missing_invalid_and_oversized_fields() {
    let response = SyncRemoveVaultMemberResponse { account_id: account(3), rotation_pending: true };
    let encoded = response.to_cbor().expect("valid removal response");
    let Value::Map(fields) = cbor::decode(&encoded).expect("response map") else {
        panic!("removal response must be a map");
    };
    for missing in ["account_id", "rotation_pending"] {
        let incomplete =
            fields.iter().filter(|(key, _)| *key != Value::Text(missing.into())).cloned().collect();
        assert!(
            SyncRemoveVaultMemberResponse::from_cbor(
                &cbor::encode(&Value::Map(incomplete)).expect("incomplete map")
            )
            .is_err(),
            "missing {missing}"
        );
    }
    let false_marker = fields
        .iter()
        .map(|(key, value)| {
            if *key == Value::Text("rotation_pending".into()) {
                (key.clone(), Value::Bool(false))
            } else {
                (key.clone(), value.clone())
            }
        })
        .collect();
    assert!(
        SyncRemoveVaultMemberResponse::from_cbor(
            &cbor::encode(&Value::Map(false_marker)).expect("false marker map")
        )
        .is_err(),
        "false pending marker"
    );
    let wrong_account = fields
        .iter()
        .map(|(key, value)| {
            if *key == Value::Text("account_id".into()) {
                (key.clone(), Value::Bytes(Uuid::nil().into_bytes().to_vec()))
            } else {
                (key.clone(), value.clone())
            }
        })
        .collect();
    assert!(
        SyncRemoveVaultMemberResponse::from_cbor(
            &cbor::encode(&Value::Map(wrong_account)).expect("wrong account map")
        )
        .is_err(),
        "invalid account"
    );
    assert!(
        SyncRemoveVaultMemberResponse::from_cbor(&vec![0; MAX_SYNC_VAULT_MEMBER_BODY_BYTES + 1])
            .is_err(),
        "oversized response"
    );
}

#[test]
fn published_shared_vault_member_vectors_match_public_codecs() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../vectors/sync-vault-members.json");
    let document = scoplen_test_vectors::VectorDocument::from_path(path).expect("vectors");
    assert_eq!(document.vectors.len(), 3);
    for vector in &document.vectors {
        let expected = decode_hex(&vector.expected);
        match vector.kind.as_str() {
            "sync.vaults.members.add.request" => {
                let input: JsonValue = serde_json::from_str(&vector.input).expect("request JSON");
                let source = SyncAddVaultMemberRequest {
                    account_id: Uuid::parse_str(input["account_id"].as_str().expect("account"))
                        .expect("account UUID"),
                    wrapped_keys: input["wrapped_keys"]
                        .as_array()
                        .expect("wrapped keys")
                        .iter()
                        .map(|entry| SyncVaultKey {
                            epoch: entry["epoch"].as_u64().expect("epoch"),
                            wrapped_vault_key: decode_hex(
                                entry["wrapped_vault_key"].as_str().expect("wrap"),
                            ),
                        })
                        .collect(),
                };
                assert_eq!(source.to_cbor().expect("encode"), expected, "{}", vector.id);
                assert_eq!(
                    SyncAddVaultMemberRequest::from_cbor(&expected).expect("decode"),
                    source
                );
            }
            "sync.vaults.members.add.response" => {
                let source = SyncAddVaultMemberResponse { account_id: account(3) };
                assert_eq!(source.to_cbor().expect("encode"), expected, "{}", vector.id);
                assert_eq!(
                    SyncAddVaultMemberResponse::from_cbor(&expected).expect("decode"),
                    source
                );
            }
            "sync.vaults.members.remove.response" => {
                let source = SyncRemoveVaultMemberResponse {
                    account_id: account(3),
                    rotation_pending: true,
                };
                assert_eq!(source.to_cbor().expect("encode"), expected, "{}", vector.id);
                assert_eq!(
                    SyncRemoveVaultMemberResponse::from_cbor(&expected).expect("decode"),
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
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let text = std::str::from_utf8(pair).expect("ASCII hex");
            u8::from_str_radix(text, 16).expect("hex byte")
        })
        .collect()
}
