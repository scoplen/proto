// SPDX-License-Identifier: Apache-2.0

use scoplen_api::sync::{
    MAX_SYNC_VAULT_KEY_EPOCHS, MAX_SYNC_VAULT_KEYS_BODY_BYTES, SyncVaultKey, SyncVaultKeysResponse,
};
use scoplen_model::cbor::{self, Value};
use serde_json::Value as JsonValue;

fn response() -> SyncVaultKeysResponse {
    SyncVaultKeysResponse {
        keys: vec![
            SyncVaultKey { epoch: 1, wrapped_vault_key: vec![1, 2] },
            SyncVaultKey { epoch: 2, wrapped_vault_key: vec![3, 4] },
        ],
    }
}

#[test]
fn shared_vault_key_response_round_trips_and_accepts_extensions() {
    let source = response();
    let encoded = source.to_cbor().expect("encode response");
    assert_eq!(SyncVaultKeysResponse::from_cbor(&encoded).expect("decode response"), source);

    let Value::Map(mut fields) = cbor::decode(&encoded).expect("response map") else {
        panic!("response must be a map");
    };
    fields.push((Value::Text("future".into()), Value::UInt(1)));
    let extended = cbor::encode(&Value::Map(fields)).expect("response extension");
    assert_eq!(SyncVaultKeysResponse::from_cbor(&extended).expect("extension decode"), source);
}

#[test]
fn shared_vault_key_response_rejects_invalid_order_and_bounds() {
    let mut invalid = response();
    invalid.keys[1].epoch = 1;
    assert!(invalid.to_cbor().is_err(), "duplicate epochs");
    invalid = response();
    invalid.keys[0].wrapped_vault_key.clear();
    assert!(invalid.to_cbor().is_err(), "empty wrap");
    invalid = SyncVaultKeysResponse {
        keys: (0..=MAX_SYNC_VAULT_KEY_EPOCHS)
            .map(|epoch| SyncVaultKey { epoch: epoch as u64 + 1, wrapped_vault_key: vec![1] })
            .collect(),
    };
    assert!(invalid.to_cbor().is_err(), "too many epochs");
    assert!(
        SyncVaultKeysResponse::from_cbor(&vec![0; MAX_SYNC_VAULT_KEYS_BODY_BYTES + 1]).is_err(),
        "oversized response"
    );

    let encoded = response().to_cbor().expect("encode response");
    let Value::Map(mut fields) = cbor::decode(&encoded).expect("response map") else {
        panic!("response must be a map");
    };
    fields.push((Value::Text("keys".into()), Value::Array(Vec::new())));
    assert!(cbor::encode(&Value::Map(fields)).is_err(), "duplicate keys field");
}

#[test]
fn published_shared_vault_key_vectors_match_public_codec() {
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../vectors/sync-vault-keys.json");
    let document = scoplen_test_vectors::VectorDocument::from_path(path).expect("vectors");
    assert_eq!(document.vectors.len(), 1);
    let vector = &document.vectors[0];
    assert_eq!(vector.kind, "sync.vaults.keys.response");
    let input: JsonValue = serde_json::from_str(&vector.input).expect("input JSON");
    let keys = input["keys"].as_array().expect("keys array");
    let source = SyncVaultKeysResponse {
        keys: keys
            .iter()
            .map(|entry| SyncVaultKey {
                epoch: entry["epoch"].as_u64().expect("epoch"),
                wrapped_vault_key: decode_hex(
                    entry["wrapped_vault_key"].as_str().expect("wrapped key"),
                ),
            })
            .collect(),
    };
    let expected = decode_hex(&vector.expected);
    assert_eq!(source.to_cbor().expect("encode"), expected);
    assert_eq!(SyncVaultKeysResponse::from_cbor(&expected).expect("decode"), source);
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
