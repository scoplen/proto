// SPDX-License-Identifier: Apache-2.0

use scoplen_api::sync::{
    MAX_SYNC_VAULT_CREATE_BODY_BYTES, MAX_SYNC_VAULT_KEY_BYTES, SessionVault,
    SyncCreateVaultRequest, SyncCreateVaultResponse, VaultKind,
};
use scoplen_model::cbor::{self, Value};
use serde_json::Value as JsonValue;
use uuid::Uuid;

fn id(last: u8) -> Uuid {
    Uuid::from_bytes([0, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, last])
}

fn request() -> SyncCreateVaultRequest {
    SyncCreateVaultRequest { vault_id: id(1), wrapped_vault_key: vec![1, 2, 3, 4] }
}

fn response() -> SyncCreateVaultResponse {
    SyncCreateVaultResponse {
        vault: SessionVault {
            id: id(1),
            kind: VaultKind::Shared,
            seq: 0,
            key_epoch: 1,
            rotation_pending: false,
        },
    }
}

#[test]
fn shared_vault_codecs_round_trip_and_accept_response_extensions() {
    let source = request();
    let encoded = source.to_cbor().expect("request encode");
    assert_eq!(SyncCreateVaultRequest::from_cbor(&encoded).expect("request decode"), source);

    let source = response();
    let encoded = source.to_cbor().expect("response encode");
    assert_eq!(SyncCreateVaultResponse::from_cbor(&encoded).expect("response decode"), source);
    let Value::Map(mut fields) = cbor::decode(&encoded).expect("response map") else {
        panic!("response must be a map");
    };
    fields.push((Value::Text("future".into()), Value::UInt(1)));
    let extended = cbor::encode(&Value::Map(fields)).expect("response extension");
    assert_eq!(SyncCreateVaultResponse::from_cbor(&extended).expect("extension decode"), source);
    SyncCreateVaultResponse::from_cbor(&extended)
        .expect("extension decode")
        .validate_for_request(&request())
        .expect("extended response matches request");
}

#[test]
fn shared_vault_creation_response_binds_to_valid_request() {
    let response = response();
    response.validate_for_request(&request()).expect("matching vault id");

    let mut different = request();
    different.vault_id = id(2);
    assert!(response.validate_for_request(&different).is_err(), "different valid vault id");

    let mut invalid_request = request();
    invalid_request.wrapped_vault_key.clear();
    assert!(response.validate_for_request(&invalid_request).is_err(), "invalid request");

    let mut invalid_response = response;
    invalid_response.vault.key_epoch = 0;
    assert!(invalid_response.validate_for_request(&request()).is_err(), "invalid response");
}

#[test]
fn shared_vault_codecs_reject_invalid_and_ambiguous_inputs() {
    let mut invalid = request();
    invalid.vault_id = Uuid::nil();
    assert!(invalid.to_cbor().is_err(), "non-UUIDv7 id");
    invalid = request();
    invalid.wrapped_vault_key.clear();
    assert!(invalid.to_cbor().is_err(), "empty key wrap");
    invalid = request();
    invalid.wrapped_vault_key = vec![0; MAX_SYNC_VAULT_KEY_BYTES + 1];
    assert!(invalid.to_cbor().is_err(), "oversized key wrap");
    assert!(
        SyncCreateVaultRequest::from_cbor(&vec![0; MAX_SYNC_VAULT_CREATE_BODY_BYTES + 1]).is_err(),
        "oversized body"
    );

    let encoded = request().to_cbor().expect("request encode");
    let Value::Map(mut fields) = cbor::decode(&encoded).expect("request map") else {
        panic!("request must be a map");
    };
    fields.push((Value::Text("future".into()), Value::UInt(1)));
    assert!(
        SyncCreateVaultRequest::from_cbor(&cbor::encode(&Value::Map(fields)).expect("unknown"))
            .is_err(),
        "unknown request field"
    );
    assert!(SyncCreateVaultRequest::from_cbor(&[0xf6]).is_err(), "non-map request");

    let mut wrong_response = response();
    wrong_response.vault.kind = VaultKind::Personal;
    assert!(wrong_response.to_cbor().is_err(), "non-shared response");
    wrong_response = response();
    wrong_response.vault.key_epoch = 2;
    assert!(wrong_response.to_cbor().is_err(), "wrong initial epoch");
}

#[test]
fn published_shared_vault_vectors_match_public_codecs() {
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../vectors/sync-vaults.json");
    let document = scoplen_test_vectors::VectorDocument::from_path(path).expect("vectors");
    assert_eq!(document.vectors.len(), 2);
    for vector in &document.vectors {
        let expected = decode_hex(&vector.expected);
        match vector.kind.as_str() {
            "sync.vaults.create.request" => {
                let value: JsonValue = serde_json::from_str(&vector.input).expect("request JSON");
                let source = SyncCreateVaultRequest {
                    vault_id: Uuid::parse_str(value["vault_id"].as_str().expect("id"))
                        .expect("UUID"),
                    wrapped_vault_key: decode_hex(
                        value["wrapped_vault_key"].as_str().expect("wrapped key"),
                    ),
                };
                assert_eq!(source.to_cbor().expect("encode"), expected, "{}", vector.id);
                assert_eq!(SyncCreateVaultRequest::from_cbor(&expected).expect("decode"), source);
            }
            "sync.vaults.create.response" => {
                let source = response();
                assert_eq!(source.to_cbor().expect("encode"), expected, "{}", vector.id);
                let decoded = SyncCreateVaultResponse::from_cbor(&expected).expect("decode");
                assert_eq!(decoded, source);
                decoded.validate_for_request(&request()).expect("published response binding");
                let mut different = request();
                different.vault_id = id(2);
                assert!(decoded.validate_for_request(&different).is_err());
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
