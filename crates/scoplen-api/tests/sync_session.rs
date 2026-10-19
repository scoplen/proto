// SPDX-License-Identifier: Apache-2.0

use scoplen_api::sync::{
    MAX_SYNC_SESSION_REQUEST_BYTES, MAX_SYNC_SESSION_RESPONSE_BYTES, SessionVault, SyncCodecError,
    SyncLimits, SyncSessionRequest, SyncSessionResponse, VaultKind,
};
use scoplen_model::cbor::{self, Value};
use serde_json::Value as JsonValue;
use uuid::Uuid;

fn id() -> Uuid {
    Uuid::from_bytes([0, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 1])
}

fn request() -> SyncSessionRequest {
    SyncSessionRequest { client_version: "0.1.0".into(), model_version: 1, device_id: id() }
}

fn response() -> SyncSessionResponse {
    SyncSessionResponse {
        server_version: "0.1.0".into(),
        max_model_version: 1,
        limits: SyncLimits {
            max_envelope_bytes: 266_240,
            max_batch_objects: 500,
            max_batch_bytes: 4_194_304,
            max_objects_per_vault: 100_000,
            max_shared_vaults_per_account: 1_000,
            max_members_per_shared_vault: 1_000,
            write_requests_per_second: 50,
            write_burst: 200,
        },
        vaults: vec![SessionVault {
            id: id(),
            kind: VaultKind::Personal,
            seq: 0,
            key_epoch: 1,
            rotation_pending: false,
        }],
    }
}

#[test]
fn published_session_vectors_match_public_codec() {
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../vectors/sync-session.json");
    let document = scoplen_test_vectors::VectorDocument::from_path(path).expect("vectors");
    assert_eq!(document.vectors.len(), 2);
    for vector in &document.vectors {
        let expected = decode_hex(&vector.expected);
        match vector.kind.as_str() {
            "sync.session.request" => {
                let source = request_from_json(&vector.input);
                assert_eq!(source.to_cbor().expect("encode"), expected);
                assert_eq!(SyncSessionRequest::from_cbor(&expected).expect("decode"), source);
            }
            "sync.session.response" => {
                let source = response_from_json(&vector.input);
                assert_eq!(source.to_cbor().expect("encode"), expected);
                assert_eq!(SyncSessionResponse::from_cbor(&expected).expect("decode"), source);
            }
            other => panic!("unexpected vector kind {other}"),
        }
    }
}

#[test]
fn published_session_budget_recipes_match_public_codecs() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../vectors");
    let bases = scoplen_test_vectors::VectorDocument::from_path(root.join("sync-session.json"))
        .expect("session vectors");
    let profiles =
        scoplen_test_vectors::VectorDocument::from_path(root.join("sync-session-limits.json"))
            .expect("budget vectors");
    assert_eq!(profiles.vectors.len(), 7);
    for vector in profiles.vectors {
        let recipe: JsonValue = serde_json::from_str(&vector.input).expect("recipe");
        let base_id = recipe["base"].as_str().expect("base id");
        let base = bases.vectors.iter().find(|base| base.id == base_id).expect("base vector");
        let base_wire = decode_hex(&base.expected);
        let mut value = cbor::decode(&base_wire).expect("base CBOR");
        let replacement = recipe["replace"].as_str();
        if let Some(field) = replacement {
            let repeat = recipe["repeat_ascii"].as_str().expect("repeat byte");
            assert_eq!(repeat.len(), 1);
            let length = usize::try_from(recipe["length"].as_u64().expect("length"))
                .expect("platform length");
            let Value::Map(ref mut fields) = value else { panic!("base map") };
            let slot = fields
                .iter_mut()
                .find(|(key, _)| key == &Value::Text(field.into()))
                .expect("replace field");
            slot.1 = Value::Text(repeat.repeat(length));
        }
        let wire = cbor::encode(&value).expect("canonical recipe CBOR");
        let (outcome, length) = vector.expected.split_once(':').expect("expected outcome:length");
        assert_eq!(wire.len(), length.parse::<usize>().expect("length"), "{}", vector.id);
        match vector.kind.as_str() {
            "sync.session.limits.request" => {
                assert_eq!(base_id, "sync-session-request-v1");
                let mut source = SyncSessionRequest::from_cbor(&base_wire).expect("base request");
                source.client_version = recipe["repeat_ascii"].as_str().expect("repeat").repeat(
                    usize::try_from(recipe["length"].as_u64().expect("length")).expect("length"),
                );
                match outcome {
                    "accept" => {
                        assert_eq!(source.to_cbor().expect("encode"), wire);
                        assert_eq!(SyncSessionRequest::from_cbor(&wire).expect("decode"), source);
                    }
                    "reject" => {
                        assert!(source.to_cbor().is_err());
                        assert!(SyncSessionRequest::from_cbor(&wire).is_err());
                    }
                    other => panic!("unknown outcome {other}"),
                }
            }
            "sync.session.limits.response" => {
                assert_eq!(base_id, "sync-session-response-v1");
                let body_limit =
                    usize::try_from(recipe["body_limit"].as_u64().expect("body limit"))
                        .expect("platform body limit");
                let mut source = SyncSessionResponse::from_cbor(&base_wire).expect("base response");
                if replacement.is_some() {
                    source.server_version =
                        recipe["repeat_ascii"].as_str().expect("repeat").repeat(
                            usize::try_from(recipe["length"].as_u64().expect("length"))
                                .expect("length"),
                        );
                }
                match outcome {
                    "accept" => {
                        assert_eq!(
                            source.to_cbor_with_body_limit(body_limit).expect("encode"),
                            wire
                        );
                        assert_eq!(
                            SyncSessionResponse::from_cbor_with_body_limit(&wire, body_limit)
                                .expect("decode"),
                            source
                        );
                    }
                    "reject" => {
                        assert!(source.to_cbor_with_body_limit(body_limit).is_err());
                        assert!(
                            SyncSessionResponse::from_cbor_with_body_limit(&wire, body_limit)
                                .is_err()
                        );
                    }
                    other => panic!("unknown outcome {other}"),
                }
                if wire.len() > MAX_SYNC_SESSION_RESPONSE_BYTES {
                    assert!(source.to_cbor().is_err());
                    assert!(SyncSessionResponse::from_cbor(&wire).is_err());
                }
            }
            other => panic!("unknown vector kind {other}"),
        }
    }
}

fn request_from_json(input: &str) -> SyncSessionRequest {
    let source: JsonValue = serde_json::from_str(input).expect("request JSON");
    SyncSessionRequest {
        client_version: string(&source, "client_version"),
        model_version: number(&source, "model_version"),
        device_id: Uuid::parse_str(&string(&source, "device_id")).expect("UUID"),
    }
}

fn response_from_json(input: &str) -> SyncSessionResponse {
    let source: JsonValue = serde_json::from_str(input).expect("response JSON");
    let limits = &source["limits"];
    let vaults = source["vaults"].as_array().expect("vault array");
    SyncSessionResponse {
        server_version: string(&source, "server_version"),
        max_model_version: number(&source, "max_model_version"),
        limits: SyncLimits {
            max_envelope_bytes: number(limits, "max_envelope_bytes"),
            max_batch_objects: number(limits, "max_batch_objects"),
            max_batch_bytes: number(limits, "max_batch_bytes"),
            max_objects_per_vault: number(limits, "max_objects_per_vault"),
            max_shared_vaults_per_account: number(limits, "max_shared_vaults_per_account"),
            max_members_per_shared_vault: number(limits, "max_members_per_shared_vault"),
            write_requests_per_second: number(limits, "write_requests_per_second"),
            write_burst: number(limits, "write_burst"),
        },
        vaults: vaults
            .iter()
            .map(|vault| SessionVault {
                id: Uuid::parse_str(&string(vault, "id")).expect("UUID"),
                kind: match string(vault, "kind").as_str() {
                    "personal" => VaultKind::Personal,
                    "shared" => VaultKind::Shared,
                    "organization" => VaultKind::Organization,
                    other => VaultKind::Unknown(other.into()),
                },
                seq: number(vault, "seq"),
                key_epoch: number(vault, "key_epoch"),
                rotation_pending: vault["rotation_pending"].as_bool().expect("boolean"),
            })
            .collect(),
    }
}

fn string(value: &JsonValue, key: &str) -> String {
    value[key].as_str().expect("text field").into()
}

fn number(value: &JsonValue, key: &str) -> u64 {
    value[key].as_u64().expect("unsigned field")
}

#[test]
fn request_rejects_missing_or_invalid_required_fields() {
    let mut invalid = request();
    invalid.client_version = " ".into();
    assert!(invalid.to_cbor().is_err());
    invalid = request();
    invalid.model_version = 0;
    assert!(invalid.to_cbor().is_err());
    invalid = request();
    invalid.device_id = Uuid::nil();
    assert!(invalid.to_cbor().is_err());

    let Value::Map(fields) = cbor::decode(&request().to_cbor().expect("encode")).expect("decode")
    else {
        panic!("request is a map");
    };
    for key in ["client_version", "model_version", "device_id"] {
        let mut missing = fields.clone();
        missing.retain(|(field, _)| field != &Value::Text(key.into()));
        let bytes = cbor::encode(&Value::Map(missing)).expect("encode");
        assert!(SyncSessionRequest::from_cbor(&bytes).is_err(), "missing {key}");
    }
    let mut wrong_type = fields;
    for (key, value) in &mut wrong_type {
        if key == &Value::Text("device_id".into()) {
            *value = Value::Text(id().to_string());
        }
    }
    assert!(
        SyncSessionRequest::from_cbor(&cbor::encode(&Value::Map(wrong_type)).expect("encode"))
            .is_err()
    );
    assert!(SyncSessionRequest::from_cbor(&[0xbf, 0xff]).is_err());
    let Value::Map(mut fields) =
        cbor::decode(&request().to_cbor().expect("encode")).expect("decode")
    else {
        panic!("request is a map");
    };
    fields.push((Value::Text("future_field".into()), Value::Bool(true)));
    assert!(
        SyncSessionRequest::from_cbor(&cbor::encode(&Value::Map(fields)).expect("encode")).is_err()
    );
}

#[test]
fn response_preserves_unknown_kind_and_ignores_extension_fields() {
    let mut future = response();
    future.vaults[0].kind = VaultKind::Unknown("future".into());
    let bytes = future.to_cbor().expect("future kind");
    assert_eq!(SyncSessionResponse::from_cbor(&bytes).expect("decode"), future);

    let Value::Map(mut fields) = cbor::decode(&bytes).expect("decode value") else {
        panic!("response is a map");
    };
    fields.push((Value::Text("future_field".into()), Value::Bool(true)));
    let extended = cbor::encode(&Value::Map(fields)).expect("encode extension");
    assert_eq!(SyncSessionResponse::from_cbor(&extended).expect("extension"), future);
}

#[test]
fn response_rejects_duplicate_vaults_zero_limits_and_bad_nested_fields() {
    let mut duplicate = response();
    duplicate.vaults.push(duplicate.vaults[0].clone());
    assert!(duplicate.to_cbor().is_err());
    let Value::Map(mut fields) =
        cbor::decode(&response().to_cbor().expect("encode")).expect("decode")
    else {
        panic!("response is a map");
    };
    for (key, value) in &mut fields {
        if key == &Value::Text("vaults".into()) {
            let Value::Array(vaults) = value else {
                panic!("vaults array");
            };
            vaults.push(vaults[0].clone());
        }
    }
    assert!(
        SyncSessionResponse::from_cbor(&cbor::encode(&Value::Map(fields)).expect("encode"))
            .is_err()
    );

    let mut zero = response();
    zero.limits.max_batch_objects = 0;
    assert!(zero.to_cbor().is_err());
    zero = response();
    zero.vaults[0].key_epoch = 0;
    assert!(zero.to_cbor().is_err());

    let Value::Map(mut fields) =
        cbor::decode(&response().to_cbor().expect("encode")).expect("decode")
    else {
        panic!("response is a map");
    };
    for (key, value) in &mut fields {
        if key == &Value::Text("limits".into()) {
            let Value::Map(limits) = value else {
                panic!("limits map");
            };
            limits.retain(|(field, _)| field != &Value::Text("max_batch_objects".into()));
        }
    }
    assert!(
        SyncSessionResponse::from_cbor(&cbor::encode(&Value::Map(fields)).expect("encode"))
            .is_err()
    );
}

#[test]
fn request_body_limit_accepts_exact_bytes_and_rejects_one_more() {
    let mut source = request();
    source.client_version = "a".repeat(4_035);
    let exact = source.to_cbor().expect("exact request");
    assert_eq!(exact.len(), MAX_SYNC_SESSION_REQUEST_BYTES);
    assert_eq!(SyncSessionRequest::from_cbor(&exact).expect("decode exact"), source);

    source.client_version.push('a');
    assert!(source.validate().is_err());
    assert!(source.to_cbor().is_err());
    let Value::Map(mut fields) = cbor::decode(&exact).expect("request map") else {
        panic!("request map")
    };
    for (key, value) in &mut fields {
        if key == &Value::Text("client_version".into()) {
            *value = Value::Text(source.client_version.clone());
        }
    }
    let over = cbor::encode(&Value::Map(fields)).expect("canonical oversized request");
    assert_eq!(over.len(), MAX_SYNC_SESSION_REQUEST_BYTES + 1);
    assert!(SyncSessionRequest::from_cbor(&over).is_err());
    assert!(matches!(
        SyncSessionRequest::from_cbor(&vec![0xff; MAX_SYNC_SESSION_REQUEST_BYTES + 1]),
        Err(SyncCodecError::Invalid(message)) if message.contains("encoded-body limit")
    ));
}

#[test]
fn response_body_budget_accepts_exact_and_raised_values() {
    let source = response();
    let wire = source.to_cbor().expect("default response");
    assert!(source.validate_with_body_limit(0).is_err());
    assert!(source.to_cbor_with_body_limit(0).is_err());
    assert!(SyncSessionResponse::from_cbor_with_body_limit(&wire, 0).is_err());
    assert_eq!(source.to_cbor_with_body_limit(wire.len()).expect("exact"), wire);
    assert_eq!(
        SyncSessionResponse::from_cbor_with_body_limit(&wire, wire.len()).expect("exact"),
        source
    );
    assert!(source.to_cbor_with_body_limit(wire.len() - 1).is_err());
    assert!(SyncSessionResponse::from_cbor_with_body_limit(&wire, wire.len() - 1).is_err());

    let mut large = source;
    large.server_version = "a".repeat(MAX_SYNC_SESSION_RESPONSE_BYTES - wire.len() + 1);
    let exact = large.to_cbor().expect("exact default response");
    assert_eq!(exact.len(), MAX_SYNC_SESSION_RESPONSE_BYTES);
    assert_eq!(SyncSessionResponse::from_cbor(&exact).expect("decode exact"), large);

    large.server_version.push('a');
    assert!(large.validate().is_err());
    assert!(large.to_cbor().is_err());
    let raised = MAX_SYNC_SESSION_RESPONSE_BYTES + 1;
    let over = large.to_cbor_with_body_limit(raised).expect("raised budget");
    assert_eq!(over.len(), raised);
    assert!(SyncSessionResponse::from_cbor(&over).is_err());
    assert_eq!(
        SyncSessionResponse::from_cbor_with_body_limit(&over, raised).expect("raised decode"),
        large
    );
}

#[test]
fn response_budget_tracks_version_kind_and_vault_header_lengths() {
    for text_len in [1, 23, 24, 255, 256, 65_535, 65_536] {
        let mut source = response();
        source.server_version = "v".repeat(text_len);
        source.vaults[0].kind = VaultKind::Unknown("k".repeat(text_len));
        source.vaults[0].seq = u64::MAX;
        source.vaults[0].key_epoch = u64::MAX;
        let wire = source.to_cbor().expect("encode");
        assert_eq!(source.to_cbor_with_body_limit(wire.len()).expect("exact"), wire);
        assert_eq!(
            SyncSessionResponse::from_cbor_with_body_limit(&wire, wire.len()).expect("decode"),
            source
        );
        assert!(source.to_cbor_with_body_limit(wire.len() - 1).is_err());
    }

    let mut many = response();
    many.vaults.clear();
    for last in 1..=24 {
        let mut vault = response().vaults.remove(0);
        vault.id = Uuid::from_bytes([0, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, last]);
        many.vaults.push(vault);
    }
    let wire = many.to_cbor().expect("24 vaults");
    assert_eq!(many.to_cbor_with_body_limit(wire.len()).expect("array header"), wire);
    assert!(many.to_cbor_with_body_limit(wire.len() - 1).is_err());
}

#[test]
fn ignored_extensions_count_toward_selected_response_budget() {
    let source = response();
    let wire = source.to_cbor().expect("response");
    let Value::Map(mut fields) = cbor::decode(&wire).expect("map") else { panic!("map") };
    fields.push((Value::Text("future".into()), Value::Bytes(vec![1, 2, 3])));
    let extended = cbor::encode(&Value::Map(fields)).expect("extension");
    assert!(extended.len() > wire.len());
    assert_eq!(
        SyncSessionResponse::from_cbor_with_body_limit(&extended, extended.len())
            .expect("extension"),
        source
    );
    assert!(SyncSessionResponse::from_cbor_with_body_limit(&extended, extended.len() - 1).is_err());
    assert!(SyncSessionResponse::from_cbor_with_body_limit(&[0xff], 1).is_err());
    assert!(matches!(
        SyncSessionResponse::from_cbor_with_body_limit(&[0xff, 0xff], 1),
        Err(SyncCodecError::Invalid(message)) if message.contains("encoded-body limit")
    ));
}

fn decode_hex(input: &str) -> Vec<u8> {
    input
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let pair = std::str::from_utf8(pair).expect("ASCII hex");
            u8::from_str_radix(pair, 16).expect("hex byte")
        })
        .collect()
}
