// SPDX-License-Identifier: Apache-2.0

use scoplen_api::sync::{
    MAX_SYNC_NOTIFICATION_ACCESS_TOKEN_BYTES, MAX_SYNC_NOTIFICATION_BODY_BYTES,
    MAX_SYNC_NOTIFICATION_DPOP_PROOF_BYTES, SYNC_NOTIFICATION_AUTH_DEADLINE_SECS,
    SyncNotificationAuth, SyncNotificationContext, SyncNotificationMethod, SyncNotificationReady,
};
use scoplen_model::cbor::{self, Value};
use serde_json::Value as JsonValue;

fn auth() -> SyncNotificationAuth {
    SyncNotificationAuth { access_token: "YQ.Yg.Yw".into(), dpop_proof: "ZA.ZQ.Zg".into() }
}

fn with_field(encoded: &[u8], key: &str, value: Value) -> Vec<u8> {
    let Value::Map(mut fields) = cbor::decode(encoded).expect("map") else {
        panic!("message must be a map");
    };
    fields.push((Value::Text(key.into()), value));
    cbor::encode(&Value::Map(fields)).expect("extended map")
}

fn from_hex(input: &str) -> Vec<u8> {
    input
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).expect("ASCII"), 16).expect("hex"))
        .collect()
}

#[test]
fn published_vectors_round_trip_through_public_codecs() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../vectors/sync-notification-auth.json");
    let document = scoplen_test_vectors::VectorDocument::from_path(path).expect("vectors");
    assert_eq!(document.vectors.len(), 4);
    for vector in &document.vectors {
        let input: JsonValue = serde_json::from_str(&vector.input).expect("JSON input");
        let expected = from_hex(&vector.expected);
        match vector.kind.as_str() {
            "sync.notification.context" => {
                let htm = match input["htm"].as_str().expect("method") {
                    "GET" => SyncNotificationMethod::Get,
                    "CONNECT" => SyncNotificationMethod::Connect,
                    other => panic!("unknown method {other}"),
                };
                let context = SyncNotificationContext { htm };
                assert_eq!(context.to_cbor().expect("encode"), expected, "{}", vector.id);
                assert_eq!(SyncNotificationContext::from_cbor(&expected).expect("decode"), context);
            }
            "sync.notification.auth" => {
                let auth = SyncNotificationAuth {
                    access_token: input["access_token"].as_str().expect("token").into(),
                    dpop_proof: input["dpop_proof"].as_str().expect("proof").into(),
                };
                assert_eq!(auth.to_cbor().expect("encode"), expected, "{}", vector.id);
                assert_eq!(SyncNotificationAuth::from_cbor(&expected).expect("decode"), auth);
            }
            "sync.notification.ready" => {
                assert_eq!(SyncNotificationReady.to_cbor().expect("encode"), expected);
                assert_eq!(
                    SyncNotificationReady::from_cbor(&expected).expect("decode"),
                    SyncNotificationReady
                );
            }
            other => panic!("unexpected vector kind {other}"),
        }
    }
}

#[test]
fn context_and_ready_accept_extensions_but_reject_other_known_fields() {
    let context = SyncNotificationContext { htm: SyncNotificationMethod::Get };
    let context_bytes = context.to_cbor().expect("context");
    let ready_bytes = SyncNotificationReady.to_cbor().expect("ready");
    assert_eq!(
        SyncNotificationContext::from_cbor(&with_field(&context_bytes, "future", Value::UInt(1)))
            .expect("context extension"),
        context
    );
    assert_eq!(
        SyncNotificationReady::from_cbor(&with_field(&ready_bytes, "future", Value::UInt(1)))
            .expect("ready extension"),
        SyncNotificationReady
    );
    for key in [
        "access_token",
        "dpop_proof",
        "authenticated",
        "vault",
        "seq",
        "rotation_pending",
        "device_revoked",
    ] {
        assert!(
            SyncNotificationContext::from_cbor(&with_field(&context_bytes, key, Value::Null))
                .is_err(),
            "context accepted {key}"
        );
    }
    for key in
        ["htm", "access_token", "dpop_proof", "vault", "seq", "rotation_pending", "device_revoked"]
    {
        assert!(
            SyncNotificationReady::from_cbor(&with_field(&ready_bytes, key, Value::Null)).is_err(),
            "ready accepted {key}"
        );
    }
    for method in ["POST", "get", ""] {
        let bytes = cbor::encode(&Value::Map(vec![(
            Value::Text("htm".into()),
            Value::Text(method.into()),
        )]))
        .expect("method");
        assert!(SyncNotificationContext::from_cbor(&bytes).is_err());
    }
    let missing = cbor::encode(&Value::Map(vec![])).expect("empty map");
    assert!(SyncNotificationContext::from_cbor(&missing).is_err());
    assert!(SyncNotificationReady::from_cbor(&missing).is_err());
    let wrong_method_type =
        cbor::encode(&Value::Map(vec![(Value::Text("htm".into()), Value::UInt(1))]))
            .expect("wrong method type");
    assert!(SyncNotificationContext::from_cbor(&wrong_method_type).is_err());
    for value in [Value::Bool(false), Value::UInt(1), Value::Text("true".into())] {
        let bytes = cbor::encode(&Value::Map(vec![(Value::Text("authenticated".into()), value)]))
            .expect("marker");
        assert!(SyncNotificationReady::from_cbor(&bytes).is_err());
    }
    assert_eq!(SYNC_NOTIFICATION_AUTH_DEADLINE_SECS, 10);
}

#[test]
fn authentication_is_strict_and_only_checks_compact_jws_syntax() {
    let auth = auth();
    let encoded = auth.to_cbor().expect("valid auth");
    for key in
        ["future", "htm", "authenticated", "vault", "seq", "rotation_pending", "device_revoked"]
    {
        assert!(
            SyncNotificationAuth::from_cbor(&with_field(&encoded, key, Value::Null)).is_err(),
            "auth accepted {key}"
        );
    }
    for key in ["access_token", "dpop_proof"] {
        let Value::Map(mut fields) = cbor::decode(&encoded).expect("map") else {
            panic!("map");
        };
        fields.retain(|(field, _)| field != &Value::Text(key.into()));
        assert!(
            SyncNotificationAuth::from_cbor(&cbor::encode(&Value::Map(fields)).expect("missing"))
                .is_err()
        );
    }
    let mut duplicate_auth = vec![0xa3];
    duplicate_auth.extend_from_slice(&encoded[1..]);
    duplicate_auth
        .extend_from_slice(&cbor::encode(&Value::Text("access_token".into())).expect("key"));
    duplicate_auth
        .extend_from_slice(&cbor::encode(&Value::Text("YQ.Yg.Yw".into())).expect("value"));
    assert!(SyncNotificationAuth::from_cbor(&duplicate_auth).is_err());
    for invalid in [
        "",
        "YQ.Yg",
        "YQ.Yg.Yw.ZA",
        ".Yg.Yw",
        "YQ..Yw",
        "YQ.Yg.",
        "a.Yg.Yw",
        "YQ=.Yg.Yw",
        "YQ/Yg.Yw",
        "YQ. Yg.Yw",
        "YQ.é.Yw",
    ] {
        assert!(
            SyncNotificationAuth {
                access_token: invalid.into(),
                dpop_proof: auth.dpop_proof.clone()
            }
            .to_cbor()
            .is_err(),
            "accepted {invalid:?}"
        );
    }
    let wrong_type = cbor::encode(&Value::Map(vec![
        (Value::Text("access_token".into()), Value::Bytes(b"YQ.Yg.Yw".to_vec())),
        (Value::Text("dpop_proof".into()), Value::Text("ZA.ZQ.Zg".into())),
    ]))
    .expect("wrong type");
    assert!(SyncNotificationAuth::from_cbor(&wrong_type).is_err());
}

#[test]
fn limits_and_deterministic_cbor_apply_before_message_decode() {
    let largest = SyncNotificationAuth {
        access_token: format!("{}.Yg.Yw", "a".repeat(MAX_SYNC_NOTIFICATION_ACCESS_TOKEN_BYTES - 6)),
        dpop_proof: format!("{}.ZQ.Zg", "d".repeat(MAX_SYNC_NOTIFICATION_DPOP_PROOF_BYTES - 6)),
    };
    let encoded = largest.to_cbor().expect("field limits inclusive");
    assert_eq!(SyncNotificationAuth::from_cbor(&encoded).expect("decode limits"), largest);
    assert!(
        SyncNotificationAuth {
            access_token: format!(
                "{}.Yg.Yw",
                "a".repeat(MAX_SYNC_NOTIFICATION_ACCESS_TOKEN_BYTES - 5)
            ),
            dpop_proof: auth().dpop_proof
        }
        .to_cbor()
        .is_err()
    );
    assert!(
        SyncNotificationAuth {
            access_token: auth().access_token,
            dpop_proof: format!("{}.ZQ.Zg", "d".repeat(MAX_SYNC_NOTIFICATION_DPOP_PROOF_BYTES - 5))
        }
        .to_cbor()
        .is_err()
    );
    let oversized = vec![0; MAX_SYNC_NOTIFICATION_BODY_BYTES + 1];
    assert!(SyncNotificationContext::from_cbor(&oversized).is_err());
    assert!(SyncNotificationAuth::from_cbor(&oversized).is_err());
    assert!(SyncNotificationReady::from_cbor(&oversized).is_err());
    let mut trailing =
        SyncNotificationContext { htm: SyncNotificationMethod::Get }.to_cbor().expect("context");
    trailing.push(0xf6);
    assert!(SyncNotificationContext::from_cbor(&trailing).is_err());
    let mut trailing = auth().to_cbor().expect("auth");
    trailing.push(0xf6);
    assert!(SyncNotificationAuth::from_cbor(&trailing).is_err());
    let mut trailing = SyncNotificationReady.to_cbor().expect("ready");
    trailing.push(0xf6);
    assert!(SyncNotificationReady::from_cbor(&trailing).is_err());
    let duplicate_context = from_hex("a26368746d634745546368746d63474554");
    let duplicate_ready =
        from_hex("a26d61757468656e74696361746564f56d61757468656e74696361746564f5");
    let noncanonical_context = from_hex("a16368746d7803474554");
    assert!(SyncNotificationContext::from_cbor(&duplicate_context).is_err());
    assert!(SyncNotificationReady::from_cbor(&duplicate_ready).is_err());
    assert!(SyncNotificationContext::from_cbor(&noncanonical_context).is_err());
    assert!(SyncNotificationContext::from_cbor(&[0xbf, 0xff]).is_err());
    assert!(SyncNotificationReady::from_cbor(&[0xf6]).is_err());
    assert!(SyncNotificationAuth::from_cbor(&[0xf6]).is_err());
}

#[test]
fn authentication_debug_and_errors_redact_credentials() {
    let credentials = SyncNotificationAuth {
        access_token: "c2VjcmV0.Yg.Yw".into(),
        dpop_proof: "ZA.ZQ.Zg".into(),
    };
    let debug = format!("{credentials:?}");
    assert!(debug.contains("[REDACTED]"));
    assert!(!debug.contains(&credentials.access_token));
    assert!(!debug.contains(&credentials.dpop_proof));
    let invalid = SyncNotificationAuth {
        access_token: format!("{}=", credentials.access_token),
        dpop_proof: credentials.dpop_proof,
    };
    let error = invalid.to_cbor().expect_err("invalid syntax");
    let displayed = format!("{error} {error:?}");
    assert!(!displayed.contains(&invalid.access_token));
    assert!(!displayed.contains(&invalid.dpop_proof));

    let secret = "sensitive-extension-value";
    let cases = [
        SyncNotificationContext::from_cbor(&with_field(
            &SyncNotificationContext { htm: SyncNotificationMethod::Get }
                .to_cbor()
                .expect("context"),
            "access_token",
            Value::Text(secret.into()),
        ))
        .expect_err("mixed context"),
        SyncNotificationAuth::from_cbor(&with_field(
            &auth().to_cbor().expect("auth"),
            "unexpected",
            Value::Text(secret.into()),
        ))
        .expect_err("unknown auth field"),
        SyncNotificationReady::from_cbor(&with_field(
            &SyncNotificationReady.to_cbor().expect("ready"),
            "dpop_proof",
            Value::Text(secret.into()),
        ))
        .expect_err("mixed ready"),
    ];
    for error in cases {
        assert!(!format!("{error} {error:?}").contains(secret));
    }
}
