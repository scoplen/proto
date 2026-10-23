// SPDX-License-Identifier: Apache-2.0
//! Public D-114 authenticated application exchange and hostile-input regressions.

use scoplen_crypto::*;
use scoplen_model::cbor::{self, Value};
use uuid::Uuid;

fn unhex(text: &str) -> Vec<u8> {
    text.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    for b in bytes {
        write!(s, "{b:02x}").unwrap();
    }
    s
}

#[test]
fn independent_published_application_vectors_match_public_exports() {
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../vectors/pairing-crypto.json");
    for v in scoplen_test_vectors::VectorDocument::from_path(path).unwrap().vectors {
        match v.kind.as_str() {
            "crypto.pairing-link" => {
                let result = PairingLink::decode(&v.input);
                if v.expected == "reject" {
                    assert!(result.is_err(), "{}", v.id);
                } else {
                    assert_eq!(result.unwrap().encode(), v.expected);
                }
            }
            "crypto.pairing-qr" => {
                let result = PairingQrPayload::decode(&v.input);
                if v.expected == "reject" {
                    assert!(result.is_err(), "{}", v.id);
                } else {
                    assert_eq!(result.unwrap().encode().as_bytes(), v.expected.as_bytes());
                }
            }
            "crypto.pairing-new-device" => {
                let result = PairingNewDevice::decode(&unhex(&v.input));
                if v.expected == "reject" {
                    assert!(result.is_err(), "{}", v.id);
                } else {
                    assert_eq!(hex(result.unwrap().encode().unwrap().as_bytes()), v.expected);
                }
            }
            "crypto.pairing-handoff" => {
                let result = PairingHandoff::decode(&unhex(&v.input));
                if v.expected == "reject" {
                    assert!(result.is_err(), "{}", v.id);
                } else {
                    assert_eq!(hex(result.unwrap().encode().unwrap().as_bytes()), v.expected);
                }
            }
            "crypto.pairing-key-anchor" => {
                let p: serde_json::Value = serde_json::from_str(&v.input).unwrap();
                let ark = unhex(p["wrapped_ark"].as_str().unwrap());
                let signing = unhex(p["account_signing_key"].as_str().unwrap());
                let kem = unhex(p["account_kem_key"].as_str().unwrap());
                let recovery = unhex(p["recovery_blob"].as_str().unwrap());
                assert_eq!(
                    hex(&pairing_key_anchor(PairingKeyProjection {
                        revision: p["revision"].as_u64().unwrap(),
                        wrapped_ark: &ark,
                        account_signing_key: &signing,
                        account_kem_key: &kem,
                        recovery_blob: &recovery
                    })
                    .unwrap()),
                    v.expected
                );
            }
            "crypto.pairing-acceptance" => {
                let p: serde_json::Value = serde_json::from_str(&v.input).unwrap();
                let id = |name: &str| Uuid::parse_str(p[name].as_str().unwrap()).unwrap();
                let c = PairingApplicationContext::new(
                    p["origin"].as_str().unwrap(),
                    PairingContext::new(
                        id("pairing_id"),
                        id("initiator_device_id"),
                        id("responder_device_id"),
                    )
                    .unwrap(),
                )
                .unwrap();
                let frame = unhex(p["frame"].as_str().unwrap());
                let cert = unhex(p["certificate"].as_str().unwrap());
                let update = unhex(p["update"].as_str().unwrap());
                let proof =
                    PairingCompletionContext::new(&c, id("account_id"), &frame, &cert, &update)
                        .unwrap();
                let (input, signature) = v.expected.split_once('|').unwrap();
                assert_eq!(hex(proof.signature_input()), input);
                proof.verify(&unhex(p["public_key"].as_str().unwrap()), &unhex(signature)).unwrap();
            }
            "crypto.pairing-approval" => {
                let f: Vec<_> = v.input.split('|').map(unhex).collect();
                assert_eq!(
                    hex(&pairing_approval_fingerprint(&f[0], &f[1], &f[2]).unwrap()),
                    v.expected
                );
            }
            other => panic!("unexpected vector kind {other}"),
        }
    }
}

fn id(n: u128) -> Uuid {
    Uuid::from_u128(0x0300_0000_0000_7000_8000_0000_0000_0000 + n)
}
fn context() -> PairingApplicationContext {
    PairingApplicationContext::new(
        "https://control.example.com",
        PairingContext::new(id(0), id(1), id(2)).unwrap(),
    )
    .unwrap()
}
fn new_device() -> PairingNewDevice {
    PairingNewDevice {
        context: context(),
        signing_public_key: P256SigningKey::from_bytes(&[2; 32]).unwrap().public_key_sec1(),
        kem_public_key: DeviceKemKeyPair::from_private_bytes(&[7; 32])
            .unwrap()
            .public_key()
            .to_vec(),
        display_name: "Second desktop".into(),
        platform: "windows".into(),
        created_at: 42,
    }
}
fn handoff() -> PairingHandoff {
    let device = new_device();
    let account = Ed25519SigningKey::from_bytes(&[1; 32]).unwrap();
    let ark = SymmetricKey::new([4; 32]);
    let kem = AccountKemKeyPair::from_private_bytes(&[6; 32]).unwrap();
    let certificate = DeviceCertificate::issue(
        &account,
        id(2),
        id(3),
        device.signing_public_key,
        device.kem_public_key.clone(),
        device.display_name,
        device.platform,
        device.created_at,
    )
    .unwrap();
    let vault_key =
        PersonalVaultKeyWrap::seal(id(3), id(4), 1, &ark, &SymmetricKey::new([8; 32])).unwrap();
    let vault_keys = cbor::encode(&Value::Map(vec![(
        Value::Text("keys".into()),
        Value::Array(vec![Value::Map(vec![
            (Value::Text("epoch".into()), Value::UInt(1)),
            (Value::Text("wrapped_vault_key".into()), Value::Bytes(vault_key.encode().to_vec())),
        ])]),
    )]))
    .unwrap();
    let mut handoff = PairingHandoff {
        context: context(),
        account_id: id(3),
        personal_vault_id: id(4),
        account_signing_public_key: account.public_key(),
        account_kem_public_key: kem.public_key().try_into().unwrap(),
        device_certificate: certificate.encode().unwrap(),
        revision: 2,
        key_bundle_update_hash: [9; 32],
        key_anchor: [0; 32],
        wrapped_ark: DeviceArkWrap::seal(id(3), id(2), &device.kem_public_key, &ark)
            .unwrap()
            .encode()
            .to_vec(),
        account_signing_key: AccountSigningKeyWrap::seal(id(3), &ark, &account)
            .unwrap()
            .encode()
            .to_vec(),
        account_kem_key: AccountKemKeyWrap::seal(id(3), &ark, &kem).unwrap().encode().to_vec(),
        recovery_blob: RecoveryBlob::wrap(&RecoveryKey::from_bytes(&[5; 32]).unwrap(), id(3), &ark)
            .unwrap()
            .encode()
            .unwrap(),
        personal_vault_keys: vault_keys,
    };
    handoff.key_anchor = pairing_key_anchor(handoff.projection()).unwrap();
    handoff
}
fn sessions() -> (PairingSession, PairingSession) {
    let code = PairingCode::from_ascii(b"01234567").unwrap();
    let (i, share) = PairingInitiator::start(&context().pairing(), &code).unwrap();
    let (r, share) = PairingResponder::respond(&context().pairing(), &code, &share).unwrap();
    let i = i.finish(&share).unwrap();
    i.verify_peer_confirmation(&r.confirmation().unwrap()).unwrap();
    r.verify_peer_confirmation(&i.confirmation().unwrap()).unwrap();
    (i, r)
}

#[test]
fn both_roles_exchange_exact_material_then_accept_with_the_retained_new_device_key() {
    let (i, r) = sessions();
    let new = new_device();
    let new_frame = new.seal(&r).unwrap();
    assert_eq!(PairingNewDevice::open(&context(), &i, &new_frame).unwrap(), new);
    assert!(PairingNewDevice::open(&context(), &i, &new_frame).is_err());
    let handoff = handoff();
    let frame = handoff.seal(&i).unwrap();
    let received = PairingHandoff::open(&context(), &r, &frame).unwrap();
    assert_eq!(received, handoff);
    let ark = DeviceArkWrap::decode(&received.wrapped_ark)
        .unwrap()
        .open(id(3), id(2), &DeviceKemKeyPair::from_private_bytes(&[7; 32]).unwrap())
        .unwrap();
    assert_eq!(ark, SymmetricKey::new([4; 32]));
    let account = AccountSigningKeyWrap::decode(&received.account_signing_key)
        .unwrap()
        .open(id(3), &ark, &received.account_signing_public_key)
        .unwrap();
    assert_eq!(account.public_key(), received.account_signing_public_key);
    let c = PairingCompletionContext::from_update_hash(
        &context(),
        id(3),
        &frame,
        &received.device_certificate,
        &received.key_bundle_update_hash,
    )
    .unwrap();
    let signer = P256SigningKey::from_bytes(&[2; 32]).unwrap();
    let acceptance = c.sign(&signer).unwrap();
    c.verify(&new.signing_public_key, &acceptance).unwrap();
    assert!(
        c.verify(&P256SigningKey::from_bytes(&[3; 32]).unwrap().public_key_sec1(), &acceptance)
            .is_err()
    );
    let changed = PairingCompletionContext::from_update_hash(
        &context(),
        id(4),
        &frame,
        &received.device_certificate,
        &received.key_bundle_update_hash,
    )
    .unwrap();
    assert!(changed.verify(&new.signing_public_key, &acceptance).is_err());
    assert!(format!("{received:?}").contains("REDACTED"));
}

fn mutated(bytes: &[u8], name: &str, replacement: Option<Value>) -> Vec<u8> {
    let Value::Map(mut fields) = cbor::decode(bytes).unwrap() else { panic!("map") };
    fields.retain(|(key, _)| key != &Value::Text(name.into()));
    if let Some(value) = replacement {
        fields.push((Value::Text(name.into()), value));
    }
    cbor::encode(&Value::Map(fields)).unwrap()
}

#[test]
fn canonical_plaintexts_reject_unknown_missing_mistyped_duplicate_and_trailing_fields() {
    let bytes = new_device().encode().unwrap();
    for bad in [
        mutated(bytes.as_bytes(), "extra", Some(Value::UInt(1))),
        mutated(bytes.as_bytes(), "platform", None),
        mutated(bytes.as_bytes(), "created_at", Some(Value::Int(-1))),
        mutated(bytes.as_bytes(), "signing_public_key", Some(Value::Bytes(vec![4; 65]))),
        mutated(bytes.as_bytes(), "origin", Some(Value::Text("http://control.example.com".into()))),
        mutated(bytes.as_bytes(), "pairing_id", Some(Value::Bytes(vec![0; 16]))),
        [bytes.as_bytes(), &[0]].concat(),
    ] {
        assert!(PairingNewDevice::decode(&bad).is_err());
    }
    let mut duplicate = bytes.as_bytes().to_vec();
    duplicate[0] += 1;
    duplicate.extend_from_slice(&cbor::encode(&Value::Text("platform".into())).unwrap());
    duplicate.extend_from_slice(&cbor::encode(&Value::Text("test".into())).unwrap());
    assert!(PairingNewDevice::decode(&duplicate).is_err());
    let handoff = handoff().encode().unwrap();
    for field in [
        "account_id",
        "personal_vault_id",
        "device_certificate",
        "key_anchor",
        "key_bundle_update_hash",
        "wrapped_ark",
        "account_kem_key",
        "recovery_blob",
        "personal_vault_keys",
    ] {
        assert!(
            PairingHandoff::decode(&mutated(handoff.as_bytes(), field, None)).is_err(),
            "missing {field}"
        );
        assert!(
            PairingHandoff::decode(&mutated(handoff.as_bytes(), field, Some(Value::Bool(true))))
                .is_err(),
            "mistyped {field}"
        );
    }
    for field in ["account_signing_public_key", "key_anchor"] {
        assert!(
            PairingHandoff::decode(&mutated(
                handoff.as_bytes(),
                field,
                Some(Value::Bytes(vec![1; 32]))
            ))
            .is_err()
        );
    }
}

#[test]
fn frame_helpers_reject_role_origin_and_device_substitution_before_material_is_used() {
    let (i, r) = sessions();
    assert!(new_device().seal(&i).is_err());
    assert!(handoff().seal(&r).is_err());
    let frame = new_device().seal(&r).unwrap();
    let wrong =
        PairingApplicationContext::new("https://other.example.com", context().pairing()).unwrap();
    assert_eq!(
        PairingNewDevice::open(&wrong, &i, &frame),
        Err(PairingApplicationError::InvalidContext)
    );
    let wrong = PairingApplicationContext::new(
        context().origin(),
        PairingContext::new(id(0), id(1), id(5)).unwrap(),
    )
    .unwrap();
    assert!(PairingNewDevice::open(&wrong, &i, &frame).is_err());
    assert!(
        PairingHandoff::open(&context(), &r, &vec![0; MAX_PAIRING_HANDOFF_FRAME_BYTES + 1])
            .is_err()
    );
    assert!(
        PairingNewDevice::open(&context(), &i, &vec![0; MAX_PAIRING_NEW_DEVICE_FRAME_BYTES + 1])
            .is_err()
    );
}

#[test]
fn full_inner_artifact_limits_fit_and_one_byte_excess_is_rejected() {
    let mut h = handoff();
    // An exact-size canonical CBOR item establishes that the outer codec does not shrink K-4.
    h.personal_vault_keys = cbor::encode(&Value::Bytes(vec![0; 4_194_304 - 5])).unwrap();
    assert_eq!(h.personal_vault_keys.len(), 4_194_304);
    h.recovery_blob = vec![1; 65_536];
    let mut cert = DeviceCertificate::decode(&h.device_certificate).unwrap();
    let signing = Ed25519SigningKey::from_bytes(&[1; 32]).unwrap();
    cert.display_name =
        "x".repeat(65_536 - cert.encode().unwrap().len() + cert.display_name.len() - 2);
    h.device_certificate = DeviceCertificate::issue(
        &signing,
        cert.device_id,
        cert.account_id,
        cert.signing_public_key,
        cert.kem_public_key,
        cert.display_name,
        cert.platform,
        cert.created_at,
    )
    .unwrap()
    .encode()
    .unwrap();
    assert_eq!(h.device_certificate.len(), 65_536);
    h.key_anchor = pairing_key_anchor(h.projection()).unwrap();
    let encoded = h.encode().unwrap();
    assert!(encoded.len() + 40 <= MAX_PAIRING_HANDOFF_FRAME_BYTES);
    assert_eq!(PairingHandoff::decode(encoded.as_bytes()).unwrap(), h);
    h.recovery_blob.push(1);
    assert!(h.encode().is_err());
    h.recovery_blob.pop();
    h.personal_vault_keys.push(0);
    assert!(h.encode().is_err());
    let mut new = new_device();
    new.display_name = "x".repeat(65_536);
    assert!(new.encode().is_err());
}

#[test]
fn acceptance_and_projection_bind_every_exact_field_and_enforce_existing_bounds() {
    let h = handoff();
    let bytes = h.encode().unwrap();
    let update = [0xa0];
    let frame = [vec![1; 40], bytes.as_bytes().to_vec()].concat();
    let c =
        PairingCompletionContext::new(&context(), id(3), &frame, &h.device_certificate, &update)
            .unwrap();
    let update_hash: [u8; 32] = {
        use sha2::Digest as _;
        sha2::Sha256::digest(update).into()
    };
    let from_hash = PairingCompletionContext::from_update_hash(
        &context(),
        id(3),
        &frame,
        &h.device_certificate,
        &update_hash,
    )
    .unwrap();
    assert_eq!(c.signature_input(), from_hash.signature_input());
    let signer = P256SigningKey::from_bytes(&[2; 32]).unwrap();
    let signature = c.sign(&signer).unwrap();
    for which in 0..7 {
        let context = match which {
            0 => PairingApplicationContext::new("https://other.example.com", context().pairing())
                .unwrap(),
            1 => PairingApplicationContext::new(
                context().origin(),
                PairingContext::new(id(5), id(1), id(2)).unwrap(),
            )
            .unwrap(),
            2 => PairingApplicationContext::new(
                context().origin(),
                PairingContext::new(id(0), id(5), id(2)).unwrap(),
            )
            .unwrap(),
            3 => PairingApplicationContext::new(
                context().origin(),
                PairingContext::new(id(0), id(1), id(5)).unwrap(),
            )
            .unwrap(),
            _ => context(),
        };
        let mut f = frame.clone();
        let mut cert = h.device_certificate.clone();
        let mut u = update.to_vec();
        match which {
            4 => f[0] ^= 1,
            5 => cert[0] ^= 1,
            6 => u[0] ^= 1,
            _ => {}
        }
        let changed = PairingCompletionContext::new(&context, id(3), &f, &cert, &u).unwrap();
        assert!(changed.verify(&signer.public_key_sec1(), &signature).is_err());
    }
    let anchor = pairing_key_anchor(h.projection()).unwrap();
    let mut p = h.projection();
    p.revision += 1;
    assert_ne!(pairing_key_anchor(p).unwrap(), anchor);
    for field in 0..4 {
        let mut p = h.projection();
        let value = vec![2; 100];
        match field {
            0 => p.wrapped_ark = &value,
            1 => p.account_signing_key = &value,
            2 => p.account_kem_key = &value,
            _ => p.recovery_blob = &value,
        }
        assert_ne!(pairing_key_anchor(p).unwrap(), anchor);
    }
    let fp = pairing_approval_fingerprint(&h.device_certificate, &update, &signature).unwrap();
    assert_ne!(
        pairing_approval_fingerprint(&h.device_certificate, &[0xa1], &signature).unwrap(),
        fp
    );
    assert!(
        pairing_approval_fingerprint(&h.device_certificate, &update, &signature[..63]).is_err()
    );
    assert!(
        pairing_approval_fingerprint(&h.device_certificate, &vec![0; 4_194_305], &signature)
            .is_err()
    );
    assert!(
        PairingCompletionContext::new(&context(), id(3), &[0; 40], &h.device_certificate, &update)
            .is_err()
    );
}
