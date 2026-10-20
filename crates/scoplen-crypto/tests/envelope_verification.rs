// SPDX-License-Identifier: Apache-2.0
//! Verify server-visible object bindings through the public K-2 surface.

use scoplen_crypto::{ObjectEnvelope, P256SigningKey, PrimitiveError, SecretBytes};
use scoplen_model::{FieldEntry, FieldPath, Hlc, Object, ObjectType, cbor};
use uuid::Uuid;

fn id(seed: u8) -> Uuid {
    let mut bytes = [seed; 16];
    bytes[6] = 0x70;
    bytes[8] = 0x80;
    Uuid::from_bytes(bytes)
}

fn fixture() -> (ObjectEnvelope, P256SigningKey) {
    let mut object = Object::new(id(1), ObjectType::HOST, 1).expect("object");
    for (field, value) in [(1, "host"), (2, "host.example")] {
        object
            .insert(
                FieldPath::field(field).expect("path"),
                FieldEntry::new(cbor::Value::Text(value.into()), Hlc::at(1).expect("clock"), id(2))
                    .expect("entry"),
            )
            .expect("insert");
    }
    let signer = P256SigningKey::from_bytes(&[1; 32]).expect("signer");
    let envelope =
        ObjectEnvelope::encrypt(id(3), 1, &object, &SecretBytes::new([2; 32]), id(4), &signer)
            .expect("encrypt");
    (ObjectEnvelope::decode(&envelope.encode().expect("encode")).expect("decode"), signer)
}

#[test]
fn opaque_verification_needs_no_vault_key_and_binds_ids_and_signer() {
    let (envelope, signer) = fixture();
    let public = signer.public_key_sec1();
    assert_eq!(envelope.verify_signature(id(3), id(1), &public), Ok(()));
    for (vault, object) in [(id(9), id(1)), (id(3), id(9))] {
        assert_eq!(
            envelope.verify_signature(vault, object, &public),
            Err(PrimitiveError::InvalidSignature)
        );
    }
    let other = P256SigningKey::from_bytes(&[3; 32]).expect("other signer");
    assert!(envelope.verify_signature(id(3), id(1), &other.public_key_sec1()).is_err());
    assert!(envelope.verify_signature(id(3), id(1), &[0; 65]).is_err());
    assert!(envelope.verify_signature(Uuid::nil(), id(1), &public).is_err());
    assert!(envelope.verify_signature(id(3), Uuid::nil(), &public).is_err());
}

#[test]
fn opaque_verification_rejects_every_tampered_signed_field() {
    let (envelope, signer) = fixture();
    let mut cases = Vec::new();
    let mut changed = envelope.clone();
    changed.key_epoch += 1;
    cases.push(changed);
    let mut changed = envelope.clone();
    changed.nonce = SecretBytes::new([9; 24]);
    cases.push(changed);
    let mut changed = envelope.clone();
    changed.ciphertext[0] ^= 1;
    cases.push(changed);
    let mut changed = envelope.clone();
    changed.signer_device_id = id(9);
    cases.push(changed);
    let mut changed = envelope;
    changed.signature[0] ^= 1;
    cases.push(changed);
    for changed in cases {
        assert_eq!(
            changed.verify_signature(id(3), id(1), &signer.public_key_sec1()),
            Err(PrimitiveError::InvalidSignature)
        );
    }
}

#[test]
fn opaque_verification_rejects_invalid_structure_before_signature_checks() {
    let (envelope, signer) = fixture();
    let mut cases = Vec::new();
    let mut changed = envelope.clone();
    changed.version = 2;
    cases.push(changed);
    let mut changed = envelope.clone();
    changed.key_epoch = 0;
    cases.push(changed);
    let mut changed = envelope.clone();
    changed.ciphertext.truncate(15);
    cases.push(changed);
    let mut changed = envelope;
    changed.signer_device_id = Uuid::nil();
    cases.push(changed);
    for changed in cases {
        assert!(changed.verify_signature(id(3), id(1), &signer.public_key_sec1()).is_err());
        assert!(
            changed
                .decrypt(id(3), id(1), &SecretBytes::new([2; 32]), &signer.public_key_sec1())
                .is_err()
        );
    }
}
