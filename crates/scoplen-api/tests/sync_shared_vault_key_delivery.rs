// SPDX-License-Identifier: Apache-2.0

use scoplen_api::sync::{
    MAX_SYNC_VAULT_KEYS_BODY_BYTES, SyncSharedVaultKeyDelivery, SyncSharedVaultKeyPublication,
};
use scoplen_crypto::{
    AccountKemKeyPair, Ed25519SigningKey, SharedVaultAuthorityContext, SharedVaultWrapContext,
    SharedVaultWrapOperation, SharedVaultWrapParty, VaultKey,
};
use scoplen_model::cbor::{self, Value};
use scoplen_test_vectors::VectorDocument;
use uuid::Uuid;

fn id(tail: u128) -> Uuid {
    Uuid::from_u128(0x0000_0000_0000_7000_8000_0000_0000_0000 | tail)
}

fn hex(input: &str) -> Vec<u8> {
    let (pairs, trailing) = input.as_bytes().as_chunks::<2>();
    assert_eq!(trailing, [0_u8; 0]);
    pairs
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn vector() -> (Vec<u8>, VaultKey) {
    let vectors =
        VectorDocument::from_bytes(include_bytes!("../../../vectors/shared-vault-wrap.json"))
            .unwrap();
    let entry = vectors
        .vectors
        .iter()
        .find(|entry| entry.kind == "sync.vaults.shared-key-delivery")
        .unwrap();
    (hex(&entry.input), VaultKey::from_slice(&hex(&entry.expected)).unwrap())
}

#[test]
fn independent_shared_key_delivery_opens_only_with_current_admission_and_reviewed_publication() {
    let (encoded, plaintext) = vector();
    let delivery = SyncSharedVaultKeyDelivery::from_cbor(&encoded).unwrap();
    assert_eq!(delivery.to_cbor().unwrap(), encoded);
    delivery.validate_for_recipient(id(1), id(2), id(5), id(6)).unwrap();
    assert!(delivery.validate_for_recipient(id(9), id(2), id(5), id(6)).is_err());
    assert!(delivery.validate_for_recipient(id(1), id(9), id(5), id(6)).is_err());
    assert!(delivery.validate_for_recipient(id(1), id(2), id(9), id(6)).is_err());
    assert!(delivery.validate_for_recipient(id(1), id(2), id(5), id(9)).is_err());

    let recipient = AccountKemKeyPair::from_private_bytes(&[9; 32]).unwrap();
    let author_kem = AccountKemKeyPair::from_private_bytes(&[17; 32]).unwrap();
    let audit = Ed25519SigningKey::from_bytes(&[16; 32]).unwrap().public_key();
    let author = SharedVaultWrapParty {
        account: id(3),
        membership: id(4),
        revision: 11,
        signing_key: Ed25519SigningKey::from_bytes(&[7; 32]).unwrap().public_key(),
    };
    let recipient_party = SharedVaultWrapParty {
        account: id(5),
        membership: id(6),
        revision: 12,
        signing_key: Ed25519SigningKey::from_bytes(&[8; 32]).unwrap().public_key(),
    };
    let expected = SharedVaultAuthorityContext {
        recipient_admission: id(7),
        author_kem_key: author_kem.public_key().try_into().unwrap(),
        wrap: SharedVaultWrapContext {
            operation: SharedVaultWrapOperation::Admit,
            organization: id(1),
            vault: id(2),
            epoch: 8,
            author,
            recipient: recipient_party,
            recipient_kem_key: recipient.public_key().try_into().unwrap(),
        },
    };
    let [key] = delivery.keys.as_slice() else { panic!("one served epoch") };
    assert_eq!(delivery.admission_id, expected.recipient_admission);
    assert_eq!(key.epoch, expected.wrap.epoch);
    assert_eq!(key.operation, expected.wrap.operation);
    assert_eq!(
        key.author,
        SyncSharedVaultKeyPublication {
            account_id: author.account,
            membership_id: author.membership,
            revision: author.revision,
            signing_public_key: author.signing_key,
            kem_public_key: expected.author_kem_key,
        }
    );
    assert_eq!(
        key.recipient,
        SyncSharedVaultKeyPublication {
            account_id: recipient_party.account,
            membership_id: recipient_party.membership,
            revision: recipient_party.revision,
            signing_public_key: recipient_party.signing_key,
            kem_public_key: expected.wrap.recipient_kem_key,
        }
    );
    let (opened, pin) = key
        .authority_receipt
        .open(&expected, &key.wrapped_vault_key, &audit, None, &recipient)
        .unwrap();
    assert_eq!(opened, plaintext);
    assert_eq!(pin.sequence, 42);
    let readmission = SharedVaultAuthorityContext { recipient_admission: id(10), ..expected };
    assert!(
        key.authority_receipt
            .open(&readmission, &key.wrapped_vault_key, &audit, None, &recipient)
            .is_err()
    );
}

fn get_field<'a>(value: &'a mut Value, name: &str) -> &'a mut Value {
    let Value::Map(fields) = value else { panic!("expected map") };
    &mut fields.iter_mut().find(|(key, _)| key == &Value::Text(name.into())).unwrap().1
}

#[test]
fn shared_key_delivery_rejects_missing_mismatched_or_malformed_evidence() {
    let (encoded, _) = vector();
    let value = cbor::decode(&encoded).unwrap();
    assert!(
        SyncSharedVaultKeyDelivery::from_cbor(&vec![0; MAX_SYNC_VAULT_KEYS_BODY_BYTES + 1])
            .is_err()
    );
    for (field, replacement) in [
        ("admission_id", Value::Bytes(vec![0; 16])),
        ("account_id", Value::Bytes(id(9).as_bytes().to_vec())),
        ("membership_id", Value::Bytes(id(9).as_bytes().to_vec())),
        ("keys", Value::Array(vec![])),
    ] {
        let mut invalid = value.clone();
        *get_field(&mut invalid, field) = replacement;
        assert!(
            SyncSharedVaultKeyDelivery::from_cbor(&cbor::encode(&invalid).unwrap()).is_err(),
            "{field}"
        );
    }

    for (field, replacement) in [
        ("epoch", Value::UInt(u64::from(u32::MAX) + 1)),
        ("operation", Value::UInt(0)),
        ("operation", Value::UInt(1)),
        ("authority_receipt", Value::Bytes(vec![0; 73])),
        ("wrapped_vault_key", Value::Bytes(vec![1; 144])),
    ] {
        let mut invalid = value.clone();
        let Value::Array(keys) = get_field(&mut invalid, "keys") else {
            panic!("expected epoch array")
        };
        *get_field(&mut keys[0], field) = replacement;
        assert!(
            SyncSharedVaultKeyDelivery::from_cbor(&cbor::encode(&invalid).unwrap()).is_err(),
            "{field}"
        );
    }

    let mut duplicate = SyncSharedVaultKeyDelivery::from_cbor(&encoded).unwrap();
    duplicate.keys.push(duplicate.keys[0].clone());
    assert!(duplicate.to_cbor().is_err());
    let mut anonymous = value;
    let Value::Map(fields) = &mut anonymous else { panic!("expected map") };
    fields.retain(|(key, _)| key == &Value::Text("keys".into()));
    assert!(SyncSharedVaultKeyDelivery::from_cbor(&cbor::encode(&anonymous).unwrap()).is_err());
}
