// SPDX-License-Identifier: Apache-2.0

use scoplen_api::{
    auth::{DeviceAccessOperation, DeviceAccessScope},
    sync::{
        MAX_SYNC_VAULT_KEY_EPOCHS, MAX_SYNC_VAULT_RECIPIENTS, MAX_SYNC_VAULT_RECIPIENTS_BODY_BYTES,
        SyncVaultRecipient, SyncVaultRecipientsResponse,
    },
};
use scoplen_model::cbor::{self, Value};
use scoplen_test_vectors::VectorDocument;
use uuid::Uuid;

fn id(last: u16) -> Uuid {
    let mut bytes = [0, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 0];
    bytes[14..].copy_from_slice(&last.to_be_bytes());
    Uuid::from_bytes(bytes)
}

fn first() -> SyncVaultRecipient {
    SyncVaultRecipient {
        membership_id: id(3),
        account_id: id(1),
        recipient_key_revision: 9,
        signing_public_key: [0x11; 32],
        kem_public_key: [0x22; 32],
    }
}

fn roster() -> SyncVaultRecipientsResponse {
    SyncVaultRecipientsResponse {
        key_epoch: 3,
        rotation_pending: true,
        served_epochs: vec![1, 3],
        recipients: vec![
            first(),
            SyncVaultRecipient {
                membership_id: id(4),
                account_id: id(2),
                recipient_key_revision: 10,
                signing_public_key: [0x33; 32],
                kem_public_key: [0x44; 32],
            },
        ],
    }
}

#[test]
fn recipient_routes_require_sync_write_for_the_exact_read_templates() {
    for (operation, path) in [
        (DeviceAccessOperation::VaultRecipientRosterRead, "/sync/v1/vaults/{vault}/recipients"),
        (
            DeviceAccessOperation::VaultRecipientRead,
            "/sync/v1/vaults/{vault}/recipients/{membership}",
        ),
    ] {
        assert_eq!(DeviceAccessOperation::from_route("GET", path), Some(operation));
        assert_eq!(operation.accepted_scopes(), &[DeviceAccessScope::SyncWrite]);
        assert!(!operation.has_accepted_scope("sync:read"));
        assert!(DeviceAccessOperation::from_route("POST", path).is_none());
        assert!(DeviceAccessOperation::from_route("GET", &format!("{path}/")).is_none());
    }
    assert!(
        DeviceAccessOperation::from_route("GET", "/sync/v1/vaults/{vault}/recipients/{account}")
            .is_none()
    );
}

#[test]
fn lookup_binds_membership_and_enforces_key_bytes_and_revision() {
    let source = first();
    let bytes = source.to_cbor().unwrap();
    let response = SyncVaultRecipient::from_cbor(&bytes).unwrap();
    assert_eq!(source, response);
    assert!(response.validate_for_membership(id(3)).is_ok());
    assert!(response.validate_for_membership(id(4)).is_err());
    assert!(response.validate_for_membership(Uuid::nil()).is_err());

    let Value::Map(fields) = cbor::decode(&bytes).unwrap() else { panic!("recipient map") };
    for (key, wrong) in [
        ("recipient_key_revision", Value::UInt(0)),
        ("account_id", Value::Bytes(Uuid::nil().as_bytes().to_vec())),
        ("membership_id", Value::Text(id(3).to_string())),
        ("signing_public_key", Value::Bytes(vec![0x11; 31])),
        ("kem_public_key", Value::Bytes(vec![0x22; 33])),
    ] {
        let mut invalid = fields.clone();
        invalid.iter_mut().find(|(field, _)| field == &Value::Text(key.into())).unwrap().1 = wrong;
        let invalid = cbor::encode(&Value::Map(invalid)).unwrap();
        assert!(SyncVaultRecipient::from_cbor(&invalid).is_err(), "invalid {key}");
    }
    let mut extended = fields;
    extended.push((Value::Text("future".into()), Value::Bool(true)));
    let extended = cbor::encode(&Value::Map(extended)).unwrap();
    assert_eq!(SyncVaultRecipient::from_cbor(&extended), Ok(source));
}

#[test]
fn roster_requires_ordered_epochs_and_unique_current_recipient_ids() {
    for served_epochs in [
        vec![],
        vec![0, 3],
        vec![1, 2],
        vec![1, 3, 3],
        vec![3, 1, 3],
        (1..=MAX_SYNC_VAULT_KEY_EPOCHS as u64 + 1).collect(),
    ] {
        let invalid = SyncVaultRecipientsResponse { served_epochs, ..roster() };
        assert!(invalid.to_cbor().is_err());
    }

    let mut invalid = roster();
    invalid.recipients.swap(0, 1);
    assert!(invalid.to_cbor().is_err(), "unsorted accounts");
    invalid = roster();
    invalid.recipients[1].account_id = invalid.recipients[0].account_id;
    assert!(invalid.to_cbor().is_err(), "duplicate accounts");
    invalid = roster();
    invalid.recipients[1].membership_id = invalid.recipients[0].membership_id;
    assert!(invalid.to_cbor().is_err(), "duplicate Memberships");
    invalid.recipients.clear();
    assert!(invalid.to_cbor().is_err(), "empty roster");
}

#[test]
fn roster_response_checks_complete_body_limits_and_accepts_extensions() {
    let mut source = roster();
    source.recipients = (0..MAX_SYNC_VAULT_RECIPIENTS)
        .map(|index| {
            let account = u16::try_from(index + 1).unwrap();
            SyncVaultRecipient {
                membership_id: id(account + 2_000),
                account_id: id(account),
                ..first()
            }
        })
        .collect();
    source.key_epoch = MAX_SYNC_VAULT_KEY_EPOCHS as u64;
    source.served_epochs = (1..=source.key_epoch).collect();
    let bytes = source.to_cbor().unwrap();
    assert_eq!(SyncVaultRecipientsResponse::from_cbor(&bytes), Ok(source.clone()));
    source.recipients.push(SyncVaultRecipient {
        membership_id: id(5_000),
        account_id: id(4_000),
        ..first()
    });
    assert!(source.to_cbor().is_err(), "too many recipients");

    let value = roster();
    let Value::Map(mut extended) = cbor::decode(&value.to_cbor().unwrap()).unwrap() else {
        panic!("roster map");
    };
    extended.push((Value::Text("future".into()), Value::Bool(true)));
    let extended = cbor::encode(&Value::Map(extended)).unwrap();
    assert_eq!(SyncVaultRecipientsResponse::from_cbor(&extended), Ok(value));
    let oversized = vec![0; MAX_SYNC_VAULT_RECIPIENTS_BODY_BYTES + 1];
    assert!(SyncVaultRecipientsResponse::from_cbor(&oversized).is_err());
    assert!(SyncVaultRecipient::from_cbor(&oversized).is_err());
}

#[test]
fn independent_recipient_vectors_match_public_codecs() {
    let vectors =
        VectorDocument::parse_str(include_str!("../../../vectors/sync-vault-recipients.json"))
            .expect("recipient vectors");
    assert_eq!(vectors.vectors.len(), 2);
    for vector in vectors.vectors {
        let bytes: Vec<_> = vector
            .expected
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|byte| u8::from_str_radix(std::str::from_utf8(byte).unwrap(), 16).unwrap())
            .collect();
        match vector.kind.as_str() {
            "sync.vaults.recipients.lookup" => {
                assert_eq!(first().to_cbor().unwrap(), bytes);
                assert_eq!(SyncVaultRecipient::from_cbor(&bytes), Ok(first()));
            }
            "sync.vaults.recipients.roster" => {
                assert_eq!(roster().to_cbor().unwrap(), bytes);
                assert_eq!(SyncVaultRecipientsResponse::from_cbor(&bytes), Ok(roster()));
            }
            _ => panic!("unexpected recipient vector {}", vector.id),
        }
    }
}
