// SPDX-License-Identifier: Apache-2.0

use scoplen_crypto::{
    AccountKemKeyPair, AccountKemKeyWrap, AccountSigningKeyWrap, DeviceArkWrap, DeviceKemKeyPair,
    Ed25519SigningKey, P256SigningKey, PersonalVaultKeyWrap, PrimitiveError, SecretBytes,
};
use scoplen_test_vectors::VectorDocument;
use uuid::Uuid;
use zeroize::Zeroize;

fn id(last: u8) -> Uuid {
    let mut bytes = [0; 16];
    bytes[6] = 0x70;
    bytes[8] = 0x80;
    bytes[15] = last;
    Uuid::from_bytes(bytes)
}

#[test]
fn device_ark_wrap_binds_account_device_and_recipient() {
    let account = id(1);
    let device = id(2);
    let recipient = DeviceKemKeyPair::from_private_bytes(&[2; 32]).expect("recipient");
    let other = DeviceKemKeyPair::from_private_bytes(&[3; 32]).expect("other recipient");
    let ark = SecretBytes::new([4; 32]);
    let wrapped = DeviceArkWrap::seal(account, device, recipient.public_key(), &ark).expect("seal");
    let bytes = wrapped.encode();
    assert_eq!(bytes.len(), 114);
    let parsed = DeviceArkWrap::decode(&bytes).expect("decode");
    assert_eq!(parsed.open(account, device, &recipient).expect("open"), ark);
    for result in [
        parsed.open(id(3), device, &recipient),
        parsed.open(account, id(3), &recipient),
        parsed.open(account, device, &other),
    ] {
        assert_eq!(result, Err(PrimitiveError::Authentication));
    }
    let mut tampered = bytes;
    tampered[113] ^= 1;
    assert_eq!(
        DeviceArkWrap::decode(&tampered).expect("decode tamper").open(account, device, &recipient),
        Err(PrimitiveError::Authentication)
    );
    let mut invalid_key = bytes;
    invalid_key[1] = 3;
    assert!(matches!(DeviceArkWrap::decode(&invalid_key), Err(PrimitiveError::InvalidKey)));
    assert!(matches!(
        DeviceArkWrap::seal(Uuid::nil(), device, recipient.public_key(), &ark),
        Err(PrimitiveError::InvalidEncoding)
    ));
    assert!(matches!(
        DeviceArkWrap::seal(account, Uuid::nil(), recipient.public_key(), &ark),
        Err(PrimitiveError::InvalidEncoding)
    ));
    assert!(matches!(
        DeviceArkWrap::seal(account, device, &[3; 65], &ark),
        Err(PrimitiveError::InvalidKey)
    ));
    reject_bad_layouts(&bytes, |input| DeviceArkWrap::decode(input).is_err());
}

#[test]
fn account_key_wraps_bind_purpose_public_key_and_ark() {
    let account = id(1);
    let ark = SecretBytes::new([4; 32]);
    let wrong_ark = SecretBytes::new([5; 32]);
    let signing = Ed25519SigningKey::from_bytes(&[6; 32]).expect("signing");
    let other_signing = Ed25519SigningKey::from_bytes(&[7; 32]).expect("other signing");
    let kem = AccountKemKeyPair::from_private_bytes(&[8; 32]).expect("kem");
    let other_kem = AccountKemKeyPair::from_private_bytes(&[9; 32]).expect("other kem");

    let signing_wrap = AccountSigningKeyWrap::seal(account, &ark, &signing).expect("seal signing");
    let signing_bytes = signing_wrap.encode();
    assert_eq!(signing_bytes.len(), 73);
    let signing_wrap = AccountSigningKeyWrap::decode(&signing_bytes).expect("decode signing");
    assert_eq!(
        signing_wrap.open(account, &ark, &signing.public_key()).expect("open signing").public_key(),
        signing.public_key()
    );
    for result in [
        signing_wrap.open(id(3), &ark, &signing.public_key()),
        signing_wrap.open(account, &wrong_ark, &signing.public_key()),
        signing_wrap.open(account, &ark, &other_signing.public_key()),
    ] {
        assert!(matches!(result, Err(PrimitiveError::Authentication)));
    }
    let mut tampered = signing_bytes;
    tampered[72] ^= 1;
    assert!(matches!(
        AccountSigningKeyWrap::decode(&tampered).expect("decode tamper").open(
            account,
            &ark,
            &signing.public_key()
        ),
        Err(PrimitiveError::Authentication)
    ));
    assert!(matches!(
        AccountSigningKeyWrap::seal(Uuid::nil(), &ark, &signing),
        Err(PrimitiveError::InvalidEncoding)
    ));
    assert!(matches!(
        AccountKemKeyWrap::decode(&signing_bytes).expect("decode different purpose").open(
            account,
            &ark,
            &<[u8; 32]>::try_from(kem.public_key()).expect("public key")
        ),
        Err(PrimitiveError::Authentication)
    ));

    let kem_wrap = AccountKemKeyWrap::seal(account, &ark, &kem).expect("seal kem");
    let kem_bytes = kem_wrap.encode();
    assert_eq!(kem_bytes.len(), 73);
    let kem_wrap = AccountKemKeyWrap::decode(&kem_bytes).expect("decode kem");
    let kem_public: [u8; 32] = kem.public_key().try_into().expect("public key");
    let other_public: [u8; 32] = other_kem.public_key().try_into().expect("public key");
    assert_eq!(
        kem_wrap.open(account, &ark, &kem_public).expect("open kem").public_key(),
        kem.public_key()
    );
    for result in [
        kem_wrap.open(id(3), &ark, &kem_public),
        kem_wrap.open(account, &wrong_ark, &kem_public),
        kem_wrap.open(account, &ark, &other_public),
    ] {
        assert!(matches!(result, Err(PrimitiveError::Authentication)));
    }
    let mut tampered = kem_bytes;
    tampered[72] ^= 1;
    assert!(matches!(
        AccountKemKeyWrap::decode(&tampered).expect("decode tamper").open(
            account,
            &ark,
            &kem_public
        ),
        Err(PrimitiveError::Authentication)
    ));
    assert!(matches!(
        AccountKemKeyWrap::seal(Uuid::nil(), &ark, &kem),
        Err(PrimitiveError::InvalidEncoding)
    ));
    reject_bad_layouts(&signing_bytes, |input| AccountSigningKeyWrap::decode(input).is_err());
    reject_bad_layouts(&kem_bytes, |input| AccountKemKeyWrap::decode(input).is_err());
}

#[test]
fn personal_vault_wrap_binds_account_vault_epoch_and_ark() {
    let account = id(1);
    let vault = id(2);
    let ark = SecretBytes::new([4; 32]);
    let wrong_ark = SecretBytes::new([5; 32]);
    let key = SecretBytes::new([10; 32]);
    let wrapped = PersonalVaultKeyWrap::seal(account, vault, 1, &ark, &key).expect("seal");
    let bytes = wrapped.encode();
    assert_eq!(bytes.len(), 73);
    let parsed = PersonalVaultKeyWrap::decode(&bytes).expect("decode");
    assert_eq!(parsed.open(account, vault, 1, &ark).expect("open"), key);
    for result in [
        parsed.open(id(3), vault, 1, &ark),
        parsed.open(account, id(3), 1, &ark),
        parsed.open(account, vault, 2, &ark),
        parsed.open(account, vault, 1, &wrong_ark),
    ] {
        assert_eq!(result, Err(PrimitiveError::Authentication));
    }
    assert!(matches!(
        PersonalVaultKeyWrap::seal(account, vault, 0, &ark, &key),
        Err(PrimitiveError::InvalidEncoding)
    ));
    for result in [
        PersonalVaultKeyWrap::seal(Uuid::nil(), vault, 1, &ark, &key),
        PersonalVaultKeyWrap::seal(account, Uuid::nil(), 1, &ark, &key),
    ] {
        assert!(matches!(result, Err(PrimitiveError::InvalidEncoding)));
    }
    let mut tampered = bytes;
    tampered[72] ^= 1;
    assert_eq!(
        PersonalVaultKeyWrap::decode(&tampered)
            .expect("decode tamper")
            .open(account, vault, 1, &ark),
        Err(PrimitiveError::Authentication)
    );
    reject_bad_layouts(&bytes, |input| PersonalVaultKeyWrap::decode(input).is_err());
}

#[test]
fn software_key_exports_are_redacted_and_zeroizable() {
    let signing = P256SigningKey::from_bytes(&[2; 32]).expect("device signing");
    let account_signing = Ed25519SigningKey::from_bytes(&[3; 32]).expect("account signing");
    let device_kem = DeviceKemKeyPair::from_private_bytes(&[4; 32]).expect("device KEM");
    let account_kem = AccountKemKeyPair::from_private_bytes(&[5; 32]).expect("account KEM");
    assert_eq!(signing.private_key_bytes().as_bytes(), &[2; 32]);
    assert_eq!(account_signing.private_key_bytes().as_bytes(), &[3; 32]);
    assert_eq!(device_kem.private_key_bytes().as_bytes(), &[4; 32]);
    assert_eq!(account_kem.private_key_bytes().as_bytes(), &[5; 32]);
    let mut exported = device_kem.private_key_bytes();
    assert_eq!(format!("{exported:?}"), "[REDACTED]");
    exported.zeroize();
    assert_eq!(exported.as_bytes(), &[0; 32]);
    assert_eq!(
        DeviceKemKeyPair::from_private_bytes(device_kem.private_key_bytes().as_bytes())
            .expect("persisted device KEM")
            .public_key(),
        device_kem.public_key()
    );
}

fn reject_bad_layouts(bytes: &[u8], rejects: impl Fn(&[u8]) -> bool) {
    assert!(rejects(&bytes[..bytes.len() - 1]));
    let mut trailing = bytes.to_vec();
    trailing.push(0);
    assert!(rejects(&trailing));
    let mut future = bytes.to_vec();
    future[0] = 2;
    assert!(rejects(&future));
}

#[test]
fn published_hierarchy_vectors_open_through_the_public_api() {
    let vectors =
        VectorDocument::parse_str(include_str!("../../../vectors/account-hierarchy.json"))
            .expect("K-2 hierarchy vectors");
    for vector in vectors.vectors {
        let fields: Vec<&str> = vector.input.split('|').collect();
        let opened = match vector.kind.as_str() {
            "crypto.hierarchy.device-ark-open" => {
                assert_eq!(fields.len(), 4);
                let recipient =
                    DeviceKemKeyPair::from_private_bytes(&unhex(fields[2])).expect("recipient");
                let artifact = unhex(fields[3]);
                let wrapped = DeviceArkWrap::decode(&artifact).expect("device artifact");
                assert_eq!(wrapped.encode().as_slice(), artifact);
                wrapped.open(uuid(fields[0]), uuid(fields[1]), &recipient)
            }
            "crypto.hierarchy.account-signing-open" => {
                assert_eq!(fields.len(), 4);
                let public_key: [u8; 32] = unhex(fields[2]).try_into().expect("public key");
                let artifact = unhex(fields[3]);
                let wrapped = AccountSigningKeyWrap::decode(&artifact).expect("signing artifact");
                assert_eq!(wrapped.encode().as_slice(), artifact);
                wrapped
                    .open(uuid(fields[0]), &ark(fields[1]), &public_key)
                    .map(|key| key.private_key_bytes())
            }
            "crypto.hierarchy.account-kem-open" => {
                assert_eq!(fields.len(), 4);
                let public_key: [u8; 32] = unhex(fields[2]).try_into().expect("public key");
                let artifact = unhex(fields[3]);
                let wrapped = AccountKemKeyWrap::decode(&artifact).expect("KEM artifact");
                assert_eq!(wrapped.encode().as_slice(), artifact);
                wrapped
                    .open(uuid(fields[0]), &ark(fields[1]), &public_key)
                    .map(|key| key.private_key_bytes())
            }
            "crypto.hierarchy.personal-vault-open" => {
                assert_eq!(fields.len(), 5);
                let artifact = unhex(fields[4]);
                let wrapped = PersonalVaultKeyWrap::decode(&artifact).expect("vault artifact");
                assert_eq!(wrapped.encode().as_slice(), artifact);
                wrapped.open(
                    uuid(fields[0]),
                    uuid(fields[1]),
                    fields[2].parse().expect("epoch"),
                    &ark(fields[3]),
                )
            }
            other => panic!("unknown K-2 hierarchy vector kind: {other}"),
        };
        if vector.expected == "reject" {
            assert_eq!(opened, Err(PrimitiveError::Authentication), "{}", vector.id);
        } else {
            assert_eq!(opened.expect(&vector.id).as_ref(), unhex(&vector.expected));
        }
    }
}

fn ark(hex: &str) -> SecretBytes<32> {
    SecretBytes::from_slice(&unhex(hex)).expect("ARK")
}

fn uuid(input: &str) -> Uuid {
    Uuid::parse_str(input).expect("UUID")
}

fn unhex(input: &str) -> Vec<u8> {
    assert_eq!(input.len() % 2, 0);
    input
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            u8::from_str_radix(std::str::from_utf8(pair).expect("hex UTF-8"), 16).expect("hex")
        })
        .collect()
}
