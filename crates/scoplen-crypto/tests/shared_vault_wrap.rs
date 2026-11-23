// SPDX-License-Identifier: Apache-2.0

use scoplen_crypto::{
    AccountKemKeyPair, Ed25519SigningKey, PrimitiveError, SharedVaultKeyWrap,
    SharedVaultWrapContext, SharedVaultWrapOperation, SharedVaultWrapParty, VaultKey,
};
use scoplen_test_vectors::VectorDocument;
use uuid::Uuid;

fn hex(value: &str) -> Vec<u8> {
    let (pairs, trailing) = value.as_bytes().as_chunks::<2>();
    assert_eq!(trailing, [0u8; 0]);
    pairs
        .iter()
        .map(|bytes| u8::from_str_radix(std::str::from_utf8(bytes).unwrap(), 16).unwrap())
        .collect()
}

fn admission_vector() -> (SharedVaultWrapContext, AccountKemKeyPair, Vec<u8>, VaultKey) {
    let document =
        VectorDocument::from_bytes(include_bytes!("../../../vectors/shared-vault-wrap.json"))
            .unwrap();
    let [vector] = document.vectors.as_slice() else { panic!("expected one shared-vault vector") };
    assert_eq!(vector.kind, "crypto.shared-vault-wrap-open");
    let fields = vector.input.split('|').collect::<Vec<_>>();
    let [
        organization,
        vault,
        epoch,
        author,
        author_member,
        author_revision,
        author_key,
        recipient,
        recipient_member,
        recipient_revision,
        recipient_key,
        private,
        wrap,
    ] = fields.as_slice()
    else {
        panic!("incorrect shared-vault fixture fields");
    };
    let kem = AccountKemKeyPair::from_private_bytes(&hex(private)).unwrap();
    let context = SharedVaultWrapContext {
        operation: SharedVaultWrapOperation::Admit,
        organization: organization.parse().unwrap(),
        vault: vault.parse().unwrap(),
        epoch: epoch.parse().unwrap(),
        author: SharedVaultWrapParty {
            account: author.parse().unwrap(),
            membership: author_member.parse().unwrap(),
            revision: author_revision.parse().unwrap(),
            signing_key: hex(author_key).try_into().unwrap(),
        },
        recipient: SharedVaultWrapParty {
            account: recipient.parse().unwrap(),
            membership: recipient_member.parse().unwrap(),
            revision: recipient_revision.parse().unwrap(),
            signing_key: hex(recipient_key).try_into().unwrap(),
        },
        recipient_kem_key: kem.public_key().try_into().unwrap(),
    };
    (context, kem, hex(wrap), VaultKey::from_slice(&hex(&vector.expected)).unwrap())
}

#[test]
fn independent_shared_vault_wrap_verifies_and_opens() {
    let (context, recipient, bytes, key) = admission_vector();
    let wrap = SharedVaultKeyWrap::decode(&bytes).unwrap();
    assert_eq!(wrap.encode().as_slice(), bytes);
    wrap.verify(&context).unwrap();
    assert_eq!(wrap.open(&context, &recipient).unwrap(), key);
}

#[test]
fn shared_vault_wrap_rejects_scope_author_and_recipient_substitutions() {
    let (context, recipient, bytes, _) = admission_vector();
    let wrap = SharedVaultKeyWrap::decode(&bytes).unwrap();
    let other_recipient = AccountKemKeyPair::from_private_bytes(&[14; 32]).unwrap();
    let new_signer = Ed25519SigningKey::from_bytes(&[15; 32]).unwrap();
    let other_id = Uuid::now_v7();
    let changes: [fn(&mut SharedVaultWrapContext); 6] = [
        |ctx| ctx.operation = SharedVaultWrapOperation::PublishEpoch,
        |ctx| ctx.epoch += 1,
        |ctx| ctx.author.revision += 1,
        |ctx| ctx.recipient.revision += 1,
        |ctx| ctx.author.signing_key = ctx.recipient.signing_key,
        |ctx| ctx.recipient.signing_key = ctx.author.signing_key,
    ];
    for change in changes {
        let mut substituted = context;
        change(&mut substituted);
        assert_eq!(wrap.verify(&substituted), Err(PrimitiveError::InvalidSignature));
    }
    let mut substituted = context;
    substituted.recipient_kem_key = other_recipient.public_key().try_into().unwrap();
    assert!(wrap.verify(&substituted).is_err());
    for forged in [
        SharedVaultWrapContext { organization: other_id, ..context },
        SharedVaultWrapContext { vault: other_id, ..context },
        SharedVaultWrapContext {
            author: SharedVaultWrapParty { account: other_id, ..context.author },
            ..context
        },
        SharedVaultWrapContext {
            author: SharedVaultWrapParty { membership: other_id, ..context.author },
            ..context
        },
        SharedVaultWrapContext {
            recipient: SharedVaultWrapParty { account: other_id, ..context.recipient },
            ..context
        },
        SharedVaultWrapContext {
            recipient: SharedVaultWrapParty { membership: other_id, ..context.recipient },
            ..context
        },
    ] {
        assert_eq!(wrap.open(&forged, &recipient), Err(PrimitiveError::InvalidSignature));
    }
    assert_eq!(wrap.open(&context, &other_recipient), Err(PrimitiveError::InvalidKey));
    let forged = SharedVaultKeyWrap::seal(
        &SharedVaultWrapContext {
            author: SharedVaultWrapParty { signing_key: new_signer.public_key(), ..context.author },
            ..context
        },
        &new_signer,
        &VaultKey::new([12; 32]),
    )
    .unwrap();
    assert_eq!(forged.open(&context, &recipient), Err(PrimitiveError::InvalidSignature));
    for offset in [1, 33, 81] {
        let mut tampered = bytes.clone();
        tampered[offset] ^= 1;
        assert_eq!(
            SharedVaultKeyWrap::decode(&tampered).unwrap().verify(&context),
            Err(PrimitiveError::InvalidSignature)
        );
    }
    let mut tampered = bytes.clone();
    tampered[0] = 2;
    assert!(SharedVaultKeyWrap::decode(&tampered).is_err());
    tampered = bytes.clone();
    tampered.push(0);
    assert!(SharedVaultKeyWrap::decode(&tampered).is_err());
    assert!(SharedVaultKeyWrap::decode(&bytes[..144]).is_err());
}

#[test]
fn shared_vault_wrap_round_trips_creation_and_epoch_publication() {
    let (admission, recipient, _, key) = admission_vector();
    let author = Ed25519SigningKey::from_bytes(&[8; 32]).unwrap();
    let creation = SharedVaultWrapContext {
        operation: SharedVaultWrapOperation::Create,
        epoch: 1,
        author: admission.recipient,
        ..admission
    };
    let publication = SharedVaultWrapContext {
        operation: SharedVaultWrapOperation::PublishEpoch,
        epoch: 2,
        ..creation
    };
    for context in [creation, publication] {
        let sealed = SharedVaultKeyWrap::seal(&context, &author, &key).unwrap();
        assert_eq!(sealed.open(&context, &recipient).unwrap(), key);
        let second = SharedVaultKeyWrap::seal(&context, &author, &key).unwrap();
        assert_ne!(sealed.encode(), second.encode());
    }
    for invalid in [
        SharedVaultWrapContext { epoch: 2, ..creation },
        SharedVaultWrapContext { epoch: 1, ..publication },
        SharedVaultWrapContext { operation: SharedVaultWrapOperation::Admit, ..creation },
        SharedVaultWrapContext { vault: Uuid::nil(), ..creation },
        SharedVaultWrapContext {
            author: SharedVaultWrapParty { revision: 0, ..creation.author },
            ..creation
        },
    ] {
        assert!(SharedVaultKeyWrap::seal(&invalid, &author, &key).is_err());
    }
}
