// SPDX-License-Identifier: Apache-2.0

use scoplen_crypto::{
    AccountKemKeyPair, Ed25519SigningKey, PrimitiveError, SharedVaultAuthorityContext,
    SharedVaultAuthorityReceipt, SharedVaultKeyWrap, SharedVaultReceiptPin, SharedVaultWrapContext,
    SharedVaultWrapOperation, SharedVaultWrapParty, VaultKey,
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

fn wrap_vectors() -> VectorDocument {
    VectorDocument::from_bytes(include_bytes!("../../../vectors/shared-vault-wrap.json")).unwrap()
}

fn admission_vector() -> (SharedVaultWrapContext, AccountKemKeyPair, Vec<u8>, VaultKey) {
    let document = wrap_vectors();
    let vector = &document.vectors[0];
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

struct AuthorityFixture {
    context: SharedVaultAuthorityContext,
    recipient: AccountKemKeyPair,
    wrap: SharedVaultKeyWrap,
    key: VaultKey,
    audit_key: [u8; 32],
    receipt: Vec<u8>,
    pin: SharedVaultReceiptPin,
}

fn authority_fixture() -> AuthorityFixture {
    let (context, recipient, wrap, key) = admission_vector();
    let doc = wrap_vectors();
    let vector = &doc.vectors[1];
    assert_eq!(vector.kind, "crypto.shared-vault-authority-open");
    let fields = vector.input.split('|').collect::<Vec<_>>();
    let [admission, author_kem, audit_key, receipt] = fields.as_slice() else {
        panic!("incorrect Shared vault authority fixture fields");
    };
    AuthorityFixture {
        context: SharedVaultAuthorityContext {
            wrap: context,
            recipient_admission: admission.parse().unwrap(),
            author_kem_key: hex(author_kem).try_into().unwrap(),
        },
        recipient,
        wrap: SharedVaultKeyWrap::decode(&wrap).unwrap(),
        key,
        audit_key: hex(audit_key).try_into().unwrap(),
        receipt: hex(receipt),
        pin: SharedVaultReceiptPin {
            sequence: 42,
            wrap_digest: hex(&vector.expected).try_into().unwrap(),
        },
    }
}

#[test]
fn independent_shared_vault_authority_receipt_matches_issuance_and_opens() {
    let f = authority_fixture();
    let audit = Ed25519SigningKey::from_bytes(&[16; 32]).unwrap();
    assert_eq!(audit.public_key(), f.audit_key);
    let receipt = SharedVaultAuthorityReceipt::decode(&f.receipt).unwrap();
    let issued =
        SharedVaultAuthorityReceipt::issue(&f.context, &f.wrap, f.pin.sequence, &audit).unwrap();
    assert_eq!(issued.encode().as_slice(), f.receipt);
    for old in [None, Some(f.pin), Some(SharedVaultReceiptPin { sequence: 41, ..f.pin })] {
        assert_eq!(
            receipt.open(&f.context, &f.wrap, &f.audit_key, old, &f.recipient).unwrap(),
            (f.key.clone(), f.pin)
        );
    }
}

#[test]
fn shared_vault_authority_rejects_substituted_scope_signers_and_wraps() {
    let f = authority_fixture();
    let receipt = SharedVaultAuthorityReceipt::decode(&f.receipt).unwrap();
    let other = Uuid::now_v7();
    let alternate_key = AccountKemKeyPair::from_private_bytes(&[18; 32]).unwrap();
    for context in [
        SharedVaultAuthorityContext { recipient_admission: other, ..f.context },
        SharedVaultAuthorityContext {
            wrap: SharedVaultWrapContext { organization: other, ..f.context.wrap },
            ..f.context
        },
        SharedVaultAuthorityContext {
            wrap: SharedVaultWrapContext { epoch: 9, ..f.context.wrap },
            ..f.context
        },
        SharedVaultAuthorityContext {
            author_kem_key: alternate_key.public_key().try_into().unwrap(),
            ..f.context
        },
    ] {
        assert!(matches!(
            receipt.open(&context, &f.wrap, &f.audit_key, None, &f.recipient),
            Err(PrimitiveError::InvalidSignature)
        ));
    }
    let unrelated = Ed25519SigningKey::from_bytes(&[19; 32]).unwrap().public_key();
    assert!(matches!(
        receipt.open(&f.context, &f.wrap, &unrelated, None, &f.recipient),
        Err(PrimitiveError::InvalidSignature)
    ));
    let mut identity = [0; 32];
    identity[0] = 1;
    assert!(matches!(
        receipt.open(&f.context, &f.wrap, &identity, None, &f.recipient),
        Err(PrimitiveError::InvalidKey)
    ));
    assert!(matches!(
        receipt.open(&f.context, &f.wrap, &f.audit_key, None, &alternate_key),
        Err(PrimitiveError::InvalidKey)
    ));

    // A second valid wrap of the same key still needs its own receipt.
    let author = Ed25519SigningKey::from_bytes(&[7; 32]).unwrap();
    let substitute = SharedVaultKeyWrap::seal(&f.context.wrap, &author, &f.key).unwrap();
    assert!(matches!(
        receipt.open(&f.context, &substitute, &f.audit_key, None, &f.recipient),
        Err(PrimitiveError::InvalidSignature)
    ));
}

#[test]
fn shared_vault_authority_rejects_malformed_stale_and_conflicting_receipts() {
    let f = authority_fixture();
    let mut malformed = f.receipt.clone();
    malformed[0] = 2;
    assert!(SharedVaultAuthorityReceipt::decode(&malformed).is_err());
    malformed[0] = 1;
    malformed[1..9].fill(0);
    assert!(SharedVaultAuthorityReceipt::decode(&malformed).is_err());
    assert!(SharedVaultAuthorityReceipt::decode(&f.receipt[..72]).is_err());
    let mut overlong = f.receipt.clone();
    overlong.push(0);
    assert!(SharedVaultAuthorityReceipt::decode(&overlong).is_err());
    let receipt = SharedVaultAuthorityReceipt::decode(&f.receipt).unwrap();
    for pin in [
        SharedVaultReceiptPin { sequence: 43, ..f.pin },
        SharedVaultReceiptPin { wrap_digest: [0; 32], ..f.pin },
    ] {
        assert!(matches!(
            receipt.open(&f.context, &f.wrap, &f.audit_key, Some(pin), &f.recipient),
            Err(PrimitiveError::InvalidSignature)
        ));
    }
    malformed.clone_from(&f.receipt);
    malformed[9] ^= 1;
    let receipt = SharedVaultAuthorityReceipt::decode(&malformed).unwrap();
    assert!(matches!(
        receipt.open(&f.context, &f.wrap, &f.audit_key, None, &f.recipient),
        Err(PrimitiveError::InvalidSignature)
    ));
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
