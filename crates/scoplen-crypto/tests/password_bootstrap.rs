// SPDX-License-Identifier: Apache-2.0

use scoplen_crypto::{
    AccountKemKeyPair, AccountKemKeyWrap, AccountSigningKeyWrap, Ed25519SigningKey,
    PASSWORD_ARK_WRAP_BYTES, PASSWORD_BOOTSTRAP_PROFILE, PasswordArkWrap, PasswordBootstrapContext,
    PasswordBootstrapError, PasswordKdfContext, PasswordSecrets, PasswordVerifier, SecretBytes,
    SecretVec, normalize_account_password,
};
use scoplen_test_vectors::VectorDocument;
use serde_json::Value;
use uuid::Uuid;

const ORIGIN: &str = "https://control.example.com";
const USERNAME: &str = "alice._-09";
const GENERATION: u64 = 0x0102_0304_0506_0708;

fn hex(text: &str) -> Vec<u8> {
    text.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            u8::from_str_radix(std::str::from_utf8(pair).expect("hex UTF-8"), 16).expect("hex")
        })
        .collect()
}

fn password() -> SecretVec {
    SecretVec::new("  Cafe\u{301} and A\0Z  ".as_bytes().to_vec())
}

fn kdf() -> PasswordKdfContext {
    PasswordKdfContext::new(
        ORIGIN,
        USERNAME,
        PASSWORD_BOOTSTRAP_PROFILE,
        &(0..16).collect::<Vec<_>>(),
    )
    .expect("stored context")
}

fn id(last: u8) -> Uuid {
    Uuid::parse_str(&format!("019c8a50-1000-7000-8000-0000000000{last:02x}"))
        .expect("synthetic UUIDv7")
}

fn roots() -> (Ed25519SigningKey, AccountKemKeyPair) {
    (
        Ed25519SigningKey::from_bytes(&[6; 32]).expect("signing root"),
        AccountKemKeyPair::from_private_bytes(&[8; 32]).expect("KEM root"),
    )
}

fn context(kdf: PasswordKdfContext) -> PasswordBootstrapContext {
    let (signing, kem) = roots();
    PasswordBootstrapContext::new(
        kdf,
        id(1),
        id(2),
        &signing.public_key(),
        kem.public_key(),
        GENERATION,
    )
    .expect("bootstrap context")
}

#[test]
fn independent_normalization_vectors_use_strict_bounded_unicode17_nfc() {
    let document =
        VectorDocument::parse_str(include_str!("../../../vectors/password-bootstrap.json"))
            .expect("D-127 vectors");
    let mut checked = 0;
    for vector in
        document.vectors.iter().filter(|value| value.kind == "crypto.password-normalization")
    {
        let result = normalize_account_password(SecretVec::new(hex(&vector.input)));
        if vector.expected == "reject" {
            assert_eq!(result, Err(PasswordBootstrapError::InvalidPassword), "{}", vector.id);
        } else {
            assert_eq!(
                result.expect(&vector.id).as_bytes(),
                hex(&vector.expected),
                "{}",
                vector.id
            );
        }
        checked += 1;
    }
    assert_eq!(checked, 18);
    for spelling in ["  Café and A\0Z  ", "  Cafe\u{301} and A\0Z  "] {
        assert_eq!(
            normalize_account_password(SecretVec::new(spelling.as_bytes().to_vec()))
                .expect("canonical equivalents")
                .as_bytes(),
            "  Café and A\0Z  ".as_bytes()
        );
    }
    assert_ne!(
        normalize_account_password(password()).expect("original"),
        normalize_account_password(SecretVec::new("  café and a\0z  ".as_bytes().to_vec()))
            .expect("case is preserved")
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn public_known_answer_opens_only_after_both_d108_roots_match() {
    let document =
        VectorDocument::parse_str(include_str!("../../../vectors/password-bootstrap.json"))
            .expect("D-127 vectors");
    let vector = document
        .vectors
        .iter()
        .find(|value| value.id == "password-bootstrap-known-answer")
        .expect("known answer");
    let input: Value = serde_json::from_str(&vector.input).expect("input");
    let expected: Value = serde_json::from_str(&vector.expected).expect("answer");
    let kdf = kdf();
    assert_eq!(kdf.derivation_context(), hex(expected["context"].as_str().expect("C")));
    assert_eq!(kdf.origin(), ORIGIN);
    assert_eq!(kdf.username(), USERNAME);
    assert_eq!(kdf.profile(), 1);
    let context = context(kdf.clone());
    assert_eq!(context.aad(), hex(expected["aad"].as_str().expect("AAD")));
    let secrets = kdf.derive(password()).expect("derive profile 1");
    assert_eq!(
        secrets.auth_secret().as_ref(),
        hex(expected["auth_secret"].as_str().expect("auth"))
    );
    let verifier = secrets.verifier();
    assert_eq!(
        verifier.as_bytes().as_slice(),
        hex(expected["verifier"].as_str().expect("verifier"))
    );
    assert_eq!(
        PasswordVerifier::from_bytes(verifier.as_bytes()).expect("stored verifier"),
        verifier
    );
    verifier
        .verify(SecretVec::new(secrets.auth_secret().as_ref().to_vec()))
        .expect("transient auth");
    for presented in [vec![], vec![0; 31], vec![0; 32], vec![0; 33]] {
        assert_eq!(
            verifier.verify(SecretVec::new(presented)),
            Err(PasswordBootstrapError::Authentication)
        );
    }
    let bytes = hex(expected["envelope"].as_str().expect("envelope"));
    let envelope = PasswordArkWrap::decode(&bytes).expect("independent envelope");
    assert_eq!(envelope.encode().as_slice(), bytes);
    let ark = SecretBytes::from_slice(&hex(input["ark"].as_str().expect("ARK"))).expect("ARK");
    assert_eq!(envelope.open(&secrets, &context).expect("authenticated envelope"), ark);

    let (signing, kem) = roots();
    let signing_wrap = AccountSigningKeyWrap::decode(&hex(expected["signing_wrap"]
        .as_str()
        .expect("D108 signing")))
    .expect("independent D108 signing");
    let kem_wrap =
        AccountKemKeyWrap::decode(&hex(expected["kem_wrap"].as_str().expect("D108 KEM")))
            .expect("independent D108 KEM");
    let opened = secrets
        .open_bootstrap(&context, &envelope, &signing_wrap, &kem_wrap)
        .expect("both roots reconstructed");
    assert_eq!(opened.ark(), &ark);
    assert_eq!(opened.keys().signing.public_key(), signing.public_key());
    assert_eq!(opened.keys().kem.public_key(), kem.public_key());
    let opened = context
        .derive_and_open(password(), &bytes, &signing_wrap.encode(), &kem_wrap.encode())
        .expect("combined public opener");
    let (opened_ark, opened_keys) = opened.into_parts();
    assert_eq!(opened_ark, ark);
    assert_eq!(opened_keys.signing.public_key(), signing.public_key());
    let wrong_signing = AccountSigningKeyWrap::seal(
        id(1),
        &ark,
        &Ed25519SigningKey::from_bytes(&[7; 32]).expect("other signing"),
    )
    .expect("wrong signing wrap");
    let wrong_kem = AccountKemKeyWrap::seal(
        id(1),
        &ark,
        &AccountKemKeyPair::from_private_bytes(&[9; 32]).expect("other KEM"),
    )
    .expect("wrong KEM wrap");
    for (signing, kem) in [(&wrong_signing, &kem_wrap), (&signing_wrap, &wrong_kem)] {
        assert!(matches!(
            secrets.open_bootstrap(&context, &envelope, signing, kem),
            Err(PasswordBootstrapError::Authentication)
        ));
    }
    let wrong_private_signing =
        AccountSigningKeyWrap::decode(&hex(expected["signing_wrap_wrong_private"]
            .as_str()
            .expect("wrong signing plaintext")))
        .expect("authenticated wrong signing plaintext");
    let wrong_private_kem = AccountKemKeyWrap::decode(&hex(expected["kem_wrap_wrong_private"]
        .as_str()
        .expect("wrong KEM plaintext")))
    .expect("authenticated wrong KEM plaintext");
    for (signing, kem) in [(&wrong_private_signing, &kem_wrap), (&signing_wrap, &wrong_private_kem)]
    {
        assert!(matches!(
            secrets.open_bootstrap(&context, &envelope, signing, kem),
            Err(PasswordBootstrapError::Authentication)
        ));
    }
    let wrong =
        kdf.derive(SecretVec::new(b"a different password".to_vec())).expect("wrong password KDF");
    assert_eq!(envelope.open(&wrong, &context), Err(PasswordBootstrapError::Authentication));
    for index in [1, 24, 25, 56, 57, 72] {
        let mut changed = bytes.clone();
        changed[index] ^= 1;
        assert_eq!(
            PasswordArkWrap::decode(&changed).expect("structural bytes").open(&secrets, &context),
            Err(PasswordBootstrapError::Authentication)
        );
    }
    assert_eq!(format!("{secrets:?}"), "PasswordSecrets { secrets: [REDACTED] }");
    assert_eq!(format!("{verifier:?}"), "PasswordVerifier { digest: [REDACTED] }");
    assert_eq!(format!("{envelope:?}"), "PasswordArkWrap { artifact: [REDACTED] }");
    assert_eq!(format!("{context:?}"), "PasswordBootstrapContext { metadata: [REDACTED] }");
    assert_eq!(format!("{kdf:?}"), "PasswordKdfContext { metadata: [REDACTED] }");
}

#[test]
fn every_aad_field_is_bound_and_production_sealing_refreshes_the_nonce() {
    let kdf = kdf();
    let secrets = kdf.derive(password()).expect("derive");
    let original = context(kdf.clone());
    let ark = SecretBytes::new([4; 32]);
    let first = PasswordArkWrap::seal(&secrets, &original, &ark).expect("seal");
    let second = PasswordArkWrap::seal(&secrets, &original, &ark).expect("rewrap");
    assert_ne!(&first.encode()[1..25], &second.encode()[1..25]);
    assert_eq!(second.open(&secrets, &original).expect("rewrap open"), ark);
    let (signing, kem) = roots();
    let other_signing = Ed25519SigningKey::from_bytes(&[7; 32]).expect("other signing");
    let other_kem = AccountKemKeyPair::from_private_bytes(&[9; 32]).expect("other KEM");
    let mut substitutions = vec![
        PasswordBootstrapContext::new(
            kdf.clone(),
            id(3),
            id(2),
            &signing.public_key(),
            kem.public_key(),
            GENERATION,
        )
        .expect("account"),
        PasswordBootstrapContext::new(
            kdf.clone(),
            id(1),
            id(3),
            &signing.public_key(),
            kem.public_key(),
            GENERATION,
        )
        .expect("vault"),
        PasswordBootstrapContext::new(
            kdf.clone(),
            id(1),
            id(2),
            &other_signing.public_key(),
            kem.public_key(),
            GENERATION,
        )
        .expect("signing"),
        PasswordBootstrapContext::new(
            kdf.clone(),
            id(1),
            id(2),
            &signing.public_key(),
            other_kem.public_key(),
            GENERATION,
        )
        .expect("KEM"),
        PasswordBootstrapContext::new(
            kdf.clone(),
            id(1),
            id(2),
            &signing.public_key(),
            kem.public_key(),
            1,
        )
        .expect("generation"),
        PasswordBootstrapContext::new(
            kdf.clone(),
            id(1),
            id(2),
            &signing.public_key(),
            kem.public_key(),
            u64::MAX,
        )
        .expect("maximum generation"),
    ];
    for kdf in [
        PasswordKdfContext::new("https://other.example.com", USERNAME, 1, kdf.salt())
            .expect("origin"),
        PasswordKdfContext::new(ORIGIN, "alice.other", 1, kdf.salt()).expect("username"),
        PasswordKdfContext::new(ORIGIN, USERNAME, 1, &[3; 16]).expect("salt"),
    ] {
        substitutions.push(context(kdf));
    }
    for substituted in substitutions {
        assert_ne!(substituted.aad(), original.aad());
        assert_eq!(first.open(&secrets, &substituted), Err(PasswordBootstrapError::Authentication));
    }
}

#[test]
fn creation_generates_a_new_salt_and_separates_credentials() {
    let first = PasswordSecrets::create(ORIGIN, USERNAME, password()).expect("new credential");
    let second = PasswordSecrets::create(ORIGIN, USERNAME, password()).expect("second credential");
    assert_ne!(first.context().salt(), second.context().salt());
    assert_ne!(first.auth_secret(), second.auth_secret());
    assert_ne!(first.verifier(), second.verifier());
}

#[test]
#[allow(clippy::too_many_lines)]
fn structural_failures_are_rejected_before_any_password_derivation() {
    for username in [
        "",
        "ab",
        "Alice",
        " alice",
        "alice ",
        "-alice",
        ".alice",
        "_alice",
        "alice@example.com",
        "alicé",
        "alice%2e",
    ] {
        assert!(matches!(
            PasswordKdfContext::new(ORIGIN, username, 1, &[0; 16]),
            Err(PasswordBootstrapError::InvalidContext)
        ));
    }
    for username in ["abc".to_owned(), "a".repeat(64), "0._-".to_owned()] {
        PasswordKdfContext::new(ORIGIN, &username, 1, &[0; 16]).expect("canonical username");
    }
    assert!(PasswordKdfContext::new(ORIGIN, &"a".repeat(65), 1, &[0; 16]).is_err());
    for origin in [
        "http://control.example.com",
        "https://CONTROL.example.com",
        "https://control.example.com/",
        "https://control.example.com:443",
        "https://user@control.example.com",
        "https://control.example.com?x",
    ] {
        assert!(matches!(
            PasswordKdfContext::new(origin, USERNAME, 1, &[0; 16]),
            Err(PasswordBootstrapError::InvalidContext)
        ));
    }
    for profile in 0..=u8::MAX {
        if profile != 1 {
            assert_eq!(
                PasswordKdfContext::new(ORIGIN, USERNAME, profile, &[0; 16]),
                Err(PasswordBootstrapError::UnsupportedProfile)
            );
        }
    }
    for length in [0, 1, 15, 17, 32, 2048] {
        assert!(matches!(
            PasswordKdfContext::new(ORIGIN, USERNAME, 1, &vec![0; length]),
            Err(PasswordBootstrapError::InvalidContext)
        ));
    }
    let kdf = kdf();
    let (signing, kem) = roots();
    for (account, vault, generation) in
        [(Uuid::nil(), id(2), 1), (id(1), Uuid::nil(), 1), (id(1), id(2), 0)]
    {
        assert!(
            PasswordBootstrapContext::new(
                kdf.clone(),
                account,
                vault,
                &signing.public_key(),
                kem.public_key(),
                generation
            )
            .is_err()
        );
    }
    for bad in [vec![], vec![0; 31], vec![0; 33]] {
        assert!(
            PasswordBootstrapContext::new(kdf.clone(), id(1), id(2), &bad, kem.public_key(), 1)
                .is_err()
        );
        assert!(
            PasswordBootstrapContext::new(
                kdf.clone(),
                id(1),
                id(2),
                &signing.public_key(),
                &bad,
                1
            )
            .is_err()
        );
        assert!(PasswordVerifier::from_bytes(&bad).is_err());
    }
    let context = context(kdf);
    for length in 0..=PASSWORD_ARK_WRAP_BYTES + 1 {
        if length == PASSWORD_ARK_WRAP_BYTES {
            continue;
        }
        let mut bytes = vec![0; length];
        if let Some(version) = bytes.first_mut() {
            *version = 1;
        }
        assert!(matches!(
            PasswordArkWrap::decode(&bytes),
            Err(PasswordBootstrapError::InvalidEncoding)
        ));
    }
    for version in 0..=u8::MAX {
        if version == 1 {
            continue;
        }
        let mut bytes = [0; PASSWORD_ARK_WRAP_BYTES];
        bytes[0] = version;
        assert!(matches!(
            PasswordArkWrap::decode(&bytes),
            Err(PasswordBootstrapError::InvalidEncoding)
        ));
    }
    let invalid_password = || SecretVec::new(vec![0xff; 2049]);
    let mut envelope = [0; 73];
    envelope[0] = 1;
    for (envelope, signing, kem) in [
        (&[][..], &envelope[..], &envelope[..]),
        (&envelope[..], &[][..], &envelope[..]),
        (&envelope[..], &envelope[..], &[][..]),
    ] {
        assert!(matches!(
            context.derive_and_open(invalid_password(), envelope, signing, kem),
            Err(PasswordBootstrapError::InvalidEncoding)
        ));
    }
}
