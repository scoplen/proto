// SPDX-License-Identifier: Apache-2.0
use scoplen_crypto::{
    AccountProbeKey, AccountRequestIntent, AccountRequestKind, AccountRequestProof,
    AccountRequestSignatureInput, Ed25519SigningKey, P256SigningKey, canonical_device_public_key,
};
use scoplen_test_vectors::VectorDocument;
use serde_json::Value;
use uuid::Uuid;

fn unhex(v: &str) -> Vec<u8> {
    v.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect()
}

#[test]
fn independent_exact_proof_vectors_cover_both_kinds_and_intents() {
    let doc =
        VectorDocument::parse_str(include_str!("../../../vectors/account-admission.json")).unwrap();
    let mut count = 0;
    for vector in doc.vectors.iter().filter(|v| v.kind == "account.admission.proof") {
        count += 1;
        let input: Value = serde_json::from_str(&vector.input).unwrap();
        let kind = if input["kind"] == "register" {
            AccountRequestKind::Register
        } else {
            AccountRequestKind::Admit
        };
        let intent = if input["intent"] == "submit" {
            AccountRequestIntent::Submit
        } else {
            AccountRequestIntent::Confirm
        };
        let field = |name: &str| unhex(input[name].as_str().unwrap());
        let attempt = field("attempt_id");
        let nonce = field("nonce");
        let digest = field("request_digest");
        let proof = AccountRequestProof::new(
            kind,
            intent,
            input["origin"].as_str().unwrap(),
            attempt.as_slice().try_into().unwrap(),
            nonce.as_slice().try_into().unwrap(),
            Uuid::parse_str(input["operation_id"].as_str().unwrap()).unwrap(),
            Uuid::parse_str(input["device_id"].as_str().unwrap()).unwrap(),
            digest.as_slice().try_into().unwrap(),
        )
        .unwrap();
        assert_eq!(proof.as_bytes(), unhex(&vector.expected));
        let signer = P256SigningKey::from_bytes(&field("signing_scalar")).unwrap();
        proof
            .verify(
                &field("signing_public_key"),
                field("device_signature").as_slice().try_into().unwrap(),
            )
            .unwrap();
        proof.verify(&signer.public_key_sec1(), &proof.sign(&signer).unwrap()).unwrap();
        let domain = if kind == AccountRequestKind::Register {
            b"spl-account-register-v1".as_slice()
        } else {
            b"spl-account-device-admit-v1".as_slice()
        };
        let account_bytes = field("account_input");
        let stable =
            AccountRequestSignatureInput::new(kind, &account_bytes[domain.len()..]).unwrap();
        assert_eq!(stable.as_bytes(), account_bytes);
        let signature = field("account_signature");
        stable
            .verify(
                field("account_public_key").as_slice().try_into().unwrap(),
                signature.as_slice().try_into().unwrap(),
            )
            .unwrap();
        assert_eq!(
            stable.request_digest(signature.as_slice().try_into().unwrap()).as_slice(),
            digest
        );
        assert_eq!(
            stable.sign(&Ed25519SigningKey::from_bytes(&[1; 32]).unwrap()).as_slice(),
            signature
        );
    }
    assert_eq!(count, 4);
}

#[test]
fn sec1_aliases_normalize_before_cross_role_freshness_checks() {
    let key = P256SigningKey::from_bytes(&[2; 32]).unwrap().public_key_sec1();
    let mut compressed = vec![2 | (key[64] & 1)];
    compressed.extend_from_slice(&key[1..33]);
    assert_eq!(canonical_device_public_key(&compressed).unwrap().as_slice(), key);
    assert!(canonical_device_public_key(&[4; 65]).is_err());
    assert!(AccountRequestSignatureInput::new(AccountRequestKind::Register, &[]).is_err());
    assert!(
        AccountRequestSignatureInput::new(AccountRequestKind::Register, &vec![0; 262_145]).is_err()
    );
}

#[test]
fn independent_probe_vectors_cover_every_domain_and_context_binding() {
    let document =
        VectorDocument::parse_str(include_str!("../../../vectors/account-admission.json")).unwrap();
    let mut salts = std::collections::BTreeSet::new();
    let mut count = 0;
    for vector in document.vectors.iter().filter(|v| v.kind == "account.admission.probe") {
        count += 1;
        let input: Value = serde_json::from_str(&vector.input).unwrap();
        let expected: Value = serde_json::from_str(&vector.expected).unwrap();
        let probe = AccountProbeKey::new(&unhex(input["probe_key"].as_str().unwrap())).unwrap();
        let origin = input["origin"].as_str().unwrap();
        let username = input["username"].as_str().unwrap();
        let salt = probe.synthetic_salt(origin, username).unwrap();
        let verifier = probe.synthetic_verifier(origin, username).unwrap();
        let identity = probe.username_admission_identity(origin, username).unwrap();
        assert_eq!(salt.as_slice(), unhex(expected["synthetic_salt"].as_str().unwrap()));
        assert_eq!(verifier.as_ref(), unhex(expected["synthetic_verifier"].as_str().unwrap()));
        assert_eq!(
            identity.as_ref(),
            unhex(expected["username_admission_identity"].as_str().unwrap())
        );
        assert_eq!(probe.synthetic_salt(origin, username).unwrap(), salt);
        assert_ne!(verifier, identity);
        assert_ne!(salt.as_slice(), &verifier.as_ref()[..16]);
        assert_ne!(salt.as_slice(), &identity.as_ref()[..16]);
        assert!(salts.insert(salt), "distinct key/context must change the synthetic salt");
        assert_eq!(format!("{probe:?}"), "AccountProbeKey([REDACTED])");
        assert_eq!(format!("{verifier:?}"), "[REDACTED]");
        assert_eq!(format!("{identity:?}"), "[REDACTED]");
    }
    assert_eq!(count, 5);
}

#[test]
fn probe_derivation_rejects_invalid_keys_and_noncanonical_contexts() {
    for length in [0, 16, 31, 33, 64] {
        assert!(AccountProbeKey::new(&vec![0x44; length]).is_err());
    }
    let probe = AccountProbeKey::new(&[0x44; 32]).unwrap();
    for origin in [
        "http://control.example.com",
        "https://control.example.com/",
        "https://Control.example.com",
        "https://control.example.com:443",
        "https://control.example.com/path",
    ] {
        assert!(probe.synthetic_salt(origin, "fixture.user").is_err());
        assert!(probe.synthetic_verifier(origin, "fixture.user").is_err());
        assert!(probe.username_admission_identity(origin, "fixture.user").is_err());
    }
    for username in ["", "ab", ".user", "Fixture.user", "user\n", "u\u{00e9}r", &"a".repeat(65)] {
        let origin = "https://control.example.com";
        assert!(probe.synthetic_salt(origin, username).is_err());
        assert!(probe.synthetic_verifier(origin, username).is_err());
        assert!(probe.username_admission_identity(origin, username).is_err());
    }
}
