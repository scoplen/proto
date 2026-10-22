// SPDX-License-Identifier: Apache-2.0
//! D-101 proof construction and verification through the public crypto API.

use std::fmt::Write as _;

use scoplen_crypto::{
    DeviceSigner, P256SigningKey, PersonalEnrollmentArtifacts, PersonalEnrollmentContext,
    PersonalEnrollmentError, PrimitiveError,
};
use scoplen_test_vectors::VectorDocument;
use serde::Deserialize;
use uuid::Uuid;

#[derive(Clone, Deserialize)]
struct Fixture {
    origin: String,
    invitation_token: String,
    account_id: String,
    personal_vault_id: String,
    account_signing_public_key: String,
    account_kem_public_key: String,
    key_bundle_update: String,
    device_certificate: String,
    wrapped_personal_vault_key: String,
}

fn unhex(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0);
    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).expect("fixture hex"))
        .collect()
}

fn hex(value: &[u8]) -> String {
    let mut output = String::with_capacity(value.len() * 2);
    for byte in value {
        write!(&mut output, "{byte:02x}").expect("string write");
    }
    output
}

impl Fixture {
    fn context(&self) -> Result<PersonalEnrollmentContext, PersonalEnrollmentError> {
        PersonalEnrollmentContext::new(
            &self.origin,
            &unhex(&self.invitation_token).try_into().expect("32-byte token"),
            Uuid::parse_str(&self.account_id).expect("fixture account id"),
            Uuid::parse_str(&self.personal_vault_id).expect("fixture vault id"),
            PersonalEnrollmentArtifacts {
                account_signing_public_key: &unhex(&self.account_signing_public_key)
                    .try_into()
                    .expect("32-byte public key"),
                account_kem_public_key: &unhex(&self.account_kem_public_key)
                    .try_into()
                    .expect("32-byte public key"),
                key_bundle_update: &unhex(&self.key_bundle_update),
                device_certificate: &unhex(&self.device_certificate),
                wrapped_personal_vault_key: &unhex(&self.wrapped_personal_vault_key),
            },
        )
    }
}

fn vectors() -> VectorDocument {
    VectorDocument::parse_str(include_str!("../../../vectors/personal-enrollment-proof.json"))
        .expect("published proof vectors")
}

fn fixture() -> Fixture {
    serde_json::from_str(&vectors().vectors[0].input).expect("fixture fields")
}

#[test]
fn published_vectors_match_independently_encoded_signature_bytes() {
    for vector in vectors().vectors {
        let input: Fixture = serde_json::from_str(&vector.input).expect("fixture fields");
        match vector.kind.as_str() {
            "enrollment.signature-input" => {
                assert_eq!(
                    hex(input.context().expect("valid context").signature_input()),
                    vector.expected,
                    "{}",
                    vector.id
                );
            }
            "enrollment.invalid-context" => {
                assert!(input.context().is_err(), "{}", vector.id);
            }
            kind => panic!("unrecognized vector kind {kind}"),
        }
    }
}

#[test]
fn every_enrollment_field_is_bound_to_the_certified_device_signature() {
    let signer = P256SigningKey::from_bytes(&[1; 32]).expect("synthetic key");
    for vector in
        vectors().vectors.into_iter().filter(|vector| vector.kind == "enrollment.signature-input")
    {
        let input: Fixture = serde_json::from_str(&vector.input).expect("fixture fields");
        let context = input.context().expect("valid context");
        let signature = context.sign(&signer).expect("device signature");
        context.verify(&signer.public_key_sec1(), &signature).expect("verified proof");
        for field in 0..9 {
            let mut changed = input.clone();
            match field {
                0 => changed.origin = "https://other.example.com".into(),
                1 => changed.invitation_token = "ff".repeat(32),
                2 => changed.account_id = Uuid::now_v7().to_string(),
                3 => changed.personal_vault_id = Uuid::now_v7().to_string(),
                4 => changed.account_signing_public_key = "44".repeat(32),
                5 => changed.account_kem_public_key = "55".repeat(32),
                6 => changed.key_bundle_update.push_str("00"),
                7 => changed.device_certificate.push_str("00"),
                8 => changed.wrapped_personal_vault_key.push_str("00"),
                _ => unreachable!(),
            }
            assert!(
                changed
                    .context()
                    .expect("valid altered context")
                    .verify(&signer.public_key_sec1(), &signature)
                    .is_err(),
                "{} field {field} was not bound",
                vector.id,
            );
        }
    }
}

#[test]
fn replacing_an_invitation_requires_a_new_proof_from_the_retained_device() {
    let original = fixture().context().expect("original context");
    let replacement_vector = vectors()
        .vectors
        .into_iter()
        .find(|vector| vector.id == "personal-enrollment-replacement-token-signature-input-v1")
        .expect("published replacement vector");
    let replacement_fixture: Fixture =
        serde_json::from_str(&replacement_vector.input).expect("fixture fields");
    let replacement = replacement_fixture.context().expect("replacement context");
    let token_digest_start = b"spl-personal-enroll-v1".len() + 2 + replacement_fixture.origin.len();
    let token_digest_end = token_digest_start + 32;
    assert_eq!(
        &original.signature_input()[..token_digest_start],
        &replacement.signature_input()[..token_digest_start],
    );
    assert_ne!(
        &original.signature_input()[token_digest_start..token_digest_end],
        &replacement.signature_input()[token_digest_start..token_digest_end],
    );
    assert_eq!(
        &original.signature_input()[token_digest_end..],
        &replacement.signature_input()[token_digest_end..],
    );

    let signer = P256SigningKey::from_bytes(&[1; 32]).expect("retained synthetic device key");
    let original_signature = original.sign(&signer).expect("original proof");
    assert!(replacement.verify(&signer.public_key_sec1(), &original_signature).is_err());
    let replacement_signature = replacement.sign(&signer).expect("replacement proof");
    replacement
        .verify(&signer.public_key_sec1(), &replacement_signature)
        .expect("replacement proof with retained device key");
    assert!(original.verify(&signer.public_key_sec1(), &replacement_signature).is_err());
    let other = P256SigningKey::from_bytes(&[2; 32]).expect("different synthetic device key");
    assert!(replacement.verify(&other.public_key_sec1(), &replacement_signature).is_err());
}

#[test]
fn noncanonical_origins_and_non_v7_ids_are_rejected_before_signing() {
    let input = fixture();
    for origin in [
        "http://example.com",
        "https://Example.com",
        "https://example.com/",
        "https://example.com:443",
        "https://example.com?query=1",
        "https://example.com#fragment",
    ] {
        let mut invalid = input.clone();
        invalid.origin = origin.into();
        assert_eq!(invalid.context(), Err(PersonalEnrollmentError::InvalidOrigin));
    }
    let non_v7 = Uuid::nil();
    let mut invalid = input.clone();
    invalid.account_id = non_v7.to_string();
    assert_eq!(invalid.context(), Err(PersonalEnrollmentError::InvalidIdentifier));
    invalid = input;
    invalid.personal_vault_id = non_v7.to_string();
    assert_eq!(invalid.context(), Err(PersonalEnrollmentError::InvalidIdentifier));
}

#[test]
fn decoded_artifact_boundaries_are_enforced_without_changing_signature_size() {
    let input = fixture();
    let key = [7; 32];
    for field in 0..3 {
        let limit = if field == 0 { 4 * 1_024 * 1_024 } else { 65_536 };
        for length in [0, 1, limit, limit + 1] {
            let bytes = vec![0xa5; length];
            let mut artifacts = PersonalEnrollmentArtifacts {
                account_signing_public_key: &key,
                account_kem_public_key: &key,
                key_bundle_update: &[1],
                device_certificate: &[2],
                wrapped_personal_vault_key: &[3],
            };
            match field {
                0 => artifacts.key_bundle_update = &bytes,
                1 => artifacts.device_certificate = &bytes,
                2 => artifacts.wrapped_personal_vault_key = &bytes,
                _ => unreachable!(),
            }
            let result = PersonalEnrollmentContext::new(
                &input.origin,
                &key,
                Uuid::parse_str(&input.account_id).expect("fixture account id"),
                Uuid::parse_str(&input.personal_vault_id).expect("fixture vault id"),
                artifacts,
            );
            if length == 0 || length > limit {
                assert_eq!(result, Err(PersonalEnrollmentError::InvalidArtifact));
            } else {
                assert_eq!(
                    result.expect("bounded input").signature_input().len(),
                    input.context().expect("fixture context").signature_input().len()
                );
            }
        }
    }
}

#[test]
fn invalid_keys_signatures_and_signer_failures_are_not_accepted() {
    struct Unavailable;
    impl DeviceSigner for Unavailable {
        fn sign(&self, _: &[u8]) -> Result<[u8; 64], PrimitiveError> {
            Err(PrimitiveError::InvalidKey)
        }
    }
    let context = fixture().context().expect("valid context");
    assert_eq!(context.sign(&Unavailable), Err(PrimitiveError::InvalidKey));
    let signer = P256SigningKey::from_bytes(&[1; 32]).expect("synthetic key");
    let other = P256SigningKey::from_bytes(&[2; 32]).expect("different synthetic key");
    let signature = context.sign(&signer).expect("sign");
    assert!(context.verify(&other.public_key_sec1(), &signature).is_err());
    assert!(context.verify(&[0; 65], &signature).is_err());
    for invalid in [&signature[..63], &[0; 64][..], &[0; 65][..]] {
        assert!(context.verify(&signer.public_key_sec1(), invalid).is_err());
    }
}

#[test]
fn diagnostics_redact_enrollment_material() {
    assert_eq!(
        format!("{:?}", fixture().context().expect("context")),
        "PersonalEnrollmentContext([REDACTED])"
    );
    let artifacts = PersonalEnrollmentArtifacts {
        account_signing_public_key: &[1; 32],
        account_kem_public_key: &[2; 32],
        key_bundle_update: b"private wrapped account keys",
        device_certificate: b"device identity",
        wrapped_personal_vault_key: b"private wrapped vault key",
    };
    assert_eq!(format!("{artifacts:?}"), "PersonalEnrollmentArtifacts([REDACTED])");
}
