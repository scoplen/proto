// SPDX-License-Identifier: Apache-2.0

use scoplen_crypto::{TeamInvitationError, TeamInvitationPassword, TeamInvitationVerifier};
use scoplen_test_vectors::VectorDocument;
use serde_json::Value;
use uuid::Uuid;

const ORIGIN: &str = "https://control.example.com";
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

fn id(last: u8) -> Uuid {
    Uuid::parse_str(&format!("019c8a50-1000-7000-8000-0000000000{last:02x}"))
        .expect("synthetic UUIDv7")
}

fn hex(text: &str) -> Vec<u8> {
    assert!(text.len().is_multiple_of(2));
    text.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            u8::from_str_radix(std::str::from_utf8(pair).expect("hex UTF-8"), 16).expect("hex")
        })
        .collect()
}

#[test]
fn independent_known_answers_bind_the_exact_domain_length_origin_identifiers_and_password() {
    let document = VectorDocument::parse_str(include_str!("../../../vectors/team-invitation.json"))
        .expect("D-136 vectors");
    let mut verifier_count = 0;
    let mut password_count = 0;
    for vector in document.vectors {
        match vector.kind.as_str() {
            "crypto.team-invitation.verifier" => {
                let input: Value = serde_json::from_str(&vector.input).expect("vector input");
                let password = TeamInvitationPassword::parse(&hex(input["password_hex"]
                    .as_str()
                    .expect("password hex")))
                .expect("canonical synthetic password");
                let organization =
                    Uuid::parse_str(input["organization_id"].as_str().expect("organization id"))
                        .expect("syntactic UUID");
                let invitation =
                    Uuid::parse_str(input["invitation_id"].as_str().expect("invitation id"))
                        .expect("syntactic UUID");
                let result = password.verifier(
                    input["origin"].as_str().expect("origin"),
                    &organization,
                    &invitation,
                );
                if vector.expected == "reject" {
                    assert_eq!(result, Err(TeamInvitationError::InvalidContext), "{}", vector.id);
                } else {
                    assert_eq!(
                        result.expect(&vector.id).as_bytes().as_slice(),
                        hex(&vector.expected),
                        "{}",
                        vector.id
                    );
                }
                verifier_count += 1;
            }
            "crypto.team-invitation.password" => {
                let bytes = hex(&vector.input);
                let result = TeamInvitationPassword::parse(&bytes);
                if vector.expected == "reject" {
                    assert_eq!(result, Err(TeamInvitationError::InvalidPassword), "{}", vector.id);
                } else {
                    assert_eq!(
                        result.expect(&vector.id).as_bytes().as_slice(),
                        bytes,
                        "{}",
                        vector.id
                    );
                }
                password_count += 1;
            }
            _ => panic!("unexpected invitation vector kind"),
        }
    }
    assert_eq!((verifier_count, password_count), (18, 16));
}

#[test]
fn canonical_password_parser_accepts_only_the_32_symbols_in_each_of_eight_positions() {
    for position in 0..8 {
        for byte in u8::MIN..=u8::MAX {
            let mut bytes = *b"01234567";
            bytes[position] = byte;
            let result = TeamInvitationPassword::parse(&bytes);
            assert_eq!(result.is_ok(), ALPHABET.contains(&byte));
        }
    }
    for length in [0, 1, 7, 9, 1024] {
        assert_eq!(
            TeamInvitationPassword::parse(&vec![b'0'; length]),
            Err(TeamInvitationError::InvalidPassword)
        );
    }
}

#[test]
fn generated_passwords_are_fresh_canonical_and_do_not_reuse_another_generation() {
    let first = TeamInvitationPassword::generate().expect("OS random password");
    let second = TeamInvitationPassword::generate().expect("OS random password");
    assert_eq!(TeamInvitationPassword::parse(first.as_bytes()).unwrap(), first);
    assert_eq!(TeamInvitationPassword::parse(second.as_bytes()).unwrap(), second);
    assert_ne!(first, second);
    assert_ne!(
        first.verifier(ORIGIN, &id(1), &id(2)).unwrap(),
        second.verifier(ORIGIN, &id(1), &id(2)).unwrap()
    );
}

#[test]
fn context_rejection_precedes_hashing_without_normalization_or_uuid_version_aliases() {
    let password = TeamInvitationPassword::parse(b"0123WXYZ").unwrap();
    for origin in [
        "",
        "http://control.example.com",
        "https://CONTROL.example.com",
        "https://control.example.com/",
        "https://control.example.com:443",
        "https://control.example.com?x=1",
        "https://user@control.example.com",
        "https://control.example.com/path",
        "https://control.example.com#fragment",
        "https://[2001:0db8::1]",
        "https://control.example.com:0",
        "https://é.example.com",
    ] {
        assert_eq!(
            password.verifier(origin, &id(1), &id(2)),
            Err(TeamInvitationError::InvalidContext)
        );
    }
    assert_eq!(
        password.verifier(&"a".repeat(2049), &id(1), &id(2)),
        Err(TeamInvitationError::InvalidContext)
    );
    for invalid in [
        Uuid::nil(),
        Uuid::parse_str("019c8a50-1000-4000-8000-000000000001").unwrap(),
        Uuid::parse_str("019c8a50-1000-7000-7000-000000000001").unwrap(),
    ] {
        assert_eq!(
            password.verifier(ORIGIN, &invalid, &id(2)),
            Err(TeamInvitationError::InvalidContext)
        );
        assert_eq!(
            password.verifier(ORIGIN, &id(1), &invalid),
            Err(TeamInvitationError::InvalidContext)
        );
    }
}

#[test]
fn password_and_verifier_clones_preserve_value_without_debug_or_error_disclosure() {
    let password = TeamInvitationPassword::parse(b"0123WXYZ").unwrap();
    let verifier = password.verifier(ORIGIN, &id(1), &id(2)).unwrap();
    assert_eq!(password, password.clone());
    assert_eq!(verifier, verifier.clone());
    assert_eq!(verifier, TeamInvitationVerifier::from_bytes(*verifier.as_bytes()));
    assert_eq!(format!("{password:?}"), "TeamInvitationPassword([REDACTED])");
    assert_eq!(format!("{verifier:?}"), "TeamInvitationVerifier([REDACTED])");
    for position in 0..32 {
        let mut changed = *verifier.as_bytes();
        changed[position] ^= 1;
        assert_ne!(verifier, TeamInvitationVerifier::from_bytes(changed));
    }
    for error in [
        TeamInvitationError::InvalidPassword,
        TeamInvitationError::InvalidContext,
        TeamInvitationError::Randomness,
    ] {
        let output = format!("{error} {error:?}");
        assert!(!output.contains("0123WXYZ"));
        assert!(!output.contains(ORIGIN));
    }
}
