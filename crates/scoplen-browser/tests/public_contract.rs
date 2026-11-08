// SPDX-License-Identifier: Apache-2.0

use scoplen_browser::{
    create_team_invitation, parse_team_invitation, password_auth, simple_rule,
    team_invitation_verifier,
};
use scoplen_crypto::{PasswordBootstrapError, SecretVec, TeamInvitationError};
use scoplen_test_vectors::VectorDocument;
use serde_json::Value;

fn hex(text: &str) -> Vec<u8> {
    text.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

#[test]
fn password_export_matches_the_independent_native_authentication_answer() {
    let document =
        VectorDocument::parse_str(include_str!("../../../vectors/password-bootstrap.json"))
            .unwrap();
    let vector = document.vectors.iter().find(|v| v.kind == "crypto.password-bootstrap").unwrap();
    let input: Value = serde_json::from_str(&vector.input).unwrap();
    let expected: Value = serde_json::from_str(&vector.expected).unwrap();
    let derive = |origin: &str, username: &str, profile: u8, salt: &[u8], bytes: Vec<u8>| {
        password_auth(origin, username, profile, salt, SecretVec::new(bytes))
    };
    let origin = input["origin"].as_str().unwrap();
    let username = input["username"].as_str().unwrap();
    let salt = hex(input["salt"].as_str().unwrap());
    let password = hex(input["password_hex"].as_str().unwrap());
    let auth = derive(origin, username, 1, &salt, password.clone()).unwrap();
    assert_eq!(auth.as_ref(), hex(expected["auth_secret"].as_str().unwrap()));
    assert_ne!(
        auth,
        derive("https://other.example.com", username, 1, &salt, password.clone()).unwrap()
    );
    assert_ne!(auth, derive(origin, "bob", 1, &salt, password.clone()).unwrap());
    assert_ne!(auth, derive(origin, username, 1, &[5; 16], password.clone()).unwrap());
    assert_eq!(
        derive(origin, username, 2, &salt, password.clone()),
        Err(PasswordBootstrapError::UnsupportedProfile)
    );
    assert_eq!(
        derive(origin, username, 1, &salt[..15], password.clone()),
        Err(PasswordBootstrapError::InvalidContext)
    );
    assert_eq!(
        derive(origin, username, 1, &salt, vec![0xff; 16]),
        Err(PasswordBootstrapError::InvalidPassword)
    );
    for vector in document.vectors.iter().filter(|v| v.kind == "crypto.password-normalization") {
        let result = derive(origin, username, 1, &salt, hex(&vector.input));
        if vector.expected == "reject" {
            assert_eq!(result, Err(PasswordBootstrapError::InvalidPassword), "{}", vector.id);
        } else {
            assert_eq!(
                result.unwrap(),
                derive(origin, username, 1, &salt, hex(&vector.expected)).unwrap(),
                "{}",
                vector.id
            );
        }
    }
}

#[test]
fn invitation_exports_match_every_public_parser_and_verifier_vector() {
    let document =
        VectorDocument::parse_str(include_str!("../../../vectors/team-invitation.json")).unwrap();
    for vector in document.vectors {
        match vector.kind.as_str() {
            "crypto.team-invitation.password" => assert_eq!(
                parse_team_invitation(SecretVec::new(hex(&vector.input))).is_ok(),
                vector.expected == "accept",
                "{}",
                vector.id
            ),
            "crypto.team-invitation.verifier" => {
                let input: Value = serde_json::from_str(&vector.input).unwrap();
                let result = team_invitation_verifier(
                    input["origin"].as_str().unwrap(),
                    input["organization_id"].as_str().unwrap(),
                    input["invitation_id"].as_str().unwrap(),
                    SecretVec::new(hex(input["password_hex"].as_str().unwrap())),
                );
                if vector.expected == "reject" {
                    assert!(result.is_err(), "{}", vector.id);
                } else {
                    assert_eq!(
                        result.unwrap().as_bytes().as_slice(),
                        hex(&vector.expected),
                        "{}",
                        vector.id
                    );
                }
            }
            _ => panic!("unexpected invitation vector kind"),
        }
    }
}

#[test]
fn invitation_creation_retains_only_redacting_secret_owners_and_fresh_random_passwords() {
    let origin = "https://control.example.com";
    let organization = "019c8a50-1000-7000-8000-000000000001";
    let invitation = "019c8a50-1000-7000-8000-000000000002";
    let first = create_team_invitation(origin, organization, invitation).unwrap();
    let second = create_team_invitation(origin, organization, invitation).unwrap();
    assert_ne!(first.password(), second.password());
    assert_eq!(
        first.verifier(),
        &team_invitation_verifier(
            origin,
            organization,
            invitation,
            SecretVec::new(first.password().as_bytes().to_vec()),
        )
        .unwrap()
    );
    assert!(
        !format!("{first:?}").contains(std::str::from_utf8(first.password().as_bytes()).unwrap())
    );
    assert!(matches!(
        create_team_invitation(origin, &organization.to_uppercase(), invitation),
        Err(TeamInvitationError::InvalidContext)
    ));
}

#[test]
fn rule_export_preserves_the_public_strict_input_and_exact_source_vectors() {
    let document =
        VectorDocument::parse_str(include_str!("../../../vectors/group-policy.json")).unwrap();
    let mut checked = 0;
    for vector in document.vectors {
        match vector.kind.as_str() {
            "group_policy.simple_input" => {
                assert_eq!(
                    simple_rule(vector.input.as_bytes()).is_ok(),
                    vector.expected != "rejected",
                    "{}",
                    vector.id
                );
                checked += 1;
            }
            "group_policy.simple_source" => {
                assert_eq!(
                    simple_rule(vector.input.as_bytes()).unwrap(),
                    vector.expected,
                    "{}",
                    vector.id
                );
                checked += 1;
            }
            _ => {}
        }
    }
    assert_eq!(checked, 28);
}
