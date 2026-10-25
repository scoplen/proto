// SPDX-License-Identifier: Apache-2.0
use scoplen_api::{
    auth::{
        DeviceAccessOperation, INITIAL_OPERATOR_ACCESS_SCOPE, OperatorAccessOperation,
        OperatorAccessRequirement, OperatorAccessScope,
    },
    operator_auth::{OperatorAuthCodecError, OperatorLogoutRequest, OperatorLogoutResponse},
    operator_logout_reference::{
        ReferenceOperatorLogoutError as Error, ReferenceOperatorLogoutFault as Fault,
        ReferenceOperatorLogoutPeer,
    },
};
use scoplen_crypto::OperatorAccessTokenClaims;
use serde_json::Value;
use uuid::Uuid;

fn claims() -> OperatorAccessTokenClaims {
    OperatorAccessTokenClaims {
        iss: "https://scoplen.example.test".into(),
        sub: Uuid::from_u128(0x018f_35d4_1f8f_7e2a_9e56_7a5e_8a9f_11a1),
        sid: Uuid::from_u128(0x018f_35d4_1f8f_7e2a_9e56_7a5e_8a9f_11a2),
        jti: Uuid::from_u128(0x018f_35d4_1f8f_7e2a_9e56_7a5e_8a9f_11a3),
        cnf_jkt: "fixture-verified-key".into(),
        scope: INITIAL_OPERATOR_ACCESS_SCOPE.into(),
        iat: 100,
        exp: 700,
    }
}

#[test]
fn fixed_messages_and_complete_body_bounds_reject_unconfirmed_results() {
    assert_eq!(OperatorLogoutRequest.to_json().unwrap(), b"{}");
    assert_eq!(OperatorLogoutResponse.to_json().unwrap(), b"{\"revoked\":true}");
    for input in [
        b"[]".as_slice(),
        b"null",
        b"",
        b"{}{}",
        b"{\"sid\":null}",
        b"{\"refresh_token\":\"secret\"}",
        b"{\"x\":{\"y\":1,\"y\":2}}",
        b"{\"x\":\"\xff\"}",
    ] {
        assert!(OperatorLogoutRequest::from_json(input).is_err());
    }
    for input in [
        b"{}".as_slice(),
        b"null",
        b"[]",
        b"{\"revoked\":false}",
        b"{\"revoked\":1}",
        b"{\"revoked\":\"true\"}",
        b"{\"revoked\":true,\"revoked\":true}",
        b"{\"revoked\":true,\"extra\":null}",
    ] {
        assert!(OperatorLogoutResponse::from_json(input).is_err());
    }
    for (seed, request) in [("request", true), ("response", false)] {
        let path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fuzz/corpus/api_json");
        let exact = std::fs::read(path.join(format!("seed-operator-logout-{seed}-exact"))).unwrap();
        assert_eq!(exact.len(), 256);
        let oversized =
            std::fs::read(path.join(format!("seed-operator-logout-{seed}-oversized"))).unwrap();
        assert_eq!(oversized.len(), 257);
        if request {
            assert_eq!(OperatorLogoutRequest::from_json(&exact), Ok(OperatorLogoutRequest));
            assert_eq!(
                OperatorLogoutRequest::from_json(&oversized),
                Err(OperatorAuthCodecError::TooLarge(256))
            );
        } else {
            assert_eq!(OperatorLogoutResponse::from_json(&exact), Ok(OperatorLogoutResponse));
            assert_eq!(
                OperatorLogoutResponse::from_json(&oversized),
                Err(OperatorAuthCodecError::TooLarge(256))
            );
        }
    }
}

#[test]
fn intrinsic_registry_never_borrows_invitation_or_device_permission() {
    let logout = OperatorAccessOperation::Logout;
    assert_eq!(logout.requirement(), OperatorAccessRequirement::SelfSessionTermination);
    assert_eq!(
        OperatorAccessOperation::from_route("POST", "/api/v1/auth/operator/logout"),
        Some(logout)
    );
    assert_eq!(DeviceAccessOperation::from_route("POST", logout.route_template()), None);
    assert_eq!(OperatorAccessScope::ALL, [OperatorAccessScope::PersonalInvitationIssue]);
    assert_eq!(INITIAL_OPERATOR_ACCESS_SCOPE, "personal-invitation:issue");
    assert_eq!(OperatorAccessScope::from_token("self-session-termination"), None);
    for (method, path) in [
        ("GET", logout.route_template()),
        ("post", logout.route_template()),
        ("DELETE", logout.route_template()),
        ("POST", "/api/v1/auth/operator/logout/"),
        ("POST", "/api/v1/auth/operator/logout?sid=x"),
        ("POST", "/api/v1/auth/operator/other"),
    ] {
        assert_eq!(OperatorAccessOperation::from_route(method, path), None);
    }
}

#[test]
fn reference_terminal_confirmation_keeps_one_transition_and_rejects_proof_replay() {
    let token = claims();
    let mut peer = ReferenceOperatorLogoutPeer::new(token.clone(), 1000);
    let other = ReferenceOperatorLogoutPeer::new(token.clone(), 1000);
    assert_eq!(peer.terminate(b"{}", &token, "first", 110), Ok(OperatorLogoutResponse));
    assert_eq!(peer.terminate(b"{}", &token, "retry", 120), Ok(OperatorLogoutResponse));
    assert_eq!(peer.revoked_at(), Some(110));
    assert_eq!(peer.revocation_events(), 1);
    assert_eq!(peer.terminate(b"{}", &token, "retry", 121), Err(Error::InvalidProof));
    assert_eq!(other.revoked_at(), None);
    assert_eq!(other.revocation_events(), 0);
}

#[test]
fn reference_terminal_branch_keeps_all_identity_binding_and_time_checks() {
    let token = claims();
    for already_revoked in [false, true] {
        for (operator, credential) in [(false, true), (true, false)] {
            let mut peer = ReferenceOperatorLogoutPeer::new(token.clone(), 1000);
            if already_revoked {
                peer.terminate(b"{}", &token, "first", 110).unwrap();
            }
            peer.set_identity_active(operator, credential);
            assert_eq!(
                peer.terminate(b"{}", &token, "new", 120),
                Err(Error::AuthenticationRequired)
            );
            assert_eq!(peer.revocation_events(), u64::from(already_revoked));
        }
        for field in 0..8 {
            let mut peer = ReferenceOperatorLogoutPeer::new(token.clone(), 1000);
            if already_revoked {
                peer.terminate(b"{}", &token, "first", 110).unwrap();
            }
            let mut changed = token.clone();
            match field {
                0 => changed.sub = Uuid::nil(),
                1 => changed.sid = Uuid::nil(),
                2 => changed.cnf_jkt = "other-key".into(),
                3 => changed.iss = "https://other.example.test".into(),
                4 => changed.scope = "*".into(),
                5 => changed.exp = 120,
                6 => changed.iat = 121,
                _ => changed.iat = 99,
            }
            assert_eq!(
                peer.terminate(b"{}", &changed, "new", 120),
                Err(Error::AuthenticationRequired)
            );
            assert_eq!(peer.revocation_events(), u64::from(already_revoked));
        }
        let mut peer = ReferenceOperatorLogoutPeer::new(token.clone(), 120);
        if already_revoked {
            peer.terminate(
                b"{}",
                &OperatorAccessTokenClaims { exp: 120, ..token.clone() },
                "first",
                110,
            )
            .unwrap();
        }
        assert_eq!(peer.terminate(b"{}", &token, "new", 120), Err(Error::AuthenticationRequired));
    }
}

#[test]
fn reference_rollback_unknown_commit_and_lost_response_allow_only_fresh_explicit_retry() {
    let token = claims();
    for (fault, error, committed) in [
        (Fault::BeforeCommit, Error::StorageUnavailable, false),
        (Fault::UnknownRollback, Error::CommitOutcomeUnknown, false),
        (Fault::UnknownCommitted, Error::CommitOutcomeUnknown, true),
        (Fault::LostResponse, Error::ResponseLost, true),
    ] {
        let mut peer = ReferenceOperatorLogoutPeer::new(token.clone(), 1000);
        peer.set_fault(fault);
        assert_eq!(peer.terminate(b"{}", &token, "first", 110), Err(error));
        assert_eq!(peer.revocation_events(), u64::from(committed));
        assert_eq!(peer.terminate(b"{}", &token, "first", 120), Err(Error::InvalidProof));
        assert_eq!(peer.terminate(b"{}", &token, "fresh", 120), Ok(OperatorLogoutResponse));
        assert_eq!(peer.revocation_events(), 1);
        assert_eq!(peer.revoked_at(), Some(if committed { 110 } else { 120 }));
        let problem = error.problem("fixture-request").unwrap();
        if error == Error::ResponseLost {
            assert!(problem.is_none());
        } else {
            let problem = problem.unwrap();
            assert!(problem.retryable);
            assert_eq!(problem.changed, error == Error::CommitOutcomeUnknown);
        }
    }
}

#[test]
fn reference_terminal_faults_preserve_transition_and_require_fresh_proofs() {
    let token = claims();
    for fault in
        [Fault::BeforeCommit, Fault::UnknownRollback, Fault::UnknownCommitted, Fault::LostResponse]
    {
        let mut peer = ReferenceOperatorLogoutPeer::new(token.clone(), 1000);
        peer.terminate(b"{}", &token, "first", 110).unwrap();
        peer.set_fault(fault);
        let error = if fault == Fault::LostResponse {
            Error::ResponseLost
        } else {
            Error::StorageUnavailable
        };
        assert_eq!(peer.terminate(b"{}", &token, "terminal", 120), Err(error));
        if let Some(problem) = error.problem("fixture-request").unwrap() {
            assert!(!problem.changed);
            assert!(problem.retryable);
        }
        assert_eq!(peer.revoked_at(), Some(110));
        assert_eq!(peer.revocation_events(), 1);
        assert_eq!(peer.terminate(b"{}", &token, "terminal", 121), Err(Error::InvalidProof));
        assert_eq!(peer.terminate(b"{}", &token, "fresh", 122), Ok(OperatorLogoutResponse));
        assert_eq!(peer.revoked_at(), Some(110));
        assert_eq!(peer.revocation_events(), 1);
    }
}

#[test]
fn reference_invalid_body_or_empty_proof_cannot_mutate_the_peer() {
    let token = claims();
    let mut peer = ReferenceOperatorLogoutPeer::new(token.clone(), 1000);
    peer.set_fault(Fault::BeforeCommit);
    let mut oversized = vec![b' '; 255];
    oversized.extend_from_slice(b"{}");
    assert_eq!(oversized.len(), 257);
    assert_eq!(peer.terminate(&oversized, &token, "first", 110), Err(Error::TooLarge));
    let problem = Error::TooLarge.problem("fixture-request").unwrap().unwrap();
    assert_eq!(problem.status, 413);
    assert!(!problem.changed);
    assert!(!problem.retryable);
    assert_eq!(peer.terminate(b"{}", &token, "", 110), Err(Error::InvalidProof));
    assert_eq!(peer.revoked_at(), None);
    assert_eq!(peer.revocation_events(), 0);
    assert_eq!(peer.terminate(b"{}", &token, "first", 110), Err(Error::StorageUnavailable));
    assert_eq!(peer.terminate(b"{}", &token, "first", 111), Err(Error::InvalidProof));
    assert_eq!(peer.terminate(b"{}", &token, "fresh", 112), Ok(OperatorLogoutResponse));
    assert_eq!(peer.revoked_at(), Some(112));
    assert_eq!(peer.revocation_events(), 1);
}

#[test]
fn reference_uncertain_result_does_not_relax_fresh_retry_family_binding() {
    let token = claims();
    for fault in [Fault::UnknownRollback, Fault::UnknownCommitted] {
        let mut peer = ReferenceOperatorLogoutPeer::new(token.clone(), 1000);
        peer.set_fault(fault);
        assert_eq!(peer.terminate(b"{}", &token, "first", 110), Err(Error::CommitOutcomeUnknown));
        let timestamp = peer.revoked_at();
        let events = peer.revocation_events();
        let mut different_family = token.clone();
        different_family.sid = Uuid::nil();
        assert_eq!(
            peer.terminate(b"{}", &different_family, "fresh", 120),
            Err(Error::AuthenticationRequired)
        );
        assert_eq!(peer.revoked_at(), timestamp);
        assert_eq!(peer.revocation_events(), events);
        peer.terminate(b"{}", &token, "valid-fresh", 121).unwrap();
        assert_eq!(peer.revocation_events(), 1);
    }
}

#[test]
fn reference_debug_never_discloses_token_bindings_or_proof_identifiers() {
    let mut token = claims();
    token.iss = "https://issuer-debug-sentinel.example.test".into();
    token.cnf_jkt = "key-debug-sentinel".into();
    token.scope = "scope-debug-sentinel".into();
    let mut peer = ReferenceOperatorLogoutPeer::new(token.clone(), 1000);
    peer.terminate(b"{}", &token, "proof-debug-sentinel", 110).unwrap();
    let debug = format!("{peer:?}");
    for private in [
        token.iss,
        token.cnf_jkt,
        token.scope,
        token.sub.to_string(),
        token.sid.to_string(),
        token.jti.to_string(),
        "proof-debug-sentinel".into(),
    ] {
        assert!(!debug.contains(&private));
    }
}

#[test]
fn independent_vectors_replay_public_codecs_registry_and_problem_flags() {
    let vectors = scoplen_test_vectors::VectorDocument::parse_str(include_str!(
        "../../../vectors/operator-logout.json"
    ))
    .unwrap();
    assert!(vectors.vectors.len() >= 16);
    for vector in vectors.vectors {
        let actual = match vector.kind.as_str() {
            "operator.logout.request" => String::from_utf8(
                OperatorLogoutRequest::from_json(vector.input.as_bytes())
                    .unwrap()
                    .to_json()
                    .unwrap(),
            )
            .unwrap(),
            "operator.logout.response" => String::from_utf8(
                OperatorLogoutResponse::from_json(vector.input.as_bytes())
                    .unwrap()
                    .to_json()
                    .unwrap(),
            )
            .unwrap(),
            "operator.logout.request.reject" => {
                assert!(
                    OperatorLogoutRequest::from_json(vector.input.as_bytes()).is_err(),
                    "{}",
                    vector.id
                );
                continue;
            }
            "operator.logout.response.reject" => {
                assert!(
                    OperatorLogoutResponse::from_json(vector.input.as_bytes()).is_err(),
                    "{}",
                    vector.id
                );
                continue;
            }
            "operator.logout.operation" => {
                let input: Value = serde_json::from_str(&vector.input).unwrap();
                OperatorAccessOperation::from_route(
                    input["method"].as_str().unwrap(),
                    input["path"].as_str().unwrap(),
                )
                .map_or("unmapped", |op| match op.requirement() {
                    OperatorAccessRequirement::SelfSessionTermination => "self-session-termination",
                    OperatorAccessRequirement::Scope(scope) => scope.as_str(),
                })
                .into()
            }
            "operator.logout.problem" => {
                let error = match vector.input.as_str() {
                    "known-rollback" => Error::StorageUnavailable,
                    "unknown-commit" => Error::CommitOutcomeUnknown,
                    "authentication-required" => Error::AuthenticationRequired,
                    _ => panic!("unexpected problem fixture"),
                };
                let problem = error.problem("fixture-request").unwrap().unwrap();
                let actual = serde_json::json!({"status":problem.status,"code":problem.code.as_str(),"changed":problem.changed,"retryable":problem.retryable});
                let expected: Value = serde_json::from_str(&vector.expected).unwrap();
                assert_eq!(actual, expected, "{}", vector.id);
                continue;
            }
            _ => panic!("unknown logout vector kind"),
        };
        assert_eq!(actual, vector.expected, "{}", vector.id);
    }
}
