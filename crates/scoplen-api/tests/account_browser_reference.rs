// SPDX-License-Identifier: Apache-2.0
use scoplen_api::account_browser::{reference::*, *};
use uuid::Uuid;

const ORIGIN: &str = "https://example.com";
const JKT: &str = "externally-verified-proof-key";
fn access(n: u8) -> AccountBrowserAccessToken {
    AccountBrowserAccessToken::from_random_bytes(&[n; 32])
}
fn refresh(n: u8) -> AccountBrowserRefreshToken {
    AccountBrowserRefreshToken::from_random_bytes(&[n; 32])
}
fn peer() -> ReferenceAccountBrowserPeer {
    ReferenceAccountBrowserPeer::new(
        AccountBrowserWriter::new(
            Uuid::parse_str("0191d3e0-8000-7000-8000-000000000001").unwrap(),
            Uuid::parse_str("0191d3e0-8000-7000-8000-000000000002").unwrap(),
        )
        .unwrap(),
        ORIGIN,
        JKT,
        1,
        &access(1),
        &refresh(2),
        1000,
    )
    .unwrap()
}
#[test]
fn rotation_keeps_real_writer_and_absolute_family_expiry_and_detects_reuse() {
    let mut peer = peer();
    let before = peer
        .authorize(
            &access(1),
            JKT,
            None,
            AccountBrowserAccessOperation::AccountProfileRead,
            "read-1",
            1001,
        )
        .unwrap();
    let response = peer
        .rotate(b"{}", &refresh(2), &access(3), &refresh(4), JKT, ORIGIN, "rotate-1", 1100)
        .unwrap();
    assert_eq!(response.0.refresh_expires_in, ACCOUNT_BROWSER_FAMILY_SECONDS - 100);
    response.to_json().unwrap();
    let after = peer
        .authorize(
            &access(3),
            JKT,
            Some(ORIGIN),
            AccountBrowserAccessOperation::InventoryHostCreate,
            "write-1",
            1101,
        )
        .unwrap();
    assert_eq!(before, after);
    assert_eq!(peer.events(), 2);
    assert_eq!(
        peer.rotate(b"{}", &refresh(2), &access(5), &refresh(6), JKT, ORIGIN, "reuse-1", 1102),
        Err(ReferenceAccountBrowserError::AuthenticationRequired)
    );
    assert_eq!(peer.events(), 3);
    assert!(
        peer.authorize(
            &access(3),
            JKT,
            None,
            AccountBrowserAccessOperation::AccountProfileRead,
            "read-2",
            1103
        )
        .is_err()
    );
    assert_eq!(
        peer.terminate(b"{}", &access(3), JKT, ORIGIN, "terminal", 1103).unwrap(),
        AccountBrowserLogoutResponse
    );
    assert_eq!(peer.events(), 3);
}
#[test]
fn refresh_unknown_commit_returns_no_credentials_and_later_reuse_revokes() {
    for fault in [
        ReferenceAccountBrowserFault::BeforeCommit,
        ReferenceAccountBrowserFault::UnknownRollback,
        ReferenceAccountBrowserFault::UnknownCommitted,
        ReferenceAccountBrowserFault::LostResponse,
    ] {
        let mut peer = peer();
        peer.set_fault(fault);
        let result =
            peer.rotate(b"{}", &refresh(2), &access(3), &refresh(4), JKT, ORIGIN, "rotate", 1100);
        assert!(result.is_err());
        let committed = matches!(
            fault,
            ReferenceAccountBrowserFault::UnknownCommitted
                | ReferenceAccountBrowserFault::LostResponse
        );
        assert_eq!(peer.events(), if committed { 2 } else { 1 });
        assert_eq!(
            peer.authorize(
                &access(3),
                JKT,
                None,
                AccountBrowserAccessOperation::AccountProfileRead,
                "probe",
                1101
            )
            .is_ok(),
            committed
        );
        let result =
            peer.rotate(b"{}", &refresh(2), &access(5), &refresh(6), JKT, ORIGIN, "explicit", 1102);
        assert_eq!(result.is_err(), committed);
    }
}
#[test]
fn logout_confirms_only_eligible_original_family_with_fresh_proof() {
    let mut peer = peer();
    peer.set_fault(ReferenceAccountBrowserFault::UnknownCommitted);
    assert_eq!(
        peer.terminate(b"{}", &access(1), JKT, ORIGIN, "first", 1100),
        Err(ReferenceAccountBrowserError::CommitOutcomeUnknown)
    );
    assert_eq!(peer.events(), 2);
    assert!(
        peer.authorize(
            &access(1),
            JKT,
            None,
            AccountBrowserAccessOperation::AccountProfileRead,
            "business",
            1101
        )
        .is_err()
    );
    assert_eq!(
        peer.terminate(b"{}", &access(1), JKT, ORIGIN, "first", 1101),
        Err(ReferenceAccountBrowserError::InvalidProof)
    );
    assert!(peer.terminate(b"{}", &access(9), JKT, ORIGIN, "other-family", 1101).is_err());
    assert!(peer.terminate(b"{}", &access(1), "other-key", ORIGIN, "other-key", 1101).is_err());
    peer.terminate(b"{}", &access(1), JKT, ORIGIN, "confirm", 1101).unwrap();
    assert_eq!(peer.events(), 2);
    assert!(peer.terminate(b"{}", &access(1), JKT, ORIGIN, "expired", 1600).is_err());
    peer.set_current_account(true, 2);
    assert!(peer.terminate(b"{}", &access(1), JKT, ORIGIN, "changed-generation", 1102).is_err());
}
#[test]
fn wrong_binding_malformed_input_and_known_rollback_change_no_family_state() {
    let mut peer = peer();
    assert!(
        peer.rotate(b"{}", &refresh(2), &access(3), &refresh(4), "other", ORIGIN, "proof", 1100)
            .is_err()
    );
    assert!(
        peer.terminate(b"{\"sid\":\"chosen\"}", &access(1), JKT, ORIGIN, "proof", 1100).is_err()
    );
    assert!(
        peer.authorize(
            &access(1),
            JKT,
            None,
            AccountBrowserAccessOperation::InventoryHostCreate,
            "proof",
            1100
        )
        .is_err()
    );
    peer.set_fault(ReferenceAccountBrowserFault::BeforeCommit);
    assert_eq!(
        peer.terminate(b"{}", &access(1), JKT, ORIGIN, "proof", 1100),
        Err(ReferenceAccountBrowserError::StorageUnavailable)
    );
    assert_eq!(peer.events(), 1);
    peer.authorize(
        &access(1),
        JKT,
        None,
        AccountBrowserAccessOperation::AccountProfileRead,
        "read",
        1101,
    )
    .unwrap();
    peer.set_current_account(false, 1);
    assert!(
        peer.authorize(
            &access(1),
            JKT,
            None,
            AccountBrowserAccessOperation::AccountProfileRead,
            "deleted",
            1102
        )
        .is_err()
    );
}

#[test]
fn uncertain_problem_flags_distinguish_refresh_from_explicit_logout_recovery() {
    let refresh = ReferenceAccountBrowserError::CommitOutcomeUnknown
        .problem(AccountBrowserOperation::Refresh, "r-1")
        .unwrap()
        .unwrap();
    let logout = ReferenceAccountBrowserError::CommitOutcomeUnknown
        .problem(AccountBrowserOperation::Logout, "r-2")
        .unwrap()
        .unwrap();
    assert_eq!(refresh.status, 503);
    assert_eq!(refresh.code.as_str(), "auth.commit_outcome_unknown");
    assert!(refresh.changed && !refresh.retryable);
    assert!(logout.changed && logout.retryable);
    assert!(
        ReferenceAccountBrowserError::ResponseLost
            .problem(AccountBrowserOperation::Refresh, "r-3")
            .unwrap()
            .is_none()
    );
}
