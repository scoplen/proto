// SPDX-License-Identifier: Apache-2.0
use scoplen_api::{
    auth::INITIAL_DEVICE_ACCESS_SCOPE,
    organization::{OrganizationCreateRequest, OrganizationListQuery, OrganizationUpdateRequest},
    organization_reference::{
        OrganizationReferenceError as Error, OrganizationReferenceFault as Fault,
        OrganizationReferencePeer,
    },
};
use scoplen_crypto::{DeviceAccessTokenClaims, DeviceOrganizationSnapshot};
use uuid::Uuid;

fn id(n: u64) -> Uuid {
    Uuid::parse_str(&format!("019bdad6-b800-7000-8000-{n:012x}")).unwrap()
}
fn claims(n: u64) -> DeviceAccessTokenClaims {
    DeviceAccessTokenClaims {
        iss: "https://control.example.com".into(),
        sub: id(n),
        did: id(n + 1),
        jti: id(n + 2),
        cnf_jkt: "fixture-proof-key".into(),
        org: vec![],
        scope: INITIAL_DEVICE_ACCESS_SCOPE.into(),
        iat: 100,
        exp: 100_000,
    }
}
const TIME: &str = "2026-10-26T00:00:00Z";
fn body() -> Vec<u8> {
    OrganizationCreateRequest::new("Operations").unwrap().to_json().unwrap()
}
fn peer(claims: &DeviceAccessTokenClaims) -> OrganizationReferencePeer {
    let mut peer = OrganizationReferencePeer::default();
    peer.set_principal(claims, true);
    peer
}

#[test]
fn creation_requires_policy_and_atomic_initial_owner() {
    let caller = claims(1);
    let mut peer = peer(&caller);
    assert_eq!(peer.create(&caller, id(10), &body(), 101, TIME), Err(Error::Denied));
    assert_eq!(peer.audit_events(), 0);
    peer.set_allow_creation(true);
    let team = peer.create(&caller, id(10), &body(), 101, TIME).unwrap();
    assert_eq!(team.membership.account_id, caller.sub);
    assert_eq!(team.membership.roles, ["owner"]);
    assert_eq!(peer.audit_events(), 1);
    assert_eq!(
        peer.list(&caller, OrganizationListQuery::default(), 102).unwrap().items.as_slice(),
        std::slice::from_ref(&team)
    );
    peer.set_allow_creation(false);
    assert_eq!(
        peer.create(&caller, id(10), b" { \"data\" : { \"name\" : \"Operations\" } } ", 103, TIME),
        Ok(team.clone())
    );
    assert_eq!(peer.audit_events(), 1);
    assert_eq!(
        peer.create(
            &caller,
            id(10),
            &OrganizationCreateRequest::new("Other").unwrap().to_json().unwrap(),
            104,
            TIME
        ),
        Err(Error::Conflict)
    );
    assert_eq!(peer.read(&caller, team.id, 105), Ok(team.clone()));
    peer.set_membership_active(team.id, false);
    assert_eq!(peer.create(&caller, id(10), &body(), 106, TIME), Err(Error::NotFound));
    assert_eq!(peer.list(&caller, OrganizationListQuery::default(), 106).unwrap().items, []);
}

#[test]
fn independent_accounts_and_current_state_override_snapshots() {
    let a = claims(1);
    let mut b = claims(20);
    let mut peer = peer(&a);
    peer.set_principal(&b, true);
    peer.set_allow_creation(true);
    let team = peer.create(&a, id(10), &body(), 101, TIME).unwrap();
    b.org.push(DeviceOrganizationSnapshot { id: team.id, sso_authenticated_at: Some(100) });
    assert_eq!(peer.read(&b, team.id, 102), Err(Error::NotFound));
    assert_eq!(peer.read(&b, id(999), 102), Err(Error::NotFound));
    assert_eq!(peer.list(&b, OrganizationListQuery::default(), 102).unwrap().items, []);
    let team_b = peer.create(&b, id(10), &body(), 102, TIME).unwrap();
    assert_ne!(team.id, team_b.id);
    assert_eq!(peer.audit_events(), 2);
    let mut wrong = a.clone();
    wrong.sub = b.sub;
    assert_eq!(peer.read(&wrong, team.id, 103), Err(Error::AuthenticationRequired));
    wrong = a.clone();
    wrong.cnf_jkt = "other-key".into();
    assert_eq!(
        peer.list(&wrong, OrganizationListQuery::default(), 103),
        Err(Error::AuthenticationRequired)
    );
    peer.set_principal(&a, false);
    assert_eq!(peer.read(&a, team.id, 104), Err(Error::AuthenticationRequired));
}

#[test]
fn missing_scopes_never_gain_authority_from_membership() {
    let caller = claims(1);
    let mut peer = peer(&caller);
    peer.set_allow_creation(true);
    let team = peer.create(&caller, id(10), &body(), 101, TIME).unwrap();
    let mut old = caller.clone();
    old.scope = "account:read keys:read keys:write sync:read sync:write".into();
    assert_eq!(peer.read(&old, team.id, 102), Err(Error::Denied));
    assert_eq!(peer.create(&old, id(11), &body(), 102, TIME), Err(Error::Denied));
    let mut read_only = caller.clone();
    read_only.scope = "orgs:read".into();
    assert_eq!(peer.read(&read_only, team.id, 102), Ok(team));
    assert_eq!(peer.create(&read_only, id(11), &body(), 102, TIME), Err(Error::Denied));
}

#[test]
fn scripted_commit_and_network_faults_confirm_exactly_one_creation() {
    for (fault, error, original_count) in [
        (Fault::Rollback, Error::StorageUnavailable, 0),
        (Fault::UnknownRollback, Error::CommitOutcomeUnknown, 0),
        (Fault::UnknownCommitted, Error::CommitOutcomeUnknown, 1),
        (Fault::LostResponse, Error::ResponseLost, 1),
    ] {
        let caller = claims(1);
        let mut peer = peer(&caller);
        peer.set_allow_creation(true);
        peer.set_fault(fault);
        assert_eq!(peer.create(&caller, id(10), &body(), 101, TIME), Err(error));
        assert_eq!(peer.audit_events(), original_count);
        let mut reopened = peer.clone();
        let team = reopened.create(&caller, id(10), &body(), 102, TIME).unwrap();
        assert_eq!(reopened.audit_events(), 1);
        assert_eq!(
            reopened.list(&caller, OrganizationListQuery::default(), 103).unwrap().items,
            [team]
        );
        if let Some(problem) = error.problem("fixture-request").unwrap() {
            assert_eq!(problem.changed, error == Error::CommitOutcomeUnknown);
            assert!(problem.retryable);
        }
    }
}

#[test]
fn paging_is_account_filtered_and_live() {
    let caller = claims(1);
    let mut peer = peer(&caller);
    peer.set_allow_creation(true);
    for n in 0..3 {
        peer.create(&caller, id(10 + n), &body(), 101, TIME).unwrap();
    }
    let first = peer.list(&caller, OrganizationListQuery { limit: 2, cursor: None }, 102).unwrap();
    assert_eq!(first.items.len(), 2);
    assert_eq!(first.next_cursor, first.items.last().map(|r| r.id));
    let second = peer
        .list(&caller, OrganizationListQuery { limit: 2, cursor: first.next_cursor }, 102)
        .unwrap();
    assert_eq!(second.items.len(), 1);
    assert!(second.next_cursor.is_none());
    assert!(second.items[0].id > first.items[1].id);
}

fn renamed_body() -> Vec<u8> {
    OrganizationUpdateRequest::new("Platform").unwrap().to_json().unwrap()
}

#[test]
fn update_noop_stale_projection_and_creation_confirmation_preserve_exact_outcomes() {
    let caller = claims(1);
    let mut peer = peer(&caller);
    peer.set_allow_creation(true);
    let original = peer.create(&caller, id(10), &body(), 101, TIME).unwrap();
    let renamed = peer
        .update(
            &caller,
            original.id,
            Some(&original.etag),
            &renamed_body(),
            102,
            "2026-10-26T00:01:00Z",
        )
        .unwrap();
    assert_eq!(renamed.name, "Platform");
    assert_eq!(renamed.created_at, original.created_at);
    assert_eq!(renamed.updated_at, "2026-10-26T00:01:00Z");
    assert_ne!(renamed.etag, original.etag);
    assert_eq!(peer.audit_events(), 2);
    assert_eq!(
        peer.update(
            &caller,
            original.id,
            Some(&renamed.etag),
            &renamed_body(),
            103,
            "2026-10-26T00:02:00Z"
        ),
        Ok(renamed.clone())
    );
    assert_eq!(peer.audit_events(), 2);
    assert_eq!(
        peer.update(&caller, original.id, Some(&original.etag), &renamed_body(), 103, TIME),
        Err(Error::PreconditionFailed)
    );
    assert_eq!(peer.create(&caller, id(10), &body(), 104, TIME), Ok(renamed.clone()));
    assert_eq!(peer.read(&caller, original.id, 104), Ok(renamed.clone()));
    assert_eq!(peer.list(&caller, OrganizationListQuery::default(), 104).unwrap().items, [renamed]);
    assert_eq!(peer.audit_events(), 2);
}

#[test]
fn current_policy_and_scope_precede_protected_etag_comparison() {
    let caller = claims(1);
    let mut peer = peer(&caller);
    peer.set_allow_creation(true);
    let original = peer.create(&caller, id(10), &body(), 101, TIME).unwrap();
    for role in
        ["owner", "administrator", "member", "approver", "security_auditor", "future_reader"]
    {
        peer.set_membership_roles(original.id, vec![role.into()], TIME).unwrap();
        let current = peer.read(&caller, original.id, 102).unwrap();
        assert_ne!(current.etag, original.etag);
        let expected = if ["owner", "administrator"].contains(&role) {
            Error::PreconditionFailed
        } else {
            Error::Denied
        };
        assert_eq!(
            peer.update(&caller, original.id, Some(&original.etag), &renamed_body(), 102, TIME),
            Err(expected),
            "{role}"
        );
        if expected == Error::PreconditionFailed {
            assert!(
                peer.update(&caller, original.id, Some(&current.etag), &body(), 102, TIME).is_ok()
            );
        }
    }
    let mut old = caller.clone();
    old.scope =
        "account:read keys:read keys:write orgs:create orgs:read sync:read sync:write".into();
    assert!(peer.read(&old, original.id, 103).is_ok());
    assert_eq!(
        peer.update(&old, original.id, Some(&original.etag), &body(), 103, TIME),
        Err(Error::Denied)
    );
    let foreign = claims(20);
    peer.set_principal(&foreign, true);
    assert_eq!(
        peer.update(&foreign, original.id, Some(&original.etag), &body(), 103, TIME),
        Err(Error::NotFound)
    );
    peer.set_membership_active(original.id, false);
    assert_eq!(
        peer.update(&caller, original.id, Some(&original.etag), &body(), 103, TIME),
        Err(Error::NotFound)
    );
    peer.set_principal(&caller, false);
    assert_eq!(
        peer.update(&caller, original.id, Some(&original.etag), &body(), 103, TIME),
        Err(Error::AuthenticationRequired)
    );
}

#[test]
fn update_faults_have_no_receipts_and_unknown_commit_requires_refresh() {
    for (fault, error, changed) in [
        (Fault::Rollback, Error::StorageUnavailable, false),
        (Fault::UnknownRollback, Error::UpdateCommitOutcomeUnknown, false),
        (Fault::UnknownCommitted, Error::UpdateCommitOutcomeUnknown, true),
        (Fault::LostResponse, Error::ResponseLost, true),
    ] {
        let caller = claims(1);
        let mut peer = peer(&caller);
        peer.set_allow_creation(true);
        let original = peer.create(&caller, id(10), &body(), 101, TIME).unwrap();
        peer.set_fault(fault);
        assert_eq!(
            peer.update(
                &caller,
                original.id,
                Some(&original.etag),
                &renamed_body(),
                102,
                "2026-10-26T00:01:00Z"
            ),
            Err(error)
        );
        let reopened = peer.clone();
        let current = reopened.read(&caller, original.id, 103).unwrap();
        assert_eq!(current.name == "Platform", changed);
        assert_eq!(reopened.audit_events(), if changed { 2 } else { 1 });
        if let Some(problem) = error.problem("fixture-request").unwrap() {
            assert_eq!(problem.changed, error == Error::UpdateCommitOutcomeUnknown);
            assert_eq!(problem.retryable, error == Error::StorageUnavailable);
        }
    }
    for (error, status, code) in [
        (Error::PreconditionRequired, 428, "organization.precondition_required"),
        (Error::PreconditionFailed, 412, "organization.precondition_failed"),
    ] {
        let problem = error.problem("fixture-request").unwrap().unwrap();
        assert_eq!(problem.status, status);
        assert_eq!(problem.code.as_str(), code);
        assert!(!problem.changed && !problem.retryable);
    }
}

#[test]
fn caller_projection_tracks_later_membership_time_in_every_read_surface() {
    let caller = claims(1);
    let mut peer = peer(&caller);
    peer.set_allow_creation(true);
    let original = peer.create(&caller, id(10), &body(), 101, TIME).unwrap();
    peer.set_membership_roles(original.id, vec!["administrator".into()], "2026-10-26T00:02:00.12Z")
        .unwrap();
    let membership = peer.read(&caller, original.id, 102).unwrap();
    let renamed = peer
        .update(
            &caller,
            original.id,
            Some(&membership.etag),
            &renamed_body(),
            103,
            "2026-10-26T00:02:00.1Z",
        )
        .unwrap();
    assert_eq!(renamed.updated_at, "2026-10-26T00:02:00.12Z");
    assert_eq!(peer.create(&caller, id(10), &body(), 104, TIME), Ok(renamed.clone()));
    assert_eq!(peer.list(&caller, OrganizationListQuery::default(), 104).unwrap().items, [renamed]);
    assert_eq!(
        peer.update(&caller, original.id, None, &body(), 105, TIME),
        Err(Error::PreconditionRequired)
    );
    assert_eq!(
        peer.update(&caller, original.id, Some("*"), &body(), 105, TIME),
        Err(Error::InvalidRequest)
    );
}
