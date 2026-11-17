// SPDX-License-Identifier: Apache-2.0

use std::str::FromStr as _;

use cedar_policy::{Context as CedarContext, Entities, PolicySet, Request};
use scoplen_api::{
    access_request::{
        AccessRequestCheckRequest, AccessRequestCheckResponse, AccessRequestCreateRequest,
        AccessRequestDecisionRequest, AccessRequestFields, AccessRequestOutcome, AccessRequestPage,
        AccessRequestResource, AccessRequestStatus,
        reference::{
            AccessRequestReferenceActor as Actor, AccessRequestReferenceCaller as Caller,
            AccessRequestReferenceContext as Context, AccessRequestReferenceFault as Fault,
            AccessRequestReferencePeer as Peer,
        },
    },
    account_browser::{AccountBrowserWriter, INITIAL_ACCOUNT_BROWSER_ACCESS_SCOPE},
    auth::INITIAL_DEVICE_ACCESS_SCOPE,
    control_plane::{
        ConnectAuthorization, OrganizationAuthorizationContext, OrganizationAuthorizer,
    },
    organization::{OrganizationMembership, OrganizationResource},
    organization_reference::OrganizationReferenceError as Error,
};
use scoplen_crypto::DeviceAccessTokenClaims;
use serde_json::json;
use uuid::Uuid;

const ORIGIN: &str = "https://control.example.com";
const NOW: u64 = 100;

fn id(value: u64) -> Uuid {
    format!("019bdad6-b800-7000-8000-{value:012}").parse().unwrap()
}
fn claims(account: u64) -> DeviceAccessTokenClaims {
    DeviceAccessTokenClaims {
        iss: ORIGIN.into(),
        sub: id(account),
        did: id(account + 1),
        jti: id(account + 3),
        cnf_jkt: format!("fixture-proof-{account}"),
        org: vec![],
        scope: INITIAL_DEVICE_ACCESS_SCOPE.into(),
        iat: 1,
        exp: 1_000_000,
    }
}
fn member(account: u64, role: &str) -> OrganizationResource {
    OrganizationResource {
        id: id(1),
        etag: "\"membership\"".into(),
        created_at: "1970-01-01T00:00:00Z".into(),
        updated_at: "1970-01-01T00:00:00Z".into(),
        name: "Request fixture".into(),
        membership: OrganizationMembership {
            id: id(account + 2),
            account_id: id(account),
            roles: vec![role.into()],
        },
    }
}
fn input(number: u64) -> AccessRequestCreateRequest {
    AccessRequestCreateRequest {
        id: id(number),
        fields: AccessRequestFields {
            host: id(40),
            remote_user: "deploy".into(),
            duration_seconds: 300,
            reason: "maintenance".into(),
        },
    }
}
fn context(claims: &DeviceAccessTokenClaims, now: u64) -> Context<'_> {
    Context { caller: Caller::Device(claims), organization: id(1), now }
}
fn view_policy() -> String {
    "permit(principal, action == Action::\"view_inventory\", resource);".into()
}
fn policies() -> PolicySet {
    PolicySet::from_str(&format!("{} permit(principal == Account::\"{}\", action == Action::\"request_access\", resource) when {{ context.duration_seconds <= 600 && context.reason == \"maintenance\" }};", view_policy(), id(10))).unwrap()
}
struct Fixture {
    peer: Peer,
    requester: DeviceAccessTokenClaims,
    approver: DeviceAccessTokenClaims,
    owner: DeviceAccessTokenClaims,
    browser: AccountBrowserWriter,
    approver_browser: AccountBrowserWriter,
}
fn fixture() -> Fixture {
    let requester = claims(10);
    let approver = claims(20);
    let owner = claims(30);
    let browser = AccountBrowserWriter::new(id(10), id(15)).unwrap();
    let approver_browser = AccountBrowserWriter::new(id(20), id(25)).unwrap();
    let mut peer = Peer::new(ORIGIN).unwrap();
    peer.set_organization_active(id(1), true);
    for (account, claims, role) in
        [(10, &requester, "member"), (20, &approver, "approver"), (30, &owner, "owner")]
    {
        peer.set_account_active(claims.sub, true);
        peer.set_device(claims, true);
        peer.set_membership(member(account, role), true).unwrap();
    }
    peer.set_browser(browser, INITIAL_ACCOUNT_BROWSER_ACCESS_SCOPE, true);
    peer.set_browser(approver_browser, INITIAL_ACCOUNT_BROWSER_ACCESS_SCOPE, true);
    peer.set_host(id(1), id(40), true).unwrap();
    peer.set_policies(id(1), policies()).unwrap();
    Fixture { peer, requester, approver, owner, browser, approver_browser }
}
fn create(f: &mut Fixture, number: u64) -> AccessRequestResource {
    AccessRequestResource::from_json(
        &f.peer
            .create(
                context(&f.requester, NOW),
                id(number + 1000),
                &input(number).to_json().unwrap(),
            )
            .unwrap(),
    )
    .unwrap()
}
fn approve() -> Vec<u8> {
    AccessRequestDecisionRequest { decision: AccessRequestOutcome::Approve }.to_json().unwrap()
}
fn deny() -> Vec<u8> {
    AccessRequestDecisionRequest { decision: AccessRequestOutcome::Deny }.to_json().unwrap()
}

#[test]
fn exact_input_check_has_no_side_effects_and_only_complete_deny_becomes_false() {
    let mut f = fixture();
    let request = AccessRequestCheckRequest { fields: input(100).fields };
    let result = f.peer.check(context(&f.requester, NOW), &request.to_json().unwrap()).unwrap();
    assert!(AccessRequestCheckResponse::from_json(&result).unwrap().allowed);
    assert_eq!(f.peer.audit(), []);
    assert_eq!(f.peer.revision(id(1)), 0);
    let mut changed = request.clone();
    changed.fields.reason = "different".into();
    let result = f.peer.check(context(&f.requester, NOW), &changed.to_json().unwrap()).unwrap();
    assert!(!AccessRequestCheckResponse::from_json(&result).unwrap().allowed);
    assert_eq!(
        f.peer.create(
            context(&f.requester, NOW),
            id(200),
            &AccessRequestCreateRequest { id: id(100), fields: changed.fields }.to_json().unwrap()
        ),
        Err(Error::Denied)
    );
    changed = request.clone();
    changed.fields.host = id(41);
    assert_eq!(
        f.peer.check(context(&f.requester, NOW), &changed.to_json().unwrap()),
        Err(Error::NotFound)
    );
    f.peer.set_policies(id(1), PolicySet::from_str(&format!("{} permit(principal, action == Action::\"request_access\", resource) when {{ context.duration_seconds * 9223372036854775807 > 0 }};", view_policy())).unwrap()).unwrap();
    assert_eq!(
        f.peer.check(context(&f.requester, NOW), &request.to_json().unwrap()),
        Err(Error::StorageUnavailable)
    );
}

#[test]
fn own_and_routed_reads_preserve_current_visibility_and_no_directory_scope_is_needed() {
    let mut f = fixture();
    let row = create(&mut f, 100);
    let mine = AccessRequestPage::from_json(
        &f.peer.list(context(&f.requester, NOW), [("view", "mine")]).unwrap(),
    )
    .unwrap();
    assert_eq!(mine.items, vec![row.clone()]);
    assert_eq!(
        AccessRequestPage::from_json(
            &f.peer.list(context(&f.requester, NOW), [("view", "approvals")]).unwrap()
        )
        .unwrap()
        .items,
        []
    );
    assert_eq!(
        AccessRequestPage::from_json(
            &f.peer.list(context(&f.approver, NOW), [("view", "approvals")]).unwrap()
        )
        .unwrap()
        .items,
        vec![row.clone()]
    );
    assert!(f.peer.read(context(&f.approver, NOW), row.id).is_ok());
    let mut read_only = f.requester.clone();
    read_only.scope = "access-requests:read".into();
    assert!(f.peer.read(context(&read_only, NOW), row.id).is_ok());
    f.peer.set_policies(id(1), PolicySet::new()).unwrap();
    assert_eq!(f.peer.read(context(&f.approver, NOW), row.id), Err(Error::NotFound));
    assert!(f.peer.read(context(&f.requester, NOW), row.id).is_ok());
    assert!(f.peer.cancel(context(&f.requester, NOW), row.id, id(500), Some(&row.etag)).is_ok());
    assert!(f.peer.host_deletion_allowed(id(1), id(40)));
}

#[test]
fn owner_cannot_approve_self_and_routing_does_not_grant_administrator_authority() {
    let mut f = fixture();
    let bytes =
        f.peer.create(context(&f.owner, NOW), id(1001), &input(101).to_json().unwrap()).unwrap();
    let row = AccessRequestResource::from_json(&bytes).unwrap();
    assert_eq!(
        f.peer.decide(context(&f.owner, NOW), row.id, id(600), Some(&row.etag), &approve()),
        Err(Error::NotFound)
    );
    f.peer.set_membership(member(20, "administrator"), true).unwrap();
    assert_eq!(
        f.peer.decide(context(&f.approver, NOW), row.id, id(601), Some(&row.etag), &approve()),
        Err(Error::NotFound)
    );
    assert_eq!(f.peer.current_grants(id(1)), []);
}

#[test]
fn approval_publishes_one_bound_finite_grant_audit_pair_and_one_revision_atomically() {
    let mut f = fixture();
    let original = create(&mut f, 100);
    let response = f
        .peer
        .decide(
            context(&f.approver, NOW + 1),
            original.id,
            id(600),
            Some(&original.etag),
            &approve(),
        )
        .unwrap();
    let row = AccessRequestResource::from_json(&response).unwrap();
    assert_eq!(row.status, AccessRequestStatus::Approved);
    row.validate_for_decision(
        &original,
        AccessRequestDecisionRequest { decision: AccessRequestOutcome::Approve },
        f.approver.sub,
    )
    .unwrap();
    assert_eq!(row.requester_membership_id, id(12));
    let grants = f.peer.current_grants(id(1));
    assert_eq!(grants.len(), 1);
    assert_eq!(grants[0].fields.membership, id(12));
    assert_eq!(grants[0].fields.host, id(40));
    assert_eq!(grants[0].fields.remote_user, "deploy");
    assert_eq!(grants[0].fields.valid_from, NOW + 1);
    assert_eq!(grants[0].fields.valid_until, Some(NOW + 301));
    assert_eq!(f.peer.revision(id(1)), 1);
    assert_eq!(
        f.peer.audit().iter().map(|value| value.kind).collect::<Vec<_>>(),
        vec![
            "organization.access_request_created",
            "organization.access_request_approved",
            "organization.grants_created"
        ]
    );
    assert_eq!(f.peer.audit()[1].actor, Some(Actor::Device(f.approver.did)));
    assert_eq!(f.peer.audit()[2].object_id, grants[0].id);
    let confirmed = f
        .peer
        .decide(
            context(&f.approver, NOW + 2),
            original.id,
            id(600),
            Some(&original.etag),
            &approve(),
        )
        .unwrap();
    assert_eq!(confirmed, response);
    assert_eq!(f.peer.current_grants(id(1)).len(), 1);
    assert_eq!(f.peer.audit().len(), 3);
    assert_eq!(
        f.peer.decide(
            context(&f.approver, NOW + 2),
            original.id,
            id(601),
            Some(&row.etag),
            &deny()
        ),
        Err(Error::Conflict)
    );

    let reference =
        |kind: &str, value: Uuid| json!({"__entity":{"type":kind,"id":value.to_string()}});
    let entity = |kind: &str, value: Uuid, attrs| json!({"uid":{"type":kind,"id":value.to_string()},"attrs":attrs,"parents":[]});
    let entities = Entities::from_json_value(json!([
        entity("Organization", id(1), json!({"name":"Request fixture"})), entity("Account",id(10),json!({"status":"active"})),
        entity("Membership",id(12),json!({"account":reference("Account",id(10)),"organization":reference("Organization",id(1)),"status":"active","roles":["member"],"groups":[]})),
        entity("Host",id(40),json!({"organization":reference("Organization",id(1)),"labels":[],"host_groups":[]})),
        entity("Device",id(11),json!({"account":reference("Account",id(10)),"platform":"linux","hardware_backed":false,"enrolled_at":0})),
    ]),None).unwrap();
    let authorizer = OrganizationAuthorizer::new(id(1), &PolicySet::new()).unwrap();
    for (now, permitted) in [(NOW + 1, true), (NOW + 300, true), (NOW + 301, false)] {
        let context = CedarContext::from_json_value(json!({"organization":reference("Organization",id(1)),"membership":reference("Membership",id(12)),"now":now,"device":reference("Device",id(11)),"remote_user":"deploy","route_kind":"direct","source_ip":"192.0.2.1"}),None).unwrap();
        let request = Request::new(
            format!("Account::\"{}\"", id(10)).parse().unwrap(),
            "Action::\"connect\"".parse().unwrap(),
            format!("Host::\"{}\"", id(40)).parse().unwrap(),
            context,
            None,
        )
        .unwrap();
        let trusted = OrganizationAuthorizationContext::new(
            id(10),
            id(1),
            id(12),
            i64::try_from(now).unwrap(),
        )
        .unwrap();
        let result = authorizer.authorize_connect(&trusted, &request, &entities, &grants).unwrap();
        assert_eq!(matches!(result, ConnectAuthorization::Allow { .. }), permitted);
    }
}

#[test]
fn deny_cancel_and_expiry_create_no_grant_or_view_revision_and_guard_hosts() {
    let mut f = fixture();
    let row = create(&mut f, 100);
    assert_eq!(f.peer.set_host(id(1), id(40), false), Err(Error::Conflict));
    let response = f
        .peer
        .decide(context(&f.approver, NOW), row.id, id(600), Some(&row.etag), &deny())
        .unwrap();
    assert_eq!(
        AccessRequestResource::from_json(&response).unwrap().status,
        AccessRequestStatus::Denied
    );
    assert!(f.peer.host_deletion_allowed(id(1), id(40)));
    let row = create(&mut f, 101);
    assert_eq!(
        f.peer.cancel(context(&f.approver, NOW), row.id, id(601), Some(&row.etag)),
        Err(Error::NotFound)
    );
    let cancelled =
        f.peer.cancel(context(&f.requester, NOW), row.id, id(602), Some(&row.etag)).unwrap();
    AccessRequestResource::from_json(&cancelled)
        .unwrap()
        .validate_for_cancel(&row, f.requester.sub)
        .unwrap();
    let row = create(&mut f, 102);
    assert_eq!(
        f.peer.decide(
            context(&f.approver, NOW + 86400),
            row.id,
            id(603),
            Some(&row.etag),
            &approve()
        ),
        Err(Error::Conflict)
    );
    assert_eq!(
        f.peer.cancel(context(&f.requester, NOW + 86400), row.id, id(604), Some(&row.etag)),
        Err(Error::Conflict)
    );
    assert_eq!(
        AccessRequestResource::from_json(
            &f.peer.read(context(&f.requester, NOW + 86400), row.id).unwrap()
        )
        .unwrap()
        .status,
        AccessRequestStatus::Pending
    );
    assert_eq!(
        AccessRequestPage::from_json(
            &f.peer.list(context(&f.approver, NOW + 86400), [("view", "approvals")]).unwrap()
        )
        .unwrap()
        .items,
        []
    );
    assert_eq!(f.peer.expire(NOW + 86400, 500), Ok(1));
    assert_eq!(f.peer.expire(NOW + 86400, 500), Ok(0));
    assert_eq!(f.peer.audit().last().unwrap().kind, "organization.access_request_expired");
    assert_eq!(f.peer.audit().last().unwrap().actor, None);
    assert_eq!(f.peer.audit().last().unwrap().actor_account, None);
    assert_eq!(f.peer.current_grants(id(1)), []);
    assert_eq!(f.peer.revision(id(1)), 0);
    f.peer.set_host(id(1), id(40), false).unwrap();
}

#[test]
fn original_membership_and_requester_eligibility_are_rechecked_at_decision() {
    for loss in ["account", "member", "rejoin", "policy", "visibility"] {
        let mut f = fixture();
        let row = create(&mut f, 100);
        match loss {
            "account" => f.peer.set_account_active(id(10), false),
            "member" => f.peer.set_membership(member(10, "member"), false).unwrap(),
            "rejoin" => {
                let mut changed = member(10, "member");
                changed.membership.id = id(99);
                f.peer.set_membership(changed, true).unwrap();
            }
            "policy" => {
                f.peer.set_policies(id(1), PolicySet::from_str(&view_policy()).unwrap()).unwrap();
            }
            "visibility" => f.peer.set_policies(id(1), PolicySet::new()).unwrap(),
            _ => unreachable!(),
        }
        let result =
            f.peer.decide(context(&f.owner, NOW), row.id, id(600), Some(&row.etag), &approve());
        assert_eq!(result, Err(Error::Conflict), "{loss}");
        assert_eq!(f.peer.current_grants(id(1)), []);
        assert_eq!(f.peer.audit().len(), 1);
    }
}

#[test]
fn original_receipts_bind_writer_payload_precondition_operation_and_do_not_restore_authority() {
    let mut f = fixture();
    let row = create(&mut f, 100);
    let original = input(100).to_json().unwrap();
    let original_bytes = f.peer.create(context(&f.requester, NOW), id(1100), &original).unwrap();
    let browser_context =
        Context { caller: Caller::AccountBrowser(f.browser), organization: id(1), now: NOW };
    assert_eq!(f.peer.create(browser_context, id(1100), &original), Err(Error::Conflict));
    let mut changed = input(100);
    changed.fields.reason = "other".into();
    assert_eq!(
        f.peer.create(context(&f.requester, NOW), id(1100), &changed.to_json().unwrap()),
        Err(Error::Conflict)
    );
    assert_eq!(
        f.peer.create(context(&f.requester, NOW), id(1101), &original),
        Err(Error::Conflict)
    );
    let response = f
        .peer
        .decide(context(&f.approver, NOW), row.id, id(600), Some(&row.etag), &approve())
        .unwrap();
    let approved = AccessRequestResource::from_json(&response).unwrap();
    assert_eq!(
        f.peer.decide(context(&f.approver, NOW), row.id, id(600), Some(&approved.etag), &approve()),
        Err(Error::Conflict)
    );
    assert_eq!(
        f.peer.decide(context(&f.approver, NOW), row.id, id(600), Some(&row.etag), &deny()),
        Err(Error::Conflict)
    );
    f.peer.withdraw_grant(id(1), approved.grant.as_ref().unwrap().id).unwrap();
    assert_eq!(
        f.peer
            .decide(context(&f.approver, NOW), row.id, id(600), Some(&row.etag), &approve())
            .unwrap(),
        response
    );
    assert_eq!(f.peer.current_grants(id(1)), []);
    f.peer.set_policies(id(1), PolicySet::new()).unwrap();
    assert_eq!(
        f.peer.create(context(&f.requester, NOW), id(1100), &original).unwrap(),
        original_bytes
    );
    assert_eq!(
        f.peer.decide(context(&f.approver, NOW), row.id, id(600), Some(&row.etag), &approve()),
        Err(Error::NotFound)
    );
    assert_eq!(
        f.peer.create(context(&f.requester, NOW + 86400), id(1100), &original),
        Err(Error::Conflict)
    );
}

#[test]
fn transaction_faults_never_publish_a_partial_grant_audit_receipt_or_revision() {
    for fault in [
        Fault::Rollback,
        Fault::AuditFailure,
        Fault::UnknownRollback,
        Fault::UnknownCommitted,
        Fault::LostResponse,
    ] {
        let mut f = fixture();
        let row = create(&mut f, 100);
        f.peer.set_fault(fault);
        let result =
            f.peer.decide(context(&f.approver, NOW), row.id, id(600), Some(&row.etag), &approve());
        let committed = matches!(fault, Fault::UnknownCommitted | Fault::LostResponse);
        assert_eq!(f.peer.current_grants(id(1)).len(), usize::from(committed));
        assert_eq!(f.peer.audit().len(), if committed { 3 } else { 1 });
        assert_eq!(f.peer.revision(id(1)), u64::from(committed));
        assert_eq!(
            result,
            Err(match fault {
                Fault::Rollback | Fault::AuditFailure => Error::StorageUnavailable,
                Fault::UnknownRollback | Fault::UnknownCommitted => Error::CommitOutcomeUnknown,
                Fault::LostResponse => Error::ResponseLost,
            })
        );
        let mut restarted = f.peer.clone();
        restarted
            .decide(context(&f.approver, NOW), row.id, id(600), Some(&row.etag), &approve())
            .unwrap();
        assert_eq!(restarted.current_grants(id(1)).len(), 1);
        assert_eq!(restarted.audit().len(), 3);
    }
}

#[test]
fn current_authority_precedes_protected_preconditions_and_browser_is_a_real_writer() {
    let mut f = fixture();
    let row = create(&mut f, 100);
    assert_eq!(
        f.peer.decide(context(&f.approver, NOW), row.id, id(600), None, &approve()),
        Err(Error::PreconditionRequired)
    );
    assert_eq!(
        f.peer.decide(context(&f.approver, NOW), row.id, id(600), Some("W/\"bad\""), &approve()),
        Err(Error::InvalidRequest)
    );
    assert_eq!(
        f.peer.decide(context(&f.approver, NOW), row.id, id(600), Some("\"stale\""), &approve()),
        Err(Error::PreconditionFailed)
    );
    f.peer.set_membership(member(20, "member"), true).unwrap();
    assert_eq!(
        f.peer.decide(context(&f.approver, NOW), row.id, id(600), None, &approve()),
        Err(Error::NotFound)
    );
    f.peer.set_membership(member(20, "approver"), true).unwrap();
    let browser_context = Context {
        caller: Caller::AccountBrowser(f.approver_browser),
        organization: id(1),
        now: NOW,
    };
    let response =
        f.peer.decide(browser_context, row.id, id(600), Some(&row.etag), &approve()).unwrap();
    assert_eq!(
        f.peer.audit()[1].actor,
        Some(Actor::AccountBrowser(f.approver_browser.family_id()))
    );
    assert_eq!(
        f.peer.decide(browser_context, row.id, id(600), Some(&row.etag), &approve()).unwrap(),
        response
    );
    assert_eq!(
        f.peer.decide(context(&f.approver, NOW), row.id, id(600), Some(&row.etag), &approve()),
        Err(Error::Conflict)
    );
    let mut missing = f.requester.clone();
    missing.scope = "policies:write".into();
    assert_eq!(f.peer.read(context(&missing, NOW), row.id), Err(Error::Denied));
    f.peer.set_browser(f.approver_browser, INITIAL_ACCOUNT_BROWSER_ACCESS_SCOPE, false);
    assert_eq!(f.peer.read(browser_context, row.id), Err(Error::AuthenticationRequired));
    let mut foreign = context(&f.requester, NOW);
    foreign.organization = id(2);
    assert_eq!(f.peer.read(foreign, row.id), Err(Error::NotFound));
    f.peer.set_membership(member(10, "member"), false).unwrap();
    assert_eq!(f.peer.read(context(&f.requester, NOW), row.id), Err(Error::NotFound));
    assert_eq!(f.peer.current_grants(id(1)), []);
}

#[test]
fn current_group_subject_and_exact_cursor_are_evaluated_per_page() {
    let mut f = fixture();
    f.peer.set_group(id(1), id(80), vec![id(12)]).unwrap();
    f.peer.set_policies(id(1),PolicySet::from_str(&format!("{} permit(principal, action == Action::\"request_access\", resource) when {{ context.membership.groups.contains(Group::\"{}\") }};",view_policy(),id(80))).unwrap()).unwrap();
    let first = create(&mut f, 100);
    create(&mut f, 101);
    let page = AccessRequestPage::from_json(
        &f.peer.list(context(&f.requester, NOW), [("view", "mine"), ("limit", "1")]).unwrap(),
    )
    .unwrap();
    assert_eq!(page.items, vec![first.clone()]);
    assert_eq!(page.next_cursor, Some(first.id));
    let cursor = first.id.to_string();
    let page = AccessRequestPage::from_json(
        &f.peer
            .list(context(&f.requester, NOW), [("view", "mine"), ("cursor", cursor.as_str())])
            .unwrap(),
    )
    .unwrap();
    assert_eq!(page.items.len(), 1);
    assert_eq!(page.next_cursor, None);
    f.peer.set_group(id(1), id(80), vec![]).unwrap();
    assert_eq!(
        f.peer.decide(context(&f.approver, NOW), first.id, id(600), Some(&first.etag), &approve()),
        Err(Error::Conflict)
    );
}
