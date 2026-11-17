// SPDX-License-Identifier: Apache-2.0

use std::str::FromStr as _;

use cedar_policy::{Context as CedarContext, Entities, PolicySet, Request};
use scoplen_api::{
    account_browser::{AccountBrowserWriter, INITIAL_ACCOUNT_BROWSER_ACCESS_SCOPE},
    auth::INITIAL_DEVICE_ACCESS_SCOPE,
    control_plane::{
        ConnectAuthorization, OrganizationAuthorizationContext, OrganizationAuthorizer,
        OrganizationHostGrant,
    },
    grant::{
        GrantCreateRequest, GrantFields, GrantPage, GrantReplaceRequest, GrantResource,
        MAX_GRANT_BYTES, MAX_GRANT_PAGE_BYTES,
        reference::{
            GrantReferenceActor as Actor, GrantReferenceCaller as Caller,
            GrantReferenceContext as Context, GrantReferenceFault as Fault, GrantReferencePeer,
        },
    },
    organization::{OrganizationCodecError, OrganizationMembership, OrganizationResource},
    organization_reference::OrganizationReferenceError as Error,
};
use scoplen_crypto::{DeviceAccessTokenClaims, DeviceOrganizationSnapshot};
use serde_json::json;
use uuid::Uuid;

const ORIGIN: &str = "https://control.example.com";
const NOW: u64 = 101;

fn id(number: u64) -> Uuid {
    format!("019bdad6-b800-7000-8000-{number:012}").parse().unwrap()
}

struct Fixture {
    peer: GrantReferencePeer,
    device: DeviceAccessTokenClaims,
    browser: AccountBrowserWriter,
    administrator: OrganizationResource,
    recipient: OrganizationResource,
}

fn fixture() -> Fixture {
    let device = DeviceAccessTokenClaims {
        iss: ORIGIN.into(),
        sub: id(20),
        did: id(21),
        jti: id(22),
        cnf_jkt: "synthetic-proof-key".into(),
        org: vec![],
        scope: INITIAL_DEVICE_ACCESS_SCOPE.into(),
        iat: 1,
        exp: 1_000_000,
    };
    let browser = AccountBrowserWriter::new(device.sub, id(23)).unwrap();
    let administrator = OrganizationResource {
        id: id(1),
        etag: "\"membership-fixture\"".into(),
        created_at: "1970-01-01T00:00:00Z".into(),
        updated_at: "1970-01-01T00:00:00Z".into(),
        name: "Grant fixture".into(),
        membership: OrganizationMembership {
            id: id(24),
            account_id: device.sub,
            roles: vec!["owner".into()],
        },
    };
    let mut recipient = administrator.clone();
    recipient.membership =
        OrganizationMembership { id: id(31), account_id: id(30), roles: vec!["member".into()] };
    let mut peer = GrantReferencePeer::new(ORIGIN).unwrap();
    peer.set_account_active(device.sub, true);
    peer.set_account_active(id(30), true);
    peer.set_device(&device, true);
    peer.set_browser(browser, INITIAL_ACCOUNT_BROWSER_ACCESS_SCOPE, true);
    peer.set_organization_active(id(1), true);
    peer.set_membership(administrator.clone(), true).unwrap();
    peer.set_membership(recipient.clone(), true).unwrap();
    peer.set_host(id(1), id(40), true).unwrap();
    Fixture { peer, device, browser, administrator, recipient }
}

fn context(caller: Caller<'_>) -> Context<'_> {
    Context { caller, organization: id(1), now: NOW }
}

fn fields() -> GrantFields {
    GrantFields {
        membership: id(31),
        host: id(40),
        remote_user: "deploy".into(),
        valid_from: 0,
        valid_until: Some(2_000),
    }
}

fn create_body(number: u64) -> Vec<u8> {
    GrantCreateRequest { id: id(number), fields: fields() }.to_json().unwrap()
}

fn replacement(user: &str) -> Vec<u8> {
    let mut value = fields();
    value.remote_user = user.into();
    GrantReplaceRequest { fields: value }.to_json().unwrap()
}

fn decode(body: &[u8]) -> GrantResource {
    GrantResource::from_json(body).unwrap()
}

#[test]
fn actual_current_loader_drives_public_connect_helper_without_receipt_authority() {
    let mut f = fixture();
    let ctx = context(Caller::Device(&f.device));
    let body = create_body(50);
    let original = f.peer.create(ctx, id(70), &body).unwrap();
    let reference =
        |kind: &str, number| json!({"__entity": {"type": kind, "id": id(number).to_string()}});
    let entity = |kind: &str, number, attrs| json!({"uid": {"type": kind, "id": id(number).to_string()}, "attrs": attrs, "parents": []});
    let entities = Entities::from_json_value(json!([
        entity("Account", 30, json!({"status": "active"})),
        entity("Organization", 1, json!({"name": "Grant fixture"})),
        entity("Membership", 31, json!({"account": reference("Account", 30), "organization": reference("Organization", 1), "status": "active", "roles": ["member"], "groups": []})),
        entity("Host", 40, json!({"organization": reference("Organization", 1), "labels": [], "host_groups": []})),
        entity("Device", 33, json!({"account": reference("Account", 30), "platform": "linux", "hardware_backed": false, "enrolled_at": 0})),
    ]), None).unwrap();
    let request = Request::new(
        format!("Account::\"{}\"", id(30)).parse().unwrap(),
        "Action::\"connect\"".parse().unwrap(),
        format!("Host::\"{}\"", id(40)).parse().unwrap(),
        CedarContext::from_json_value(json!({"organization": reference("Organization", 1), "membership": reference("Membership", 31), "device": reference("Device", 33), "now": NOW, "remote_user": "deploy", "route_kind": "direct", "source_ip": "192.0.2.1"}), None).unwrap(),
        None,
    ).unwrap();
    let trusted =
        OrganizationAuthorizationContext::new(id(30), id(1), id(31), i64::try_from(NOW).unwrap())
            .unwrap();
    let authorizer = OrganizationAuthorizer::new(id(1), &PolicySet::new()).unwrap();
    assert_eq!(
        authorizer
            .authorize_connect(&trusted, &request, &entities, &f.peer.current_grants(id(1)))
            .unwrap(),
        ConnectAuthorization::Allow { not_after: Some(2_000) }
    );
    f.peer.set_membership(f.recipient.clone(), false).unwrap();
    f.peer.set_membership(f.recipient, true).unwrap();
    assert_eq!(f.peer.create(ctx, id(70), &body).unwrap(), original);
    assert_eq!(
        authorizer
            .authorize_connect(&trusted, &request, &entities, &f.peer.current_grants(id(1)))
            .unwrap(),
        ConnectAuthorization::Deny
    );
}

#[test]
fn both_profiles_crud_use_current_cedar_and_real_audit_writers() {
    for browser in [false, true] {
        let mut f = fixture();
        let caller =
            if browser { Caller::AccountBrowser(f.browser) } else { Caller::Device(&f.device) };
        let ctx = context(caller);
        let original = f.peer.create(ctx, id(70), &create_body(50)).unwrap();
        let first = decode(&original);
        assert_eq!(f.peer.read(ctx, id(50)).unwrap(), original);
        let page = GrantPage::from_json(&f.peer.list(ctx, []).unwrap()).unwrap();
        assert_eq!(page.items.as_slice(), std::slice::from_ref(&first));
        let changed =
            f.peer.replace(ctx, id(50), Some(&first.etag), &replacement("operator")).unwrap();
        let current = decode(&changed);
        assert_eq!(current.fields.remote_user, "operator");
        assert_ne!(current.etag, first.etag);
        f.peer.delete(ctx, id(50), Some(&current.etag)).unwrap();
        assert_eq!(f.peer.read(ctx, id(50)), Err(Error::NotFound));
        assert_eq!(
            GrantPage::from_json(&f.peer.list(ctx, []).unwrap()).unwrap().items,
            [] as [GrantResource; 0]
        );
        assert_eq!(f.peer.current_grants(id(1)), [] as [OrganizationHostGrant; 0]);
        assert_eq!(f.peer.revision(id(1)), 3);
        let expected = if browser {
            Actor::AccountBrowser(f.browser.family_id())
        } else {
            Actor::Device(f.device.did)
        };
        for event in f.peer.audit() {
            assert_eq!(event.actor, expected);
            assert_eq!(event.actor_account, f.device.sub);
            assert_eq!(event.organization, id(1));
            assert_eq!(event.object_id, id(50));
        }
        assert_eq!(
            f.peer.audit().iter().map(|event| event.kind).collect::<Vec<_>>(),
            [
                "organization.grants_created",
                "organization.grants_updated",
                "organization.grants_deleted"
            ]
        );
    }
}

#[test]
fn complete_byte_overflow_uses_existing_413_problem_without_changing_state() {
    let mut f = fixture();
    let ctx = context(Caller::Device(&f.device));
    let original = f.peer.create(ctx, id(70), &create_body(50)).unwrap();
    let mut create = create_body(51);
    create.resize(MAX_GRANT_BYTES + 1, b' ');
    let mut replace = replacement("operator");
    replace.resize(MAX_GRANT_BYTES + 1, b' ');
    for caller in [Caller::Device(&f.device), Caller::AccountBrowser(f.browser)] {
        assert_eq!(f.peer.create(context(caller), id(71), &create), Err(Error::TooLarge));
        assert_eq!(
            f.peer.replace(context(caller), id(50), Some(&decode(&original).etag), &replace),
            Err(Error::TooLarge)
        );
    }
    assert_eq!(
        GrantPage::from_json(&vec![b' '; MAX_GRANT_PAGE_BYTES + 1]),
        Err(OrganizationCodecError::TooLarge)
    );
    let problem = Error::TooLarge.problem("/api/v1/orgs/example/grants").unwrap().unwrap();
    assert_eq!(problem.status, 413);
    assert_eq!(problem.code.as_str(), "organization.invalid_request");
    assert!(!problem.changed && !problem.retryable);
    assert_eq!(f.peer.read(ctx, id(50)).unwrap(), original);
    assert_eq!(f.peer.audit().len(), 1);
    assert_eq!(f.peer.revision(id(1)), 1);
}

#[test]
fn even_a_current_manager_of_both_teams_cannot_read_foreign_rows_or_reuse_global_ids() {
    let mut f = fixture();
    let ctx = context(Caller::Device(&f.device));
    let body = create_body(50);
    f.peer.create(ctx, id(70), &body).unwrap();
    let mut administrator = f.administrator.clone();
    administrator.id = id(2);
    administrator.membership.id = id(25);
    let mut recipient = f.recipient.clone();
    recipient.id = id(2);
    recipient.membership.id = id(32);
    f.peer.set_organization_active(id(2), true);
    f.peer.set_membership(administrator, true).unwrap();
    f.peer.set_membership(recipient, true).unwrap();
    f.peer.set_host(id(2), id(41), true).unwrap();
    let foreign = Context { organization: id(2), ..ctx };
    assert_eq!(f.peer.read(foreign, id(50)), Err(Error::NotFound));
    assert_eq!(f.peer.create(foreign, id(70), &body), Err(Error::Conflict));
    let mut request = GrantCreateRequest {
        id: id(50),
        fields: GrantFields { membership: id(32), host: id(41), ..fields() },
    };
    assert_eq!(f.peer.create(foreign, id(71), &request.to_json().unwrap()), Err(Error::Conflict));
    request.id = id(51);
    f.peer.create(foreign, id(71), &request.to_json().unwrap()).unwrap();
    assert_eq!(f.peer.read(ctx, id(51)), Err(Error::NotFound));
    assert_eq!(f.peer.current_grants(id(1)).len(), 1);
    assert_eq!(f.peer.current_grants(id(2)).len(), 1);
}

#[test]
fn immutable_confirmation_never_reconstructs_changed_or_withdrawn_rows() {
    let mut f = fixture();
    let ctx = context(Caller::Device(&f.device));
    let body = create_body(50);
    let original = f.peer.create(ctx, id(70), &body).unwrap();
    let changed = f
        .peer
        .replace(ctx, id(50), Some(&decode(&original).etag), &replacement("operator"))
        .unwrap();
    let mut reordered = b" \n".to_vec();
    reordered.extend_from_slice(&body);
    assert_eq!(f.peer.create(ctx, id(70), &reordered).unwrap(), original);
    assert_eq!(f.peer.read(ctx, id(50)).unwrap(), changed);
    f.peer.delete(ctx, id(50), Some(&decode(&changed).etag)).unwrap();
    f.peer.set_host(id(1), id(40), false).unwrap();
    f.peer.set_membership(f.recipient, false).unwrap();
    assert_eq!(f.peer.create(ctx, id(70), &body).unwrap(), original);
    assert_eq!(f.peer.read(ctx, id(50)), Err(Error::NotFound));
    assert_eq!(f.peer.current_grants(id(1)), [] as [OrganizationHostGrant; 0]);
    assert_eq!(f.peer.create(ctx, id(71), &body), Err(Error::Conflict));
    assert_eq!(f.peer.audit().len(), 3);
    assert_eq!(f.peer.revision(id(1)), 3);
}

#[test]
fn receipts_bind_original_account_device_or_browser_family_and_payload() {
    let mut f = fixture();
    let body = create_body(50);
    let ctx = context(Caller::Device(&f.device));
    f.peer.create(ctx, id(70), &body).unwrap();
    assert_eq!(
        f.peer.create(context(Caller::AccountBrowser(f.browser)), id(70), &body),
        Err(Error::Conflict)
    );
    assert_eq!(f.peer.create(ctx, id(70), &create_body(51)), Err(Error::Conflict));
    let mut changed = GrantCreateRequest::from_json(&body).unwrap();
    changed.fields.valid_until = None;
    assert_eq!(f.peer.create(ctx, id(70), &changed.to_json().unwrap()), Err(Error::Conflict));
    let mut other_device = f.device.clone();
    other_device.did = id(25);
    f.peer.set_device(&other_device, true);
    assert_eq!(
        f.peer.create(context(Caller::Device(&other_device)), id(70), &body),
        Err(Error::Conflict)
    );
    let browser_ctx = context(Caller::AccountBrowser(f.browser));
    let second = create_body(51);
    f.peer.create(browser_ctx, id(71), &second).unwrap();
    let other_browser = AccountBrowserWriter::new(f.device.sub, id(26)).unwrap();
    f.peer.set_browser(other_browser, INITIAL_ACCOUNT_BROWSER_ACCESS_SCOPE, true);
    assert_eq!(
        f.peer.create(context(Caller::AccountBrowser(other_browser)), id(71), &second),
        Err(Error::Conflict)
    );
    assert_eq!(
        f.peer.create(Context { now: NOW + 86_400, ..ctx }, id(70), &body),
        Err(Error::Conflict)
    );
    assert_eq!(f.peer.audit().len(), 2);
}

#[test]
fn confirmation_rechecks_current_management_authority_before_receipt_lookup() {
    let mut f = fixture();
    let body = create_body(50);
    let ctx = context(Caller::Device(&f.device));
    f.peer.create(ctx, id(70), &body).unwrap();
    f.administrator.membership.roles = vec!["member".into()];
    f.peer.set_membership(f.administrator.clone(), true).unwrap();
    assert_eq!(f.peer.create(ctx, id(70), &body), Err(Error::Denied));
    f.administrator.membership.roles = vec!["owner".into()];
    f.peer.set_membership(f.administrator.clone(), false).unwrap();
    assert_eq!(f.peer.create(ctx, id(70), &body), Err(Error::NotFound));
    f.peer.set_membership(f.administrator, true).unwrap();
    f.peer.set_device(&f.device, false);
    assert_eq!(f.peer.create(ctx, id(70), &body), Err(Error::AuthenticationRequired));
    f.peer.set_device(&f.device, true);
    f.peer.set_browser(f.browser, INITIAL_ACCOUNT_BROWSER_ACCESS_SCOPE, false);
    assert_eq!(
        f.peer.read(context(Caller::AccountBrowser(f.browser)), id(50)),
        Err(Error::AuthenticationRequired)
    );
}

#[test]
fn preconditions_follow_current_authority_and_equal_replacement_is_a_noop() {
    let mut f = fixture();
    let ctx = context(Caller::Device(&f.device));
    let original = f.peer.create(ctx, id(70), &create_body(50)).unwrap();
    let first = decode(&original);
    assert_eq!(
        f.peer.replace(ctx, id(50), None, &replacement("deploy")),
        Err(Error::PreconditionRequired)
    );
    assert_eq!(f.peer.delete(ctx, id(50), Some("*")), Err(Error::InvalidRequest));
    assert_eq!(
        f.peer.replace(ctx, id(50), Some("\"stale\""), &replacement("operator")),
        Err(Error::PreconditionFailed)
    );
    f.peer.set_fault(Fault::AuditFailure);
    assert_eq!(
        f.peer.replace(ctx, id(50), Some(&first.etag), &replacement("deploy")).unwrap(),
        original
    );
    assert_eq!(f.peer.audit().len(), 1);
    assert_eq!(f.peer.revision(id(1)), 1);
    assert_eq!(
        f.peer.replace(ctx, id(50), Some(&first.etag), &replacement("operator")),
        Err(Error::StorageUnavailable)
    );
    f.administrator.membership.roles = vec!["member".into()];
    f.peer.set_membership(f.administrator, true).unwrap();
    assert_eq!(f.peer.replace(ctx, id(50), None, &replacement("operator")), Err(Error::Denied));
    assert_eq!(f.peer.delete(ctx, id(50), Some("invalid")), Err(Error::Denied));
}

#[test]
fn current_roles_scopes_and_forbids_control_both_auth_profiles() {
    let mut f = fixture();
    f.peer.create(context(Caller::Device(&f.device)), id(70), &create_body(50)).unwrap();
    for (role, read, write) in [
        ("owner", true, true),
        ("administrator", true, true),
        ("security_auditor", true, false),
        ("member", false, false),
    ] {
        f.administrator.membership.roles = vec![role.into()];
        f.peer.set_membership(f.administrator.clone(), true).unwrap();
        for (caller, number) in
            [(Caller::Device(&f.device), 51), (Caller::AccountBrowser(f.browser), 52)]
        {
            assert_eq!(f.peer.read(context(caller), id(50)).is_ok(), read, "{role}");
            assert_eq!(
                f.peer.create(context(caller), id(number + 20), &create_body(number)).is_ok(),
                write,
                "{role}"
            );
        }
        // Remove this role's created row from the next scenario by resetting the fixture.
        f.peer = fixture().peer;
        f.peer.create(context(Caller::Device(&f.device)), id(70), &create_body(50)).unwrap();
    }
    f.peer
        .set_policies(
            id(1),
            PolicySet::from_str(
                "forbid(principal, action == Action::\"manage_policy\", resource);",
            )
            .unwrap(),
        )
        .unwrap();
    for caller in [Caller::Device(&f.device), Caller::AccountBrowser(f.browser)] {
        assert_eq!(f.peer.create(context(caller), id(71), &create_body(51)), Err(Error::Denied));
    }
    f.peer.set_browser(f.browser, "teams:manage orgs:write policies:*", true);
    assert_eq!(f.peer.read(context(Caller::AccountBrowser(f.browser)), id(50)), Err(Error::Denied));
    let mut restricted = f.device.clone();
    restricted.scope = "teams:manage policies:*".into();
    assert_eq!(f.peer.read(context(Caller::Device(&restricted)), id(50)), Err(Error::Denied));
}

#[test]
fn jwt_membership_snapshots_and_foreign_references_never_supply_current_authority() {
    let mut f = fixture();
    let mut stale = f.device.clone();
    stale.org = vec![DeviceOrganizationSnapshot { id: id(1), sso_authenticated_at: Some(100) }];
    f.administrator.membership.roles = vec!["member".into()];
    f.peer.set_membership(f.administrator.clone(), true).unwrap();
    assert_eq!(
        f.peer.create(context(Caller::Device(&stale)), id(70), &create_body(50)),
        Err(Error::Denied)
    );
    f.administrator.membership.roles = vec!["owner".into()];
    f.peer.set_membership(f.administrator, true).unwrap();
    let mut foreign = f.recipient.clone();
    foreign.id = id(2);
    foreign.membership.id = id(32);
    f.peer.set_membership(foreign, true).unwrap();
    f.peer.set_host(id(2), id(41), true).unwrap();
    let ctx = context(Caller::Device(&f.device));
    for (membership, host) in
        [(id(32), id(40)), (id(99), id(40)), (id(31), id(41)), (id(31), id(99))]
    {
        let mut request = GrantCreateRequest::from_json(&create_body(50)).unwrap();
        request.fields.membership = membership;
        request.fields.host = host;
        assert_eq!(
            f.peer.create(ctx, id(70), &request.to_json().unwrap()),
            Err(Error::InvalidRequest)
        );
    }
    f.peer.create(ctx, id(70), &create_body(50)).unwrap();
    assert_eq!(f.peer.read(Context { organization: id(2), ..ctx }, id(50)), Err(Error::NotFound));
    let mut wrong_origin = f.device.clone();
    wrong_origin.iss = "https://other.example.com".into();
    assert_eq!(
        f.peer.read(context(Caller::Device(&wrong_origin)), id(50)),
        Err(Error::AuthenticationRequired)
    );
    let mut wrong_key = f.device.clone();
    wrong_key.cnf_jkt = "different-key".into();
    assert_eq!(
        f.peer.read(context(Caller::Device(&wrong_key)), id(50)),
        Err(Error::AuthenticationRequired)
    );
}

#[test]
fn suspension_restore_rejoin_and_dissolution_retain_withdrawal_markers() {
    for new_membership in [false, true] {
        let mut f = fixture();
        let ctx = context(Caller::Device(&f.device));
        let original = f.peer.create(ctx, id(70), &create_body(50)).unwrap();
        f.peer.set_membership(f.recipient.clone(), false).unwrap();
        if new_membership {
            f.recipient.membership.id = id(32);
        }
        f.peer.set_membership(f.recipient.clone(), true).unwrap();
        assert_eq!(f.peer.read(ctx, id(50)), Err(Error::NotFound));
        assert_eq!(f.peer.create(ctx, id(70), &create_body(50)).unwrap(), original);
        assert_eq!(f.peer.current_grants(id(1)), [] as [OrganizationHostGrant; 0]);
        assert!(f.peer.host_deletion_allowed(id(1), id(40)));
        assert_eq!(f.peer.audit().len(), 1);
        let fresh = GrantCreateRequest {
            id: id(51),
            fields: GrantFields { membership: f.recipient.membership.id, ..fields() },
        };
        f.peer.create(ctx, id(71), &fresh.to_json().unwrap()).unwrap();
        assert_eq!(f.peer.current_grants(id(1)).len(), 1);
        f.peer.set_organization_active(id(1), false);
        assert_eq!(f.peer.read(ctx, id(51)), Err(Error::NotFound));
        f.peer.set_organization_active(id(1), true);
        assert_eq!(f.peer.read(ctx, id(51)), Err(Error::NotFound));
        assert_eq!(f.peer.current_grants(id(1)), [] as [OrganizationHostGrant; 0]);
        assert_eq!(f.peer.audit().len(), 2);
    }
}

#[test]
fn expired_and_future_rows_remain_readable_and_block_host_deletion_until_withdrawn() {
    let mut f = fixture();
    let ctx = context(Caller::Device(&f.device));
    f.peer.set_host(id(1), id(41), true).unwrap();
    for (number, start, end) in [(50, 0, Some(1)), (51, 2000, None)] {
        let request = GrantCreateRequest {
            id: id(number),
            fields: GrantFields { valid_from: start, valid_until: end, ..fields() },
        };
        let created = f.peer.create(ctx, id(number + 20), &request.to_json().unwrap()).unwrap();
        assert_eq!(f.peer.read(ctx, id(number)).unwrap(), created);
        assert_eq!(f.peer.set_host(id(1), id(40), false), Err(Error::Conflict));
    }
    assert_eq!(f.peer.current_grants(id(1)).len(), 2);
    let original = decode(&f.peer.read(ctx, id(50)).unwrap());
    let retargeted =
        GrantReplaceRequest { fields: GrantFields { host: id(41), ..original.fields } };
    f.peer.replace(ctx, id(50), Some(&original.etag), &retargeted.to_json().unwrap()).unwrap();
    let future = decode(&f.peer.read(ctx, id(51)).unwrap());
    f.peer.delete(ctx, id(51), Some(&future.etag)).unwrap();
    assert!(f.peer.host_deletion_allowed(id(1), id(40)));
    f.peer.set_host(id(1), id(40), false).unwrap();
    assert!(!f.peer.host_deletion_allowed(id(1), id(41)));
}

#[test]
fn create_faults_preserve_atomicity_and_original_key_confirmation() {
    for fault in [
        Fault::Rollback,
        Fault::AuditFailure,
        Fault::UnknownRollback,
        Fault::UnknownCommitted,
        Fault::LostResponse,
    ] {
        let mut f = fixture();
        let ctx = context(Caller::Device(&f.device));
        f.peer.set_fault(fault);
        let result = f.peer.create(ctx, id(70), &create_body(50));
        let committed = matches!(fault, Fault::UnknownCommitted | Fault::LostResponse);
        let expected = match fault {
            Fault::Rollback | Fault::AuditFailure => Error::StorageUnavailable,
            Fault::UnknownRollback | Fault::UnknownCommitted => Error::CommitOutcomeUnknown,
            Fault::LostResponse => Error::ResponseLost,
        };
        assert_eq!(result, Err(expected));
        assert_eq!(f.peer.audit().len(), usize::from(committed));
        assert_eq!(f.peer.revision(id(1)), u64::from(committed));
        let mut reopened = f.peer.clone();
        let confirmed = reopened.create(ctx, id(70), &create_body(50)).unwrap();
        assert_eq!(reopened.read(ctx, id(50)).unwrap(), confirmed);
        assert_eq!(reopened.audit().len(), 1);
        assert_eq!(reopened.revision(id(1)), 1);
    }
}

#[test]
fn replace_delete_faults_require_refresh_without_substituting_etags() {
    for delete in [false, true] {
        for fault in [
            Fault::Rollback,
            Fault::AuditFailure,
            Fault::UnknownRollback,
            Fault::UnknownCommitted,
            Fault::LostResponse,
        ] {
            let mut f = fixture();
            let ctx = context(Caller::Device(&f.device));
            let original = decode(&f.peer.create(ctx, id(70), &create_body(50)).unwrap());
            f.peer.set_fault(fault);
            let result = if delete {
                f.peer.delete(ctx, id(50), Some(&original.etag))
            } else {
                f.peer
                    .replace(ctx, id(50), Some(&original.etag), &replacement("operator"))
                    .map(|_| ())
            };
            let committed = matches!(fault, Fault::UnknownCommitted | Fault::LostResponse);
            let expected = match fault {
                Fault::Rollback | Fault::AuditFailure => Error::StorageUnavailable,
                Fault::UnknownRollback | Fault::UnknownCommitted => {
                    Error::UpdateCommitOutcomeUnknown
                }
                Fault::LostResponse => Error::ResponseLost,
            };
            assert_eq!(result, Err(expected));
            assert_eq!(f.peer.audit().len(), 1 + usize::from(committed));
            assert_eq!(f.peer.revision(id(1)), 1 + u64::from(committed));
            let current = f.peer.read(ctx, id(50));
            if committed && delete {
                assert_eq!(current, Err(Error::NotFound));
                assert_eq!(f.peer.delete(ctx, id(50), Some(&original.etag)), Err(Error::NotFound));
            } else if committed {
                assert_eq!(decode(&current.unwrap()).fields.remote_user, "operator");
                assert_eq!(
                    f.peer.replace(ctx, id(50), Some(&original.etag), &replacement("operator")),
                    Err(Error::PreconditionFailed)
                );
            } else {
                assert_eq!(decode(&current.unwrap()), original);
            }
        }
    }
}

#[test]
fn list_uses_live_uuid_cursor_without_filter_or_sort_aliases() {
    let mut f = fixture();
    let ctx = context(Caller::AccountBrowser(f.browser));
    for number in [52, 50, 51] {
        f.peer.create(ctx, id(number + 20), &create_body(number)).unwrap();
    }
    let first = GrantPage::from_json(&f.peer.list(ctx, [("limit", "2")]).unwrap()).unwrap();
    assert_eq!(first.items.iter().map(|item| item.id).collect::<Vec<_>>(), [id(50), id(51)]);
    assert_eq!(first.next_cursor, Some(id(51)));
    let cursor = id(51).to_string();
    let second = GrantPage::from_json(
        &f.peer.list(ctx, [("limit", "2"), ("cursor", cursor.as_str())]).unwrap(),
    )
    .unwrap();
    assert_eq!(second.items.iter().map(|item| item.id).collect::<Vec<_>>(), [id(52)]);
    assert_eq!(second.next_cursor, None);
    for parameters in [
        vec![("filter", "expired")],
        vec![("sort", "id")],
        vec![("limit", "0")],
        vec![("limit", "2"), ("limit", "3")],
    ] {
        assert_eq!(f.peer.list(ctx, parameters), Err(Error::InvalidRequest));
    }
}
