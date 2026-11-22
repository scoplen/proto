// SPDX-License-Identifier: Apache-2.0
use cedar_policy::PolicySet;
use scoplen_api::{
    account_browser::{AccountBrowserWriter, INITIAL_ACCOUNT_BROWSER_ACCESS_SCOPE},
    auth::INITIAL_DEVICE_ACCESS_SCOPE,
    auth_connection_draft::reference::{
        DraftCaller, DraftContext, DraftReferencePeer, DraftWriter,
    },
    organization::{OrganizationMembership, OrganizationResource},
    organization_reference::{
        OrganizationReferenceError as Error, OrganizationReferenceFault as Fault,
    },
};
use scoplen_crypto::DeviceAccessTokenClaims;
use uuid::Uuid;

const ORIGIN: &str = "https://control.example.com";
const BODY: &[u8] = br#"{"data":{"issuer":"https://issuer.example/tenant/"}}"#;
const NOW: u64 = 1000;
fn id(n: u64) -> Uuid {
    format!("019bdad6-b800-7000-8000-{n:012}").parse().unwrap()
}
fn context(caller: DraftCaller<'_>) -> DraftContext<'_> {
    DraftContext { caller, organization: id(1), now: NOW }
}
fn member(org: Uuid, role: &str) -> OrganizationResource {
    OrganizationResource {
        id: org,
        etag: "\"membership\"".into(),
        name: "Example team".into(),
        created_at: "1970-01-01T00:00:00Z".into(),
        updated_at: "1970-01-01T00:00:00Z".into(),
        membership: OrganizationMembership {
            id: id(10),
            account_id: id(2),
            roles: vec![role.into()],
        },
    }
}
fn fixture() -> (DraftReferencePeer, DeviceAccessTokenClaims, AccountBrowserWriter) {
    let token = DeviceAccessTokenClaims {
        iss: ORIGIN.into(),
        sub: id(2),
        did: id(3),
        jti: id(4),
        cnf_jkt: "fixture-proof".into(),
        org: vec![],
        scope: INITIAL_DEVICE_ACCESS_SCOPE.into(),
        iat: 1,
        exp: 1_000_000,
    };
    let browser = AccountBrowserWriter::new(token.sub, id(5)).unwrap();
    let mut peer = DraftReferencePeer::new(ORIGIN).unwrap();
    peer.set_account(token.sub, true);
    peer.set_device(&token, true);
    peer.set_browser(browser, INITIAL_ACCOUNT_BROWSER_ACCESS_SCOPE, true);
    peer.set_organization(id(1), true);
    peer.set_membership(member(id(1), "owner"), true).unwrap();
    (peer, token, browser)
}

#[test]
fn original_confirmation_survives_cancel_and_recreate_without_mutating_the_replacement() {
    let (mut peer, token, browser) = fixture();
    let device = context(DraftCaller::Device(&token));
    let web = context(DraftCaller::Browser(browser));
    let first = peer.create(device, id(11), Some("*"), BODY).unwrap();
    assert_eq!(peer.read(web).unwrap(), first);
    assert_eq!(peer.create(web, id(12), Some("*"), BODY), Err(Error::PreconditionFailed));
    peer.cancel(web, id(12), Some(&first.etag())).unwrap();
    let later = peer.create(web, id(13), Some("*"), BODY).unwrap();
    assert_ne!(first.id, later.id);
    assert_eq!(peer.cancel(device, id(14), Some(&first.etag())), Err(Error::PreconditionFailed));
    peer.cancel(web, id(12), Some(&first.etag())).unwrap();
    let reformatted = br#" { "data" : { "issuer" : "https://issuer.example/\u0074enant/" } } "#;
    assert_eq!(peer.create(device, id(11), Some("*"), reformatted).unwrap(), first);
    assert_eq!(peer.read(web).unwrap(), later);
    assert_eq!(peer.audit().len(), 3);
    assert_eq!(peer.audit()[0].writer, DraftWriter::Device(token.did));
    assert_eq!(peer.audit()[1].writer, DraftWriter::Browser(browser.family_id()));
    assert_eq!(peer.audit()[1].generation, first.id);
    assert!(!format!("{:?}", peer.audit()).contains("issuer.example"));
    assert!(!format!("{later:?}").contains("issuer.example"));
}

#[test]
fn receipt_is_bound_to_tenant_method_payload_condition_original_writer_and_expiry() {
    let (mut peer, token, browser) = fixture();
    let dev = context(DraftCaller::Device(&token));
    let web = context(DraftCaller::Browser(browser));
    let original = peer.create(web, id(11), Some("*"), BODY).unwrap();
    let changed = br#"{"data":{"issuer":"https://issuer.example/tenant"}}"#;
    assert_eq!(peer.create(web, id(11), Some("*"), changed), Err(Error::Conflict));
    assert_eq!(peer.create(dev, id(11), Some("*"), BODY), Err(Error::Conflict));
    let fresh_family = AccountBrowserWriter::new(token.sub, id(33)).unwrap();
    peer.set_browser(fresh_family, INITIAL_ACCOUNT_BROWSER_ACCESS_SCOPE, true);
    assert_eq!(
        peer.create(context(DraftCaller::Browser(fresh_family)), id(11), Some("*"), BODY),
        Err(Error::Conflict)
    );
    let org = id(20);
    peer.set_organization(org, true);
    peer.set_membership(member(org, "administrator"), true).unwrap();
    assert_eq!(
        peer.create(DraftContext { organization: org, ..web }, id(11), Some("*"), BODY),
        Err(Error::Conflict)
    );
    assert_eq!(peer.cancel(web, id(11), Some(&original.etag())), Err(Error::Conflict));
    peer.cancel(web, id(12), Some(&original.etag())).unwrap();
    assert_eq!(peer.cancel(web, id(12), Some("\"changed\"")), Err(Error::Conflict));
    assert_eq!(
        peer.create(DraftContext { now: NOW + 86_399, ..web }, id(11), Some("*"), BODY),
        Ok(original)
    );
    assert_eq!(
        peer.create(DraftContext { now: NOW + 86_400, ..web }, id(11), Some("*"), BODY),
        Err(Error::Conflict)
    );
    assert_eq!(peer.audit().len(), 2);
}

#[test]
fn current_membership_role_floor_cedar_scope_and_writer_precede_protected_lookups() {
    let (mut peer, token, browser) = fixture();
    let dev = context(DraftCaller::Device(&token));
    let web = context(DraftCaller::Browser(browser));
    let current = peer.create(dev, id(11), Some("*"), BODY).unwrap();
    let org = dev.organization;
    peer.set_membership(member(org, "administrator"), true).unwrap();
    assert_eq!(peer.read(web).unwrap(), current);
    peer.set_policies(org, r#"permit(principal, action == Action::"manage_organization", resource);"#.parse::<PolicySet>().unwrap()).unwrap();
    for role in ["member", "approver", "security_auditor"] {
        peer.set_membership(member(org, role), true).unwrap();
        assert_eq!(peer.create(dev, id(11), Some("*"), BODY), Err(Error::Denied));
        assert_eq!(peer.cancel(web, id(13), Some("\"other\"")), Err(Error::Denied));
        assert_eq!(peer.read(web), Err(Error::Denied));
    }
    peer.set_membership(member(org, "owner"), true).unwrap();
    peer.set_policies(org, r#"forbid(principal, action == Action::"manage_organization", resource);"#.parse::<PolicySet>().unwrap()).unwrap();
    assert_eq!(peer.create(dev, id(11), Some("*"), BODY), Err(Error::Denied));
    peer.set_policies(org, PolicySet::new()).unwrap();
    peer.set_membership(member(org, "owner"), false).unwrap();
    assert_eq!(peer.create(dev, id(11), Some("*"), BODY), Err(Error::NotFound));
    peer.set_membership(member(org, "owner"), true).unwrap();
    peer.set_organization(org, false);
    assert_eq!(peer.read(web), Err(Error::NotFound));
    peer.set_organization(org, true);
    assert_eq!(peer.read(DraftContext { organization: id(66), ..web }), Err(Error::NotFound));
    peer.set_browser(browser, "orgs:write teams:manage", true);
    assert_eq!(peer.read(web), Err(Error::Denied));
    let mut old = token.clone();
    old.scope = "orgs:write".into();
    assert_eq!(peer.read(context(DraftCaller::Device(&old))), Err(Error::Denied));
    peer.set_browser(browser, INITIAL_ACCOUNT_BROWSER_ACCESS_SCOPE, false);
    assert_eq!(peer.read(web), Err(Error::AuthenticationRequired));
    peer.set_device(&token, false);
    assert_eq!(peer.read(dev), Err(Error::AuthenticationRequired));
    assert_eq!(peer.audit().len(), 1);
}

#[test]
fn rollback_unknown_commit_and_lost_reply_keep_audit_receipt_and_slot_atomic() {
    for fault in
        [Fault::Rollback, Fault::UnknownRollback, Fault::UnknownCommitted, Fault::LostResponse]
    {
        let (mut peer, token, _) = fixture();
        let ctx = context(DraftCaller::Device(&token));
        peer.set_fault(fault);
        let expected = match fault {
            Fault::Rollback => Error::StorageUnavailable,
            Fault::LostResponse => Error::ResponseLost,
            Fault::UnknownRollback | Fault::UnknownCommitted => Error::CommitOutcomeUnknown,
        };
        assert_eq!(peer.create(ctx, id(12), Some("*"), BODY), Err(expected));
        let committed = matches!(fault, Fault::UnknownCommitted | Fault::LostResponse);
        assert_eq!(peer.read(ctx).is_ok(), committed);
        assert_eq!(peer.audit().len(), usize::from(committed));
        let first = peer.create(ctx, id(12), Some("*"), BODY).unwrap();
        assert_eq!(peer.audit().len(), 1);
        peer.set_fault(fault);
        assert_eq!(peer.cancel(ctx, id(13), Some(&first.etag())), Err(expected));
        assert_eq!(peer.read(ctx).is_err(), committed);
        assert_eq!(peer.audit().len(), 1 + usize::from(committed));
        peer.cancel(ctx, id(13), Some(&first.etag())).unwrap();
        assert_eq!(peer.audit().len(), 2);
        assert_eq!(peer.read(ctx), Err(Error::NotFound));
    }
}
