// SPDX-License-Identifier: Apache-2.0
use cedar_policy::PolicySet;
use scoplen_api::{
    account_browser::{AccountBrowserWriter, INITIAL_ACCOUNT_BROWSER_ACCESS_SCOPE},
    auth::INITIAL_DEVICE_ACCESS_SCOPE,
    inventory_import::{
        InventoryImportFields, InventoryImportRequest, InventoryImportRow,
        reference::{
            InventoryImportReferenceCaller as Caller, InventoryImportReferenceContext as Context,
            InventoryImportReferenceFault as Fault, InventoryImportReferencePeer as Peer,
            InventoryImportReferenceWriter as Writer,
        },
    },
    organization::{OrganizationMembership, OrganizationResource},
    organization_reference::OrganizationReferenceError as Error,
};
use scoplen_crypto::DeviceAccessTokenClaims;
use uuid::Uuid;

const ORIGIN: &str = "https://control.example.com";
fn id(number: u64) -> Uuid {
    format!("019bdad6-b800-7000-8000-{number:012}").parse().unwrap()
}
fn claims() -> DeviceAccessTokenClaims {
    DeviceAccessTokenClaims {
        iss: ORIGIN.into(),
        sub: id(10),
        did: id(11),
        jti: id(13),
        cnf_jkt: "fixture-proof".into(),
        org: vec![],
        scope: INITIAL_DEVICE_ACCESS_SCOPE.into(),
        iat: 1,
        exp: 100_000,
    }
}
fn member(role: &str) -> OrganizationResource {
    OrganizationResource {
        id: id(1),
        etag: "\"member\"".into(),
        created_at: "1970-01-01T00:00:00Z".into(),
        updated_at: "1970-01-01T00:00:00Z".into(),
        name: "Import fixture".into(),
        membership: OrganizationMembership {
            id: id(12),
            account_id: id(10),
            roles: vec![role.into()],
        },
    }
}
fn request() -> InventoryImportRequest {
    InventoryImportRequest {
        rows: [20, 30]
            .map(|number| InventoryImportRow {
                host_id: id(number),
                access_profile_id: id(number + 1),
                fields: InventoryImportFields {
                    name: "Duplicate".into(),
                    address: "same.example.test".into(),
                    port: 22,
                    username: "operator".into(),
                    login_name: None,
                },
            })
            .into(),
    }
}
fn context(claims: &DeviceAccessTokenClaims) -> Context<'_> {
    Context { caller: Caller::Device(claims), organization: id(1), now: 100 }
}
fn peer() -> Peer {
    let mut peer = Peer::new(ORIGIN).unwrap();
    peer.set_account_active(id(10), true);
    peer.set_device(&claims(), true);
    peer.set_organization_active(id(1), true);
    peer.set_membership(member("owner"), true).unwrap();
    peer
}

#[test]
fn one_atomic_image_preserves_row_order_origins_audit_revision_and_single_hint() {
    let mut peer = peer();
    let claims = claims();
    let request = request();
    let bytes = request.to_json().unwrap();
    let result = peer.create(context(&claims), id(40), &bytes).unwrap();
    result.validate_for_request(&request).unwrap();
    assert_eq!(peer.revision(id(1)), 1);
    assert_eq!(peer.hints(), &[id(1)]);
    assert_eq!(peer.audit().len(), 4);
    for (index, object_id) in [id(20), id(21), id(30), id(31)].iter().enumerate() {
        let (object, sequence) = peer.object(id(1), *object_id).unwrap();
        assert_eq!(*sequence, u64::try_from(index + 1).unwrap());
        assert!(object.fields.values().all(|entry| entry.origin == claims.did));
        assert_eq!(peer.audit()[index].object_id, *object_id);
        assert_eq!(peer.audit()[index].writer, Writer::Device(claims.did));
    }
    assert_eq!(peer.create(context(&claims), id(40), &bytes).unwrap(), result);
    assert_eq!(peer.audit().len(), 4);
    assert_eq!(peer.revision(id(1)), 1);
    assert_eq!(peer.hints().len(), 1);
    // Original confirmation precedes new-object quota and does not require current target visibility.
    peer.set_object_count(id(1), 100_000);
    peer.set_policies(
        id(1),
        "forbid(principal, action == Action::\"view_inventory\", resource);".parse().unwrap(),
    );
    assert_eq!(peer.create(context(&claims), id(40), &bytes).unwrap(), result);
    let mut changed = request;
    changed.rows[0].fields.name = "Changed".into();
    assert_eq!(
        peer.create(context(&claims), id(40), &changed.to_json().unwrap()),
        Err(Error::Conflict)
    );
}

#[test]
fn all_precommit_faults_have_no_partial_objects_sequences_receipts_audit_or_hints() {
    for fault in
        [Fault::Rollback, Fault::EncodingFailure, Fault::AuditFailure, Fault::UnknownRollback]
    {
        let mut peer = peer();
        let claims = claims();
        let bytes = request().to_json().unwrap();
        peer.set_fault(fault);
        assert_eq!(
            peer.create(context(&claims), id(40), &bytes),
            Err(if fault == Fault::UnknownRollback {
                Error::CommitOutcomeUnknown
            } else {
                Error::StorageUnavailable
            })
        );
        for object in [20, 21, 30, 31] {
            assert!(peer.object(id(1), id(object)).is_none());
        }
        assert_eq!(peer.audit(), []);
        assert_eq!(peer.hints(), &[] as &[Uuid]);
        assert_eq!(peer.revision(id(1)), 0);
        peer.create(context(&claims), id(40), &bytes).unwrap();
        assert_eq!(peer.object(id(1), id(20)).unwrap().1, 1);
    }
}

#[test]
fn unknown_commit_and_lost_response_confirm_only_original_writer_and_intent() {
    for fault in [Fault::UnknownCommitted, Fault::LostResponse] {
        let mut peer = peer();
        let claims = claims();
        let bytes = request().to_json().unwrap();
        peer.set_fault(fault);
        assert_eq!(peer.create(context(&claims), id(40), &bytes), Err(Error::CommitOutcomeUnknown));
        assert_eq!(peer.audit().len(), 4);
        assert_eq!(peer.hints().len(), usize::from(fault == Fault::LostResponse));
        let browser = AccountBrowserWriter::new(id(10), id(14)).unwrap();
        peer.set_browser(browser, INITIAL_ACCOUNT_BROWSER_ACCESS_SCOPE, true);
        let browser_context =
            Context { caller: Caller::AccountBrowser(browser), organization: id(1), now: 100 };
        assert_eq!(peer.create(browser_context, id(40), &bytes), Err(Error::Conflict));
        peer.create(context(&claims), id(40), &bytes).unwrap();
        assert_eq!(peer.audit().len(), 4);
        let mut later = context(&claims);
        later.now = 86_500;
        assert_eq!(peer.create(later, id(40), &bytes), Err(Error::Conflict));
        let mut fresh = request();
        fresh.rows[0].host_id = id(50);
        fresh.rows[0].access_profile_id = id(51);
        fresh.rows[1].host_id = id(60);
        fresh.rows[1].access_profile_id = id(61);
        peer.create(later, id(40), &fresh.to_json().unwrap()).unwrap();
    }
}

#[test]
fn browser_family_refresh_preserves_origin_and_receipt_without_fake_device() {
    let mut peer = peer();
    let bytes = request().to_json().unwrap();
    let browser = AccountBrowserWriter::new(id(10), id(14)).unwrap();
    peer.set_browser(browser, INITIAL_ACCOUNT_BROWSER_ACCESS_SCOPE, true);
    let context =
        Context { caller: Caller::AccountBrowser(browser), organization: id(1), now: 100 };
    let result = peer.create(context, id(40), &bytes).unwrap();
    assert!(
        peer.object(id(1), id(20))
            .unwrap()
            .0
            .fields
            .values()
            .all(|entry| entry.origin == browser.family_id())
    );
    assert_eq!(peer.audit()[0].writer, Writer::AccountBrowser(browser.family_id()));
    peer.set_browser(browser, INITIAL_ACCOUNT_BROWSER_ACCESS_SCOPE, true);
    assert_eq!(peer.create(context, id(40), &bytes).unwrap(), result);
    let other = AccountBrowserWriter::new(id(10), id(15)).unwrap();
    peer.set_browser(other, INITIAL_ACCOUNT_BROWSER_ACCESS_SCOPE, true);
    assert_eq!(
        peer.create(Context { caller: Caller::AccountBrowser(other), ..context }, id(40), &bytes),
        Err(Error::Conflict)
    );
    peer.set_browser(browser, INITIAL_ACCOUNT_BROWSER_ACCESS_SCOPE, false);
    assert_eq!(peer.create(context, id(40), &bytes), Err(Error::AuthenticationRequired));
}

#[test]
fn current_authority_foreign_team_used_ids_quota_and_independent_reference_read() {
    let bytes = request().to_json().unwrap();
    let claims = claims();
    for tombstone in [20, 31] {
        let mut peer = peer();
        peer.reserve_used_id(id(1), id(tombstone));
        assert_eq!(peer.create(context(&claims), id(40), &bytes), Err(Error::Conflict));
        assert_eq!(peer.audit(), []);
    }
    let mut quota = peer();
    quota.set_object_count(id(1), 99_997);
    assert_eq!(quota.create(context(&claims), id(40), &bytes), Err(Error::Conflict));
    let mut foreign = peer();
    let mut routed = context(&claims);
    routed.organization = id(2);
    assert_eq!(foreign.create(routed, id(40), &bytes), Err(Error::NotFound));
    let mut denied = peer();
    denied.set_membership(member("member"), true).unwrap();
    assert_eq!(denied.create(context(&claims), id(40), &bytes), Err(Error::Denied));
    let policies:PolicySet="permit(principal, action == Action::\"manage_inventory\", resource); permit(principal, action == Action::\"view_inventory\", resource is Host);".parse().unwrap();
    denied.set_policies(id(1), policies);
    assert_eq!(denied.create(context(&claims), id(40), &bytes), Err(Error::NotFound));
    assert_eq!(denied.audit(), []);
    let mut inactive = peer();
    inactive.set_account_active(id(10), false);
    assert_eq!(
        inactive.create(context(&claims), id(40), &bytes),
        Err(Error::AuthenticationRequired)
    );
    let mut no_scope = claims.clone();
    no_scope.scope = "inventory:read".into();
    assert_eq!(peer().create(context(&no_scope), id(40), &bytes), Err(Error::Denied));
}
