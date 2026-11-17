// SPDX-License-Identifier: Apache-2.0
use std::str::FromStr as _;

use cedar_policy::PolicySet;
use scoplen_api::{
    account_browser::{AccountBrowserWriter, INITIAL_ACCOUNT_BROWSER_ACCESS_SCOPE},
    audit::{
        AuditCategory, AuditPage, AuditResourceKind, AuditVerification, MAX_AUDIT_PAGE_BYTES,
        MAX_AUDIT_VERIFICATION_BYTES, MAX_AUDIT_VERIFY_EVENT_BYTES,
        reference::{
            AuditReferenceCaller as Caller, AuditReferenceError as Error, AuditReferencePeer,
        },
    },
    auth::INITIAL_DEVICE_ACCESS_SCOPE,
    organization::{OrganizationMembership, OrganizationResource},
};
use scoplen_crypto::{DeviceAccessTokenClaims, DeviceOrganizationSnapshot};
use scoplen_test_vectors::VectorDocument;
use uuid::Uuid;

const TIME: &str = "2026-11-17T00:00:00Z";
const RANGE: [(&str, &str); 2] = [("from_sequence", "1"), ("to_sequence", "1")];

fn id(n: u64) -> Uuid {
    Uuid::parse_str(&format!("0191d3e0-8000-7000-8000-{n:012x}")).unwrap()
}

fn body(name: &str) -> Vec<u8> {
    VectorDocument::from_bytes(include_bytes!("../../../vectors/audit.json"))
        .unwrap()
        .vectors
        .into_iter()
        .find(|v| v.id == name)
        .unwrap()
        .input
        .into_bytes()
}

struct Fixture {
    peer: AuditReferencePeer,
    device: DeviceAccessTokenClaims,
    browser: AccountBrowserWriter,
    membership: OrganizationResource,
}

fn fixture() -> Fixture {
    let device = DeviceAccessTokenClaims {
        iss: "https://control.example.com".into(),
        sub: id(20),
        did: id(21),
        jti: id(22),
        cnf_jkt: "synthetic-proof-key".into(),
        org: vec![],
        scope: INITIAL_DEVICE_ACCESS_SCOPE.into(),
        iat: 100,
        exp: 10_000,
    };
    let browser = AccountBrowserWriter::new(device.sub, id(23)).unwrap();
    let membership = OrganizationResource {
        id: id(1),
        etag: "\"audit-fixture\"".into(),
        created_at: TIME.into(),
        updated_at: TIME.into(),
        name: "Audit fixture".into(),
        membership: OrganizationMembership {
            id: id(24),
            account_id: device.sub,
            roles: vec!["owner".into()],
        },
    };
    let mut peer = AuditReferencePeer::default();
    peer.set_account_active(device.sub, true);
    peer.set_device(&device, true);
    peer.set_browser(browser, INITIAL_ACCOUNT_BROWSER_ACCESS_SCOPE, true);
    peer.set_organization_active(membership.id, true);
    peer.set_membership(membership.clone(), true).unwrap();
    peer.set_page_response(&body("audit-page-v1"));
    peer.set_verification_response(&body("audit-verification-checkpoint-v1"), 1, 100);
    peer.set_storage_available(true);
    Fixture { peer, device, browser, membership }
}

#[test]
fn grant_history_is_readable_by_both_profiles_with_exact_resource_filters() {
    let mut f = fixture();
    let original = body("audit-grant-page-v1");
    let page = AuditPage::from_json(&original).unwrap();
    let target = page.items[0].resource.as_ref().unwrap().id;
    for event in &page.items {
        assert_eq!(event.category, AuditCategory::Authorization);
        assert_eq!(event.resource.as_ref().unwrap().kind, AuditResourceKind::Grant);
        assert_eq!(event.resource.as_ref().unwrap().id, target);
    }
    f.peer.set_page_response(&original);
    let filter = format!("resource eq \"grant:{target}\"");
    for caller in [Caller::Device(&f.device), Caller::AccountBrowser(f.browser)] {
        assert_eq!(
            f.peer.list(caller, id(1), [("filter", filter.as_str())], 101).unwrap(),
            original
        );
        for wrong in [
            format!("resource eq \"policy:{target}\""),
            format!("resource eq \"grant:{}\"", id(99)),
        ] {
            assert_eq!(
                f.peer.list(caller, id(1), [("filter", wrong.as_str())], 101),
                Err(Error::StorageUnavailable)
            );
        }
        assert_eq!(
            f.peer.list(
                caller,
                id(1),
                [("filter", format!("resource eq \"Grant:{target}\"").as_str())],
                101
            ),
            Err(Error::InvalidRequest)
        );
    }
}

#[test]
fn both_profiles_return_unchanged_original_responses_without_current_actor_or_target_lookup() {
    let mut f = fixture();
    let page = body("audit-page-v1");
    let mut extended = b" \n".to_vec();
    extended.extend_from_slice(&page[..page.len() - 1]);
    extended.extend_from_slice(b",\"future\":{\"retained\":true}} ");
    f.peer.set_page_response(&extended);
    let evidence = body("audit-verification-checkpoint-v1");
    for caller in [Caller::Device(&f.device), Caller::AccountBrowser(f.browser)] {
        for _ in 0..2 {
            assert_eq!(f.peer.list(caller, id(1), [], 101).unwrap(), extended);
            assert_eq!(f.peer.verify(caller, id(1), RANGE, 101).unwrap(), evidence);
        }
    }
    let decoded = AuditPage::from_json(&extended).unwrap();
    assert_eq!(decoded.items[0].actor_account_id, Some(id(2)));
    assert_ne!(decoded.items[0].actor_account_id, Some(f.device.sub));
    assert_eq!(decoded.items[0].resource.as_ref().unwrap().id, id(3));
}

#[test]
fn current_cedar_roles_and_policy_changes_apply_to_each_read_and_profile() {
    let mut f = fixture();
    for role in ["owner", "security_auditor", "administrator", "member", "approver"] {
        f.membership.membership.roles = vec![role.into()];
        f.peer.set_membership(f.membership.clone(), true).unwrap();
        for caller in [Caller::Device(&f.device), Caller::AccountBrowser(f.browser)] {
            let allowed = matches!(role, "owner" | "security_auditor");
            assert_eq!(f.peer.list(caller, id(1), [], 101).is_ok(), allowed, "{role}");
            assert_eq!(f.peer.verify(caller, id(1), RANGE, 101).is_ok(), allowed, "{role}");
        }
    }
    f.peer.set_policies(id(1), PolicySet::from_str(
        "permit(principal is Account, action == Action::\"view_audit\", resource is Organization);"
    ).unwrap()).unwrap();
    assert!(f.peer.list(Caller::Device(&f.device), id(1), [], 101).is_ok());
    f.peer.set_policies(id(1), PolicySet::new()).unwrap();
    assert_eq!(f.peer.list(Caller::Device(&f.device), id(1), [], 101), Err(Error::Denied));
    f.membership.membership.roles = vec!["owner".into()];
    f.peer.set_membership(f.membership, true).unwrap();
    f.peer
        .set_policies(
            id(1),
            PolicySet::from_str(
                "forbid(principal, action == Action::\"view_audit\", resource is Organization);",
            )
            .unwrap(),
        )
        .unwrap();
    assert_eq!(
        f.peer.verify(Caller::AccountBrowser(f.browser), id(1), RANGE, 101),
        Err(Error::Denied)
    );
}

#[test]
fn current_membership_tenant_and_account_remain_required_under_custom_permits() {
    let mut f = fixture();
    f.peer.set_policies(id(1), PolicySet::from_str(
        "permit(principal is Account, action == Action::\"view_audit\", resource is Organization);"
    ).unwrap()).unwrap();
    f.device.org = vec![DeviceOrganizationSnapshot { id: id(1), sso_authenticated_at: Some(100) }];
    assert_eq!(f.peer.list(Caller::Device(&f.device), id(99), [], 101), Err(Error::NotFound));
    f.peer.set_membership(f.membership.clone(), false).unwrap();
    for caller in [Caller::Device(&f.device), Caller::AccountBrowser(f.browser)] {
        assert_eq!(f.peer.list(caller, id(1), [], 101), Err(Error::NotFound));
        assert_eq!(f.peer.verify(caller, id(1), RANGE, 101), Err(Error::NotFound));
    }
    f.peer.set_membership(f.membership.clone(), true).unwrap();
    f.peer.set_organization_active(id(1), false);
    assert_eq!(f.peer.list(Caller::Device(&f.device), id(1), [], 101), Err(Error::NotFound));
    f.peer.set_organization_active(id(1), true);
    f.peer.set_account_active(f.device.sub, false);
    assert_eq!(
        f.peer.verify(Caller::AccountBrowser(f.browser), id(1), RANGE, 101),
        Err(Error::AuthenticationRequired)
    );
    f.peer.set_account_active(f.device.sub, true);
    assert!(f.peer.list(Caller::Device(&f.device), id(1), [], 101).is_ok());
}

#[test]
fn exact_scope_and_current_device_or_browser_bindings_cannot_be_restored_by_membership() {
    let mut f = fixture();
    for scope in ["orgs:read", "audit:read-extra", "*", "inventory:read policies:read"] {
        f.device.scope = scope.into();
        f.peer.set_browser(f.browser, scope, true);
        assert_eq!(f.peer.list(Caller::Device(&f.device), id(1), [], 101), Err(Error::Denied));
        assert_eq!(
            f.peer.verify(Caller::AccountBrowser(f.browser), id(1), RANGE, 101),
            Err(Error::Denied)
        );
    }
    f.device.scope = INITIAL_DEVICE_ACCESS_SCOPE.into();
    f.peer.set_device(&f.device, false);
    assert_eq!(
        f.peer.list(Caller::Device(&f.device), id(1), [], 101),
        Err(Error::AuthenticationRequired)
    );
    f.peer.set_device(&f.device, true);
    let mut wrong = f.device.clone();
    wrong.cnf_jkt = "other-key".into();
    assert_eq!(
        f.peer.list(Caller::Device(&wrong), id(1), [], 101),
        Err(Error::AuthenticationRequired)
    );
    wrong = f.device.clone();
    wrong.sub = id(99);
    assert_eq!(
        f.peer.list(Caller::Device(&wrong), id(1), [], 101),
        Err(Error::AuthenticationRequired)
    );
    for now in [99, 10_000] {
        assert_eq!(
            f.peer.list(Caller::Device(&f.device), id(1), [], now),
            Err(Error::AuthenticationRequired)
        );
    }
    f.peer.set_browser(f.browser, INITIAL_ACCOUNT_BROWSER_ACCESS_SCOPE, false);
    assert_eq!(
        f.peer.verify(Caller::AccountBrowser(f.browser), id(1), RANGE, 101),
        Err(Error::AuthenticationRequired)
    );
    f.peer.set_browser(f.browser, INITIAL_ACCOUNT_BROWSER_ACCESS_SCOPE, true);
    let wrong = AccountBrowserWriter::new(id(99), f.browser.family_id()).unwrap();
    assert_eq!(
        f.peer.list(Caller::AccountBrowser(wrong), id(1), [], 101),
        Err(Error::AuthenticationRequired)
    );
    assert!(f.peer.verify(Caller::AccountBrowser(f.browser), id(1), RANGE, 101).is_ok());
}

#[test]
fn scripted_pages_bind_filter_cursor_limit_organization_and_original_encoded_bounds() {
    let mut f = fixture();
    let caller = Caller::Device(&f.device);
    for parameters in [
        vec![("limit", "1")],
        vec![("cursor", "9007199254740993")],
        vec![("filter", "outcome eq \"failure\"")],
        vec![("filter", "actor_account_id eq \"0191d3e0-8000-7000-8000-000000000014\"")],
    ] {
        assert_eq!(f.peer.list(caller, id(1), parameters, 101), Err(Error::StorageUnavailable));
    }
    let original = body("audit-page-v1");
    let foreign =
        String::from_utf8(original).unwrap().replace(&id(1).to_string(), &id(99).to_string());
    f.peer.set_page_response(foreign.as_bytes());
    assert_eq!(f.peer.list(caller, id(1), [], 101), Err(Error::StorageUnavailable));
    f.peer.set_page_response(b"{\"items\":[],\"next_cursor\":null}");
    let mut exact = vec![b' '; MAX_AUDIT_PAGE_BYTES - 31];
    exact.extend_from_slice(b"{\"items\":[],\"next_cursor\":null}");
    assert_eq!(exact.len(), MAX_AUDIT_PAGE_BYTES);
    f.peer.set_page_response(&exact);
    assert_eq!(f.peer.list(caller, id(1), [], 101).unwrap(), exact);
    exact.push(b' ');
    f.peer.set_page_response(&exact);
    assert_eq!(f.peer.list(caller, id(1), [], 101), Err(Error::TooLarge));
    assert_eq!(f.peer.list(caller, id(1), [("sort", "sequence")], 101), Err(Error::InvalidRequest));
    assert_eq!(f.peer.list(caller, Uuid::nil(), [], 101), Err(Error::InvalidRequest));
}

#[test]
fn verification_scripts_distinguish_integrity_failure_invalid_range_bounds_and_storage() {
    let mut f = fixture();
    let caller = Caller::AccountBrowser(f.browser);
    let failed = body("audit-verification-failure-v1");
    f.peer.set_verification_response(&failed, 1, MAX_AUDIT_VERIFY_EVENT_BYTES);
    assert_eq!(f.peer.verify(caller, id(1), RANGE, 101).unwrap(), failed);
    let decoded = AuditVerification::from_json(&failed).unwrap();
    assert!(!decoded.valid);
    assert_eq!(decoded.failure_sequence, Some(1));
    assert_eq!(decoded.checked_events, 0);
    assert_eq!(
        f.peer.verify(caller, id(1), [("from_sequence", "1"), ("to_sequence", "2")], 101),
        Err(Error::InvalidRequest)
    );
    assert_eq!(
        f.peer.verify(caller, id(1), [("from_sequence", "1"), ("to_sequence", "4097")], 101),
        Err(Error::TooLarge)
    );
    f.peer.set_verification_response(&failed, 1, MAX_AUDIT_VERIFY_EVENT_BYTES + 1);
    assert_eq!(f.peer.verify(caller, id(1), RANGE, 101), Err(Error::TooLarge));
    let mut exact = vec![b' '; MAX_AUDIT_VERIFICATION_BYTES - failed.len()];
    exact.extend_from_slice(&failed);
    f.peer.set_verification_response(&exact, 1, 100);
    assert_eq!(f.peer.verify(caller, id(1), RANGE, 101).unwrap(), exact);
    exact.push(b' ');
    f.peer.set_verification_response(&exact, 1, 100);
    assert_eq!(f.peer.verify(caller, id(1), RANGE, 101), Err(Error::TooLarge));
    f.peer.set_verification_response(&failed, 2, 100);
    assert_eq!(
        f.peer.verify(caller, id(1), [("from_sequence", "2"), ("to_sequence", "2")], 101),
        Err(Error::StorageUnavailable)
    );
    f.peer.set_storage_available(false);
    assert_eq!(f.peer.verify(caller, id(1), RANGE, 101), Err(Error::StorageUnavailable));
    f.peer.set_storage_available(true);
    assert_eq!(f.peer.verify(caller, id(1), RANGE, 101).unwrap(), failed);
}

#[test]
fn all_reference_problems_preserve_the_read_only_boundary_and_registered_classifications() {
    for (error, status, code) in [
        (Error::InvalidRequest, 400, "organization.invalid_request"),
        (Error::AuthenticationRequired, 401, "auth.authentication_required"),
        (Error::Denied, 403, "policy.denied"),
        (Error::NotFound, 404, "organization.not_found"),
        (Error::TooLarge, 413, "organization.invalid_request"),
        (Error::StorageUnavailable, 503, "organization.storage_unavailable"),
    ] {
        let problem = error.problem("urn:request:audit-fixture").unwrap();
        assert_eq!(problem.status, status);
        assert_eq!(problem.code.as_str(), code);
        assert!(!problem.changed);
        assert_eq!(problem.retryable, error == Error::StorageUnavailable);
    }
}
