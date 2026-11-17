// SPDX-License-Identifier: Apache-2.0
use std::str::FromStr;

use cedar_policy::{Context, Decision, Entities, EntityUid, Policy, PolicyId, PolicySet, Request};
use scoplen_api::{
    control_plane::{
        ConnectAuthorization as Connect, OrganizationAuthorizationContext,
        OrganizationAuthorizationError as Error, OrganizationAuthorizer, OrganizationHostGrant,
    },
    grant::GrantFields,
};
use serde_json::{Value, json};
use uuid::Uuid;

const GRANT: &str = "019a0000-0000-7000-8000-000000000201";
const OTHER: &str = "019a0000-0000-7000-8000-000000000202";
const PERMIT: &str = "permit(principal, action == Action::\"connect\", resource);";

struct Fixture(Value);

impl Fixture {
    fn new() -> Self {
        let mut fixture =
            Self(serde_json::from_str(include_str!("fixtures/tenant-authorization.json")).unwrap());
        fixture.entity_mut("Membership")["attrs"]["roles"] = json!(["member"]);
        fixture
    }

    fn id(&self, kind: &str) -> Uuid {
        self.0["ids"][kind].as_str().unwrap().parse().unwrap()
    }

    fn uid(&self, kind: &str) -> EntityUid {
        format!("{kind}::\"{}\"", self.id(kind)).parse().unwrap()
    }

    fn entity_mut(&mut self, kind: &str) -> &mut Value {
        self.0["entities"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|entity| entity["uid"]["type"] == kind)
            .unwrap()
    }

    fn entities(&self) -> Entities {
        Entities::from_json_value(self.0["entities"].clone(), None).unwrap()
    }

    fn trusted(&self, now: i64) -> OrganizationAuthorizationContext {
        OrganizationAuthorizationContext::new(
            self.id("Account"),
            self.id("Organization"),
            self.id("Membership"),
            now,
        )
        .unwrap()
    }

    fn request(&self, now: i64, user: &str, action: &str, kind: &str) -> Request {
        let reference =
            |kind: &str| json!({"__entity": {"type": kind, "id": self.id(kind).to_string()}});
        let mut context = json!({"organization": reference("Organization"), "membership": reference("Membership"), "now": now});
        if action == "connect" {
            context.as_object_mut().unwrap().extend(
                json!({
                    "device": reference("Device"), "remote_user": user,
                    "route_kind": "direct", "source_ip": "192.0.2.1"
                })
                .as_object()
                .unwrap()
                .clone(),
            );
        }
        Request::new(
            self.uid("Account"),
            format!("Action::\"{action}\"").parse().unwrap(),
            self.uid(kind),
            Context::from_json_value(context, None).unwrap(),
            None,
        )
        .unwrap()
    }

    fn authorizer(&self, source: &str) -> OrganizationAuthorizer {
        OrganizationAuthorizer::new(self.id("Organization"), &PolicySet::from_str(source).unwrap())
            .unwrap()
    }

    fn grant(&self, until: Option<u64>) -> OrganizationHostGrant {
        OrganizationHostGrant {
            id: GRANT.parse().unwrap(),
            organization: self.id("Organization"),
            fields: GrantFields {
                membership: self.id("Membership"),
                host: self.id("Host"),
                remote_user: "operator".into(),
                valid_from: 100,
                valid_until: until,
            },
        }
    }

    fn decide(
        &self,
        now: i64,
        source: &str,
        grants: &[OrganizationHostGrant],
    ) -> Result<Connect, Error> {
        self.authorizer(source).authorize_connect(
            &self.trusted(now),
            &self.request(now, "operator", "connect", "Host"),
            &self.entities(),
            grants,
        )
    }
}

#[test]
fn exclusive_interval_is_evaluated_by_the_public_shared_authorizer() {
    let f = Fixture::new();
    let grants = [f.grant(Some(400))];
    for (now, expected) in [
        (99, Connect::Deny),
        (100, Connect::Allow { not_after: Some(400) }),
        (399, Connect::Allow { not_after: Some(400) }),
        (400, Connect::Deny),
    ] {
        assert_eq!(f.decide(now, "", &grants), Ok(expected), "now={now}");
    }
    assert_eq!(f.decide(100, "", &[]), Ok(Connect::Deny));
}

#[test]
fn grant_alternatives_use_the_latest_expiry_without_unrelated_extension() {
    let f = Fixture::new();
    let short = f.grant(Some(400));
    let mut long = f.grant(Some(1_000));
    long.id = OTHER.parse().unwrap();
    assert_eq!(
        f.decide(100, "", &[short.clone(), long.clone()]),
        Ok(Connect::Allow { not_after: Some(1_000) })
    );
    long.fields.valid_from = 200;
    assert_eq!(
        f.decide(100, "", &[short.clone(), long.clone()]),
        Ok(Connect::Allow { not_after: Some(400) })
    );
    long.fields.valid_from = 100;
    long.fields.membership = OTHER.parse().unwrap();
    assert_eq!(
        f.decide(100, "", &[short.clone(), long.clone()]),
        Ok(Connect::Allow { not_after: Some(400) })
    );
    long.fields.membership = f.id("Membership");
    long.fields.host = OTHER.parse().unwrap();
    assert_eq!(f.decide(100, "", &[short, long]), Ok(Connect::Allow { not_after: Some(400) }));
}

#[test]
fn nonexpiring_and_independent_ordinary_permits_keep_their_ordinary_lifetime() {
    let mut f = Fixture::new();
    let mut nonexpiring = f.grant(None);
    nonexpiring.id = OTHER.parse().unwrap();
    assert_eq!(
        f.decide(100, "", &[f.grant(Some(400)), nonexpiring]),
        Ok(Connect::Allow { not_after: None })
    );
    assert_eq!(
        f.decide(100, PERMIT, &[f.grant(Some(400))]),
        Ok(Connect::Allow { not_after: None })
    );
    f.entity_mut("Membership")["attrs"]["roles"] = json!(["owner"]);
    assert_eq!(f.decide(100, "", &[f.grant(Some(400))]), Ok(Connect::Allow { not_after: None }));
}

#[test]
fn explicit_forbids_and_any_evaluation_error_still_prohibit_issuance() {
    let f = Fixture::new();
    let grants = [f.grant(Some(400))];
    assert_eq!(
        f.decide(100, "forbid(principal, action == Action::\"connect\", resource);", &grants),
        Ok(Connect::Deny)
    );
    let overflow = "forbid(principal, action == Action::\"connect\", resource) when { context.now + 9223372036854775807 > 0 };";
    assert_eq!(f.decide(100, overflow, &grants), Err(Error::Evaluation));
}

#[test]
fn exact_remote_user_is_a_cedar_value_and_cannot_inject_policy_source() {
    let f = Fixture::new();
    let mut grant = f.grant(Some(400));
    grant.fields.remote_user = "ops\"; permit(principal, action, resource); //".into();
    let policies = grant.policy_set(f.id("Account")).unwrap();
    assert_eq!(policies.templates().count(), 1);
    assert_eq!(policies.policies().count(), 1);
    assert_eq!(f.decide(100, "", &[grant.clone()]), Ok(Connect::Deny));
    let authorizer = f.authorizer("");
    assert_eq!(
        authorizer.authorize_connect(
            &f.trusted(100),
            &f.request(100, &grant.fields.remote_user, "connect", "Host"),
            &f.entities(),
            &[grant.clone()]
        ),
        Ok(Connect::Allow { not_after: Some(400) })
    );
    assert_eq!(
        authorizer.authorize_connect(
            &f.trusted(100),
            &f.request(100, "OPERATOR", "connect", "Host"),
            &f.entities(),
            &[f.grant(Some(400))]
        ),
        Ok(Connect::Deny)
    );
}

#[test]
fn current_identity_device_and_tenant_guards_cannot_be_bypassed_by_a_grant() {
    for (kind, attribute, value) in [
        ("Account", "status", json!("suspended")),
        ("Membership", "status", json!("removed")),
        (
            "Device",
            "account",
            json!({"__entity": {"type": "Account", "id": "019a0000-0000-7000-8000-000000000002"}}),
        ),
    ] {
        let mut f = Fixture::new();
        f.entity_mut(kind)["attrs"][attribute] = value;
        assert!(f.decide(100, PERMIT, &[f.grant(Some(400))]).is_err(), "{kind}.{attribute}");
    }
    let f = Fixture::new();
    let mut foreign = f.grant(Some(400));
    foreign.organization = OTHER.parse().unwrap();
    assert_eq!(f.decide(100, PERMIT, &[foreign]), Err(Error::BoundaryViolation));
    let mut invalid = f.grant(Some(400));
    invalid.fields.valid_until = Some(100);
    assert_eq!(f.decide(100, PERMIT, &[invalid]), Err(Error::InvalidConfiguration));
}

#[test]
fn grants_supply_neither_visibility_nor_a_host_group_principal() {
    let f = Fixture::new();
    let authorizer = f.authorizer("");
    assert_eq!(
        authorizer.authorize(
            &f.trusted(100),
            &f.request(100, "operator", "view_inventory", "Host"),
            &f.entities()
        ),
        Ok(Decision::Deny)
    );
    for (action, kind) in [("view_inventory", "Host"), ("connect", "HostGroup")] {
        assert_eq!(
            authorizer.authorize_connect(
                &f.trusted(100),
                &f.request(100, "operator", action, kind),
                &f.entities(),
                &[f.grant(Some(400))]
            ),
            Err(Error::InvalidRequest)
        );
    }
}

#[test]
fn colliding_custom_policy_ids_keep_their_own_authority_and_grant_cutoff() {
    let f = Fixture::new();
    let grant = f.grant(Some(400));
    let mut custom = PolicySet::new();
    custom
        .add(
            Policy::parse(
                Some(PolicyId::new(format!("grant-{}", grant.id))),
                "permit(principal, action == Action::\"connect\", resource) when { false };",
            )
            .unwrap(),
        )
        .unwrap();
    let authorizer = OrganizationAuthorizer::new(f.id("Organization"), &custom).unwrap();
    assert_eq!(
        authorizer.authorize_connect(
            &f.trusted(100),
            &f.request(100, "operator", "connect", "Host"),
            &f.entities(),
            &[grant]
        ),
        Ok(Connect::Allow { not_after: Some(400) })
    );
    let grant = f.grant(Some(400));
    let ordinary = grant.policy_set(f.id("Account")).unwrap();
    let authorizer = OrganizationAuthorizer::new(f.id("Organization"), &ordinary).unwrap();
    assert_eq!(
        authorizer.authorize_connect(
            &f.trusted(100),
            &f.request(100, "operator", "connect", "Host"),
            &f.entities(),
            &[grant]
        ),
        Ok(Connect::Allow { not_after: None })
    );
}

#[test]
fn every_explicit_host_keeps_its_own_cutoff_for_the_consumer_minimum() {
    let mut f = Fixture::new();
    let mut host = f.entity_mut("Host").clone();
    host["uid"]["id"] = json!(OTHER);
    f.0["entities"].as_array_mut().unwrap().push(host);
    let first = f.grant(Some(400));
    let mut second = f.grant(Some(700));
    second.id = "019a0000-0000-7000-8000-000000000203".parse().unwrap();
    second.fields.host = OTHER.parse().unwrap();
    let authorizer = f.authorizer("");
    let grants = [first, second];
    let mut bounds = Vec::new();
    for host_id in [f.id("Host"), OTHER.parse().unwrap()] {
        f.0["ids"]["Host"] = json!(host_id.to_string());
        let decision = authorizer
            .authorize_connect(
                &f.trusted(100),
                &f.request(100, "operator", "connect", "Host"),
                &f.entities(),
                &grants,
            )
            .unwrap();
        let Connect::Allow { not_after: Some(bound) } = decision else {
            panic!("finite Host permit")
        };
        bounds.push(bound);
    }
    assert_eq!(bounds, [400, 700]);
    assert_eq!(bounds.into_iter().min(), Some(400));
}
