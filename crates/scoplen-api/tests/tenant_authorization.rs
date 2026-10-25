// SPDX-License-Identifier: Apache-2.0

use std::{collections::HashMap, str::FromStr};

use cedar_policy::{
    Authorizer, Context, Decision, Entities, EntityUid, PolicyId, PolicySet, Request, Schema,
    SlotId, Template,
};
use scoplen_api::control_plane::{
    BUILT_IN_POLICIES, CEDAR_SCHEMA, OrganizationAuthorizationContext,
    OrganizationAuthorizationError as Error, OrganizationAuthorizer,
};
use serde_json::{Value, json};
use uuid::Uuid;

const PERMIT_ALL: &str = "permit(principal, action, resource);";
const FOREIGN_ID: &str = "019a0000-0000-7000-8000-000000000999";

#[derive(Clone)]
struct Fixture(Value);

impl Fixture {
    fn new() -> Self {
        Self(
            serde_json::from_str(include_str!("fixtures/tenant-authorization.json"))
                .expect("fixture"),
        )
    }

    fn id(&self, kind: &str) -> &str {
        self.0["ids"][kind].as_str().expect("fixture id")
    }

    fn uuid(&self, kind: &str) -> Uuid {
        self.id(kind).parse().expect("UUIDv7")
    }

    fn uid(&self, kind: &str) -> EntityUid {
        format!("{kind}::\"{}\"", self.id(kind)).parse().expect("entity uid")
    }

    fn entity_mut(&mut self, kind: &str) -> &mut Value {
        self.0["entities"]
            .as_array_mut()
            .expect("entity array")
            .iter_mut()
            .find(|entity| entity["uid"]["type"] == kind)
            .expect("fixture entity")
    }

    fn remove(&mut self, kind: &str) {
        let id = self.id(kind).to_owned();
        self.0["entities"]
            .as_array_mut()
            .expect("entity array")
            .retain(|entity| entity["uid"]["id"] != id);
    }

    fn entities(&self) -> Entities {
        // Deliberately omit the schema: the public boundary must revalidate it.
        Entities::from_json_value(self.0["entities"].clone(), None).expect("raw entities")
    }

    fn trusted(&self, now: i64) -> OrganizationAuthorizationContext {
        OrganizationAuthorizationContext::new(
            self.uuid("Account"),
            self.uuid("Organization"),
            self.uuid("Membership"),
            now,
        )
        .expect("trusted context")
    }

    fn context(&self, action: &str) -> Value {
        let mut context = json!({
            "organization": entity_ref("Organization", self.id("Organization")),
            "membership": entity_ref("Membership", self.id("Membership")),
            "now": 1,
        });
        let extra = match action {
            "connect" => json!({
                "device": entity_ref("Device", self.id("Device")),
                "remote_user": "operator", "route_kind": "direct",
                "sso_age_seconds": 0, "source_ip": "192.0.2.1",
            }),
            "request_access" => json!({"duration_seconds": 300, "reason": "Maintenance"}),
            "approve_access" => json!({
                "requester": entity_ref("Account", self.id("OtherAccount")),
                "resource": entity_ref("Host", self.id("Host")),
            }),
            "view_recording" | "monitor_session" | "terminate_session" => json!({
                "host": entity_ref("Host", self.id("Host")),
                "account": entity_ref("Account", self.id("OtherAccount")),
            }),
            _ => json!({}),
        };
        context
            .as_object_mut()
            .expect("context map")
            .extend(extra.as_object().expect("extra map").clone());
        context
    }

    fn request(&self, action: &str, resource_kind: &str) -> Request {
        self.request_with(action, resource_kind, self.context(action))
    }

    fn request_with(&self, action: &str, resource_kind: &str, context: Value) -> Request {
        Request::new(
            self.uid("Account"),
            format!("Action::\"{action}\"").parse().expect("action"),
            self.uid(resource_kind),
            Context::from_json_value(context, None).expect("raw context"),
            None,
        )
        .expect("raw request")
    }

    fn authorizer(&self, custom: &str) -> OrganizationAuthorizer {
        OrganizationAuthorizer::new(
            self.uuid("Organization"),
            &custom.parse().expect("custom policy"),
        )
        .expect("validated policies")
    }

    fn decide(&self, custom: &str, action: &str, resource: &str) -> Result<Decision, Error> {
        self.authorizer(custom).authorize(
            &self.trusted(1),
            &self.request(action, resource),
            &self.entities(),
        )
    }

    fn role(&mut self, role: &str) {
        self.entity_mut("Membership")["attrs"]["roles"] = json!([role]);
    }
}

fn entity_ref(kind: &str, id: &str) -> Value {
    json!({"__entity": {"type": kind, "id": id}})
}

#[test]
fn public_fixture_covers_every_role_action_and_inventory_type() {
    let base = Fixture::new();
    assert_eq!(base.0["version"], 1);
    let actions = base.0["role_actions"]["owner"].as_array().expect("owner actions");
    assert_eq!(actions.len(), 13);
    for (role, allowed) in base.0["role_actions"].as_object().expect("roles") {
        let mut fixture = base.clone();
        fixture.role(role);
        let authorizer = fixture.authorizer("");
        let entities = fixture.entities();
        for action in actions {
            let action = action.as_str().expect("action");
            let resource = match action {
                "view_inventory" | "connect" | "request_access" => "Host",
                "approve_access" => "AccessRequest",
                "view_recording" | "monitor_session" | "terminate_session" => "Session",
                _ => "Organization",
            };
            let expected = if allowed.as_array().expect("allowed actions").contains(&json!(action))
            {
                Decision::Allow
            } else {
                Decision::Deny
            };
            assert_eq!(
                authorizer.authorize(
                    &fixture.trusted(1),
                    &fixture.request(action, resource),
                    &entities
                ),
                Ok(expected),
                "{role}: {action}"
            );
        }
        let inventory = base.0["inventory_types"].as_array().expect("inventory types");
        assert_eq!(inventory.len(), 7);
        for resource in inventory {
            let resource = resource.as_str().expect("inventory type");
            let expected =
                if ["owner", "administrator", "security_auditor"].contains(&role.as_str()) {
                    Decision::Allow
                } else {
                    Decision::Deny
                };
            assert_eq!(
                authorizer.authorize(
                    &fixture.trusted(1),
                    &fixture.request("view_inventory", resource),
                    &entities
                ),
                Ok(expected),
                "{role}: {resource}"
            );
        }
        let expected = if role == "owner" { Decision::Allow } else { Decision::Deny };
        assert_eq!(
            authorizer.authorize(
                &fixture.trusted(1),
                &fixture.request("request_access", "HostGroup"),
                &entities
            ),
            Ok(expected)
        );
    }
}

#[test]
fn member_requires_explicit_scoped_read_and_independent_operation_permission() {
    let mut fixture = Fixture::new();
    fixture.role("member");
    // The hydrated Group is literally named owner, but names grant no role.
    assert_eq!(fixture.decide("", "view_inventory", "Host"), Ok(Decision::Deny));
    let read = format!(
        r#"permit(principal, action == Action::"view_inventory", resource == {});"#,
        fixture.uid("Host")
    );
    assert_eq!(fixture.decide(&read, "view_inventory", "Host"), Ok(Decision::Allow));
    assert_eq!(fixture.decide(&read, "view_inventory", "HostGroup"), Ok(Decision::Deny));
    assert_eq!(fixture.decide(&read, "connect", "Host"), Ok(Decision::Deny));
    let connect = r#"permit(principal, action == Action::"connect", resource);"#;
    assert_eq!(fixture.decide(connect, "connect", "Host"), Ok(Decision::Allow));
    assert_eq!(fixture.decide(connect, "view_inventory", "Host"), Ok(Decision::Deny));
}

#[test]
fn public_negative_vectors_cannot_be_overridden_by_permit_all() {
    let base = Fixture::new();
    for case in base.0["invalid_attribute_cases"].as_array().expect("negative cases") {
        let mut fixture = base.clone();
        let kind = case["entity"].as_str().expect("entity");
        let attribute = case["attribute"].as_str().expect("attribute");
        fixture.entity_mut(kind)["attrs"][attribute] = case["value"].clone();
        assert!(fixture.decide(PERMIT_ALL, "view_inventory", "Host").is_err(), "{case}");
    }
}

#[test]
fn trusted_identity_owner_membership_and_time_cannot_be_replaced_by_request_context() {
    let fixture = Fixture::new();
    let authorizer = fixture.authorizer(PERMIT_ALL);
    for (name, value) in [
        ("organization", entity_ref("Organization", FOREIGN_ID)),
        ("membership", entity_ref("Membership", FOREIGN_ID)),
        ("now", json!(2)),
    ] {
        let mut context = fixture.context("view_inventory");
        context[name] = value;
        let request = fixture.request_with("view_inventory", "Host", context);
        assert_eq!(
            authorizer.authorize(&fixture.trusted(1), &request, &fixture.entities()),
            Err(Error::BoundaryViolation)
        );
    }
    let other = OrganizationAuthorizationContext::new(
        fixture.uuid("OtherAccount"),
        fixture.uuid("Organization"),
        fixture.uuid("Membership"),
        1,
    )
    .expect("other Account context");
    assert_eq!(
        authorizer.authorize(
            &other,
            &fixture.request("view_inventory", "Host"),
            &fixture.entities()
        ),
        Err(Error::BoundaryViolation)
    );
    let foreign_owner = OrganizationAuthorizer::new(
        FOREIGN_ID.parse().expect("foreign org"),
        &PERMIT_ALL.parse().expect("policy"),
    )
    .expect("other org authorizer");
    assert_eq!(
        foreign_owner.authorize(
            &fixture.trusted(1),
            &fixture.request("view_inventory", "Host"),
            &fixture.entities()
        ),
        Err(Error::BoundaryViolation)
    );
}

#[test]
fn ownership_of_every_loaded_tenant_entity_is_mandatory_even_when_unused_by_policy() {
    for kind in [
        "Membership",
        "Group",
        "HostGroup",
        "GatewayNetwork",
        "Host",
        "AccessProfile",
        "Route",
        "Snippet",
        "TrustRecord",
        "AccessRequest",
        "Session",
    ] {
        let mut fixture = Fixture::new();
        fixture.entity_mut(kind)["attrs"]["organization"] = entity_ref("Organization", FOREIGN_ID);
        assert_eq!(
            fixture.decide(PERMIT_ALL, "view_inventory", "Host"),
            Err(Error::BoundaryViolation),
            "{kind}"
        );
    }
}

#[test]
fn every_related_entity_must_be_hydrated_in_the_selected_organization() {
    for (kind, attribute, target, set) in [
        ("Membership", "groups", "Group", true),
        ("Host", "host_groups", "HostGroup", true),
        ("Host", "gateway_network", "GatewayNetwork", false),
        ("HostGroup", "parents", "HostGroup", true),
        ("AccessProfile", "host", "Host", false),
        ("TrustRecord", "host", "Host", false),
        ("AccessRequest", "resource", "Host", false),
        ("AccessRequest", "requester", "Account", false),
        ("Session", "host", "Host", false),
        ("Session", "account", "Account", false),
        ("Device", "account", "Account", false),
    ] {
        let mut fixture = Fixture::new();
        let value = entity_ref(target, FOREIGN_ID);
        fixture.entity_mut(kind)["attrs"][attribute] = if set { json!([value]) } else { value };
        assert!(
            fixture.decide(PERMIT_ALL, "view_inventory", "Host").is_err(),
            "{kind}.{attribute}"
        );
    }
    for kind in ["Account", "Organization", "Membership", "Group", "HostGroup", "Host"] {
        let mut fixture = Fixture::new();
        fixture.remove(kind);
        assert!(fixture.decide(PERMIT_ALL, "view_inventory", "Host").is_err(), "missing {kind}");
    }
}

#[test]
fn optional_direct_host_gateway_and_trust_host_use_absence_without_a_sentinel() {
    let mut fixture = Fixture::new();
    assert_eq!(fixture.decide("", "view_inventory", "Host"), Ok(Decision::Allow));
    assert_eq!(fixture.decide("", "view_inventory", "TrustRecord"), Ok(Decision::Allow));
    let gateway = entity_ref("GatewayNetwork", fixture.id("GatewayNetwork"));
    fixture.entity_mut("Host")["attrs"]["gateway_network"] = gateway;
    let host = entity_ref("Host", fixture.id("Host"));
    fixture.entity_mut("TrustRecord")["attrs"]["host"] = host;
    assert_eq!(fixture.decide("", "view_inventory", "TrustRecord"), Ok(Decision::Allow));
    fixture.remove("GatewayNetwork");
    assert!(fixture.decide(PERMIT_ALL, "view_inventory", "Host").is_err());
}

#[test]
fn connect_device_and_action_specific_resource_projections_are_bound() {
    let mut fixture = Fixture::new();
    let other = entity_ref("Account", fixture.id("OtherAccount"));
    fixture.entity_mut("Device")["attrs"]["account"] = other;
    assert_eq!(fixture.decide(PERMIT_ALL, "connect", "Host"), Err(Error::BoundaryViolation));
    let fixture = Fixture::new();
    let authorizer = fixture.authorizer(PERMIT_ALL);
    for (action, kind, name, target) in [
        ("approve_access", "AccessRequest", "requester", "Account"),
        ("approve_access", "AccessRequest", "resource", "Host"),
        ("view_recording", "Session", "host", "Host"),
        ("monitor_session", "Session", "account", "Account"),
        ("terminate_session", "Session", "host", "Host"),
    ] {
        let mut context = fixture.context(action);
        context[name] = entity_ref(target, FOREIGN_ID);
        assert_eq!(
            authorizer.authorize(
                &fixture.trusted(1),
                &fixture.request_with(action, kind, context),
                &fixture.entities()
            ),
            Err(Error::BoundaryViolation)
        );
    }
    let mut missing_device = fixture.clone();
    missing_device.remove("Device");
    assert_eq!(missing_device.decide(PERMIT_ALL, "connect", "Host"), Err(Error::BoundaryViolation));
}

#[test]
fn cross_tenant_role_union_cannot_widen_a_members_authority() {
    let owner = Fixture::new();
    let second_id = "019a0000-0000-7000-8000-000000000011";
    let mut member = Fixture(
        serde_json::from_str(
            &serde_json::to_string(&owner.0)
                .expect("fixture JSON")
                .replace(owner.id("Organization"), second_id),
        )
        .expect("second Organization"),
    );
    member.role("member");
    assert_eq!(owner.decide("", "manage_members", "Organization"), Ok(Decision::Allow));
    assert_eq!(member.decide("", "manage_members", "Organization"), Ok(Decision::Deny));
    let mut foreign_membership = owner.0["entities"]
        .as_array()
        .expect("entities")
        .iter()
        .find(|entity| entity["uid"]["type"] == "Membership")
        .expect("owner membership")
        .clone();
    foreign_membership["uid"]["id"] = json!(FOREIGN_ID);
    member.0["entities"].as_array_mut().expect("entities").push(foreign_membership);
    // A global union containing the other team's Owner membership is invalid.
    assert!(member.decide(PERMIT_ALL, "manage_members", "Organization").is_err());
}

#[test]
fn unknown_retired_and_wrong_type_actions_fail_before_custom_permits() {
    let fixture = Fixture::new();
    for (action, resource) in [
        ("future_action", "Host"),
        ("issuePersonalInvitation", "Organization"),
        ("view_inventory", "Organization"),
        ("connect", "Snippet"),
        ("manage_inventory", "Host"),
    ] {
        assert_eq!(
            fixture.decide(PERMIT_ALL, action, resource),
            Err(Error::InvalidRequest),
            "{action}:{resource}"
        );
    }
    let raw = Request::new(
        format!("Operator::\"{}\"", fixture.id("Account")).parse().expect("Operator"),
        r#"Action::"view_inventory""#.parse().expect("action"),
        fixture.uid("Host"),
        Context::from_json_value(fixture.context("view_inventory"), None).expect("context"),
        None,
    )
    .expect("unvalidated request");
    assert_eq!(
        fixture.authorizer(PERMIT_ALL).authorize(&fixture.trusted(1), &raw, &fixture.entities()),
        Err(Error::BoundaryViolation)
    );
}

#[test]
fn incomplete_corrupt_noncanonical_or_legacy_entities_fail_closed() {
    for (kind, attribute) in
        [("Host", "organization"), ("Membership", "roles"), ("Account", "status")]
    {
        let mut fixture = Fixture::new();
        fixture.entity_mut(kind)["attrs"].as_object_mut().expect("attrs").remove(attribute);
        assert_eq!(
            fixture.decide(PERMIT_ALL, "view_inventory", "Host"),
            Err(Error::InvalidEntities)
        );
    }
    let mut legacy = Fixture::new();
    legacy.entity_mut("Account")["attrs"]["groups"] = json!([]);
    assert_eq!(legacy.decide(PERMIT_ALL, "view_inventory", "Host"), Err(Error::InvalidEntities));
    for invalid in
        ["owner", "019a0000-0000-4000-8000-000000000030", "019A0000-0000-7000-8000-000000000030"]
    {
        let mut fixture = Fixture::new();
        fixture.entity_mut("Route")["uid"]["id"] = json!(invalid);
        assert_eq!(
            fixture.decide(PERMIT_ALL, "view_inventory", "Host"),
            Err(Error::InvalidEntities)
        );
    }
    let mut duplicate = Fixture::new();
    let mut member = duplicate.entity_mut("Membership").clone();
    member["uid"]["id"] = json!(FOREIGN_ID);
    duplicate.0["entities"].as_array_mut().expect("entities").push(member);
    assert_eq!(duplicate.decide(PERMIT_ALL, "view_inventory", "Host"), Err(Error::InvalidEntities));
    let mut inherited = Fixture::new();
    let parent = json!([{"type": "Group", "id": inherited.id("Group")}]);
    inherited.entity_mut("Account")["parents"] = parent;
    assert_eq!(inherited.decide(PERMIT_ALL, "view_inventory", "Host"), Err(Error::InvalidEntities));
}

#[test]
fn any_evaluation_error_denies_even_when_another_policy_allows() {
    let fixture = Fixture::new();
    let policies = "permit(principal, action, resource); permit(principal, action, resource) when { context.now + 1 > 0 };";
    let mut context = fixture.context("view_inventory");
    context["now"] = json!(i64::MAX);
    let request = fixture.request_with("view_inventory", "Host", context);
    // Cedar's ordinary response can Allow while retaining an arithmetic error.
    let schema = Schema::from_str(CEDAR_SCHEMA).expect("schema");
    let entities =
        Entities::from_json_value(fixture.0["entities"].clone(), Some(&schema)).expect("entities");
    let response =
        Authorizer::new().is_authorized(&request, &policies.parse().expect("policies"), &entities);
    assert_eq!(response.decision(), Decision::Allow);
    assert_eq!(response.diagnostics().errors().count(), 1);
    assert_eq!(
        fixture.authorizer(policies).authorize(&fixture.trusted(i64::MAX), &request, &entities),
        Err(Error::Evaluation)
    );
}

#[test]
fn missing_guard_entity_cannot_turn_an_errored_forbid_into_authority() {
    let mut fixture = Fixture::new();
    fixture.remove("Membership");
    let schema = Schema::from_str(CEDAR_SCHEMA).expect("schema");
    let entities = Entities::from_json_value(fixture.0["entities"].clone(), Some(&schema))
        .expect("typed graph with missing dependency");
    let mut policies = PolicySet::from_str(BUILT_IN_POLICIES).expect("guards");
    policies.merge(&PERMIT_ALL.parse().expect("custom permit"), true).expect("merge");
    let response = Authorizer::new().is_authorized(
        &fixture.request("view_inventory", "Host"),
        &policies,
        &entities,
    );
    assert_eq!(response.decision(), Decision::Allow);
    assert!(response.diagnostics().errors().next().is_some());
    assert_eq!(fixture.decide(PERMIT_ALL, "view_inventory", "Host"), Err(Error::BoundaryViolation));
}

#[test]
fn historical_session_account_is_attribution_and_does_not_need_current_membership() {
    let mut fixture = Fixture::new();
    fixture.role("security_auditor");
    let other_id = fixture.id("OtherAccount").to_owned();
    let account = fixture.0["entities"]
        .as_array_mut()
        .expect("entities")
        .iter_mut()
        .find(|entity| entity["uid"]["id"] == other_id)
        .expect("historical Account");
    account["attrs"]["status"] = json!("inactive");
    assert_eq!(fixture.decide("", "view_recording", "Session"), Ok(Decision::Allow));
    assert_eq!(fixture.decide("", "terminate_session", "Session"), Ok(Decision::Deny));
}

#[test]
fn immutable_cedar_forbids_also_deny_direct_permit_all_binding_attempts() {
    let fixture = Fixture::new();
    let schema = Schema::from_str(CEDAR_SCHEMA).expect("schema");
    let mut policies = PolicySet::from_str(BUILT_IN_POLICIES).expect("built-ins");
    policies.merge(&PERMIT_ALL.parse().expect("custom permit"), true).expect("merge");
    for (kind, attribute, value) in [
        ("Account", "status", json!("inactive")),
        ("Membership", "status", json!("inactive")),
        ("Membership", "account", entity_ref("Account", fixture.id("OtherAccount"))),
        ("Membership", "organization", entity_ref("Organization", FOREIGN_ID)),
        ("Host", "organization", entity_ref("Organization", FOREIGN_ID)),
    ] {
        let mut changed = fixture.clone();
        changed.entity_mut(kind)["attrs"][attribute] = value;
        let entities = Entities::from_json_value(changed.0["entities"].clone(), Some(&schema))
            .expect("typed entities");
        let response = Authorizer::new().is_authorized(
            &changed.request("view_inventory", "Host"),
            &policies,
            &entities,
        );
        assert_eq!(response.decision(), Decision::Deny, "{kind}.{attribute}");
    }
}

#[test]
fn guarded_optional_email_is_valid_without_invented_empty_email() {
    let mut fixture = Fixture::new();
    fixture.role("member");
    let guarded = r#"permit(principal, action == Action::"view_inventory", resource) when { principal has email && principal.email == "reader@example.test" };"#;
    assert_eq!(fixture.decide(guarded, "view_inventory", "Host"), Ok(Decision::Deny));
    fixture.entity_mut("Account")["attrs"]["email"] = json!("reader@example.test");
    assert_eq!(fixture.decide(guarded, "view_inventory", "Host"), Ok(Decision::Allow));
    let unguarded = r#"permit(principal, action == Action::"view_inventory", resource) when { principal.email == "reader@example.test" };"#;
    assert!(matches!(
        OrganizationAuthorizer::new(
            fixture.uuid("Organization"),
            &unguarded.parse().expect("policy")
        ),
        Err(Error::InvalidConfiguration)
    ));
}

#[test]
fn linked_grants_and_colliding_custom_policy_ids_are_preserved() {
    let mut fixture = Fixture::new();
    fixture.role("member");
    let mut custom = PolicySet::new();
    custom.add_template(Template::parse(Some(PolicyId::new("policy0")),
        r#"permit(principal == ?principal, action == Action::"view_inventory", resource == ?resource);"#).expect("template"))
        .expect("add template");
    custom
        .link(
            PolicyId::new("policy0"),
            PolicyId::new("policy1"),
            HashMap::from([
                (SlotId::principal(), fixture.uid("Account")),
                (SlotId::resource(), fixture.uid("Host")),
            ]),
        )
        .expect("link template");
    let authorizer = OrganizationAuthorizer::new(fixture.uuid("Organization"), &custom)
        .expect("combined policies");
    assert_eq!(
        authorizer.authorize(
            &fixture.trusted(1),
            &fixture.request("view_inventory", "Host"),
            &fixture.entities()
        ),
        Ok(Decision::Allow)
    );
    assert_eq!(
        authorizer.authorize(
            &fixture.trusted(1),
            &fixture.request("view_inventory", "Snippet"),
            &fixture.entities()
        ),
        Ok(Decision::Deny)
    );
    fixture.entity_mut("Membership")["attrs"]["status"] = json!("inactive");
    assert_eq!(
        authorizer.authorize(
            &fixture.trusted(1),
            &fixture.request("view_inventory", "Host"),
            &fixture.entities()
        ),
        Err(Error::BoundaryViolation)
    );
}

#[test]
fn invalid_trusted_identifiers_and_time_are_rejected_without_sensitive_diagnostics() {
    let fixture = Fixture::new();
    let invalid: Uuid = "019a0000-0000-4000-8000-000000000001".parse().expect("UUIDv4");
    for (account, organization, membership, now) in [
        (invalid, fixture.uuid("Organization"), fixture.uuid("Membership"), 1),
        (fixture.uuid("Account"), invalid, fixture.uuid("Membership"), 1),
        (fixture.uuid("Account"), fixture.uuid("Organization"), invalid, 1),
        (fixture.uuid("Account"), fixture.uuid("Organization"), fixture.uuid("Membership"), -1),
    ] {
        let error = OrganizationAuthorizationContext::new(account, organization, membership, now)
            .expect_err("invalid context");
        assert_eq!(error, Error::InvalidContext);
        assert!(!error.to_string().contains(fixture.id("Account")));
    }
}
