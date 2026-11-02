// SPDX-License-Identifier: Apache-2.0

use std::str::FromStr;

use cedar_policy::{Context, Decision, Entities, EntityUid, PolicySet, Request};
use scoplen_api::{
    control_plane::{OrganizationAuthorizationContext, OrganizationAuthorizer},
    group_policy::{
        GroupCreateRequest, GroupFields, GroupPage, GroupReplaceRequest, GroupResource,
        GroupSource, MAX_GROUP_POLICY_BYTES, MAX_GROUP_POLICY_PAGE_BYTES, MAX_POLICY_SOURCE_BYTES,
        PolicyCreateRequest, PolicyFields, PolicyPage, PolicyReplaceRequest, PolicyResource,
        SimpleRule, SimpleRuleInput, SimpleRuleSelector, SimpleRuleSubject, parse_policy_source,
        policy_references,
    },
    organization::OrganizationListQuery,
};
use scoplen_model::ObjectType;
use serde_json::{Value, json};
use uuid::Uuid;

const SOURCE: &str = "permit(principal, action == Action::\"view_inventory\", resource);";
const TIME: &str = "2026-11-01T00:00:00Z";

fn id(number: u64) -> Uuid {
    format!("019bdad6-b800-7000-8000-{number:012}").parse().unwrap()
}

fn fields() -> GroupFields {
    GroupFields { name: "Operations".into(), members: vec![id(3), id(2)] }
}

fn group() -> GroupResource {
    GroupResource {
        id: id(4),
        etag: "\"current\"".into(),
        created_at: TIME.into(),
        updated_at: TIME.into(),
        fields: fields(),
        source: GroupSource::Local,
    }
}

fn policy() -> PolicyResource {
    PolicyResource {
        id: id(5),
        etag: "\"current\"".into(),
        created_at: TIME.into(),
        updated_at: TIME.into(),
        fields: PolicyFields { name: "Read hosts".into(), source: SOURCE.into(), enabled: true },
    }
}

#[test]
fn group_requests_are_strict_and_sorted_without_writable_source() {
    let create = GroupCreateRequest { id: id(4), fields: fields() };
    let bytes = create.to_json().unwrap();
    let canonical = GroupCreateRequest::from_json(&bytes).unwrap();
    assert_eq!(canonical.fields.members, vec![id(2), id(3)]);
    assert_eq!(canonical.to_json().unwrap(), bytes);
    let mut value: Value = serde_json::from_slice(&bytes).unwrap();
    value["data"]["source"] = json!("local");
    assert!(GroupCreateRequest::from_json(&serde_json::to_vec(&value).unwrap()).is_err());
    value["data"].as_object_mut().unwrap().remove("source");
    value["data"]["members"] = json!([id(2).to_string(), id(2).to_string()]);
    assert!(GroupCreateRequest::from_json(&serde_json::to_vec(&value).unwrap()).is_err());
    let replace =
        GroupReplaceRequest { fields: GroupFields { name: "Empty".into(), members: vec![] } };
    assert_eq!(GroupReplaceRequest::from_json(&replace.to_json().unwrap()).unwrap(), replace);
    let mut too_many = fields();
    too_many.members = (1..=4097).map(id).collect();
    assert!(too_many.validate().is_err());
    too_many.members.pop();
    too_many.validate().unwrap();
    for input in [
        b"{\"data\":{\"name\":\"a\",\"name\":\"b\",\"members\":[]}}".as_slice(),
        b"{\"data\":{\"name\":\" x\",\"members\":[]}}",
        b"{\"data\":{\"name\":\"x\",\"members\":null}}",
    ] {
        assert!(GroupReplaceRequest::from_json(input).is_err());
    }
    assert!(!format!("{create:?}").contains("Operations"));
}

#[test]
fn resource_and_page_metadata_bindings_extensions_and_original_item_budgets() {
    let mut item = group();
    item.fields.members.sort_unstable();
    let encoded = item.to_json().unwrap();
    assert_eq!(
        GroupResource::from_http_json(
            &encoded,
            Some("\"current\""),
            Some("no-store"),
            Some("no-cache")
        )
        .unwrap(),
        item
    );
    assert!(
        GroupResource::from_http_json(
            &encoded,
            Some("\"other\""),
            Some("no-store"),
            Some("no-cache")
        )
        .is_err()
    );
    item.validate_for_request(id(4)).unwrap();
    assert!(item.validate_for_request(id(5)).is_err());
    let mut extended: Value = serde_json::from_slice(&encoded).unwrap();
    extended["future"] = json!({"version":2});
    extended["data"]["future"] = json!(true);
    assert_eq!(GroupResource::from_json(&serde_json::to_vec(&extended).unwrap()).unwrap(), item);
    let page = GroupPage { items: vec![item.clone()], next_cursor: Some(item.id) };
    assert_eq!(GroupPage::from_json(&page.to_json().unwrap()).unwrap(), page);
    page.validate_for_query(OrganizationListQuery { limit: 1, cursor: Some(id(3)) }).unwrap();
    assert!(
        page.validate_for_query(OrganizationListQuery { limit: 1, cursor: Some(id(4)) }).is_err()
    );
    assert!(GroupPage { items: vec![item.clone(), item], next_cursor: None }.to_json().is_err());
    let item = format!(
        "{{\"future\":\"{}\",{}",
        "x".repeat(MAX_GROUP_POLICY_BYTES),
        std::str::from_utf8(&encoded).unwrap().trim_start_matches('{')
    );
    let page = format!("{{\"items\":[{item}],\"next_cursor\":null}}");
    assert!(page.len() < MAX_GROUP_POLICY_PAGE_BYTES);
    assert!(GroupPage::from_json(page.as_bytes()).is_err());
    let read_only = GroupResource { source: GroupSource::Idp, ..group() };
    assert_eq!(
        GroupResource::from_json(&read_only.to_json().unwrap()).unwrap().source,
        GroupSource::Idp
    );
}

#[test]
fn exact_complete_request_resource_page_and_policy_source_bounds() {
    let create = GroupCreateRequest { id: id(4), fields: fields() }.to_json().unwrap();
    for extra in [0, 1] {
        let mut input = vec![b' '; MAX_GROUP_POLICY_BYTES + extra - create.len()];
        input.extend_from_slice(&create);
        assert_eq!(GroupCreateRequest::from_json(&input).is_ok(), extra == 0);
    }
    let resource = group().to_json().unwrap();
    for extra in [0, 1] {
        let mut input = vec![b' '; MAX_GROUP_POLICY_BYTES + extra - resource.len()];
        input.extend_from_slice(&resource);
        assert_eq!(GroupResource::from_json(&input).is_ok(), extra == 0);
    }
    let page = GroupPage { items: vec![], next_cursor: None }.to_json().unwrap();
    for extra in [0, 1] {
        let mut input = vec![b' '; MAX_GROUP_POLICY_PAGE_BYTES + extra - page.len()];
        input.extend_from_slice(&page);
        assert_eq!(GroupPage::from_json(&input).is_ok(), extra == 0);
    }
    let mut source = format!("{SOURCE}\n//");
    source.push_str(&"x".repeat(MAX_POLICY_SOURCE_BYTES - source.len()));
    parse_policy_source(&source).unwrap();
    source.push('x');
    assert!(parse_policy_source(&source).is_err());
    let data = PolicyFields { name: "Too large".into(), source, enabled: false };
    assert!(PolicyReplaceRequest { fields: data }.to_json().is_err());
}

#[test]
fn policy_profile_uses_parsed_actions_and_expressions_including_forbids_and_sets() {
    for source in [
        "permit(principal, action == Action::\"view_inventory\", resource) when { context.now > 1 };",
        "forbid(principal, action == Action::\"view_inventory\", resource) unless { context[\"now\"] > 1 };",
        "permit(principal, action in [Action::\"connect\", Action::\"view_inventory\"], resource) when { context.now > 1 };",
        "forbid(principal, action, resource) when { context.now > 1 };",
        "permit(principal, action, resource) when { [Action::\"view_inventory\"].contains(action) && context.now > 1 };",
        "permit(principal, action == Action::\"view_inventory\", resource) when { context has now };",
        "permit(principal, action == Action::\"view_inventory\", resource) when { (if true then context else context).now > 1 };",
        "permit(principal, action == Action::\"view_inventory\", resource) when { context == context };",
    ] {
        assert!(parse_policy_source(source).is_err(), "{source}");
    }
    for source in [
        SOURCE,
        "permit(principal, action == Action::\"connect\", resource) when { context.now > 1 };",
        "forbid(principal, action in [Action::\"connect\"], resource) when { context.now > 1 };",
        "// context.now is prose\npermit(principal, action == Action::\"view_inventory\", resource);",
        "permit(principal, action == Action::\"view_inventory\", resource) when { \"context.now\" == \"context.now\" };",
        "permit(principal, action == Action::\"view_inventory\", resource) when { context.organization == context.membership.organization };",
    ] {
        parse_policy_source(source).unwrap_or_else(|_| panic!("legal source rejected: {source}"));
    }
    for source in [
        "",
        "permit(principal == ?principal, action, resource);",
        "permit(principal, action, resource); permit(principal, action, resource);",
        "permit(principal, action == Action::\"invented\", resource);",
        "permit(principal, action == Action::\"view_inventory\", resource) when { context.nonexistent };",
    ] {
        assert!(parse_policy_source(source).is_err(), "{source}");
    }
}

#[test]
fn policy_codecs_preserve_source_and_inspection_does_not_require_explicit_owner_literal() {
    let value = policy();
    let create = PolicyCreateRequest { id: value.id, fields: value.fields.clone() };
    assert_eq!(PolicyCreateRequest::from_json(&create.to_json().unwrap()).unwrap(), create);
    let replace = PolicyReplaceRequest { fields: value.fields.clone() };
    assert_eq!(PolicyReplaceRequest::from_json(&replace.to_json().unwrap()).unwrap(), replace);
    let bytes = value.to_json().unwrap();
    assert_eq!(
        PolicyResource::from_http_json(
            &bytes,
            Some("\"current\""),
            Some("no-store"),
            Some("no-cache")
        )
        .unwrap(),
        value
    );
    value.validate_for_request(id(1), value.id).unwrap();
    assert_eq!(policy_references(&parse_policy_source(SOURCE).unwrap(), id(1)).unwrap(), []);
    let source = format!(
        "permit(principal, action == Action::\"view_inventory\", resource == Host::\"{}\") when {{ context.organization == Organization::\"{}\" }};",
        id(9),
        id(1)
    );
    let parsed = parse_policy_source(&source).unwrap();
    let references = policy_references(&parsed, id(1)).unwrap();
    assert_eq!(references.len(), 2);
    assert!(policy_references(&parsed, id(2)).is_err());
    let source = "permit(principal, action == Action::\"view_inventory\", resource == Host::\"not-a-uuid\");";
    assert!(policy_references(&parse_policy_source(source).unwrap(), id(1)).is_err());
    assert!(!format!("{replace:?}").contains(SOURCE));
    let page = PolicyPage { items: vec![value], next_cursor: None };
    assert_eq!(PolicyPage::from_json(&page.to_json().unwrap()).unwrap(), page);
    assert!(PolicyPage::from_http_json(&page.to_json().unwrap(), None, Some("no-cache")).is_err());
}

fn simple(rule: SimpleRule) -> SimpleRuleInput {
    SimpleRuleInput { organization: id(1), subject: SimpleRuleSubject::Membership(id(2)), rule }
}

#[test]
fn generator_is_deterministic_sorted_escaped_and_rejects_invalid_inputs() {
    let value = simple(SimpleRule::View {
        resources: vec![
            SimpleRuleSelector { object_type: ObjectType::SNIPPET, id: id(6) },
            SimpleRuleSelector { object_type: ObjectType::HOST, id: id(5) },
        ],
    });
    let mut reversed = value.clone();
    let SimpleRule::View { resources } = &mut reversed.rule else { unreachable!() };
    resources.reverse();
    assert_eq!(value.generate().unwrap(), reversed.generate().unwrap());
    let encoded = value.to_json().unwrap();
    assert_eq!(
        SimpleRuleInput::from_json(&encoded).unwrap().generate().unwrap(),
        value.generate().unwrap()
    );
    let connect = simple(SimpleRule::Connect {
        hosts: vec![id(6), id(5)],
        host_groups: vec![id(7)],
        remote_user: "deploy\\\"\u{00e9}".into(),
    });
    let source = connect.generate().unwrap();
    assert!(source.contains("context.remote_user == \"deploy\\\\\\\"é\""));
    parse_policy_source(&source).unwrap();
    let cases = [
        SimpleRule::View { resources: vec![] },
        SimpleRule::View {
            resources: vec![SimpleRuleSelector { object_type: ObjectType::CREDENTIAL, id: id(3) }],
        },
        SimpleRule::View {
            resources: vec![SimpleRuleSelector { object_type: ObjectType::HOST, id: id(3) }; 2],
        },
        SimpleRule::Connect { hosts: vec![], host_groups: vec![], remote_user: "deploy".into() },
        SimpleRule::Connect {
            hosts: vec![id(3)],
            host_groups: vec![],
            remote_user: "bad\nuser".into(),
        },
    ];
    for rule in cases {
        assert!(simple(rule).generate().is_err());
    }
    let mut value: Value = serde_json::from_slice(&encoded).unwrap();
    value["group"] = json!(id(3).to_string());
    assert!(SimpleRuleInput::from_json(&serde_json::to_vec(&value).unwrap()).is_err());
    value.as_object_mut().unwrap().remove("group");
    value["view"][0]["type"] = json!(1.0);
    assert!(SimpleRuleInput::from_json(&serde_json::to_vec(&value).unwrap()).is_err());
    let maximum = simple(SimpleRule::Connect {
        hosts: (1..=64).map(id).collect(),
        host_groups: (65..=128).map(id).collect(),
        remote_user: "x".repeat(255),
    });
    assert!(maximum.generate().unwrap().len() <= MAX_POLICY_SOURCE_BYTES);
    assert!(
        simple(SimpleRule::Connect {
            hosts: (1..=65).map(id).collect(),
            host_groups: vec![],
            remote_user: "deploy".into()
        })
        .generate()
        .is_err()
    );
}

fn fixture() -> Value {
    serde_json::from_str(include_str!("fixtures/tenant-authorization.json")).unwrap()
}

fn fixture_uuid(fixture: &Value, name: &str) -> Uuid {
    fixture["ids"][name].as_str().unwrap().parse().unwrap()
}

fn fixture_uid(fixture: &Value, name: &str) -> EntityUid {
    format!("{name}::\"{}\"", fixture["ids"][name].as_str().unwrap()).parse().unwrap()
}

fn decide(fixture: &Value, source: &str, action: &str, resource: &str, user: &str) -> Decision {
    let reference = |name| json!({"__entity":{"type":name,"id":fixture["ids"][name]}});
    let mut context = json!({"organization":reference("Organization"), "membership":reference("Membership"), "now":1});
    if action == "connect" {
        context.as_object_mut().unwrap().extend(json!({"device":reference("Device"), "remote_user":user,"route_kind":"direct","sso_age_seconds":0,"source_ip":"192.0.2.1"}).as_object().unwrap().clone());
    }
    let request = Request::new(
        fixture_uid(fixture, "Account"),
        format!("Action::\"{action}\"").parse().unwrap(),
        fixture_uid(fixture, resource),
        Context::from_json_value(context, None).unwrap(),
        None,
    )
    .unwrap();
    let trusted = OrganizationAuthorizationContext::new(
        fixture_uuid(fixture, "Account"),
        fixture_uuid(fixture, "Organization"),
        fixture_uuid(fixture, "Membership"),
        1,
    )
    .unwrap();
    OrganizationAuthorizer::new(
        fixture_uuid(fixture, "Organization"),
        &PolicySet::from_str(source).unwrap(),
    )
    .unwrap()
    .authorize(
        &trusted,
        &request,
        &Entities::from_json_value(fixture["entities"].clone(), None).unwrap(),
    )
    .unwrap()
}

#[test]
fn generated_rules_authorize_real_member_group_and_host_group_contexts_independently() {
    let mut fixture = fixture();
    let membership = fixture["entities"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|entity| entity["uid"]["type"] == "Membership")
        .unwrap();
    membership["attrs"]["roles"] = json!(["member"]);
    let input = SimpleRuleInput {
        organization: fixture_uuid(&fixture, "Organization"),
        subject: SimpleRuleSubject::Membership(fixture_uuid(&fixture, "Membership")),
        rule: SimpleRule::View {
            resources: vec![SimpleRuleSelector {
                object_type: ObjectType::HOST,
                id: fixture_uuid(&fixture, "Host"),
            }],
        },
    };
    let view = input.generate().unwrap();
    assert_eq!(decide(&fixture, &view, "view_inventory", "Host", "operator"), Decision::Allow);
    assert_eq!(
        decide(&fixture, &view, "view_inventory", "AccessProfile", "operator"),
        Decision::Deny
    );
    assert_eq!(decide(&fixture, &view, "connect", "Host", "operator"), Decision::Deny);
    let connect = SimpleRuleInput {
        subject: SimpleRuleSubject::Group(fixture_uuid(&fixture, "Group")),
        rule: SimpleRule::Connect {
            hosts: vec![],
            host_groups: vec![fixture_uuid(&fixture, "HostGroup")],
            remote_user: "operator".into(),
        },
        ..input
    };
    let source = connect.generate().unwrap();
    assert_eq!(decide(&fixture, &source, "connect", "Host", "operator"), Decision::Allow);
    assert_eq!(decide(&fixture, &source, "connect", "Host", "root"), Decision::Deny);
    assert_eq!(decide(&fixture, &source, "view_inventory", "Host", "operator"), Decision::Deny);
    for entity in fixture["entities"].as_array_mut().unwrap() {
        if entity["uid"]["type"] == "Membership" {
            entity["attrs"]["groups"] = json!([]);
        }
    }
    assert_eq!(decide(&fixture, &source, "connect", "Host", "operator"), Decision::Deny);
}

#[test]
fn independent_vectors_exercise_public_codecs_and_generator() {
    let document = scoplen_test_vectors::VectorDocument::parse_str(include_str!(
        "../../../vectors/group-policy.json"
    ))
    .unwrap();
    for vector in document.vectors {
        let input = vector.input.as_bytes();
        let result = match vector.kind.as_str() {
            "group_policy.group_create" => {
                GroupCreateRequest::from_json(input).and_then(|value| value.to_json())
            }
            "group_policy.group_replace" => {
                GroupReplaceRequest::from_json(input).and_then(|value| value.to_json())
            }
            "group_policy.group_resource" => {
                GroupResource::from_json(input).and_then(|value| value.to_json())
            }
            "group_policy.group_page" => {
                GroupPage::from_json(input).and_then(|value| value.to_json())
            }
            "group_policy.policy_create" => {
                PolicyCreateRequest::from_json(input).and_then(|value| value.to_json())
            }
            "group_policy.policy_replace" => {
                PolicyReplaceRequest::from_json(input).and_then(|value| value.to_json())
            }
            "group_policy.policy_resource" => {
                PolicyResource::from_json(input).and_then(|value| value.to_json())
            }
            "group_policy.policy_page" => {
                PolicyPage::from_json(input).and_then(|value| value.to_json())
            }
            "group_policy.simple_input" => {
                SimpleRuleInput::from_json(input).and_then(|value| value.to_json())
            }
            "group_policy.simple_source" => SimpleRuleInput::from_json(input)
                .and_then(|value| value.generate())
                .map(String::into_bytes),
            "group_policy.profile" => {
                parse_policy_source(&vector.input).map(|_| b"accepted".to_vec())
            }
            _ => panic!("unknown vector kind {}", vector.kind),
        };
        if vector.expected == "rejected" {
            assert!(result.is_err(), "{}", vector.id);
        } else {
            assert_eq!(
                String::from_utf8(result.unwrap_or_else(|_| panic!("{} rejected", vector.id)))
                    .unwrap(),
                vector.expected,
                "{}",
                vector.id
            );
        }
    }
}
