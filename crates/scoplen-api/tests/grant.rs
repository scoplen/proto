// SPDX-License-Identifier: Apache-2.0

use scoplen_api::{
    account_browser::{
        AccountBrowserAccessOperation, AccountBrowserAccessRequirement, AccountBrowserAccessScope,
    },
    auth::{DeviceAccessOperation, DeviceAccessScope, INITIAL_DEVICE_ACCESS_SCOPE},
    grant::{
        GrantCreateRequest, GrantFields, GrantPage, GrantReplaceRequest, GrantResource,
        MAX_GRANT_BYTES, MAX_GRANT_PAGE_BYTES, MAX_GRANT_TIMESTAMP_SECONDS, format_grant_timestamp,
        parse_grant_timestamp,
    },
    organization::{OrganizationCodecError, OrganizationListQuery},
};
use serde_json::{Value, json};
use uuid::Uuid;

fn id(number: u64) -> Uuid {
    format!("019bdad6-b800-7000-8000-{number:012}").parse().unwrap()
}

fn fields() -> GrantFields {
    GrantFields {
        membership: id(2),
        host: id(3),
        remote_user: "deploy".into(),
        valid_from: 0,
        valid_until: Some(MAX_GRANT_TIMESTAMP_SECONDS),
    }
}

fn resource(number: u64) -> GrantResource {
    GrantResource {
        id: id(number),
        etag: "\"current\"".into(),
        created_at: "2026-11-01T00:00:00Z".into(),
        updated_at: "2026-11-01T00:00:00Z".into(),
        fields: fields(),
    }
}

#[test]
fn independent_vectors_match_public_codecs_and_canonical_output() {
    let document = scoplen_test_vectors::VectorDocument::parse_str(include_str!(
        "../../../vectors/grant.json"
    ))
    .unwrap();
    for vector in document.vectors {
        let input = vector.input.as_bytes();
        let result = match vector.kind.as_str() {
            "grant.create" => GrantCreateRequest::from_json(input).and_then(|v| v.to_json()),
            "grant.replace" => GrantReplaceRequest::from_json(input).and_then(|v| v.to_json()),
            "grant.resource" => GrantResource::from_json(input).and_then(|v| v.to_json()),
            "grant.page" => GrantPage::from_json(input).and_then(|v| v.to_json()),
            "grant.timestamp" => {
                parse_grant_timestamp(&vector.input).map(|v| v.to_string().into_bytes())
            }
            kind => panic!("unknown Grant vector kind {kind}"),
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

#[test]
fn exact_whole_second_timestamp_profile_covers_calendar_boundaries() {
    for (text, seconds) in [
        ("1970-01-01T00:00:00Z", 0),
        ("2000-02-29T00:00:00Z", 951_782_400),
        ("2038-01-19T03:14:08Z", 2_147_483_648),
        ("9999-12-31T23:59:59Z", MAX_GRANT_TIMESTAMP_SECONDS),
    ] {
        assert_eq!(parse_grant_timestamp(text).unwrap(), seconds);
        assert_eq!(format_grant_timestamp(seconds).unwrap(), text);
    }
    for text in [
        "1969-12-31T23:59:59Z",
        "0000-01-01T00:00:00Z",
        "10000-01-01T00:00:00Z",
        "2100-02-29T00:00:00Z",
        "2001-04-31T00:00:00Z",
        "2000-01-01T24:00:00Z",
        "2016-12-31T23:59:60Z",
        "2000-01-01t00:00:00z",
        "2000-01-01T00:00:00.000Z",
        "2000-01-01T00:00:00+00:00",
        " 2000-01-01T00:00:00Z",
    ] {
        assert!(parse_grant_timestamp(text).is_err(), "{text}");
    }
    assert!(format_grant_timestamp(MAX_GRANT_TIMESTAMP_SECONDS + 1).is_err());
    assert!(format_grant_timestamp(u64::MAX).is_err());
}

#[test]
fn fields_preserve_exact_users_and_require_positive_finite_intervals() {
    let mut value = fields();
    value.remote_user = " e\u{301} ".into();
    value.valid_from = MAX_GRANT_TIMESTAMP_SECONDS;
    value.valid_until = None;
    let request = GrantReplaceRequest { fields: value.clone() };
    let bytes = request.to_json().unwrap();
    assert_eq!(GrantReplaceRequest::from_json(&bytes).unwrap().fields, value);
    for until in [Some(0), Some(MAX_GRANT_TIMESTAMP_SECONDS), Some(u64::MAX)] {
        value.valid_until = until;
        assert!(value.validate().is_err());
    }
    value.valid_until = None;
    for user in [String::new(), "x".repeat(256), "a\n".into(), "a\u{85}".into(), "a\u{7f}".into()] {
        value.remote_user = user;
        assert!(value.validate().is_err());
    }
    value.remote_user = "é".repeat(127) + "x";
    value.validate().unwrap();
    assert!(!format!("{value:?}").contains(&value.remote_user));
}

#[test]
fn original_resource_and_embedded_item_byte_bounds_precede_normalization() {
    let bytes = resource(4).to_json().unwrap();
    let mut padded = bytes.clone();
    padded.resize(MAX_GRANT_BYTES, b' ');
    GrantResource::from_json(&padded).unwrap();
    padded.push(b' ');
    assert_eq!(GrantResource::from_json(&padded), Err(OrganizationCodecError::TooLarge));
    // Internal whitespace belongs to the original embedded Resource budget.
    let mut oversized = bytes;
    oversized.insert(1, b' ');
    oversized.splice(1..1, std::iter::repeat_n(b' ', MAX_GRANT_BYTES));
    let mut page = b"{\"items\":[".to_vec();
    page.extend_from_slice(&oversized);
    page.extend_from_slice(b"],\"next_cursor\":null}");
    assert_eq!(GrantPage::from_json(&page), Err(OrganizationCodecError::TooLarge));
    let empty = b"{\"items\":[],\"next_cursor\":null}";
    let mut page = empty.to_vec();
    page.resize(MAX_GRANT_PAGE_BYTES, b' ');
    GrantPage::from_json(&page).unwrap();
    page.push(b' ');
    assert_eq!(GrantPage::from_json(&page), Err(OrganizationCodecError::TooLarge));
    let request = GrantCreateRequest { id: id(4), fields: fields() };
    let mut bytes = request.to_json().unwrap();
    bytes.resize(MAX_GRANT_BYTES + 1, b' ');
    assert_eq!(GrantCreateRequest::from_json(&bytes), Err(OrganizationCodecError::TooLarge));
}

#[test]
fn response_extensions_are_bounded_but_duplicates_and_missing_fields_are_rejected() {
    let original = resource(4);
    let mut value: Value = serde_json::from_slice(&original.to_json().unwrap()).unwrap();
    value["future"] = json!({"version": 2});
    value["data"]["future"] = json!([1, 2, 3]);
    assert_eq!(GrantResource::from_json(&serde_json::to_vec(&value).unwrap()).unwrap(), original);
    let text = serde_json::to_string(&value)
        .unwrap()
        .replace("\"version\":2", "\"version\":2,\"version\":3");
    assert!(GrantResource::from_json(text.as_bytes()).is_err());
    value["data"].as_object_mut().unwrap().remove("valid_until");
    assert!(GrantResource::from_json(&serde_json::to_vec(&value).unwrap()).is_err());
}

#[test]
fn captured_context_page_order_and_http_metadata_are_required() {
    let value = resource(4);
    let request = GrantCreateRequest { id: id(4), fields: fields() };
    value.validate_for_create(&request).unwrap();
    assert!(value.validate_for_id(id(5)).is_err());
    let mut changed = fields();
    changed.remote_user.push('x');
    assert!(value.validate_for_fields(&changed).is_err());
    let bytes = value.to_json().unwrap();
    GrantResource::from_http_json(&bytes, Some("\"current\""), Some("no-store"), Some("no-cache"))
        .unwrap();
    for tag in [None, Some("\"other\""), Some("W/\"current\"")] {
        assert!(
            GrantResource::from_http_json(&bytes, tag, Some("no-store"), Some("no-cache")).is_err()
        );
    }
    assert!(
        GrantResource::from_http_json(
            &bytes,
            Some("\"current\""),
            Some("private"),
            Some("no-cache")
        )
        .is_err()
    );
    let page = GrantPage { items: vec![value], next_cursor: Some(id(4)) };
    page.validate_for_query(OrganizationListQuery { limit: 1, cursor: Some(id(3)) }).unwrap();
    assert!(
        page.validate_for_query(OrganizationListQuery { limit: 1, cursor: Some(id(4)) }).is_err()
    );
    let mut invalid = page.clone();
    invalid.next_cursor = Some(id(5));
    assert!(invalid.validate().is_err());
    invalid = page.clone();
    invalid.items.push(resource(4));
    assert!(invalid.validate().is_err());
    invalid.items = (1..=501).map(resource).collect();
    assert!(invalid.validate().is_err());
    invalid.items.pop();
    invalid.next_cursor = None;
    invalid.validate().unwrap();
    assert!(
        invalid.validate_for_query(OrganizationListQuery { limit: 499, cursor: None }).is_err()
    );
    assert!(GrantPage::from_http_json(&page.to_json().unwrap(), None, Some("no-cache")).is_err());
}

#[test]
fn both_auth_profiles_register_only_the_five_exact_grant_operations() {
    use AccountBrowserAccessOperation as Browser;
    use DeviceAccessOperation as Device;
    for (device, browser, method, suffix, write) in [
        (Device::OrganizationGrantList, Browser::OrganizationGrantList, "GET", "", false),
        (Device::OrganizationGrantRead, Browser::OrganizationGrantRead, "GET", "/{id}", false),
        (Device::OrganizationGrantCreate, Browser::OrganizationGrantCreate, "POST", "", true),
        (Device::OrganizationGrantReplace, Browser::OrganizationGrantReplace, "PUT", "/{id}", true),
        (
            Device::OrganizationGrantDelete,
            Browser::OrganizationGrantDelete,
            "DELETE",
            "/{id}",
            true,
        ),
    ] {
        let path = format!("/api/v1/orgs/{{org}}/grants{suffix}");
        assert_eq!(Device::from_route(method, &path), Some(device));
        assert_eq!(Browser::from_route(method, &path), Some(browser));
        assert_eq!(
            device.accepted_scopes(),
            &[if write {
                DeviceAccessScope::PoliciesWrite
            } else {
                DeviceAccessScope::PoliciesRead
            }]
        );
        assert_eq!(
            browser.requirement(),
            if write {
                AccountBrowserAccessRequirement::AnyScope(&[
                    AccountBrowserAccessScope::PoliciesWrite,
                ])
            } else {
                AccountBrowserAccessRequirement::AnyScope(&[
                    AccountBrowserAccessScope::PoliciesRead,
                ])
            }
        );
        assert!(!device.has_accepted_scope("owner orgs:write teams:manage policies:*"));
        assert!(device.has_accepted_scope(INITIAL_DEVICE_ACCESS_SCOPE));
        assert_eq!(browser.uses_browser_writer_receipt(), method == "POST");
        assert_eq!(Device::from_route(&method.to_lowercase(), &path), None);
        assert_eq!(Browser::from_route(method, &(path + "/")), None);
    }
    for (method, path) in [
        ("PATCH", "/api/v1/orgs/{org}/grants/{id}"),
        ("POST", "/api/v1/orgs/{org}/grants/{id}"),
        ("DELETE", "/api/v1/orgs/{org}/grants"),
        ("GET", "/api/v1/orgs/{org}/grants/019bdad6-b800-7000-8000-000000000004"),
    ] {
        assert_eq!(Device::from_route(method, path), None);
        assert_eq!(Browser::from_route(method, path), None);
    }
}
