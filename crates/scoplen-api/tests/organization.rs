// SPDX-License-Identifier: Apache-2.0
use scoplen_api::organization::{
    MAX_ORGANIZATION_CREATE_BYTES, MAX_ORGANIZATION_PAGE_BYTES, MAX_ORGANIZATION_RESOURCE_BYTES,
    OrganizationCodecError as Error, OrganizationCreateRequest, OrganizationListQuery,
    OrganizationMembership, OrganizationPage, OrganizationResource,
    parse_organization_idempotency_key,
};
use scoplen_test_vectors::VectorDocument;
use serde_json::{Value, json};
use uuid::Uuid;

fn id(n: u64) -> Uuid {
    Uuid::parse_str(&format!("019bdad6-b800-7000-8000-{n:012x}")).unwrap()
}
fn resource() -> OrganizationResource {
    OrganizationResource {
        id: id(1),
        etag: "\"1\"".into(),
        created_at: "2026-10-26T00:00:00Z".into(),
        updated_at: "2026-10-26T00:00:00Z".into(),
        name: "Operations".into(),
        membership: OrganizationMembership {
            id: id(2),
            account_id: id(3),
            roles: vec!["owner".into()],
        },
    }
}

#[test]
fn published_independent_vectors_use_public_codecs() {
    let vectors =
        VectorDocument::parse_str(include_str!("../../../vectors/organizations.json")).unwrap();
    assert_eq!(vectors.vectors.len(), 45);
    for vector in vectors.vectors {
        let input = vector.input.as_bytes();
        let canonical = match vector.kind.as_str() {
            "organization.create" => {
                Some(OrganizationCreateRequest::from_json(input).unwrap().to_json().unwrap())
            }
            "organization.resource" => {
                Some(OrganizationResource::from_json(input).unwrap().to_json().unwrap())
            }
            "organization.page" => {
                Some(OrganizationPage::from_json(input).unwrap().to_json().unwrap())
            }
            "organization.create.reject" => {
                assert!(OrganizationCreateRequest::from_json(input).is_err(), "{}", vector.id);
                None
            }
            "organization.resource.reject" => {
                assert!(OrganizationResource::from_json(input).is_err(), "{}", vector.id);
                None
            }
            "organization.page.reject" => {
                assert!(OrganizationPage::from_json(input).is_err(), "{}", vector.id);
                None
            }
            "organization.query" => {
                let pairs: Vec<[String; 2]> = serde_json::from_slice(input).unwrap();
                let actual = OrganizationListQuery::from_parameters(
                    pairs.iter().map(|p| (p[0].as_str(), p[1].as_str())),
                );
                if vector.expected == "rejected" {
                    assert!(actual.is_err(), "{}", vector.id);
                } else {
                    let query = actual.unwrap();
                    assert_eq!(
                        json!({ "limit": query.limit, "cursor": query.cursor.map(|id| id.to_string()) }),
                        serde_json::from_str::<Value>(&vector.expected).unwrap()
                    );
                }
                None
            }
            "organization.bound" => {
                let recipe: Value = serde_json::from_slice(input).unwrap();
                let bytes = usize::try_from(recipe["bytes"].as_u64().unwrap()).unwrap();
                let base = recipe["base"].as_str().unwrap();
                let body = format!("{}{base}", " ".repeat(bytes - base.len()));
                let accepted = match recipe["kind"].as_str().unwrap() {
                    "create" => OrganizationCreateRequest::from_json(body.as_bytes()).is_ok(),
                    "resource" => OrganizationResource::from_json(body.as_bytes()).is_ok(),
                    "page" => OrganizationPage::from_json(body.as_bytes()).is_ok(),
                    other => panic!("unknown bound {other}"),
                };
                assert_eq!(accepted, vector.expected == "accepted", "{}", vector.id);
                None
            }
            other => panic!("unknown vector {other}"),
        };
        if let Some(bytes) = canonical {
            assert_eq!(bytes, vector.expected.as_bytes(), "{}", vector.id);
        }
    }
}

#[test]
fn unicode_name_byte_bound_and_mutable_fields_are_validated() {
    assert!(OrganizationCreateRequest::new("é".repeat(64)).is_ok());
    for name in [
        "é".repeat(65),
        "\u{3000}team".into(),
        "team\u{3000}".into(),
        "te\0am".into(),
        String::new(),
    ] {
        assert!(OrganizationCreateRequest::new(name).is_err());
    }
    let composed = OrganizationCreateRequest::new("Cafe\u{301}").unwrap();
    assert_eq!(composed.name, "Cafe\u{301}");
    let mut changed = resource();
    changed.membership.roles = vec!["owner".into(); 2];
    assert!(changed.to_json().is_err());
    changed = resource();
    changed.membership.roles = (0..33).map(|n| format!("role{n}")).collect();
    assert!(changed.to_json().is_err());
    changed = resource();
    changed.name = "private-name\n".into();
    assert!(changed.to_json().is_err());
    assert!(!format!("{changed:?}").contains("private-name"));
    assert!(!format!("{:?}", changed.to_json().unwrap_err()).contains("private-name"));
}

#[test]
fn contextual_page_checks_reject_foreign_accounts_and_continuations() {
    let item = resource();
    assert_eq!(item.validate_for_account(id(3)), Ok(()));
    assert_eq!(item.validate_for_account(id(4)), Err(Error::Context));
    let mut page = OrganizationPage { items: vec![item.clone()], next_cursor: None };
    assert_eq!(page.validate_for_account(id(3), OrganizationListQuery::default()), Ok(()));
    assert_eq!(
        page.validate_for_account(id(4), OrganizationListQuery::default()),
        Err(Error::Context)
    );
    assert_eq!(
        page.validate_for_account(id(3), OrganizationListQuery { limit: 50, cursor: Some(id(1)) }),
        Err(Error::Context)
    );
    let mut second = item;
    second.id = id(5);
    page.items.push(second);
    assert_eq!(
        page.validate_for_account(id(3), OrganizationListQuery { limit: 1, cursor: None }),
        Err(Error::Context)
    );
    page.next_cursor = Some(id(5));
    assert!(page.to_json().is_ok());
    page.items.reverse();
    assert!(page.to_json().is_err());
}

#[test]
fn raw_page_items_keep_their_whitespace_and_extension_bound() {
    let source = String::from_utf8(resource().to_json().unwrap()).unwrap();
    for extra in [0, 1] {
        let spaces = " ".repeat(MAX_ORGANIZATION_RESOURCE_BYTES + extra - source.len());
        let expanded = format!("{}{} }}", &source[..source.len() - 1], &spaces[..spaces.len() - 1]);
        assert_eq!(expanded.len(), MAX_ORGANIZATION_RESOURCE_BYTES + extra);
        let page = format!("{{\"items\":[{expanded}],\"next_cursor\":null}}");
        assert_eq!(OrganizationPage::from_json(page.as_bytes()).is_ok(), extra == 0);
    }
    let mut extended: Value = serde_json::from_str(&source).unwrap();
    extended["extension"] = Value::String("x".repeat(MAX_ORGANIZATION_RESOURCE_BYTES));
    let page = json!({"items":[extended],"next_cursor":null});
    assert_eq!(
        OrganizationPage::from_json(&serde_json::to_vec(&page).unwrap()),
        Err(Error::TooLarge)
    );
}

#[test]
fn response_metadata_and_idempotency_syntax_are_exact() {
    let bytes = resource().to_json().unwrap();
    assert!(
        OrganizationResource::from_http_json(
            &bytes,
            Some("\"1\""),
            Some("no-store"),
            Some("no-cache")
        )
        .is_ok()
    );
    for (etag, cache, pragma) in [
        (None, Some("no-store"), Some("no-cache")),
        (Some("\"2\""), Some("no-store"), Some("no-cache")),
        (Some("\"1\""), None, Some("no-cache")),
        (Some("\"1\""), Some("no-store"), None),
    ] {
        assert_eq!(
            OrganizationResource::from_http_json(&bytes, etag, cache, pragma),
            Err(Error::HttpMetadata)
        );
    }
    assert_eq!(parse_organization_idempotency_key(&id(1).to_string()), Ok(id(1)));
    for text in [id(1).to_string().to_uppercase(), format!(" {}", id(1)), Uuid::nil().to_string()] {
        assert!(parse_organization_idempotency_key(&text).is_err());
    }
    let empty = b"{\"items\":[],\"next_cursor\":null}";
    assert!(OrganizationPage::from_http_json(empty, Some("no-store"), Some("no-cache")).is_ok());
    assert_eq!(
        OrganizationPage::from_http_json(empty, Some("public"), Some("no-cache")),
        Err(Error::HttpMetadata)
    );
}

#[test]
fn collection_limits_and_strict_utf8_apply_before_exposure() {
    let item = resource();
    let mut page = OrganizationPage { items: vec![], next_cursor: None };
    for n in 0..500 {
        let mut next = item.clone();
        next.id = id(10 + n);
        page.items.push(next);
    }
    let bytes = page.to_json().unwrap();
    assert!(bytes.len() <= MAX_ORGANIZATION_PAGE_BYTES);
    assert_eq!(OrganizationPage::from_json(&bytes), Ok(page.clone()));
    let mut next = item;
    next.id = id(999);
    page.items.push(next);
    assert!(page.to_json().is_err());
    for body in [b"\xff{}".as_slice(), b"\xef\xbb\xbf{}".as_slice()] {
        assert!(OrganizationCreateRequest::from_json(body).is_err());
    }
    assert_eq!(
        OrganizationCreateRequest::from_json(&vec![b' '; MAX_ORGANIZATION_CREATE_BYTES + 1]),
        Err(Error::TooLarge)
    );
}
