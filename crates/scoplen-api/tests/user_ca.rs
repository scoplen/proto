// SPDX-License-Identifier: Apache-2.0
use scoplen_api::organization::{
    OrganizationCodecError as Error, OrganizationListQuery, parse_organization_idempotency_key,
};
use scoplen_api::user_ca::{
    MAX_USER_CA_CREATE_BYTES, MAX_USER_CA_PAGE_BYTES, MAX_USER_CA_RESOURCE_BYTES,
    USER_CA_RECEIPT_LIFETIME_SECONDS, UserCaCreateRequest, UserCaPage, UserCaResource,
    user_ca_fingerprint,
};
use scoplen_test_vectors::VectorDocument;
use serde_json::{Value, json};
use uuid::Uuid;

const PUBLIC_KEY: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINdamAGCsQq31Uv+08lkBzoO4XLz2qYjJa8CGmj3B1Ea";
const FINGERPRINT: &str = "SHA256:bbXpuKG6zhzdmnxq256TlqzFBzRl2f6OOg722cYNbU8";

fn id(n: u64) -> Uuid {
    Uuid::parse_str(&format!("019bdad6-b800-7000-8000-{n:012x}")).unwrap()
}

fn resource() -> UserCaResource {
    UserCaResource {
        id: id(1),
        etag: "\"1\"".into(),
        created_at: "2026-11-01T00:00:00Z".into(),
        updated_at: "2026-11-01T00:00:00.123Z".into(),
        public_key: PUBLIC_KEY.into(),
        fingerprint: FINGERPRINT.into(),
    }
}

#[test]
fn independent_published_vectors_use_the_public_codecs() {
    let document =
        VectorDocument::parse_str(include_str!("../../../vectors/user-ca.json")).unwrap();
    assert_eq!(document.vectors.len(), 107);
    for vector in document.vectors {
        let input = vector.input.as_bytes();
        let encoded = match vector.kind.as_str() {
            "user_ca.create" => {
                Some(UserCaCreateRequest::from_json(input).unwrap().to_json().unwrap())
            }
            "user_ca.resource" => {
                Some(UserCaResource::from_json(input).unwrap().to_json().unwrap())
            }
            "user_ca.page" => Some(UserCaPage::from_json(input).unwrap().to_json().unwrap()),
            "user_ca.create.reject" => {
                assert!(UserCaCreateRequest::from_json(input).is_err(), "{}", vector.id);
                None
            }
            "user_ca.resource.reject" => {
                assert!(UserCaResource::from_json(input).is_err(), "{}", vector.id);
                None
            }
            "user_ca.page.reject" => {
                assert!(UserCaPage::from_json(input).is_err(), "{}", vector.id);
                None
            }
            "user_ca.problem" => {
                let problem = scoplen_api::ProblemDetails::from_json(input, 4096).unwrap();
                assert_eq!(
                    serde_json::to_value(problem).unwrap(),
                    serde_json::from_str::<Value>(&vector.expected).unwrap(),
                    "{}",
                    vector.id
                );
                None
            }
            "user_ca.bound" => {
                let recipe: Value = serde_json::from_slice(input).unwrap();
                let bytes = usize::try_from(recipe["bytes"].as_u64().unwrap()).unwrap();
                let base = recipe["base"].as_str().unwrap();
                let body = format!("{}{base}", " ".repeat(bytes - base.len()));
                let accepted = match recipe["kind"].as_str().unwrap() {
                    "create" => UserCaCreateRequest::from_json(body.as_bytes()).is_ok(),
                    "resource" => UserCaResource::from_json(body.as_bytes()).is_ok(),
                    "page" => UserCaPage::from_json(body.as_bytes()).is_ok(),
                    other => panic!("unknown bound {other}"),
                };
                assert_eq!(accepted, vector.expected == "accepted", "{}", vector.id);
                None
            }
            "user_ca.item-bound" => {
                let recipe: Value = serde_json::from_slice(input).unwrap();
                let base = recipe["base"].as_str().unwrap();
                let bytes = usize::try_from(recipe["bytes"].as_u64().unwrap()).unwrap();
                let item =
                    format!("{}{} }}", &base[..base.len() - 1], " ".repeat(bytes - base.len() - 1));
                assert_eq!(item.len(), bytes);
                let body = format!("{{\"items\":[{item}],\"next_cursor\":null}}");
                assert_eq!(
                    UserCaPage::from_json(body.as_bytes()).is_ok(),
                    vector.expected == "accepted",
                    "{}",
                    vector.id
                );
                None
            }
            "user_ca.page-count" => {
                let recipe: Value = serde_json::from_slice(input).unwrap();
                let count = recipe["count"].as_u64().unwrap();
                let items: Vec<_> = (1..=count)
                    .map(|n| {
                        let mut item = recipe["base"].clone();
                        item["id"] = Value::String(id(n).to_string());
                        item
                    })
                    .collect();
                let body = serde_json::to_vec(&json!({"items":items,"next_cursor":null})).unwrap();
                assert_eq!(
                    UserCaPage::from_json(&body).is_ok(),
                    vector.expected == "accepted",
                    "{}",
                    vector.id
                );
                None
            }
            other => panic!("unrecognized user-CA vector kind {other}"),
        };
        if let Some(encoded) = encoded {
            assert_eq!(encoded, vector.expected.as_bytes(), "{}", vector.id);
        }
    }
}

#[test]
fn creation_is_exact_and_retains_no_caller_selected_signing_material() {
    let request = UserCaCreateRequest::new(id(1)).unwrap();
    assert_eq!(
        request.to_json().unwrap(),
        format!("{{\"id\":\"{}\",\"data\":{{\"kind\":\"user\",\"backend\":\"local\"}}}}", id(1))
            .as_bytes()
    );
    assert_eq!(UserCaCreateRequest::from_json(&request.to_json().unwrap()), Ok(request));
    assert!(UserCaCreateRequest::new(Uuid::nil()).is_err());
    let invalid = UserCaCreateRequest { id: Uuid::nil() };
    assert!(invalid.to_json().is_err());
    assert!(!format!("{request:?}").contains(&id(1).to_string()));
    assert_eq!(USER_CA_RECEIPT_LIFETIME_SECONDS, 86_400);
    assert_eq!(parse_organization_idempotency_key(&id(2).to_string()), Ok(id(2)));
    for input in [id(2).to_string().to_uppercase(), format!(" {}", id(2)), Uuid::nil().to_string()]
    {
        assert!(parse_organization_idempotency_key(&input).is_err());
    }
}

#[test]
fn fingerprint_hashes_the_complete_decoded_ssh_blob_and_revalidates_mutable_fields() {
    assert_eq!(user_ca_fingerprint(PUBLIC_KEY), Ok(FINGERPRINT.into()));
    let mut item = resource();
    assert_eq!(item.validate(), Ok(()));
    item.fingerprint.push('=');
    assert_eq!(item.validate(), Err(Error::InvalidField("fingerprint")));
    item = resource();
    item.public_key.push_str(" public-comment");
    assert_eq!(item.to_json(), Err(Error::InvalidField("public_key")));
    assert!(!format!("{item:?}").contains("public-comment"));
    assert!(!format!("{:?}", item.validate().unwrap_err()).contains("public-comment"));
    for key in [
        String::new(),
        PUBLIC_KEY.replace(' ', "\t"),
        format!("{PUBLIC_KEY}\n"),
        format!("{PUBLIC_KEY}="),
        "ssh-rsa AAAAB3NzaC1yc2EAAAADAQAB".into(),
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAAA==".into(),
    ] {
        assert_eq!(user_ca_fingerprint(&key), Err(Error::InvalidField("public_key")));
    }
}

#[test]
fn contextual_checks_bind_ids_query_count_and_cursor_without_inventing_a_tenant_field() {
    let first = resource();
    assert_eq!(first.validate_for_id(id(1)), Ok(()));
    assert_eq!(first.validate_for_id(id(2)), Err(Error::Context));
    assert!(first.validate_for_id(Uuid::nil()).is_err());
    let mut second = first.clone();
    second.id = id(2);
    let mut page = UserCaPage { items: vec![first, second], next_cursor: Some(id(2)) };
    assert_eq!(page.validate_for_query(OrganizationListQuery::default()), Ok(()));
    assert_eq!(
        page.validate_for_query(OrganizationListQuery { limit: 1, cursor: None }),
        Err(Error::Context)
    );
    assert_eq!(
        page.validate_for_query(OrganizationListQuery { limit: 50, cursor: Some(id(1)) }),
        Err(Error::Context)
    );
    page.items.remove(0);
    assert_eq!(
        page.validate_for_query(OrganizationListQuery { limit: 1, cursor: Some(id(1)) }),
        Ok(())
    );
    page.next_cursor = Some(id(1));
    assert!(page.to_json().is_err());
    let query =
        OrganizationListQuery::from_parameters([("limit", "500"), ("cursor", &id(1).to_string())])
            .unwrap();
    assert_eq!(query.limit, 500);
    assert_eq!(query.cursor, Some(id(1)));
    for pairs in [
        vec![("limit", "0")],
        vec![("limit", "501")],
        vec![("kind", "user")],
        vec![("cursor", "")],
        vec![("limit", "1"), ("limit", "2")],
    ] {
        assert!(OrganizationListQuery::from_parameters(pairs).is_err());
    }
}

#[test]
fn raw_item_whitespace_and_ignored_extensions_remain_inside_the_item_budget() {
    let base = String::from_utf8(resource().to_json().unwrap()).unwrap();
    for extra in [0, 1] {
        let bytes = MAX_USER_CA_RESOURCE_BYTES + extra;
        let item = format!("{}{} }}", &base[..base.len() - 1], " ".repeat(bytes - base.len() - 1));
        assert_eq!(item.len(), bytes);
        let body = format!("{{\"items\":[{item}],\"next_cursor\":null}}");
        assert_eq!(UserCaPage::from_json(body.as_bytes()).is_ok(), extra == 0);
    }
    let mut item: Value = serde_json::from_str(&base).unwrap();
    item["future"] = Value::String("x".repeat(MAX_USER_CA_RESOURCE_BYTES));
    let body = serde_json::to_vec(&json!({"items":[item],"next_cursor":null})).unwrap();
    assert!(body.len() < MAX_USER_CA_PAGE_BYTES);
    assert_eq!(UserCaPage::from_json(&body), Err(Error::TooLarge));
}

#[test]
fn complete_budgets_apply_before_decoding_and_during_encoding() {
    assert_eq!(
        UserCaCreateRequest::from_json(&vec![b' '; MAX_USER_CA_CREATE_BYTES + 1]),
        Err(Error::TooLarge)
    );
    assert_eq!(
        UserCaResource::from_json(&vec![b' '; MAX_USER_CA_RESOURCE_BYTES + 1]),
        Err(Error::TooLarge)
    );
    assert_eq!(
        UserCaPage::from_json(&vec![b' '; MAX_USER_CA_PAGE_BYTES + 1]),
        Err(Error::TooLarge)
    );
    let mut item = resource();
    item.created_at = format!("2026-11-01T00:00:00.{}Z", "0".repeat(MAX_USER_CA_RESOURCE_BYTES));
    assert_eq!(item.to_json(), Err(Error::TooLarge));
    item.created_at = format!("2026-11-01T00:00:00.{}Z", "0".repeat(16_000));
    assert!(item.to_json().is_ok());
    let items = (1..=65).map(|n| UserCaResource { id: id(n), ..item.clone() }).collect();
    let page = UserCaPage { items, next_cursor: None };
    assert_eq!(page.to_json(), Err(Error::TooLarge));
}

#[test]
fn resource_http_etag_and_both_cache_headers_are_exact() {
    let bytes = resource().to_json().unwrap();
    assert!(
        UserCaResource::from_http_json(&bytes, Some("\"1\""), Some("no-store"), Some("no-cache"))
            .is_ok()
    );
    for (etag, cache, pragma) in [
        (None, Some("no-store"), Some("no-cache")),
        (Some("\"2\""), Some("no-store"), Some("no-cache")),
        (Some("\"1\""), None, Some("no-cache")),
        (Some("\"1\""), Some("no-store"), None),
        (Some("\"1\""), Some("public"), Some("no-cache")),
    ] {
        assert_eq!(
            UserCaResource::from_http_json(&bytes, etag, cache, pragma),
            Err(Error::HttpMetadata)
        );
    }
    let page = UserCaPage { items: vec![resource()], next_cursor: None }.to_json().unwrap();
    assert!(UserCaPage::from_http_json(&page, Some("no-store"), Some("no-cache")).is_ok());
    assert_eq!(UserCaPage::from_http_json(&page, Some("no-store"), None), Err(Error::HttpMetadata));
}
