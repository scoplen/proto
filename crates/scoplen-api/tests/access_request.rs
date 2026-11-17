// SPDX-License-Identifier: Apache-2.0

use scoplen_api::{
    access_request::{
        AccessRequestCheckRequest, AccessRequestCheckResponse, AccessRequestCreateRequest,
        AccessRequestDecisionRequest, AccessRequestFields, AccessRequestListQuery,
        AccessRequestOutcome, AccessRequestPage, AccessRequestResource, AccessRequestStatus,
        AccessRequestView, MAX_ACCESS_REQUEST_BYTES, MAX_ACCESS_REQUEST_PAGE_BYTES,
        MAX_ACCESS_REQUEST_RESOURCE_BYTES,
    },
    organization::OrganizationCodecError as Error,
};
use scoplen_test_vectors::VectorDocument;
use serde_json::{Value, json};
use uuid::Uuid;

fn vectors() -> VectorDocument {
    VectorDocument::parse_str(include_str!("../../../vectors/access-request.json")).unwrap()
}

fn canonical(kind: &str, input: &[u8]) -> Result<Vec<u8>, Error> {
    match kind {
        "access_request.fields" => AccessRequestFields::from_json(input)?.to_json(),
        "access_request.check_request" => AccessRequestCheckRequest::from_json(input)?.to_json(),
        "access_request.check_response" => AccessRequestCheckResponse::from_json(input)?.to_json(),
        "access_request.create" => AccessRequestCreateRequest::from_json(input)?.to_json(),
        "access_request.decision" => AccessRequestDecisionRequest::from_json(input)?.to_json(),
        "access_request.resource" => AccessRequestResource::from_json(input)?.to_json(),
        "access_request.page" => AccessRequestPage::from_json(input)?.to_json(),
        "access_request.query" => {
            #[derive(serde::Serialize)]
            struct Wire {
                view: &'static str,
                limit: u16,
                cursor: Option<String>,
            }
            let pairs: Vec<(String, String)> =
                serde_json::from_slice(input).map_err(|_| Error::InvalidJson)?;
            let query = AccessRequestListQuery::from_parameters(
                pairs.iter().map(|(name, value)| (name.as_str(), value.as_str())),
            )?;
            serde_json::to_vec(&Wire {
                view: match query.view {
                    AccessRequestView::Mine => "mine",
                    AccessRequestView::Approvals => "approvals",
                },
                limit: query.page.limit,
                cursor: query.page.cursor.map(|id| id.to_string()),
            })
            .map_err(|_| Error::InvalidJson)
        }
        _ => panic!("unrecognized public vector kind {kind}"),
    }
}

fn resource() -> AccessRequestResource {
    let document = vectors();
    let vector =
        document.vectors.iter().find(|value| value.id == "access-request-resource-v1").unwrap();
    AccessRequestResource::from_json(vector.input.as_bytes()).unwrap()
}

#[test]
fn independent_published_vectors_use_public_codecs() {
    let document = vectors();
    assert!(document.vectors.len() >= 200);
    for vector in document.vectors {
        let result = canonical(&vector.kind, vector.input.as_bytes());
        if vector.expected == "rejected" {
            assert!(result.is_err(), "{} unexpectedly accepted", vector.id);
        } else {
            assert_eq!(
                String::from_utf8(result.unwrap_or_else(|error| panic!("{}: {error}", vector.id)))
                    .unwrap(),
                vector.expected,
                "{}",
                vector.id
            );
        }
    }
}

#[test]
fn original_encoded_bounds_are_enforced_before_extensions_are_discarded() {
    let request = AccessRequestCheckRequest { fields: resource().fields };
    let mut bytes = request.to_json().unwrap();
    bytes.resize(MAX_ACCESS_REQUEST_BYTES, b' ');
    assert!(AccessRequestCheckRequest::from_json(&bytes).is_ok());
    bytes.push(b' ');
    assert_eq!(AccessRequestCheckRequest::from_json(&bytes), Err(Error::TooLarge));
    let row = resource();
    let mut bytes = row.to_json().unwrap();
    bytes.resize(MAX_ACCESS_REQUEST_RESOURCE_BYTES, b' ');
    assert!(AccessRequestResource::from_json(&bytes).is_ok());
    bytes.push(b' ');
    assert_eq!(AccessRequestResource::from_json(&bytes), Err(Error::TooLarge));
    let page = AccessRequestPage { items: vec![], next_cursor: None };
    let mut bytes = page.to_json().unwrap();
    bytes.resize(MAX_ACCESS_REQUEST_PAGE_BYTES, b' ');
    assert!(AccessRequestPage::from_json(&bytes).is_ok());
    bytes.push(b' ');
    assert_eq!(AccessRequestPage::from_json(&bytes), Err(Error::TooLarge));
    let mut bytes = b"{\"items\":[".to_vec();
    let mut value: Value = serde_json::from_slice(&row.to_json().unwrap()).unwrap();
    value["future"] = json!("x".repeat(MAX_ACCESS_REQUEST_RESOURCE_BYTES));
    bytes.extend(serde_json::to_vec(&value).unwrap());
    bytes.extend(b"],\"next_cursor\":null}");
    assert_eq!(AccessRequestPage::from_json(&bytes), Err(Error::TooLarge));
}

#[test]
fn response_headers_original_owners_and_query_continuations_are_checked() {
    let row = resource();
    let bytes = row.to_json().unwrap();
    assert!(
        AccessRequestResource::from_http_json(
            &bytes,
            Some(&row.etag),
            Some("no-store"),
            Some("no-cache")
        )
        .is_ok()
    );
    assert_eq!(
        AccessRequestResource::from_http_json(
            &bytes,
            Some("\"different\""),
            Some("no-store"),
            Some("no-cache")
        ),
        Err(Error::HttpMetadata)
    );
    assert_eq!(
        AccessRequestResource::from_http_json(&bytes, Some(&row.etag), None, Some("no-cache")),
        Err(Error::HttpMetadata)
    );
    let request = AccessRequestCreateRequest { id: row.id, fields: row.fields.clone() };
    assert!(row.validate_for_create(&request, row.requester_account_id).is_ok());
    assert_eq!(row.validate_for_create(&request, Uuid::now_v7()), Err(Error::Context));
    let mut changed = request.clone();
    changed.fields.reason.push('!');
    assert_eq!(row.validate_for_create(&changed, row.requester_account_id), Err(Error::Context));
    let page = AccessRequestPage { items: vec![row.clone()], next_cursor: None };
    let mine = AccessRequestListQuery::from_parameters([("view", "mine")]).unwrap();
    assert!(page.validate_for_query(row.requester_account_id, mine).is_ok());
    assert_eq!(page.validate_for_query(Uuid::now_v7(), mine), Err(Error::Context));
    let mut after = mine;
    after.page.cursor = Some(row.id);
    assert_eq!(page.validate_for_query(row.requester_account_id, after), Err(Error::Context));
    assert!(
        AccessRequestCheckResponse::from_http_json(
            b"{\"allowed\":false}",
            Some("no-store"),
            Some("no-cache")
        )
        .is_ok()
    );
    assert!(
        AccessRequestPage::from_http_json(
            &page.to_json().unwrap(),
            Some("no-store"),
            Some("no-cache")
        )
        .is_ok()
    );
}

#[test]
fn unknown_status_is_preserved_without_pending_actions_and_reason_debug_is_redacted() {
    let mut row = resource();
    row.status = AccessRequestStatus::Unknown("revoked".into());
    let encoded = row.to_json().unwrap();
    assert_eq!(AccessRequestResource::from_json(&encoded).unwrap().status, row.status);
    let mut query = AccessRequestListQuery::from_parameters([("view", "approvals")]).unwrap();
    let page = AccessRequestPage { items: vec![row.clone()], next_cursor: None };
    assert_eq!(page.validate_for_query(row.requester_account_id, query), Err(Error::Context));
    query.view = AccessRequestView::Mine;
    assert!(page.validate_for_query(row.requester_account_id, query).is_ok());
    let reason = row.fields.reason.clone();
    for debug in [format!("{row:?}"), format!("{:?}", row.fields), format!("{page:?}")] {
        assert!(!debug.contains(&reason));
    }
    row.status = AccessRequestStatus::Unknown("pending".into());
    assert!(row.to_json().is_err());
}

#[test]
fn duplicates_in_ignored_extensions_invalid_utf8_and_page_item_count_are_rejected() {
    let mut bytes = resource().to_json().unwrap();
    bytes.pop();
    bytes.extend(b",\"future\":{\"a\":1,\"a\":2}}");
    assert_eq!(AccessRequestResource::from_json(&bytes), Err(Error::InvalidJson));
    assert!(AccessRequestCheckResponse::from_json(b"\xef\xbb\xbf{\"allowed\":true}").is_err());
    assert!(AccessRequestCheckResponse::from_json(b"{\"allowed\":true,\"x\":\"\xff\"}").is_err());
    assert!(
        AccessRequestPage { items: vec![resource(); 501], next_cursor: None }.to_json().is_err()
    );
}

#[test]
fn decision_confirmation_is_bound_to_the_reviewed_request_input_and_actor() {
    let document = vectors();
    let vector = document
        .vectors
        .iter()
        .find(|value| value.id == "access-request-resource-approved-v1")
        .unwrap();
    let mut approved = AccessRequestResource::from_json(vector.input.as_bytes()).unwrap();
    let original = resource();
    let input = AccessRequestDecisionRequest { decision: AccessRequestOutcome::Approve };
    let actor = approved.decision.as_ref().unwrap().actor_account_id;
    approved.validate_for_decision(&original, input, actor).unwrap();
    assert_eq!(
        approved.validate_for_decision(&original, input, Uuid::now_v7()),
        Err(Error::Context)
    );
    assert_eq!(
        approved.validate_for_decision(
            &original,
            AccessRequestDecisionRequest { decision: AccessRequestOutcome::Deny },
            actor
        ),
        Err(Error::Context)
    );
    approved.fields.remote_user = "another".into();
    assert_eq!(approved.validate_for_decision(&original, input, actor), Err(Error::Context));
}
