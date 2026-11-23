// SPDX-License-Identifier: Apache-2.0

use scoplen_api::{
    account_browser::{AccountBrowserAccessOperation, AccountBrowserFetchCredentials},
    auth::DeviceAccessOperation,
    auth_connection_draft::{
        DraftRequestError,
        test_login::{
            DraftLoginAttempt, DraftLoginCredentials, DraftLoginRequest, DraftLoginStarted,
        },
    },
};
use uuid::Uuid;

const ORG: &str = "0191d3e0-8000-7000-8000-000000000001";
const GENERATION: &str = "0191d3e0-8000-7000-8000-000000000002";
const ATTEMPT: &str = "0191d3e0-8000-7000-8000-000000000003";
const ISSUER: &str = "https://issuer.example:8443/tenant/";
const JSON: (&str, &str) = ("Content-Type", "application/json");
const TAG: (&str, &str) = ("If-Match", "\"0191d3e0-8000-7000-8000-000000000002\"");
const BODY: &[u8] = br#"{"client_id":"fixture id","client_secret":" test secret "}"#;

#[test]
fn draft_login_request_has_exact_headers_and_preserves_redacted_credentials() {
    use DraftRequestError::{Invalid, MediaType, PreconditionRequired, TooLarge};
    let start = DraftLoginRequest::from_http("POST", None, [JSON, TAG], BODY).unwrap();
    assert!(!format!("{start:?}").contains("test secret"));
    let DraftLoginRequest::Start { if_match, credentials } = start else {
        panic!("expected start")
    };
    assert_eq!(if_match, TAG.1);
    assert_eq!(credentials.client_secret.as_bytes(), b" test secret ");
    assert_eq!(credentials.client_id.as_bytes(), b"fixture id");
    assert_eq!(credentials.to_json().unwrap().as_bytes(), BODY);
    let mut exact_body = vec![b' '; 4_096 - BODY.len()];
    exact_body.extend(BODY);
    assert!(DraftLoginRequest::from_http("POST", None, [JSON, TAG], &exact_body).is_ok());
    exact_body.push(b' ');
    assert_eq!(DraftLoginRequest::from_http("POST", None, [JSON, TAG], &exact_body), Err(TooLarge));
    assert_eq!(DraftLoginRequest::from_http("POST", None, [JSON], BODY), Err(PreconditionRequired));
    assert_eq!(DraftLoginRequest::from_http("POST", None, [TAG], BODY), Err(MediaType));
    assert_eq!(
        DraftLoginRequest::from_http("POST", None, [JSON, TAG], &[b' '; 4097]),
        Err(TooLarge)
    );
    for headers in [
        vec![JSON, TAG, ("if-match", TAG.1)],
        vec![JSON, TAG, ("Idempotency-Key", ORG)],
        vec![JSON, ("If-Match", "*")],
        vec![JSON, TAG, ("If-None-Match", "*")],
    ] {
        assert_eq!(DraftLoginRequest::from_http("POST", None, headers, BODY), Err(Invalid));
    }
    assert_eq!(DraftLoginRequest::from_http("GET", None, [], &[]), Ok(DraftLoginRequest::Read));
    assert_eq!(DraftLoginRequest::from_http("GET", Some(""), [], &[]), Err(Invalid));
    assert_eq!(DraftLoginRequest::from_http("GET", None, [TAG], &[]), Err(Invalid));
    assert_eq!(DraftLoginRequest::from_http("GET", None, [], BODY), Err(Invalid));

    for invalid in [
        br#"{"client_id":"","client_secret":"fixture"}"#.as_slice(),
        br#"{"client_id":"fixture","client_secret":"line\nfeed"}"#,
        br#"{"client_id":"fixture","client_secret":"first","client_secret":"second"}"#,
        br#"{"client_id":"fixture","client_secret":"fixture","issuer":"https://another.example"}"#,
    ] {
        assert!(DraftLoginCredentials::from_json(invalid).is_err());
    }
    for (count, accepted) in [(256, true), (257, false)] {
        let body =
            serde_json::json!({"client_id":"fixture", "client_secret":"\u{e9}".repeat(count)});
        assert_eq!(DraftLoginCredentials::from_json(body.to_string().as_bytes()).is_ok(), accepted);
    }
}

fn ids() -> (Uuid, Uuid, Uuid) {
    (ORG.parse().unwrap(), GENERATION.parse().unwrap(), ATTEMPT.parse().unwrap())
}

#[test]
fn status_and_start_responses_are_bound_to_original_context_and_provider_origin() {
    let (org, generation, attempt) = ids();
    let mut body = serde_json::json!({
        "id": ATTEMPT, "organization_id": ORG, "draft_generation": GENERATION,
        "status": "verified", "expires_at": "2026-11-23T03:00:00.000Z"
    });
    let status = |body: &serde_json::Value, ids| {
        DraftLoginAttempt::from_http_json(
            body.to_string().as_bytes(),
            ids,
            Some("no-store"),
            Some("no-cache"),
        )
    };
    let wire = status(&body, ids()).unwrap().to_json().unwrap();
    assert_eq!(serde_json::from_slice::<serde_json::Value>(&wire).unwrap(), body);
    let mut exact_response = vec![b' '; 8_192 - wire.len()];
    exact_response.extend(&wire);
    let padded = |bytes: &[u8]| {
        DraftLoginAttempt::from_http_json(bytes, ids(), Some("no-store"), Some("no-cache"))
    };
    assert!(padded(&exact_response).is_ok());
    exact_response.push(b' ');
    assert!(padded(&exact_response).is_err());
    for wrong in [(generation, generation, attempt), (org, org, attempt), (org, generation, org)] {
        assert!(status(&body, wrong).is_err());
    }
    assert!(
        DraftLoginAttempt::from_http_json(&wire, ids(), Some("public"), Some("no-cache")).is_err()
    );
    let start = |body: &serde_json::Value| {
        DraftLoginStarted::from_http_json(
            body.to_string().as_bytes(),
            (org, generation),
            ISSUER,
            Some("no-store"),
            Some("no-cache"),
        )
    };
    body["authorization_url"] = "https://issuer.example:8443/authorize?state=test".into();
    assert!(status(&body, ids()).is_err());
    assert!(start(&body).is_err());
    body["status"] = "pending".into();
    let started = start(&body).unwrap();
    assert!(!format!("{started:?}").contains("state=test"));
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(started.to_json(ISSUER).unwrap().as_bytes())
            .unwrap(),
        body
    );
    for wrong in [
        "https://issuer.example/authorize?state=test",
        "https://other.example:8443/authorize",
        "http://issuer.example:8443/authorize",
        "https://@issuer.example:8443/authorize",
        "https://issuer.example:8443/authorize#fragment",
        "/authorize",
    ] {
        body["authorization_url"] = wrong.into();
        assert!(start(&body).is_err(), "invalid navigation accepted");
    }
}

#[test]
fn test_start_is_the_only_browser_business_operation_that_accepts_cookie_delivery() {
    use AccountBrowserAccessOperation::{AuthDraftTestRead, AuthDraftTestStart};
    for operation in [AuthDraftTestStart, AuthDraftTestRead] {
        assert_eq!(
            AccountBrowserAccessOperation::from_route(
                operation.http_method(),
                operation.route_template()
            ),
            Some(operation)
        );
        assert!(
            DeviceAccessOperation::from_route(operation.http_method(), operation.route_template())
                .is_none()
        );
        assert!(!operation.uses_browser_writer_receipt());
    }
    assert_eq!(
        AccountBrowserAccessOperation::ALL
            .into_iter()
            .filter(|op| op.fetch_credentials() == AccountBrowserFetchCredentials::SameOrigin)
            .collect::<Vec<_>>(),
        [AuthDraftTestStart]
    );
}
