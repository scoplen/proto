// SPDX-License-Identifier: Apache-2.0
use scoplen_api::auth_connection_draft::{
    DraftCreate, DraftRequest, DraftRequestError, DraftResource,
};
use scoplen_test_vectors::VectorDocument;
use serde::Deserialize;

#[derive(Deserialize)]
struct Response {
    body: String,
    organization: String,
    etag: Option<String>,
    cache: Option<String>,
    pragma: Option<String>,
}

#[test]
fn independent_vectors_bind_bounded_issuer_and_resource_to_the_current_organization() {
    let doc =
        VectorDocument::parse_str(include_str!("../../../vectors/auth-connection-draft.json"))
            .unwrap();
    for v in doc.vectors {
        let actual = match v.kind.as_str() {
            "auth.draft.create" => {
                DraftCreate::from_json(v.input.as_bytes()).and_then(|r| r.to_json())
            }
            "auth.draft.resource" => {
                let response: Response = serde_json::from_str(&v.input).unwrap();
                DraftResource::from_http_json(
                    response.body.as_bytes(),
                    response.organization.parse().unwrap(),
                    response.etag.as_deref(),
                    response.cache.as_deref(),
                    response.pragma.as_deref(),
                )
                .and_then(|r| r.to_json())
            }
            other => panic!("unrecognized vector kind {other}"),
        };
        if v.expected == "rejected" {
            assert!(actual.is_err(), "{}", v.id);
        } else {
            assert_eq!(actual.unwrap(), v.expected.as_bytes(), "{}", v.id);
        }
    }
    assert!(DraftCreate::from_json(&[255]).is_err());
}

#[test]
fn draft_http_syntax_requires_exact_methods_headers_conditions_and_empty_reads() {
    use DraftRequestError::{Invalid, MediaType, PreconditionRequired, TooLarge};
    let id = "0191d3e0-8000-7000-8000-000000000002";
    let key = ("Idempotency-Key", id);
    let json = ("Content-Type", "application/json");
    let empty = ("If-None-Match", "*");
    let tag = ("If-Match", "\"generation\"");
    let body = br#"{"data":{"issuer":"https://issuer.example/tenant/"}}"#;
    assert!(matches!(
        DraftRequest::from_http("POST", None, [key, empty, json], body),
        Ok(DraftRequest::Create(_, _))
    ));
    assert_eq!(DraftRequest::from_http("GET", None, [], &[]), Ok(DraftRequest::Read));
    assert_eq!(
        DraftRequest::from_http("DELETE", None, [key, tag], &[]),
        Ok(DraftRequest::Cancel(id.parse().unwrap(), tag.1))
    );
    for (method, query, headers, payload, expected) in [
        ("POST", None, vec![key, json], body.as_slice(), PreconditionRequired),
        ("DELETE", None, vec![key], &[], PreconditionRequired),
        ("GET", Some(""), vec![], &[], Invalid),
        ("GET", None, vec![key], &[], Invalid),
        ("GET", None, vec![empty], &[], Invalid),
        ("GET", None, vec![tag], &[], Invalid),
        ("GET", None, vec![("If-Modified-Since", "yesterday")], &[], Invalid),
        ("GET", None, vec![], b" ", Invalid),
        ("DELETE", None, vec![key, tag], b"{}", Invalid),
        ("POST", None, vec![key, empty, tag, json], body, Invalid),
        ("DELETE", None, vec![key, empty, tag], &[], Invalid),
        ("POST", None, vec![key, empty, ("if-none-match", "*"), json], body, Invalid),
        ("POST", None, vec![key, key, empty, json], body, Invalid),
        ("POST", None, vec![empty, json], body, Invalid),
        ("PATCH", None, vec![], &[], Invalid),
        ("DELETE", None, vec![key, ("If-Match", "*")], &[], Invalid),
        ("POST", None, vec![key, ("If-None-Match", "\"other\""), json], body, Invalid),
        ("POST", None, vec![key, empty], body, MediaType),
        ("POST", None, vec![key, empty, ("Content-Type", "text/plain")], body, MediaType),
        ("POST", None, vec![key, empty, json], &[32; 4097], TooLarge),
    ] {
        assert_eq!(DraftRequest::from_http(method, query, headers, payload), Err(expected));
    }
}
