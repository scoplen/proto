// SPDX-License-Identifier: Apache-2.0

use scoplen_api::gateway_ticket::{
    GatewayEdgeAddress, GatewayTicketCodecError, GatewayTicketRequest, GatewayTicketResponse,
    MAX_GATEWAY_TICKET_REQUEST_BYTES, MAX_GATEWAY_TICKET_RESPONSE_BYTES,
};
use scoplen_api::{ErrorCode, ProblemDetails};

const HOST: &str = "018f35d4-1f8f-7e2a-9e56-7a5e8a9f11a1";
const KEY: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINdamAGCsQq31Uv+08lkBzoO4XLz2qYjJa8CGmj3B1Ea";
const TICKET: &str = "e30.e30.c2ln";

fn request_json() -> String {
    format!("{{\"host\":\"{HOST}\",\"remote_user\":\"deploy\",\"ssh_public_key\":\"{KEY}\"}}")
}

fn response_json() -> String {
    format!(
        "{{\"ticket\":\"{TICKET}\",\"edge_addresses\":[{{\"host\":\"edge.example\",\"port\":443}}],\"gateway_host_ca_public_key\":\"{KEY}\"}}"
    )
}

#[test]
fn public_request_and_response_match_issuance_vectors() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../vectors/gateway-ticket-issuance.json");
    let document = scoplen_test_vectors::VectorDocument::from_path(path).expect("vectors");
    assert_eq!(document.vectors.len(), 2);
    for vector in document.vectors {
        let actual = match vector.kind.as_str() {
            "gateway.ticket_issuance.request_json" => {
                let request = GatewayTicketRequest::from_json(vector.input.as_bytes())
                    .expect("request vector");
                let encoded = request.to_json().expect("request encoding");
                assert_eq!(
                    GatewayTicketRequest::from_json(&encoded).expect("request roundtrip"),
                    request
                );
                encoded
            }
            "gateway.ticket_issuance.response_json" => {
                let response = GatewayTicketResponse::from_json(vector.input.as_bytes())
                    .expect("response vector");
                let encoded = response.to_json().expect("response encoding");
                assert_eq!(
                    GatewayTicketResponse::from_json(&encoded).expect("response roundtrip"),
                    response
                );
                encoded
            }
            other => panic!("unknown vector kind {other}"),
        };
        assert_eq!(actual, vector.expected.as_bytes(), "{}", vector.id);
    }
}

#[test]
fn request_rejects_bad_json_fields_and_forbidden_header() {
    let valid = request_json();
    assert_eq!(
        GatewayTicketRequest::from_http_json(valid.as_bytes(), true),
        Err(GatewayTicketCodecError::IdempotencyKey)
    );
    assert!(GatewayTicketRequest::from_http_json(valid.as_bytes(), false).is_ok());
    for bad in [
        "null".to_owned(),
        "{}".to_owned(),
        valid.replace(&format!("\"host\":\"{HOST}\","), ""),
        valid.replace("\"remote_user\":\"deploy\"", "\"remote_user\":7"),
        valid.replace(
            "\"remote_user\":\"deploy\"",
            "\"remote_user\":\"deploy\",\"remote_user\":\"root\"",
        ),
        valid.replace("\"remote_user\":\"deploy\"", "\"extra\":true,\"remote_user\":\"deploy\""),
        valid.replace(HOST, "018f35d4-1f8f-4e2a-9e56-7a5e8a9f11a1"),
        valid.replace(HOST, "018F35D4-1F8F-7E2A-9E56-7A5E8A9F11A1"),
        valid.replace("deploy", "de\\u0000ploy"),
        valid.replace("deploy", "de\\u000aploy"),
        valid.replace("deploy", &"x".repeat(256)),
    ] {
        assert!(GatewayTicketRequest::from_json(bad.as_bytes()).is_err(), "bad request accepted");
    }
    let mut exact = valid.clone();
    exact.push_str(&" ".repeat(MAX_GATEWAY_TICKET_REQUEST_BYTES - exact.len()));
    assert!(GatewayTicketRequest::from_json(exact.as_bytes()).is_ok());
    exact.push(' ');
    assert_eq!(
        GatewayTicketRequest::from_json(exact.as_bytes()),
        Err(GatewayTicketCodecError::RequestTooLarge)
    );
    assert_eq!(GatewayTicketRequest::from_json(&[0xff]), Err(GatewayTicketCodecError::InvalidJson));
}

#[test]
fn request_rejects_noncanonical_or_unsupported_ssh_keys() {
    let valid = request_json();
    let alternatives = [
        KEY.replace("ssh-ed25519 ", "ssh-rsa "),
        format!("{KEY} comment"),
        format!("command=\"x\" {KEY}"),
        format!("{KEY}\n"),
        KEY.replace("B1Ea", "B1E"),
        KEY.replace('+', "-"),
        KEY.replace("ssh-ed25519", "ssh-ed25519-cert-v01@openssh.com"),
        "-----BEGIN OPENSSH PRIVATE KEY-----".to_owned(),
        "x".repeat(8193),
    ];
    for bad in alternatives {
        let input = valid.replace(KEY, &bad.replace('\n', "\\n"));
        assert!(GatewayTicketRequest::from_json(input.as_bytes()).is_err(), "invalid key accepted");
    }
}

#[test]
fn response_accepts_extensions_but_rejects_duplicates_at_every_level() {
    let valid = response_json();
    let extended = valid.replace("\"port\":443", "\"port\":443,\"priority\":2").replace(
        &format!("\"gateway_host_ca_public_key\":\"{KEY}\""),
        &format!("\"gateway_host_ca_public_key\":\"{KEY}\",\"future\":{{\"nested\":true}}"),
    );
    assert_eq!(
        GatewayTicketResponse::from_json(extended.as_bytes()).expect("extensions"),
        GatewayTicketResponse::from_json(valid.as_bytes()).expect("base")
    );
    for bad in [
        extended.replace("\"priority\":2", "\"priority\":2,\"priority\":3"),
        extended.replace("\"nested\":true", "\"nested\":true,\"nested\":false"),
        extended.replace("\"future\":{", "\"future\":null,\"future\":{"),
        valid.replace(
            &format!("\"ticket\":\"{TICKET}\""),
            &format!("\"ticket\":\"{TICKET}\",\"ticket\":\"{TICKET}\""),
        ),
        valid.replace("\"port\":443", "\"port\":443,\"port\":8443"),
    ] {
        assert!(
            GatewayTicketResponse::from_json(bad.as_bytes()).is_err(),
            "duplicate key accepted"
        );
    }
}

#[test]
fn response_rejects_malformed_ticket_addresses_and_ca_key() {
    let valid = response_json();
    for (case, bad) in [
        valid.replace(TICKET, "a.b.c"),
        valid.replace(TICKET, "e30.e30.c2ln="),
        valid.replace(TICKET, "e30..c2ln"),
        valid.replace(TICKET, "e30.e30.c2ln.extra"),
        valid.replace(TICKET, &format!("{}.e30.c2ln", "a".repeat(4096))),
        valid.replace("edge.example", "Edge.example"),
        valid.replace("edge.example", "edge.example."),
        valid.replace("edge.example", "01.2.3.4"),
        valid.replace("edge.example", "edge.123"),
        valid.replace("edge.example", "edge.0x1a"),
        valid.replace("edge.example", "0x"),
        valid.replace("edge.example", "edge.0x"),
        valid.replace("edge.example", "[2001:db8::1]"),
        valid.replace("edge.example", "edge.example:443"),
        valid.replace("\"port\":443", "\"port\":0"),
        valid.replace("\"port\":443", "\"port\":65536"),
        valid.replace("\"port\":443", "\"port\":1.0"),
        valid.replace("\"port\":443", "\"port\":\"443\""),
        valid.replace(KEY, "ssh-rsa not-a-key"),
        valid.replace("\"edge_addresses\":[{\"host\":\"edge.example\",\"port\":443}]", "\"edge_addresses\":[]"),
        valid.replace("\"edge_addresses\":[{\"host\":\"edge.example\",\"port\":443}]", "\"edge_addresses\":[{\"host\":\"edge.example\",\"port\":443},{\"host\":\"edge.example\",\"port\":443}]"),
    ]
    .into_iter()
    .enumerate()
    {
        assert!(GatewayTicketResponse::from_json(bad.as_bytes()).is_err(), "bad response accepted: case {case}");
    }
    let one = r#"{"host":"edge.example","port":443}"#;
    let too_many = valid.replace(one, &vec![one; 17].join(","));
    assert!(GatewayTicketResponse::from_json(too_many.as_bytes()).is_err());
    let mut exact = valid.clone();
    exact.push_str(&" ".repeat(MAX_GATEWAY_TICKET_RESPONSE_BYTES - exact.len()));
    assert!(GatewayTicketResponse::from_json(exact.as_bytes()).is_ok());
    exact.push(' ');
    assert_eq!(
        GatewayTicketResponse::from_json(exact.as_bytes()),
        Err(GatewayTicketCodecError::ResponseTooLarge)
    );
}

#[test]
fn public_constructors_preserve_preference_order_and_redact_values() {
    let request = GatewayTicketRequest::new(HOST.parse().expect("uuid"), "secret-user", KEY)
        .expect("request");
    let edges = vec![
        GatewayEdgeAddress::new("edge.example", 443).expect("edge"),
        GatewayEdgeAddress::new("2001:db8::1", 8443).expect("ipv6"),
    ];
    let response = GatewayTicketResponse::new(TICKET, edges.clone(), KEY).expect("response");
    assert_eq!(response.edge_addresses, edges);
    let debug = format!("{request:?} {response:?} {edges:?}");
    for value in ["secret-user", KEY, TICKET, "edge.example", "2001:db8::1", "8443", HOST] {
        assert!(!debug.contains(value), "credential or input leaked in Debug");
    }
    let error = GatewayTicketResponse::new("header.payload.signature", edges, KEY)
        .expect_err("invalid ticket");
    assert!(!error.to_string().contains("header.payload.signature"));
}

#[test]
fn gateway_invalid_request_has_a_published_problem_vector() {
    assert!(ErrorCode::new("gateway.invalid_request").expect("code").is_known());
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../vectors/api-problem.json");
    let document = scoplen_test_vectors::VectorDocument::from_path(path).expect("vectors");
    for (id, status) in [
        ("api-problem-gateway-invalid-request-json", 400),
        ("api-problem-gateway-request-too-large-json", 413),
    ] {
        let vector =
            document.vectors.iter().find(|vector| vector.id == id).expect("gateway problem vector");
        let problem: ProblemDetails = serde_json::from_str(&vector.input).expect("problem");
        assert_eq!(problem.code.as_str(), "gateway.invalid_request");
        assert_eq!(problem.status, status);
        assert!(!problem.changed && !problem.retryable);
        assert_eq!(serde_json::to_string(&problem).expect("encode"), vector.expected);
    }
}
