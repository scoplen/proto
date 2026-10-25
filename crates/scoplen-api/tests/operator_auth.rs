// SPDX-License-Identifier: Apache-2.0
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use cedar_policy::{Context, Decision, Entities, PolicySet, Request, Schema};
use scoplen_api::{
    auth::{
        DeviceAccessOperation, INITIAL_OPERATOR_ACCESS_SCOPE, OperatorAccessOperation,
        OperatorAccessRequirement, OperatorAccessScope,
    },
    control_plane::{CEDAR_SCHEMA, OrganizationAuthorizationContext, OrganizationAuthorizer},
    operator_auth::*,
};
use serde_json::{Value, json};
use std::str::FromStr;
use uuid::Uuid;

fn canonical(kind: &str, input: &[u8]) -> Result<Vec<u8>, OperatorAuthCodecError> {
    match kind {
        "operator.problem" => Ok(serde_json::to_vec(
            &serde_json::from_slice::<scoplen_api::ProblemDetails>(input).unwrap(),
        )
        .unwrap()),
        "operator.setup-options.request" => {
            OperatorSetupOptionsRequest::from_json(input)?.to_json()
        }
        "operator.setup-finish.request" => OperatorSetupFinishRequest::from_json(input)?.to_json(),
        "operator.login-options.request" => {
            OperatorLoginOptionsRequest::from_json(input)?.to_json()
        }
        "operator.login-finish.request" => OperatorLoginFinishRequest::from_json(input)?.to_json(),
        "operator.setup-options.response" => {
            OperatorSetupOptionsResponse::from_json(input)?.to_json()
        }
        "operator.login-options.response" => {
            OperatorLoginOptionsResponse::from_json(input)?.to_json()
        }
        "operator.setup-finish.response" => {
            OperatorSetupFinishResponse::from_json(input)?.to_json()
        }
        _ => panic!("unregistered Operator vector kind {kind}"),
    }
}

#[test]
fn independent_public_vectors_and_named_parser_corpus_replay() {
    let document = scoplen_test_vectors::VectorDocument::parse_str(include_str!(
        "../../../vectors/operator-auth.json"
    ))
    .unwrap();
    assert!(document.vectors.len() >= 16);
    for vector in document.vectors {
        if let Some(kind) = vector.kind.strip_suffix(".reject") {
            assert!(canonical(kind, vector.input.as_bytes()).is_err(), "{}", vector.id);
        } else {
            assert_eq!(
                canonical(&vector.kind, vector.input.as_bytes()).unwrap(),
                vector.expected.as_bytes(),
                "{}",
                vector.id
            );
        }
    }
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fuzz/corpus/api_json");
    for (seed, kind) in [
        ("setup-options-request", "operator.setup-options.request"),
        ("setup-finish-opaque", "operator.setup-finish.request"),
        ("login-options-request", "operator.login-options.request"),
        ("login-finish-opaque", "operator.login-finish.request"),
        ("setup-options-response", "operator.setup-options.response"),
        ("login-options-response", "operator.login-options.response"),
        ("setup-finish-response", "operator.setup-finish.response"),
    ] {
        let exact = std::fs::read(root.join(format!("seed-operator-{seed}-exact"))).unwrap();
        assert!(canonical(kind, &exact).is_ok());
        let oversized =
            std::fs::read(root.join(format!("seed-operator-{seed}-oversized"))).unwrap();
        assert!(matches!(canonical(kind, &oversized), Err(OperatorAuthCodecError::TooLarge(_))));
    }
}

fn id() -> Uuid {
    Uuid::parse_str("018f35d4-1f8f-7e2a-9e56-7a5e8a9f11a1").unwrap()
}

fn setup() -> OperatorSetupFinishRequest {
    OperatorSetupFinishRequest {
        setup_token: [0x91; 32],
        ceremony_id: id(),
        credential_id: vec![0xff],
        client_data_json: vec![0xff],
        attestation_object: vec![0xff],
    }
}

fn login() -> OperatorLoginFinishRequest {
    OperatorLoginFinishRequest {
        ceremony_id: id(),
        credential_id: vec![0xff],
        client_data_json: vec![0xff],
        authenticator_data: vec![0; 37],
        signature: vec![0xff; 8],
        user_handle: [0xff; 16],
    }
}

fn options() -> OperatorSetupOptionsResponse {
    OperatorSetupOptionsResponse {
        ceremony_id: id(),
        expires_at: "2026-10-22T12:00:00Z".into(),
        operator_id: id(),
        rp_id: "scoplen.example.test".into(),
        challenge: [0x11; 32],
        timeout: 300_000,
    }
}

#[test]
fn every_public_message_round_trips_without_interpreting_embedded_webauthn() {
    macro_rules! check {
        ($value:expr, $kind:ty) => {{
            let original = $value;
            let bytes = original.to_json().unwrap();
            assert_eq!(<$kind>::from_json(&bytes), Ok(original));
        }};
    }
    check!(OperatorSetupOptionsRequest { setup_token: [1; 32] }, OperatorSetupOptionsRequest);
    check!(setup(), OperatorSetupFinishRequest);
    check!(OperatorLoginOptionsRequest, OperatorLoginOptionsRequest);
    check!(login(), OperatorLoginFinishRequest);
    check!(options(), OperatorSetupOptionsResponse);
    check!(
        OperatorLoginOptionsResponse {
            ceremony_id: id(),
            expires_at: "2026-10-22T12:00:00Z".into(),
            rp_id: "scoplen.example.test".into(),
            challenge: [3; 32]
        },
        OperatorLoginOptionsResponse
    );
    check!(OperatorSetupFinishResponse { operator_id: id() }, OperatorSetupFinishResponse);
    // Invalid UTF-8 JSON, CBOR and DER are lexical bytes. The live finish verifier consumes
    // the ceremony before rejecting these, which cannot happen in this outer wire codec.
    assert_eq!(
        OperatorLoginFinishRequest::from_json(&login().to_json().unwrap()).unwrap().signature,
        vec![0xff; 8]
    );
    assert!(!format!("{:?}", setup()).contains("145"));
    assert_eq!(OperatorLoginOptionsRequest.to_json().unwrap(), b"{}");
    let encoded = String::from_utf8(setup().to_json().unwrap()).unwrap();
    assert!(encoded.starts_with("{\"setup_token\":"));
    let names =
        ["setup_token", "ceremony_id", "credential_id", "client_data_json", "attestation_object"];
    let indices = names.map(|name| encoded.find(&format!("\"{name}\":")).unwrap());
    assert!(indices.windows(2).all(|pair| pair[0] < pair[1]));
}

#[test]
fn requests_reject_outer_aliases_and_unknown_names() {
    for bytes in [
        b"[]".as_slice(),
        b"null",
        b"{\"extra\":1}",
        b"{\"extra\":{\"x\":1,\"x\":2}}",
        b"{\"setup_token\":null}",
    ] {
        assert!(OperatorLoginOptionsRequest::from_json(bytes).is_err());
    }
    let valid = serde_json::from_slice::<Value>(&setup().to_json().unwrap()).unwrap();
    for (field, value) in [
        ("setup_token", json!("AA=")),
        ("setup_token", json!("AB")),
        ("credential_id", json!("_x")),
        ("ceremony_id", json!(id().to_string().to_uppercase())),
        ("ceremony_id", json!(Uuid::nil().to_string())),
        ("extra", json!(true)),
        ("client_data_json", Value::Null),
    ] {
        let mut input = valid.clone();
        input[field] = value;
        assert!(
            OperatorSetupFinishRequest::from_json(&serde_json::to_vec(&input).unwrap()).is_err(),
            "{field}"
        );
    }
    let duplicate = format!(
        "{{\"setup_token\":\"{}\",\"setup_token\":\"{}\"}}",
        URL_SAFE_NO_PAD.encode([1; 32]),
        URL_SAFE_NO_PAD.encode([2; 32])
    );
    assert_eq!(
        OperatorSetupOptionsRequest::from_json(duplicate.as_bytes()),
        Err(OperatorAuthCodecError::InvalidJson)
    );
}

#[test]
fn decoded_byte_bounds_are_enforced_at_both_public_boundaries() {
    for (field, min, max) in [
        ("credential_id", 1, 1023),
        ("client_data_json", 1, 4096),
        ("attestation_object", 1, 16384),
    ] {
        for size in [min - 1, min, max, max + 1] {
            let mut request = setup();
            match field {
                "credential_id" => request.credential_id = vec![7; size],
                "client_data_json" => request.client_data_json = vec![7; size],
                _ => request.attestation_object = vec![7; size],
            }
            assert_eq!(request.to_json().is_ok(), (min..=max).contains(&size));
            let mut value: Value = serde_json::from_slice(&setup().to_json().unwrap()).unwrap();
            value[field] = json!(URL_SAFE_NO_PAD.encode(vec![7; size]));
            assert_eq!(
                OperatorSetupFinishRequest::from_json(&serde_json::to_vec(&value).unwrap()).is_ok(),
                (min..=max).contains(&size)
            );
        }
    }
    for (field, min, max) in
        [("authenticator_data", 37, 4096), ("signature", 8, 72), ("user_handle", 16, 16)]
    {
        for size in [min - 1, min, max, max + 1] {
            let mut value: Value = serde_json::from_slice(&login().to_json().unwrap()).unwrap();
            value[field] = json!(URL_SAFE_NO_PAD.encode(vec![7; size]));
            assert_eq!(
                OperatorLoginFinishRequest::from_json(&serde_json::to_vec(&value).unwrap()).is_ok(),
                (min..=max).contains(&size)
            );
        }
    }
}

#[test]
fn complete_body_limits_include_whitespace_and_ignored_extensions() {
    macro_rules! cap {
        ($kind:ty,$value:expr,$limit:expr) => {{
            let mut bytes = $value.to_json().unwrap();
            bytes.resize($limit, b' ');
            assert!(<$kind>::from_json(&bytes).is_ok());
            bytes.push(b' ');
            assert_eq!(<$kind>::from_json(&bytes), Err(OperatorAuthCodecError::TooLarge($limit)));
        }};
    }
    cap!(OperatorSetupOptionsRequest, OperatorSetupOptionsRequest { setup_token: [1; 32] }, 256);
    cap!(OperatorLoginOptionsRequest, OperatorLoginOptionsRequest, 256);
    cap!(OperatorSetupFinishRequest, setup(), 32768);
    cap!(OperatorLoginFinishRequest, login(), 16384);
    cap!(OperatorSetupOptionsResponse, options(), 4096);
    cap!(OperatorSetupFinishResponse, OperatorSetupFinishResponse { operator_id: id() }, 256);
}

#[test]
fn options_readers_allow_extensions_but_require_saved_policy() {
    let mut value: Value = serde_json::from_slice(&options().to_json().unwrap()).unwrap();
    value["extension"] = json!({"future":1});
    value["public_key"]["rp"]["future"] = json!(true);
    assert_eq!(
        OperatorSetupOptionsResponse::from_json(&serde_json::to_vec(&value).unwrap()),
        Ok(options())
    );
    for (pointer, replacement) in [
        ("/public_key/pubKeyCredParams/0/alg", json!(-257)),
        ("/public_key/attestation", json!("direct")),
        ("/public_key/authenticatorSelection/residentKey", json!("preferred")),
        ("/public_key/authenticatorSelection/requireResidentKey", json!(false)),
        ("/public_key/authenticatorSelection/userVerification", json!("preferred")),
        ("/public_key/excludeCredentials", json!([{}])),
        ("/public_key/user/id", json!(URL_SAFE_NO_PAD.encode([0; 16]))),
        ("/public_key/timeout", json!(1999)),
        ("/expires_at", json!("2026-10-22T12:00:00.0Z")),
    ] {
        let mut changed = value.clone();
        *changed.pointer_mut(pointer).unwrap() = replacement;
        assert!(
            OperatorSetupOptionsResponse::from_json(&serde_json::to_vec(&changed).unwrap())
                .is_err(),
            "{pointer}"
        );
    }
    let encoded = String::from_utf8(options().to_json().unwrap())
        .unwrap()
        .replace("\"name\":\"Scoplen\"", "\"name\":\"Scoplen\",\"extension\":{\"x\":1,\"x\":2}");
    assert_eq!(
        OperatorSetupOptionsResponse::from_json(encoded.as_bytes()),
        Err(OperatorAuthCodecError::InvalidJson)
    );
    for rp in [
        "127.0.0.1",
        "[::1]",
        "EXAMPLE.test",
        "example.test:443",
        "https://example.test",
        "example.test/",
        "",
        "example.test.",
    ] {
        let mut response = options();
        response.rp_id = rp.into();
        assert!(response.to_json().is_err(), "{rp}");
    }
    let response = OperatorLoginOptionsResponse {
        ceremony_id: id(),
        expires_at: options().expires_at,
        rp_id: options().rp_id,
        challenge: [3; 32],
    };
    let mut value: Value = serde_json::from_slice(&response.to_json().unwrap()).unwrap();
    for (field, replacement) in [
        ("allowCredentials", json!([{}])),
        ("timeout", json!(299_000)),
        ("userVerification", json!("preferred")),
    ] {
        value["public_key"][field] = replacement;
        assert!(
            OperatorLoginOptionsResponse::from_json(&serde_json::to_vec(&value).unwrap()).is_err()
        );
        value = serde_json::from_slice(&response.to_json().unwrap()).unwrap();
    }
}

#[test]
fn operator_scope_is_independent_and_routes_fail_closed() {
    assert_eq!(INITIAL_OPERATOR_ACCESS_SCOPE, "personal-invitation:issue");
    let operation = OperatorAccessOperation::PersonalInvitationIssue;
    assert_eq!(
        OperatorAccessOperation::from_route("POST", operation.route_template()),
        Some(operation)
    );
    assert_eq!(DeviceAccessOperation::from_route("POST", operation.route_template()), None);
    assert_eq!(
        operation.requirement(),
        OperatorAccessRequirement::Scope(OperatorAccessScope::PersonalInvitationIssue)
    );
    for (method, path) in [
        ("GET", operation.route_template()),
        ("post", operation.route_template()),
        ("POST", "/api/v1/accounts/me"),
        ("POST", "/api/v1/admin/personal-invitations/"),
    ] {
        assert_eq!(OperatorAccessOperation::from_route(method, path), None);
    }
    for scope in [
        "*",
        "personal-invitation:*",
        "xpersonal-invitation:issue",
        "account:read",
        "PERSONAL-INVITATION:ISSUE",
    ] {
        assert!(!OperatorAccessScope::PersonalInvitationIssue.is_present_in(scope));
        assert_eq!(OperatorAccessScope::from_token(scope), None);
    }
}

#[test]
fn retired_invitation_action_is_not_registered_for_any_principal() {
    let schema = Schema::from_str(CEDAR_SCHEMA).unwrap();
    for kind in ["Operator", "Account"] {
        assert!(
            Request::new(
                format!("{kind}::\"{}\"", id()).parse().unwrap(),
                "Action::\"issuePersonalInvitation\"".parse().unwrap(),
                "Deployment::\"self\"".parse().unwrap(),
                Context::empty(),
                Some(&schema),
            )
            .is_err()
        );
    }
}

#[test]
fn tenant_owner_authority_does_not_grant_operator_or_deployment_actions() {
    let schema = Schema::from_str(CEDAR_SCHEMA).unwrap();
    let organization = Uuid::from_u128(id().as_u128() + 1);
    let membership = Uuid::from_u128(id().as_u128() + 2);
    let entities = Entities::from_json_value(json!([
        {"uid":{"type":"Account","id":id().to_string()},"attrs":{"status":"active"},"parents":[]},
        {"uid":{"type":"Organization","id":organization.to_string()},"attrs":{"name":"fixture"},"parents":[]},
        {"uid":{"type":"Membership","id":membership.to_string()},"attrs":{
            "account":{"__entity":{"type":"Account","id":id().to_string()}},
            "organization":{"__entity":{"type":"Organization","id":organization.to_string()}},
            "status":"active","roles":["owner"],"groups":[]},"parents":[]}
    ]), Some(&schema)).unwrap();
    let context = Context::from_json_str(
        &json!({
            "organization":{"__entity":{"type":"Organization","id":organization.to_string()}},
            "membership":{"__entity":{"type":"Membership","id":membership.to_string()}},
            "now":1
        })
        .to_string(),
        None,
    )
    .unwrap();
    let authorizer = OrganizationAuthorizer::new(organization, &PolicySet::new()).unwrap();
    let trusted = OrganizationAuthorizationContext::new(id(), organization, membership, 1).unwrap();
    for (kind, action, allowed) in [
        ("Account", "manage_inventory", true),
        ("Operator", "manage_inventory", false),
        ("Account", "futureDeploymentAction", false),
        ("Account", "issuePersonalInvitation", false),
    ] {
        let request = Request::new(
            format!("{kind}::\"{}\"", id()).parse().unwrap(),
            format!("Action::\"{action}\"").parse().unwrap(),
            format!("Organization::\"{organization}\"").parse().unwrap(),
            context.clone(),
            None,
        )
        .unwrap();
        assert_eq!(
            authorizer
                .authorize(&trusted, &request, &entities)
                .is_ok_and(|decision| decision == Decision::Allow),
            allowed
        );
    }
}
