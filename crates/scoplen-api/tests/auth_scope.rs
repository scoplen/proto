// SPDX-License-Identifier: Apache-2.0
use std::collections::HashSet;

use scoplen_api::{
    ProblemDetails,
    auth::{DeviceAccessOperation, DeviceAccessScope, INITIAL_DEVICE_ACCESS_SCOPE},
};
use scoplen_crypto::{
    DeviceAccessToken, DeviceAccessTokenClaims, DpopError, DpopProof, DpopTarget, DpopToken,
    Ed25519SigningKey, P256SigningKey, TrustedDeviceAccessTokenKeys, dpop_jwk_thumbprint,
};
use scoplen_test_vectors::VectorDocument;
use serde::Deserialize;
use uuid::Uuid;

#[derive(Deserialize)]
struct RouteInput {
    method: String,
    route_template: String,
}

#[derive(Deserialize)]
struct ContainsInput {
    scope: String,
    required: String,
}

#[test]
fn published_scope_vectors_use_the_public_registry() {
    let document = VectorDocument::parse_str(include_str!("../../../vectors/auth-scopes.json"))
        .expect("D-107 scope vectors");
    let mut initial = 0;
    let mut tokens = 0;
    let mut routes = 0;
    let mut contains = 0;
    let mut problems = 0;
    for vector in document.vectors {
        let actual = match vector.kind.as_str() {
            "auth.scope.initial" => {
                assert_eq!(vector.input, "first-party-device");
                initial += 1;
                INITIAL_DEVICE_ACCESS_SCOPE.to_owned()
            }
            "auth.scope.token" => {
                tokens += 1;
                DeviceAccessScope::from_token(&vector.input)
                    .map_or("unknown", DeviceAccessScope::as_str)
                    .to_owned()
            }
            "auth.scope.operation" => {
                routes += 1;
                let input: RouteInput = serde_json::from_str(&vector.input).expect(&vector.id);
                DeviceAccessOperation::from_route(&input.method, &input.route_template).map_or_else(
                    || "unmapped".to_owned(),
                    |operation| {
                        operation
                            .accepted_scopes()
                            .iter()
                            .map(|scope| scope.as_str())
                            .collect::<Vec<_>>()
                            .join("|")
                    },
                )
            }
            "auth.scope.contains" => {
                contains += 1;
                let input: ContainsInput = serde_json::from_str(&vector.input).expect(&vector.id);
                let required =
                    DeviceAccessScope::from_token(&input.required).expect("registered requirement");
                if required.is_present_in(&input.scope) { "present" } else { "missing" }.to_owned()
            }
            "auth.scope.problem" => {
                problems += 1;
                let problem: ProblemDetails =
                    serde_json::from_str(&vector.input).expect(&vector.id);
                assert_eq!(problem.status, 403);
                assert_eq!(problem.code.as_str(), "policy.denied");
                assert!(!problem.changed && !problem.retryable);
                assert_eq!(
                    ProblemDetails::from_cbor(&problem.to_cbor().expect("problem CBOR")),
                    Ok(problem.clone())
                );
                serde_json::to_string(&problem).expect("problem JSON")
            }
            _ => panic!("unrecognized scope vector {}", vector.kind),
        };
        assert_eq!(actual, vector.expected, "{}", vector.id);
    }
    assert_eq!(initial, 1);
    assert_eq!(problems, 1);
    assert!(tokens >= 17 && routes >= 41 && contains >= 10);
}

#[test]
fn initial_scope_ceiling_is_exact_sorted_and_unambiguous() {
    let tokens: Vec<_> =
        DeviceAccessScope::ALL.into_iter().map(DeviceAccessScope::as_str).collect();
    assert_eq!(
        tokens,
        [
            "account:read",
            "ca:read",
            "ca:write",
            "certificates:issue",
            "inventory:read",
            "inventory:write",
            "keys:read",
            "keys:write",
            "orgs:create",
            "orgs:read",
            "orgs:write",
            "policies:read",
            "policies:write",
            "sync:read",
            "sync:write",
            "teams:join",
            "teams:manage"
        ]
    );
    assert_eq!(tokens.join(" "), INITIAL_DEVICE_ACCESS_SCOPE);
    assert!(tokens.windows(2).all(|pair| pair[0].as_bytes() < pair[1].as_bytes()));
    for scope in DeviceAccessScope::ALL {
        assert_eq!(DeviceAccessScope::from_token(scope.as_str()), Some(scope));
        assert!(scope.is_present_in(INITIAL_DEVICE_ACCESS_SCOPE));
    }
}

#[test]
fn every_registered_operation_has_a_unique_canonical_route_and_exact_alternatives() {
    let mut routes = HashSet::new();
    for operation in DeviceAccessOperation::ALL {
        assert!(routes.insert((operation.http_method(), operation.route_template())));
        assert_eq!(
            DeviceAccessOperation::from_route(operation.http_method(), operation.route_template()),
            Some(operation)
        );
        for scope in DeviceAccessScope::ALL {
            assert_eq!(
                operation.has_accepted_scope(scope.as_str()),
                operation.accepted_scopes().contains(&scope)
            );
        }
    }
    assert_eq!(routes.len(), 82);
    for operation in
        [DeviceAccessOperation::TeamInvitationRead, DeviceAccessOperation::TeamMemberRemove]
    {
        assert_eq!(
            operation.accepted_scopes(),
            &[DeviceAccessScope::TeamsJoin, DeviceAccessScope::TeamsManage]
        );
        assert!(!operation.has_accepted_scope("teams:* orgs:write owner"));
        assert!(operation.has_accepted_scope("teams:join"));
        assert!(operation.has_accepted_scope("teams:manage"));
    }
}

#[test]
fn notification_routes_accept_both_defined_opening_methods_with_exact_read_scope() {
    for method in ["GET", "CONNECT"] {
        let operation = DeviceAccessOperation::from_route(method, "/sync/v1/notify")
            .expect("registered notification handshake");
        assert_eq!(operation, DeviceAccessOperation::Notifications);
        assert_eq!(operation.accepted_scopes(), &[DeviceAccessScope::SyncRead]);
        for scope in DeviceAccessScope::ALL {
            assert_eq!(
                operation.has_accepted_scope(scope.as_str()),
                scope == DeviceAccessScope::SyncRead
            );
        }
    }
}

#[test]
fn notification_routes_reject_other_methods_paths_and_queries() {
    for method in [
        "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE", "get", "connect", "Get",
        "Connect", "CONNECT ", " CONNECT",
    ] {
        assert_eq!(DeviceAccessOperation::from_route(method, "/sync/v1/notify"), None);
    }
    for method in ["GET", "CONNECT"] {
        for route in [
            "/sync/v1/notify/",
            "/sync/v1/Notify",
            "/sync/v1/%6Eotify",
            "/sync/v1/notify?",
            "/sync/v1/notify?future=1",
            "/sync/v1/notify#fragment",
            "/sync/v1/notify/events",
            "https://example.com/sync/v1/notify",
        ] {
            assert_eq!(DeviceAccessOperation::from_route(method, route), None, "{method} {route}");
        }
    }
    for operation in DeviceAccessOperation::ALL {
        if operation != DeviceAccessOperation::Notifications {
            assert_eq!(
                DeviceAccessOperation::from_route("CONNECT", operation.route_template()),
                None
            );
        }
    }
}

#[test]
fn unknown_valid_scope_claims_remain_verifiable_and_grant_no_registered_rights() {
    const NOW: u64 = 1_700_000_000;
    let issuer = "https://control.example.com";
    let signing_key = Ed25519SigningKey::from_bytes(&[0x42; 32]).expect("synthetic signing key");
    let device = P256SigningKey::from_bytes(&[0x24; 32]).expect("synthetic device key");
    let mut trusted = TrustedDeviceAccessTokenKeys::new(issuer).expect("canonical issuer");
    trusted.insert("access-1", &signing_key.public_key()).expect("trusted signer");
    let id = |suffix| {
        Uuid::parse_str(&format!("00000000-0000-7000-8000-{suffix:012x}")).expect("UUIDv7")
    };
    for scope in ["future:read", "admin owner sync:*", "SYNC:READ", INITIAL_DEVICE_ACCESS_SCOPE] {
        let claims = DeviceAccessTokenClaims {
            iss: issuer.to_owned(),
            sub: id(1),
            did: id(2),
            jti: id(3),
            cnf_jkt: dpop_jwk_thumbprint(&device.public_key_sec1()).expect("thumbprint"),
            org: vec![],
            scope: scope.to_owned(),
            iat: NOW,
            exp: NOW + 600,
        };
        let token = DeviceAccessToken::sign(
            &signing_key,
            &trusted,
            "access-1",
            &device.public_key_sec1(),
            &claims,
        )
        .expect("D-100 lexical scope compatibility");
        let verified = token.verify(&trusted, NOW).expect("valid signature and claims");
        assert_eq!(verified.claims().scope, scope);
        for operation in DeviceAccessOperation::ALL {
            assert_eq!(
                operation.has_accepted_scope(&verified.claims().scope),
                scope == INITIAL_DEVICE_ACCESS_SCOPE
            );
        }
    }
}

#[test]
fn authored_openapi_uses_the_shared_scope_ceiling_and_account_requirement() {
    let document: serde_json::Value =
        serde_json::from_str(include_str!("../openapi/v1.yaml")).expect("authored OpenAPI");
    assert_eq!(
        document["paths"]["/auth/device"]["post"]["x-scoplen-initial-device-scope"],
        INITIAL_DEVICE_ACCESS_SCOPE
    );
    assert_eq!(
        document["paths"]["/accounts/me"]["get"]["x-scoplen-required-device-scope"],
        DeviceAccessScope::AccountRead.as_str()
    );
    assert_eq!(
        document["paths"]["/accounts/me/devices"]["get"]["x-scoplen-required-device-scope"],
        DeviceAccessScope::AccountRead.as_str()
    );
}

#[test]
fn group_policy_operations_match_authored_routes_and_independent_coarse_permissions() {
    let document: serde_json::Value =
        serde_json::from_str(include_str!("../openapi/v1.yaml")).expect("authored OpenAPI");
    let operations = [
        (
            DeviceAccessOperation::OrganizationGroupCreate,
            "POST",
            "/groups",
            DeviceAccessScope::TeamsManage,
        ),
        (
            DeviceAccessOperation::OrganizationGroupList,
            "GET",
            "/groups",
            DeviceAccessScope::PoliciesRead,
        ),
        (
            DeviceAccessOperation::OrganizationGroupRead,
            "GET",
            "/groups/{id}",
            DeviceAccessScope::PoliciesRead,
        ),
        (
            DeviceAccessOperation::OrganizationGroupReplace,
            "PUT",
            "/groups/{id}",
            DeviceAccessScope::TeamsManage,
        ),
        (
            DeviceAccessOperation::OrganizationGroupDelete,
            "DELETE",
            "/groups/{id}",
            DeviceAccessScope::TeamsManage,
        ),
        (
            DeviceAccessOperation::OrganizationPolicyCreate,
            "POST",
            "/policies",
            DeviceAccessScope::PoliciesWrite,
        ),
        (
            DeviceAccessOperation::OrganizationPolicyList,
            "GET",
            "/policies",
            DeviceAccessScope::PoliciesRead,
        ),
        (
            DeviceAccessOperation::OrganizationPolicyRead,
            "GET",
            "/policies/{id}",
            DeviceAccessScope::PoliciesRead,
        ),
        (
            DeviceAccessOperation::OrganizationPolicyReplace,
            "PUT",
            "/policies/{id}",
            DeviceAccessScope::PoliciesWrite,
        ),
        (
            DeviceAccessOperation::OrganizationPolicyDelete,
            "DELETE",
            "/policies/{id}",
            DeviceAccessScope::PoliciesWrite,
        ),
    ];
    for (operation, method, suffix, scope) in operations {
        let template = format!("/api/v1/orgs/{{org}}{suffix}");
        assert_eq!(operation.http_method(), method);
        assert_eq!(operation.route_template(), template);
        assert_eq!(operation.accepted_scopes(), &[scope]);
        assert_eq!(DeviceAccessOperation::from_route(method, &template), Some(operation));
        assert_eq!(DeviceAccessOperation::from_route(&method.to_lowercase(), &template), None);
        assert_eq!(DeviceAccessOperation::from_route(method, &format!("{template}/")), None);
        assert_eq!(DeviceAccessOperation::from_route(method, &format!("{template}?limit=1")), None);
        let openapi_path = format!("/orgs/{{org}}{suffix}");
        assert_eq!(
            document["paths"][openapi_path][method.to_lowercase()]["x-scoplen-required-device-scope"],
            scope.as_str()
        );
        for other in DeviceAccessScope::ALL {
            assert_eq!(operation.has_accepted_scope(other.as_str()), scope == other);
        }
    }
    for path in ["/api/v1/orgs/{org}/groups/{id}", "/api/v1/orgs/{org}/policies/{id}"] {
        assert_eq!(DeviceAccessOperation::from_route("PATCH", path), None);
    }
}

#[test]
fn organization_update_proof_binds_actual_patch_and_exact_organization() {
    let operation = DeviceAccessOperation::OrganizationUpdate;
    let key = P256SigningKey::from_bytes(&[0x24; 32]).unwrap();
    let jkt = dpop_jwk_thumbprint(&key.public_key_sec1()).unwrap();
    let path = "/api/v1/orgs/019bdad6-b800-7000-8000-000000000001";
    let target =
        DpopTarget::new(operation.http_method(), "https://control.example.com", path).unwrap();
    let proof = DpopProof::sign(
        &key,
        &key.public_key_sec1(),
        &target,
        DpopToken::Protected("fixture.access"),
        1000,
        None,
    )
    .unwrap();
    assert!(
        proof.verify(&target, DpopToken::Protected("fixture.access"), &jkt, 1000, None).is_ok()
    );
    for (method, path) in [
        ("GET", path),
        ("POST", path),
        ("PATCH", "/api/v1/orgs/019bdad6-b800-7000-8000-000000000002"),
    ] {
        let other = DpopTarget::new(method, "https://control.example.com", path).unwrap();
        assert_eq!(
            proof.verify(&other, DpopToken::Protected("fixture.access"), &jkt, 1000, None),
            Err(DpopError::InvalidProof)
        );
    }
}

#[test]
fn inventory_registry_matches_each_authored_method_route_and_scope() {
    let document: serde_json::Value =
        serde_json::from_str(include_str!("../openapi/v1.yaml")).unwrap();
    let mut count = 0;
    for operation in DeviceAccessOperation::ALL {
        let scopes = operation.accepted_scopes();
        if !scopes.contains(&DeviceAccessScope::InventoryRead)
            && !scopes.contains(&DeviceAccessScope::InventoryWrite)
        {
            continue;
        }
        assert_eq!(scopes.len(), 1);
        let path = operation.route_template().strip_prefix("/api/v1").unwrap();
        let method = operation.http_method().to_ascii_lowercase();
        let authored = &document["paths"][path][&method];
        assert_eq!(authored["x-scoplen-required-device-scope"], scopes[0].as_str());
        assert_eq!(
            authored["security"],
            serde_json::json!([{ "accessToken": [], "dpopProof": [] }])
        );
        count += 1;
    }
    assert_eq!(count, 35);
}

#[test]
fn public_user_ca_and_issuance_routes_match_the_authored_scope_contract() {
    let document: serde_json::Value =
        serde_json::from_str(include_str!("../openapi/v1.yaml")).unwrap();
    for operation in [
        DeviceAccessOperation::UserCaList,
        DeviceAccessOperation::UserCaRead,
        DeviceAccessOperation::UserCaKrlRead,
        DeviceAccessOperation::UserCaCreate,
        DeviceAccessOperation::UserCertificateIssue,
    ] {
        let path = operation.route_template().strip_prefix("/api/v1").unwrap();
        let method = operation.http_method().to_ascii_lowercase();
        assert_eq!(
            document["paths"][path][method]["x-scoplen-required-device-scope"],
            operation.accepted_scopes()[0].as_str()
        );
        assert_eq!(operation.accepted_scopes().len(), 1);
        assert!(!operation.has_accepted_scope("owner orgs:write ca:* certificates:*"));
    }
    for (method, path) in [
        ("PATCH", "/api/v1/orgs/{org}/certificate-authorities/{id}"),
        ("DELETE", "/api/v1/orgs/{org}/certificate-authorities/{id}"),
        ("GET", "/api/v1/orgs/{org}/certificates"),
    ] {
        assert_eq!(DeviceAccessOperation::from_route(method, path), None);
    }
}
