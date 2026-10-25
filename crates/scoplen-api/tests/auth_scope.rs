// SPDX-License-Identifier: Apache-2.0
use std::collections::HashSet;

use scoplen_api::{
    ProblemDetails,
    auth::{DeviceAccessOperation, DeviceAccessScope, INITIAL_DEVICE_ACCESS_SCOPE},
};
use scoplen_crypto::{
    DeviceAccessToken, DeviceAccessTokenClaims, Ed25519SigningKey, P256SigningKey,
    TrustedDeviceAccessTokenKeys, dpop_jwk_thumbprint,
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
                DeviceAccessOperation::from_route(&input.method, &input.route_template)
                    .map_or("unmapped", |operation| operation.required_scope().as_str())
                    .to_owned()
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
    assert!(tokens >= 10 && routes >= 23 && contains >= 10);
}

#[test]
fn initial_scope_ceiling_is_exact_sorted_and_unambiguous() {
    let tokens: Vec<_> =
        DeviceAccessScope::ALL.into_iter().map(DeviceAccessScope::as_str).collect();
    assert_eq!(tokens, ["account:read", "keys:read", "keys:write", "sync:read", "sync:write"]);
    assert_eq!(tokens.join(" "), INITIAL_DEVICE_ACCESS_SCOPE);
    assert!(tokens.windows(2).all(|pair| pair[0].as_bytes() < pair[1].as_bytes()));
    for scope in DeviceAccessScope::ALL {
        assert_eq!(DeviceAccessScope::from_token(scope.as_str()), Some(scope));
        assert!(scope.is_present_in(INITIAL_DEVICE_ACCESS_SCOPE));
    }
}

#[test]
fn every_registered_operation_has_a_unique_canonical_route_and_required_scope() {
    let mut routes = HashSet::new();
    for operation in DeviceAccessOperation::ALL {
        assert!(routes.insert((operation.http_method(), operation.route_template())));
        assert_eq!(
            DeviceAccessOperation::from_route(operation.http_method(), operation.route_template()),
            Some(operation)
        );
        for scope in DeviceAccessScope::ALL {
            assert_eq!(
                operation.required_scope().is_present_in(scope.as_str()),
                scope == operation.required_scope()
            );
        }
    }
    assert_eq!(routes.len(), 17);
}

#[test]
fn notification_routes_accept_both_defined_opening_methods_with_exact_read_scope() {
    for method in ["GET", "CONNECT"] {
        let operation = DeviceAccessOperation::from_route(method, "/sync/v1/notify")
            .expect("registered notification handshake");
        assert_eq!(operation, DeviceAccessOperation::Notifications);
        assert_eq!(operation.required_scope(), DeviceAccessScope::SyncRead);
        for scope in DeviceAccessScope::ALL {
            assert_eq!(
                operation.required_scope().is_present_in(scope.as_str()),
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
                operation.required_scope().is_present_in(&verified.claims().scope),
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
        DeviceAccessOperation::AccountProfileRead.required_scope().as_str()
    );
    assert_eq!(
        document["paths"]["/accounts/me/devices"]["get"]["x-scoplen-required-device-scope"],
        DeviceAccessOperation::AccountDevicesRead.required_scope().as_str()
    );
}
