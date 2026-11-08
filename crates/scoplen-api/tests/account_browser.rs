// SPDX-License-Identifier: Apache-2.0
use scoplen_api::{
    account_browser::*,
    auth::{BrowserAuthTokenResponse, DeviceAccessOperation, INITIAL_DEVICE_ACCESS_SCOPE},
};
use serde_json::Value;
use std::fmt::Write as _;
use uuid::Uuid;

fn vectors() -> scoplen_test_vectors::VectorDocument {
    scoplen_test_vectors::VectorDocument::from_path(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../vectors/account-browser.json"),
    )
    .unwrap()
}

fn canonical(kind: &str, input: &[u8]) -> Result<Vec<u8>, AccountBrowserCodecError> {
    match kind {
        "options.request" => AccountBrowserPasswordOptionsRequest::from_json(input)?.to_json(),
        "options.response" => AccountBrowserPasswordOptionsResponse::from_json(input)?.to_json(),
        "login.request" => {
            Ok(AccountBrowserPasswordLoginRequest::from_json(input)?.to_json()?.as_bytes().to_vec())
        }
        "login.response" => AccountBrowserPasswordLoginResponse::from_json(input)?.to_json(),
        "refresh.request" => Ok(AccountBrowserRefreshRequest::from_json(input)?.to_json().to_vec()),
        "refresh.response" => AccountBrowserRefreshResponse::from_json(input)?.to_json(),
        "logout.request" => Ok(AccountBrowserLogoutRequest::from_json(input)?.to_json().to_vec()),
        "logout.response" => Ok(AccountBrowserLogoutResponse::from_json(input)?.to_json().to_vec()),
        _ => panic!("unknown message vector kind {kind}"),
    }
}

#[test]
fn independent_wire_digest_operation_and_writer_vectors() {
    let mut operations = 0;
    for vector in vectors().vectors {
        let kind = vector.kind.strip_prefix("account.browser.").unwrap();
        match kind {
            "access.digest" | "refresh.digest" => {
                let digest = if kind == "access.digest" {
                    AccountBrowserAccessToken::parse(&vector.input).unwrap().digest()
                } else {
                    AccountBrowserRefreshToken::parse(&vector.input).unwrap().digest()
                };
                let hex = digest.iter().fold(String::new(), |mut text, byte| {
                    write!(&mut text, "{byte:02x}").unwrap();
                    text
                });
                assert_eq!(hex, vector.expected, "{}", vector.id);
            }
            "access.reject" => {
                assert!(AccountBrowserAccessToken::parse(&vector.input).is_err(), "{}", vector.id);
            }
            "refresh.reject" => {
                assert!(AccountBrowserRefreshToken::parse(&vector.input).is_err(), "{}", vector.id);
            }
            "scope" => assert_eq!(INITIAL_ACCOUNT_BROWSER_ACCESS_SCOPE, vector.expected),
            "writer" => {
                let input: Value = serde_json::from_str(&vector.input).unwrap();
                let expected: Value = serde_json::from_str(&vector.expected).unwrap();
                let writer = AccountBrowserWriter::new(
                    Uuid::parse_str(input["account_id"].as_str().unwrap()).unwrap(),
                    Uuid::parse_str(input["family_id"].as_str().unwrap()).unwrap(),
                )
                .unwrap();
                assert_eq!(writer.kind(), expected["kind"].as_str().unwrap());
                assert_eq!(writer.family_id().to_string(), expected["origin"].as_str().unwrap());
                assert!(AccountBrowserWriter::new(Uuid::nil(), writer.family_id()).is_err());
                assert_ne!(
                    writer,
                    AccountBrowserWriter::new(
                        writer.account_id(),
                        Uuid::parse_str("0191d3e0-8000-7000-8000-000000000003").unwrap()
                    )
                    .unwrap()
                );
            }
            "operation" | "operation.logout" | "operation.reject" => {
                let input: Value = serde_json::from_str(&vector.input).unwrap();
                let operation = AccountBrowserAccessOperation::from_route(
                    input["method"].as_str().unwrap(),
                    input["path"].as_str().unwrap(),
                );
                if kind.ends_with("reject") {
                    assert!(operation.is_none(), "{}", vector.id);
                    continue;
                }
                let operation = operation.unwrap();
                operations += 1;
                if kind.ends_with("logout") {
                    assert_eq!(
                        operation.requirement(),
                        AccountBrowserAccessRequirement::SelfSessionTermination
                    );
                    continue;
                }
                let expected: Value = serde_json::from_str(&vector.expected).unwrap();
                let AccountBrowserAccessRequirement::AnyScope(scopes) = operation.requirement()
                else {
                    panic!("business operation has scopes")
                };
                let actual: Vec<_> = scopes.iter().map(|scope| scope.as_str()).collect();
                assert_eq!(
                    serde_json::to_value(actual).unwrap(),
                    expected["scopes"],
                    "{}",
                    vector.id
                );
                assert_eq!(
                    operation.uses_browser_writer_receipt(),
                    expected["writerReceipt"].as_bool().unwrap()
                );
            }
            _ => {
                let rejected = kind.ends_with(".reject");
                let result = canonical(kind.trim_end_matches(".reject"), vector.input.as_bytes());
                if rejected {
                    assert!(result.is_err(), "{}", vector.id);
                } else {
                    let bytes = result.unwrap();
                    assert_eq!(
                        serde_json::from_slice::<Value>(&bytes).unwrap(),
                        serde_json::from_str::<Value>(&vector.expected).unwrap(),
                        "{}",
                        vector.id
                    );
                    assert_eq!(canonical(kind, &bytes).unwrap(), bytes);
                }
            }
        }
    }
    assert_eq!(operations, AccountBrowserAccessOperation::ALL.len());
}

#[test]
fn complete_encoded_bounds_apply_before_reused_parsers() {
    let document = vectors();
    for kind in [
        "options.request",
        "options.response",
        "login.request",
        "login.response",
        "refresh.request",
        "refresh.response",
        "logout.request",
        "logout.response",
    ] {
        let vector =
            document.vectors.iter().find(|v| v.kind == format!("account.browser.{kind}")).unwrap();
        let limit = match kind {
            "options.request" | "refresh.request" | "logout.request" | "logout.response" => 256,
            "options.response" => 1024,
            "login.request" => 512,
            _ => 8192,
        };
        let mut input = vec![b' '; limit - vector.input.len()];
        input.extend_from_slice(vector.input.as_bytes());
        assert!(canonical(kind, &input).is_ok(), "{kind} exact");
        input.push(b' ');
        assert_eq!(
            canonical(kind, &input),
            Err(AccountBrowserCodecError::TooLarge),
            "{kind} overflow"
        );
        assert!(canonical(kind, &[b'{', b'"', 0xff, b'"', b':', b'0', b'}']).is_err());
        let mut bom = vec![0xef, 0xbb, 0xbf];
        bom.extend_from_slice(vector.input.as_bytes());
        assert!(canonical(kind, &bom).is_err());
    }
}

#[test]
fn profiles_are_separate_and_secrets_are_redacted() {
    assert_eq!(
        AccountBrowserAccessScope::ALL.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(" "),
        INITIAL_ACCOUNT_BROWSER_ACCESS_SCOPE
    );
    for forbidden in [
        "ca:read",
        "certificates:issue",
        "keys:read",
        "sync:read",
        "personal-invitation:issue",
        "*",
        "orgs:read-extra",
    ] {
        assert!(AccountBrowserAccessScope::from_token(forbidden).is_none());
    }
    assert_eq!(DeviceAccessOperation::ALL.len(), 81);
    assert!(INITIAL_DEVICE_ACCESS_SCOPE.contains("keys:write"));
    let access = AccountBrowserAccessToken::from_random_bytes(&[7; 32]);
    let refresh = AccountBrowserRefreshToken::from_random_bytes(&[7; 32]);
    assert_ne!(access.digest(), refresh.digest());
    assert!(!format!("{access:?} {refresh:?}").contains(access.as_str()));
    let response = AccountBrowserPasswordLoginResponse(
        BrowserAuthTokenResponse::new(access.as_str()).unwrap(),
    );
    assert!(!format!("{response:?}").contains(access.as_str()));
    assert_eq!(AccountBrowserOperation::ALL.len(), 4);
    for op in AccountBrowserOperation::ALL {
        assert_eq!(AccountBrowserOperation::from_route("POST", op.route()), Some(op));
        assert!(AccountBrowserOperation::from_route("GET", op.route()).is_none());
        assert!(AccountBrowserOperation::from_route("POST", &format!("{}?", op.route())).is_none());
    }
}

#[test]
fn metadata_enforces_origin_proof_and_distinct_credentials() {
    let origin = "https://example.com";
    let base = AccountBrowserHttpMetadata {
        content_type: "application/json",
        origin: Some(origin),
        dpop: Some("header.payload.signature"),
        ..Default::default()
    };
    for op in [AccountBrowserOperation::PasswordOptions, AccountBrowserOperation::PasswordLogin] {
        base.validate(op, origin).unwrap();
        AccountBrowserHttpMetadata {
            refresh_cookie_count: 2,
            has_other_refresh_credentials: true,
            ..base
        }
        .validate(op, origin)
        .unwrap();
        assert!(
            AccountBrowserHttpMetadata { authorization: Some("DPoP native"), ..base }
                .validate(op, origin)
                .is_err()
        );
    }
    let refresh = AccountBrowserHttpMetadata { refresh_cookie_count: 1, ..base };
    refresh.validate(AccountBrowserOperation::Refresh, origin).unwrap();
    for count in [0, 2] {
        assert!(
            AccountBrowserHttpMetadata { refresh_cookie_count: count, ..refresh }
                .validate(AccountBrowserOperation::Refresh, origin)
                .is_err()
        );
    }
    assert!(
        AccountBrowserHttpMetadata { has_other_refresh_credentials: true, ..refresh }
            .validate(AccountBrowserOperation::Refresh, origin)
            .is_err()
    );
    let access = AccountBrowserAccessToken::from_random_bytes(&[3; 32]);
    let auth = format!("DPoP {}", access.as_str());
    AccountBrowserHttpMetadata { authorization: Some(&auth), ..base }
        .validate(AccountBrowserOperation::Logout, origin)
        .unwrap();
    for bad in [
        AccountBrowserHttpMetadata { origin: None, ..base },
        AccountBrowserHttpMetadata { origin: Some("https://other.example"), ..base },
        AccountBrowserHttpMetadata { dpop: None, ..base },
        AccountBrowserHttpMetadata { dpop: Some(" "), ..base },
        AccountBrowserHttpMetadata { has_query: true, ..base },
        AccountBrowserHttpMetadata { has_if_match: true, ..base },
        AccountBrowserHttpMetadata { has_idempotency_key: true, ..base },
        AccountBrowserHttpMetadata { content_encoding: Some("gzip"), ..base },
    ] {
        assert!(bad.validate(AccountBrowserOperation::PasswordOptions, origin).is_err());
    }
}

#[test]
fn cookie_and_business_metadata_follow_endpoint_credential_modes() {
    assert_eq!(
        AccountBrowserOperation::PasswordOptions.fetch_credentials(),
        AccountBrowserFetchCredentials::Omit
    );
    assert_eq!(
        AccountBrowserOperation::PasswordLogin.fetch_credentials(),
        AccountBrowserFetchCredentials::SameOrigin
    );
    assert_eq!(
        AccountBrowserOperation::Refresh.fetch_credentials(),
        AccountBrowserFetchCredentials::SameOrigin
    );
    assert_eq!(
        AccountBrowserOperation::Logout.fetch_credentials(),
        AccountBrowserFetchCredentials::Omit
    );
    let refresh = AccountBrowserRefreshToken::from_random_bytes(&[3; 32]);
    let cookie = account_browser_refresh_cookie(&refresh, 123).unwrap();
    assert_eq!(
        std::str::from_utf8(cookie.as_bytes()).unwrap(),
        format!(
            "__Secure-spl-account-refresh={}; Path=/api/v1/auth/accounts/browser/refresh; HttpOnly; Secure; SameSite=Strict; Max-Age=123",
            refresh.as_str()
        )
    );
    assert!(account_browser_refresh_cookie(&refresh, 0).is_err());
    assert!(account_browser_refresh_cookie(&refresh, ACCOUNT_BROWSER_FAMILY_SECONDS + 1).is_err());
    let token = AccountBrowserAccessToken::from_random_bytes(&[5; 32]);
    let authorization = format!("DPoP {}", token.as_str());
    let base = AccountBrowserProtectedHttpMetadata {
        authorization: &authorization,
        dpop: "header.payload.signature",
        origin: None,
    };
    assert!(!format!("{base:?}").contains(token.as_str()));
    assert!(
        !format!(
            "{:?}",
            AccountBrowserHttpMetadata {
                authorization: Some(&authorization),
                dpop: Some("sensitive-proof"),
                ..Default::default()
            }
        )
        .contains(token.as_str())
    );
    assert_eq!(
        base.validate(AccountBrowserAccessOperation::AccountProfileRead, "https://example.com")
            .unwrap(),
        token
    );
    assert!(
        base.validate(AccountBrowserAccessOperation::OrganizationCreate, "https://example.com")
            .is_err()
    );
    AccountBrowserProtectedHttpMetadata { origin: Some("https://example.com"), ..base }
        .validate(AccountBrowserAccessOperation::OrganizationCreate, "https://example.com")
        .unwrap();
    assert!(
        AccountBrowserProtectedHttpMetadata { origin: Some("https://other.example"), ..base }
            .validate(AccountBrowserAccessOperation::AccountProfileRead, "https://example.com")
            .is_err()
    );
    assert!(
        AccountBrowserProtectedHttpMetadata { authorization: "DPoP eyJ.native.jwt", ..base }
            .validate(AccountBrowserAccessOperation::AccountProfileRead, "https://example.com")
            .is_err()
    );
}
