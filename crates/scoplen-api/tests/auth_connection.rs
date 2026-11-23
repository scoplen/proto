// SPDX-License-Identifier: Apache-2.0
use scoplen_api::{
    account_browser::{AccountBrowserAccessOperation as Operation, AccountBrowserFetchCredentials},
    auth::DeviceAccessOperation,
    auth_connection::{
        Activation, ActivationCandidate, ActivationContext, ActivationStarted, ConnectionRequest,
        ConnectionResource, ConnectionStatus, ConnectionTarget, ExpectedRevision,
    },
    auth_connection_draft::{
        DraftRequestError,
        callback::{
            activation_cookie_name, activation_cookie_name_from_query, member_link_cookie_name,
            member_link_cookie_name_from_query,
        },
        test_login::DraftLoginStatus,
    },
};
use scoplen_crypto::{SecretBytes, SecretVec};

const ORG: &str = "0191d3e0-8000-7000-8000-000000000001";
const DRAFT: &str = "0191d3e0-8000-7000-8000-000000000002";
const REVISION: &str = "0191d3e0-8000-7000-8000-000000000003";
const ATTEMPT: &str = "0191d3e0-8000-7000-8000-000000000004";
const KEY: (&str, &str) = ("Idempotency-Key", "0191d3e0-8000-7000-8000-000000000005");
const TAG: (&str, &str) = ("If-Match", "\"0191d3e0-8000-7000-8000-000000000003\"");
const EMPTY: (&str, &str) = ("If-None-Match", "*");
const JSON: (&str, &str) = ("Content-Type", "application/json");
const NO_STORE: Option<&str> = Some("no-store");
const NO_CACHE: Option<&str> = Some("no-cache");

fn candidate_body() -> String {
    serde_json::json!({
        "draft_generation": DRAFT, "client_id": "client:+ ", "client_secret": " secret+:% ",
        "space_id": "spc_Existing_Team"
    })
    .to_string()
}

#[test]
fn activation_requests_enforce_head_conditions_and_only_durable_writer_keys() {
    let body = candidate_body();
    for (header, expected) in [
        (TAG, ExpectedRevision::Current(REVISION.parse().unwrap())),
        (EMPTY, ExpectedRevision::Empty),
    ] {
        let ConnectionRequest::Start { expected: actual, candidate } =
            ConnectionRequest::from_http(
                Operation::AuthActivationStart,
                None,
                [header, JSON],
                body.as_bytes(),
            )
            .unwrap()
        else {
            panic!("expected activation start");
        };
        assert_eq!(actual, expected);
        assert_eq!(candidate.credentials.client_secret.as_bytes(), b" secret+:% ");
        assert_eq!(candidate.credentials.client_id.as_bytes(), b"client:+ ");
        assert_eq!(candidate.space_id, "spc_Existing_Team");
        assert!(!format!("{candidate:?}").contains("secret+"));
        assert_eq!(
            ActivationCandidate::from_json(candidate.to_json().unwrap().as_bytes()).unwrap(),
            candidate
        );
        assert_eq!(
            ConnectionRequest::from_http(
                Operation::AuthActivationConfirm,
                None,
                [header, KEY],
                b""
            )
            .unwrap(),
            ConnectionRequest::Confirm { expected, key: KEY.1.parse().unwrap() },
        );
    }
    assert_eq!(
        ConnectionRequest::from_http(Operation::AuthConnectionSuspend, None, [TAG, KEY], b"")
            .unwrap(),
        ConnectionRequest::Suspend {
            revision: REVISION.parse().unwrap(),
            key: KEY.1.parse().unwrap()
        },
    );
    for headers in [
        vec![TAG, JSON, EMPTY],
        vec![TAG, JSON, KEY],
        vec![TAG, JSON, ("if-match", TAG.1)],
        vec![("If-Match", "*"), JSON],
        vec![("If-Match", "\"opaque\""), JSON],
        vec![TAG, JSON, ("If-Range", TAG.1)],
        vec![TAG, JSON, ("content-type", JSON.1)],
    ] {
        assert_eq!(
            ConnectionRequest::from_http(
                Operation::AuthActivationStart,
                None,
                headers,
                body.as_bytes()
            ),
            Err(DraftRequestError::Invalid)
        );
    }
    assert_eq!(
        ConnectionRequest::from_http(Operation::AuthActivationStart, None, [JSON], body.as_bytes()),
        Err(DraftRequestError::PreconditionRequired)
    );
    assert_eq!(
        ConnectionRequest::from_http(Operation::AuthActivationStart, None, [TAG], body.as_bytes()),
        Err(DraftRequestError::MediaType)
    );
    assert_eq!(
        ConnectionRequest::from_http(
            Operation::AuthActivationStart,
            None,
            [TAG, JSON],
            &[b' '; 4097]
        ),
        Err(DraftRequestError::TooLarge)
    );
    for operation in [
        Operation::AuthConnectionRead,
        Operation::AuthActivationRead,
        Operation::AuthActivationAbandon,
    ] {
        assert!(ConnectionRequest::from_http(operation, None, [], b"").is_ok());
        assert!(ConnectionRequest::from_http(operation, None, [KEY], b"").is_err());
        assert!(ConnectionRequest::from_http(operation, None, [JSON], b"").is_err());
        assert!(ConnectionRequest::from_http(operation, Some(""), [], b"").is_err());
    }
    assert!(
        ConnectionRequest::from_http(Operation::AuthActivationConfirm, None, [TAG], b"").is_err()
    );
    assert!(
        ConnectionRequest::from_http(Operation::AuthConnectionSuspend, None, [EMPTY, KEY], b"")
            .is_err()
    );
}

#[test]
fn candidate_fields_are_bounded_exact_and_duplicate_free() {
    let body = candidate_body();
    for variant in [
        body.replace("spc_Existing_Team", "Spc_Existing_Team"),
        body.replace("spc_Existing_Team", "spc_has/space"),
        body.replace("client:+ ", &"é".repeat(257)),
        body.replace("client:+ ", "line\\nfeed"),
        body.replace("\"space_id\":", "\"space_id\":\"spc_alias\",\"space_id\":"),
        body.replace("\"space_id\":", "\"issuer\":\"https://provider.example/\",\"space_id\":"),
    ] {
        assert!(ActivationCandidate::from_json(variant.as_bytes()).is_err());
    }
}

fn target() -> ConnectionTarget {
    ConnectionTarget {
        issuer: "https://Provider.example:8443/tenant/".into(),
        client_id: "registered-client".into(),
        space_id: "spc_PreExisting".into(),
    }
}

#[test]
fn connection_resource_requires_exact_owner_tag_and_equal_revision_timestamps() {
    let original = ConnectionResource {
        id: REVISION.parse().unwrap(),
        organization_id: ORG.parse().unwrap(),
        created_at: "2026-11-23T08:05:00.123Z".into(),
        status: ConnectionStatus::Suspended,
        target: target(),
    };
    let encoded = original.to_json().unwrap();
    let decode = |bytes: &[u8], organization, tag: Option<&str>| {
        ConnectionResource::from_http_json(bytes, organization, None, tag, NO_STORE, NO_CACHE)
    };
    assert_eq!(
        decode(&encoded, original.organization_id, Some(&original.etag())).unwrap(),
        original,
    );
    let mut value: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
    assert!(decode(&encoded, DRAFT.parse().unwrap(), Some(TAG.1)).is_err());
    assert!(decode(&encoded, original.organization_id, Some("\"other\"")).is_err());
    value["data"]["client_secret"] = "private".into();
    assert!(
        decode(&serde_json::to_vec(&value).unwrap(), original.organization_id, Some(TAG.1))
            .is_err()
    );
    value["data"].as_object_mut().unwrap().remove("client_secret");
    for (status, valid) in [(ConnectionStatus::Active, false), (ConnectionStatus::Suspended, true)]
    {
        assert_eq!(
            ConnectionResource::from_http_json(
                &encoded,
                original.organization_id,
                Some(status),
                Some(TAG.1),
                NO_STORE,
                NO_CACHE
            )
            .is_ok(),
            valid,
        );
    }
    value["updated_at"] = "2026-11-23T08:05:01Z".into();
    assert!(
        decode(&serde_json::to_vec(&value).unwrap(), original.organization_id, Some(TAG.1))
            .is_err()
    );
}

#[test]
fn activation_start_and_status_bind_the_original_candidate_and_provider_origin() {
    let mut start = ActivationStarted {
        attempt: Activation {
            id: ATTEMPT.parse().unwrap(),
            status: DraftLoginStatus::Pending,
            expires_at: "2026-11-23T08:06:00Z".into(),
            context: ActivationContext {
                organization_id: ORG.parse().unwrap(),
                draft_generation: DRAFT.parse().unwrap(),
                expected_revision: ExpectedRevision::Current(REVISION.parse().unwrap()),
                target: target(),
            },
        },
        authorization_url: SecretVec::new(
            b"https://provider.example:8443/authorize?state=opaque".to_vec(),
        ),
    };
    let encoded = start.to_json().unwrap();
    let decode = |bytes: &[u8], expected: &ActivationContext| {
        ActivationStarted::from_http_json(bytes, expected, None, NO_STORE, NO_CACHE)
    };
    assert_eq!(decode(encoded.as_bytes(), &start.attempt.context).unwrap(), start);
    let mut wrong = start.attempt.context.clone();
    wrong.expected_revision = ExpectedRevision::Empty;
    assert!(decode(encoded.as_bytes(), &wrong).is_err());
    wrong = start.attempt.context.clone();
    wrong.target.space_id = "spc_Other".into();
    assert!(decode(encoded.as_bytes(), &wrong).is_err());
    let mut reply: serde_json::Value = serde_json::from_slice(encoded.as_bytes()).unwrap();
    reply["authorization_url"] = "https://other.example:8443/authorize".into();
    assert!(decode(&serde_json::to_vec(&reply).unwrap(), &start.attempt.context).is_err());
    assert!(
        Activation::from_http_json(encoded.as_bytes(), &start.attempt, None, NO_STORE, NO_CACHE)
            .is_err()
    );

    let original = Activation::from_http_json(
        &start.attempt.to_json().unwrap(),
        &start.attempt,
        None,
        NO_STORE,
        NO_CACHE,
    )
    .unwrap();
    start.attempt.status = DraftLoginStatus::Verified;
    assert!(start.to_json().is_err());
    let status = start.attempt.to_json().unwrap();
    assert_eq!(
        Activation::from_http_json(&status, &original, None, NO_STORE, NO_CACHE).unwrap(),
        start.attempt
    );
    assert!(
        Activation::from_http_json(&status, &original, Some(TAG.1), NO_STORE, NO_CACHE).is_err()
    );
    assert!(
        Activation::from_http_json(&status, &original, None, Some("public"), NO_CACHE).is_err()
    );
    for (field, value) in [
        ("id", DRAFT),
        ("organization_id", ATTEMPT),
        ("draft_generation", ORG),
        ("client_id", "different-client"),
        ("expires_at", "2026-11-23T08:06:01Z"),
        ("id_token", "private"),
    ] {
        let mut response: serde_json::Value = serde_json::from_slice(&status).unwrap();
        response[field] = value.into();
        assert!(
            Activation::from_http_json(
                &serde_json::to_vec(&response).unwrap(),
                &original,
                None,
                NO_STORE,
                NO_CACHE
            )
            .is_err()
        );
    }
}

#[test]
fn activation_callback_cookie_name_is_state_specific_and_rejects_ambiguous_state() {
    let state = SecretBytes::from_slice(&(0..32).collect::<Vec<u8>>()).unwrap();
    let encoded = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
    let known =
        "__Host-spl-auth-activate-630dcd2966c4336691125448bbb25b4ff412a49c732db2c8abc1b8581bd710dd";
    assert_eq!(activation_cookie_name(&state), known);
    assert_ne!(activation_cookie_name(&SecretBytes::from_slice(&[5; 32]).unwrap()), known);
    assert_eq!(
        activation_cookie_name_from_query(&format!("code=opaque&%73tate={encoded}")).unwrap(),
        known
    );
    for query in [
        "code=opaque".into(),
        "state=%broken".into(),
        format!("state={encoded}&%73tate={encoded}"),
        format!("state={encoded}_"),
        format!("state={encoded}&extra={}", "x".repeat(8192)),
    ] {
        assert!(activation_cookie_name_from_query(&query).is_err());
    }
}

#[test]
fn member_link_callback_cookie_is_distinct_and_uses_only_canonical_state() {
    let state = SecretBytes::from_slice(&(0..32).collect::<Vec<u8>>()).unwrap();
    let encoded = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
    let name =
        "__Host-spl-auth-link-630dcd2966c4336691125448bbb25b4ff412a49c732db2c8abc1b8581bd710dd";
    assert_eq!(member_link_cookie_name(&state), name);
    assert_ne!(activation_cookie_name(&state), name);
    assert_ne!(member_link_cookie_name(&SecretBytes::from_slice(&[5; 32]).unwrap()), name);
    for query in
        [format!("code=opaque&state={encoded}"), format!("error=access_denied&%73tate={encoded}")]
    {
        assert_eq!(member_link_cookie_name_from_query(&query).unwrap(), name);
    }
    for query in [
        "code=opaque".to_owned(),
        format!("state={encoded}&%73tate={encoded}"),
        format!("state={encoded}%3D"),
        format!("state={encoded}&extra={}", "x".repeat(8192)),
    ] {
        assert!(member_link_cookie_name_from_query(&query).is_err());
    }
}

#[test]
fn only_activation_start_receives_cookies_and_only_durable_transitions_have_receipts() {
    for operation in [
        Operation::AuthConnectionRead,
        Operation::AuthActivationStart,
        Operation::AuthActivationRead,
        Operation::AuthActivationAbandon,
        Operation::AuthActivationConfirm,
        Operation::AuthConnectionSuspend,
    ] {
        assert_eq!(
            Operation::from_route(operation.http_method(), operation.route_template()),
            Some(operation)
        );
        assert!(
            DeviceAccessOperation::from_route(operation.http_method(), operation.route_template())
                .is_none()
        );
        assert_eq!(
            operation.fetch_credentials(),
            if operation == Operation::AuthActivationStart {
                AccountBrowserFetchCredentials::SameOrigin
            } else {
                AccountBrowserFetchCredentials::Omit
            }
        );
        assert_eq!(
            operation.uses_browser_writer_receipt(),
            matches!(
                operation,
                Operation::AuthActivationConfirm | Operation::AuthConnectionSuspend
            )
        );
    }
}
