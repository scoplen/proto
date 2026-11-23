// SPDX-License-Identifier: Apache-2.0
use scoplen_api::{
    account_browser::AccountBrowserAccessOperation as Operation,
    auth_connection::ConnectionTarget,
    auth_connection_draft::{DraftRequestError, test_login::DraftLoginStatus},
    member_link::*,
    organization::OrganizationCodecError,
};
use scoplen_crypto::SecretVec;
use serde_json::{Value, json};
use uuid::Uuid;

const ORG: &str = "0191d3e0-8000-7000-8000-00000000000a";
const MEMBER: &str = "0191d3e0-8000-7000-8000-00000000000b";
const REVISION: &str = "0191d3e0-8000-7000-8000-00000000000c";
const ATTEMPT: &str = "0191d3e0-8000-7000-8000-00000000000d";
const LINK: &str = "0191d3e0-8000-7000-8000-00000000000e";
const KEY: &str = "0191d3e0-8000-7000-8000-00000000000f";
const TIME: &str = "2026-11-23T10:20:30Z";
const ISSUER: &str = "https://login.example.test:8443/idp";
const NAVIGATION: &str = "https://login.example.test:8443/oauth/authorize?state=one-time";
const NO_TAG: LinkResponseHeaders<'static> =
    LinkResponseHeaders { etag: None, cache_control: Some("no-store"), pragma: Some("no-cache") };

fn id(value: &str) -> Uuid {
    value.parse().unwrap()
}

fn context() -> LinkMembership {
    LinkMembership { organization_id: id(ORG), membership_id: id(MEMBER) }
}

fn connection() -> LinkConnection {
    LinkConnection {
        id: id(REVISION),
        target: ConnectionTarget {
            issuer: ISSUER.into(),
            client_id: "client".into(),
            space_id: "spc_team".into(),
        },
    }
}

fn link() -> MemberLink {
    MemberLink { id: id(LINK), created_at: TIME.into(), membership: context() }
}

fn attempt() -> LinkAttempt {
    LinkAttempt {
        id: id(ATTEMPT),
        membership: context(),
        connection_revision: id(REVISION),
        status: DraftLoginStatus::Pending,
        expires_at: TIME.into(),
    }
}

fn bytes(value: &Value) -> Vec<u8> {
    serde_json::to_vec(value).unwrap()
}

#[test]
fn member_link_requests_bind_every_route_and_reject_nonempty_wire() {
    let revision = connection().etag();
    let link = link().etag();
    let revision_header = [("If-Match", revision.as_str())];
    let link_header = [("if-match", link.as_str())];
    let confirm_headers = [revision_header[0], ("Idempotency-Key", KEY)];
    for (operation, target, headers, action) in [
        (Operation::AuthLinkSelfRead, None, &[][..], LinkAction::ReadSelf),
        (
            Operation::AuthLinkStart,
            None,
            &revision_header[..],
            LinkAction::Start { revision: id(REVISION) },
        ),
        (
            Operation::AuthLinkAttemptRead,
            Some(ATTEMPT),
            &[],
            LinkAction::ReadAttempt { attempt: id(ATTEMPT) },
        ),
        (
            Operation::AuthLinkAbandon,
            Some(ATTEMPT),
            &[],
            LinkAction::Abandon { attempt: id(ATTEMPT) },
        ),
        (
            Operation::AuthLinkConfirm,
            Some(ATTEMPT),
            &confirm_headers,
            LinkAction::Confirm { attempt: id(ATTEMPT), revision: id(REVISION), key: id(KEY) },
        ),
        (
            Operation::AuthLinkSelfUnlink,
            None,
            &link_header,
            LinkAction::UnlinkSelf { link: id(LINK) },
        ),
        (
            Operation::AuthLinkNamedRead,
            Some(MEMBER),
            &[],
            LinkAction::ReadNamed { membership: id(MEMBER) },
        ),
        (
            Operation::AuthLinkNamedWithdraw,
            Some(MEMBER),
            &link_header,
            LinkAction::WithdrawNamed { membership: id(MEMBER), link: id(LINK) },
        ),
    ] {
        assert_eq!(
            MemberLinkRequest::from_http(
                operation,
                ORG,
                target,
                None,
                headers.iter().copied(),
                b""
            ),
            Ok(MemberLinkRequest { organization_id: id(ORG), action })
        );
        for (query, body) in [(Some(""), b"".as_slice()), (None, b" ".as_slice()), (None, b"{}")] {
            assert_eq!(
                MemberLinkRequest::from_http(
                    operation,
                    ORG,
                    target,
                    query,
                    headers.iter().copied(),
                    body
                ),
                Err(DraftRequestError::Invalid)
            );
        }
        assert!(
            MemberLinkRequest::from_http(
                operation,
                ORG,
                target,
                None,
                headers.iter().copied().chain([("Content-Type", "")]),
                b"",
            )
            .is_err()
        );
    }
}

#[test]
fn link_conditions_require_exact_tags_and_only_confirm_accepts_one_writer_key() {
    let tag = connection().etag();
    let start = |headers: &[(&str, &str)]| {
        MemberLinkRequest::from_http(
            Operation::AuthLinkStart,
            ORG,
            None,
            None,
            headers.iter().copied(),
            b"",
        )
    };
    assert_eq!(start(&[]), Err(DraftRequestError::PreconditionRequired));
    for value in ["*", REVISION, &format!("W/{tag}"), &format!("{tag}, {tag}"), &tag.to_uppercase()]
    {
        assert_eq!(start(&[("If-Match", value)]), Err(DraftRequestError::Invalid));
    }
    for (name, value) in [
        ("if-MATCH", tag.as_str()),
        ("If-None-Match", "*"),
        ("If-Unmodified-Since", TIME),
        ("If-Modified-Since", TIME),
        ("If-Range", tag.as_str()),
        ("Idempotency-Key", KEY),
    ] {
        assert_eq!(start(&[("If-Match", &tag), (name, value)]), Err(DraftRequestError::Invalid));
    }
    for (org, target) in [
        (ORG.to_uppercase(), ATTEMPT.to_owned()),
        (ORG.into(), ATTEMPT.to_uppercase()),
        (ORG.into(), Uuid::nil().to_string()),
    ] {
        assert_eq!(
            MemberLinkRequest::from_http(
                Operation::AuthLinkAttemptRead,
                &org,
                Some(&target),
                None,
                [],
                b""
            ),
            Err(DraftRequestError::Invalid)
        );
    }
    let confirm = |headers: &[(&str, &str)]| {
        MemberLinkRequest::from_http(
            Operation::AuthLinkConfirm,
            ORG,
            Some(ATTEMPT),
            None,
            headers.iter().copied(),
            b"",
        )
    };
    assert_eq!(confirm(&[("If-Match", &tag)]), Err(DraftRequestError::Invalid));
    assert_eq!(
        confirm(&[("If-Match", &tag), ("Idempotency-Key", &KEY.to_uppercase())]),
        Err(DraftRequestError::Invalid)
    );
    assert_eq!(
        confirm(&[("If-Match", &tag), ("Idempotency-Key", KEY), ("idempotency-key", KEY)]),
        Err(DraftRequestError::Invalid)
    );
}

#[test]
fn current_status_and_confirmed_link_enforce_membership_and_exact_metadata() {
    let link = link();
    let tag = link.etag();
    let headers = LinkResponseHeaders { etag: Some(&tag), ..NO_TAG };
    let payload = link.to_json().unwrap();
    assert_eq!(MemberLink::from_http_json(&payload, context(), headers).unwrap(), link);
    assert!(MemberLink::from_http_json(&payload, context(), NO_TAG).is_err());
    assert_eq!(
        MemberLink::from_http_json(
            &payload,
            LinkMembership { membership_id: id(ORG), ..context() },
            headers
        ),
        Err(OrganizationCodecError::Context)
    );
    let mut result: Value = serde_json::from_slice(&payload).unwrap();
    result["etag"] = json!(format!("\"{REVISION}\""));
    assert_eq!(
        MemberLink::from_http_json(&bytes(&result), context(), headers),
        Err(OrganizationCodecError::HttpMetadata)
    );

    let status = MemberLinkStatus { membership: context(), link: Some(link) };
    let self_status = SelfLinkStatus { status: status.clone(), connection: Some(connection()) };
    let self_bytes = self_status.to_json().unwrap();
    assert_eq!(
        SelfLinkStatus::from_http_json(&self_bytes, context(), NO_TAG).unwrap(),
        self_status
    );
    assert_eq!(
        MemberLinkStatus::from_http_json(&status.to_json().unwrap(), context(), NO_TAG).unwrap(),
        status
    );
    assert!(MemberLinkStatus::from_http_json(&self_bytes, context(), NO_TAG).is_err());
    assert!(SelfLinkStatus::from_http_json(&self_bytes, context(), headers).is_err());
    let empty = SelfLinkStatus {
        status: MemberLinkStatus { membership: context(), link: None },
        connection: None,
    };
    let body = empty.to_json().unwrap();
    assert_eq!(SelfLinkStatus::from_http_json(&body, context(), NO_TAG).unwrap(), empty);
    let mut value: Value = serde_json::from_slice(&body).unwrap();
    value.as_object_mut().unwrap().remove("link");
    assert!(SelfLinkStatus::from_http_json(&bytes(&value), context(), NO_TAG).is_err());
    assert!(NO_TAG.validate_empty(b"").is_ok());
    assert!(NO_TAG.validate_empty(b" ").is_err());
    assert!(headers.validate_empty(b"").is_err());
}

#[test]
fn link_start_and_status_bind_attempt_revision_and_provider_origin() {
    let original = attempt();
    let connection = connection();
    let started = LinkAttemptStarted {
        attempt: original.clone(),
        authorization_url: SecretVec::new(NAVIGATION.as_bytes().to_vec()),
    };
    assert!(!format!("{started:?}").contains("one-time"));
    let body = started.to_json(ISSUER).unwrap();
    assert_eq!(
        LinkAttemptStarted::from_http_json(body.as_bytes(), context(), &connection, NO_TAG)
            .unwrap(),
        started
    );
    assert!(LinkAttempt::from_http_json(body.as_bytes(), &original, NO_TAG).is_err());
    let verified = LinkAttempt { status: DraftLoginStatus::Verified, ..original.clone() };
    let body = verified.to_json().unwrap();
    assert_eq!(LinkAttempt::from_http_json(&body, &original, NO_TAG).unwrap(), verified);
    let status: Value = serde_json::from_slice(&body).unwrap();
    for (field, value) in [
        ("id", LINK),
        ("organization_id", MEMBER),
        ("membership_id", ORG),
        ("connection_revision", LINK),
        ("expires_at", "2026-11-23T10:21:30Z"),
    ] {
        let mut changed = status.clone();
        changed[field] = json!(value);
        assert_eq!(
            LinkAttempt::from_http_json(&bytes(&changed), &original, NO_TAG),
            Err(OrganizationCodecError::Context)
        );
    }
    let pristine: Value =
        serde_json::from_slice(started.to_json(ISSUER).unwrap().as_bytes()).unwrap();
    for (field, value) in [
        ("status", "failed"),
        ("expires_at", "2026-02-30T10:20:30Z"),
        ("authorization_url", "https://login.example.test/oauth/authorize"),
        ("authorization_url", "https://other.example.test:8443/oauth/authorize"),
        ("authorization_url", "https://user@login.example.test:8443/oauth/authorize"),
    ] {
        let mut changed = pristine.clone();
        changed[field] = json!(value);
        assert!(
            LinkAttemptStarted::from_http_json(&bytes(&changed), context(), &connection, NO_TAG)
                .is_err(),
            "{field}"
        );
    }
}

#[test]
fn link_responses_reject_duplicates_private_fields_and_complete_overflow() {
    let status = SelfLinkStatus {
        status: MemberLinkStatus { membership: context(), link: Some(link()) },
        connection: Some(connection()),
    };
    let encoded = status.to_json().unwrap();
    let mut padded = vec![b' '; 8192 - encoded.len()];
    padded.extend_from_slice(&encoded);
    assert!(SelfLinkStatus::from_http_json(&padded, context(), NO_TAG).is_ok());
    padded.push(b' ');
    assert_eq!(
        SelfLinkStatus::from_http_json(&padded, context(), NO_TAG),
        Err(OrganizationCodecError::TooLarge)
    );
    let value: Value = serde_json::from_slice(&encoded).unwrap();
    for field in [
        "sub",
        "subject",
        "subject_digest",
        "subject_comparison",
        "comparison_value",
        "claims",
        "client_secret",
        "access_token",
        "refresh_token",
        "id_token",
        "authorization_url",
    ] {
        for location in ["root", "link", "connection"] {
            let mut changed = value.clone();
            if location == "root" {
                changed[field] = Value::Null;
            } else {
                changed[location][field] = Value::Null;
            }
            assert!(
                SelfLinkStatus::from_http_json(&bytes(&changed), context(), NO_TAG).is_err(),
                "{location}.{field}"
            );
        }
    }
    let mut extended = value;
    extended["link"]["future"] = json!({"value": 1});
    assert_eq!(
        SelfLinkStatus::from_http_json(&bytes(&extended), context(), NO_TAG).unwrap(),
        status
    );
    let duplicate =
        serde_json::to_string(&extended).unwrap().replace("\"value\":1", "\"value\":1,\"value\":2");
    assert_eq!(
        SelfLinkStatus::from_http_json(duplicate.as_bytes(), context(), NO_TAG),
        Err(OrganizationCodecError::InvalidJson)
    );
}
