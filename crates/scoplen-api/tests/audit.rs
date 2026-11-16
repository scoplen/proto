// SPDX-License-Identifier: Apache-2.0
use scoplen_api::{
    account_browser::{
        AccountBrowserAccessOperation, AccountBrowserAccessRequirement, AccountBrowserAccessScope,
        INITIAL_ACCOUNT_BROWSER_ACCESS_SCOPE,
    },
    audit::*,
    auth::{DeviceAccessOperation, DeviceAccessScope, INITIAL_DEVICE_ACCESS_SCOPE},
};
use scoplen_crypto::ed25519_verify;
use scoplen_test_vectors::VectorDocument;
use serde_json::Value;
use sha2::{Digest, Sha256};
use uuid::Uuid;

fn vectors() -> VectorDocument {
    VectorDocument::from_bytes(include_bytes!("../../../vectors/audit.json"))
        .expect("independent D-144 vectors")
}
fn event() -> AuditEvent {
    AuditEvent::from_json(
        vectors()
            .vectors
            .iter()
            .find(|v| v.id == "audit-browser-event-v1")
            .unwrap()
            .input
            .as_bytes(),
    )
    .unwrap()
}
fn result() -> AuditVerification {
    AuditVerification::from_json(
        vectors()
            .vectors
            .iter()
            .find(|v| v.id == "audit-verification-checkpoint-v1")
            .unwrap()
            .input
            .as_bytes(),
    )
    .unwrap()
}
fn unhex(text: &str) -> Vec<u8> {
    (0..text.len()).step_by(2).map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap()).collect()
}

#[test]
fn independent_wire_query_and_calendar_vectors_use_public_codecs() {
    let mut counts = std::collections::BTreeMap::new();
    for vector in vectors().vectors {
        *counts.entry(vector.kind.clone()).or_insert(0) += 1;
        let bytes = vector.input.as_bytes();
        let decoded = match vector.kind.as_str() {
            "audit.event" => AuditEvent::from_json(bytes).and_then(|v| v.to_json()),
            "audit.page" => AuditPage::from_json(bytes).and_then(|v| v.to_json()),
            "audit.verification" => AuditVerification::from_json(bytes).and_then(|v| v.to_json()),
            "audit.query" | "audit.range" => {
                let pairs: Vec<(String, String)> = serde_json::from_str(&vector.input).unwrap();
                let parameters = pairs.iter().map(|(a, b)| (a.as_str(), b.as_str()));
                if vector.kind == "audit.query" {
                    AuditListQuery::from_parameters(parameters).map(|_| b"accepted".to_vec())
                } else {
                    AuditRange::from_parameters(parameters).map(|_| b"accepted".to_vec())
                }
            }
            "audit.timestamp" => {
                let actual = parse_audit_timestamp(&vector.input);
                if vector.expected == "rejected" {
                    assert!(actual.is_err(), "{}", vector.id);
                } else {
                    let time = actual.expect(&vector.id);
                    assert_eq!(time.to_string(), vector.expected, "{}", vector.id);
                    assert_eq!(
                        format_audit_timestamp(time).unwrap(),
                        vector.input,
                        "{}",
                        vector.id
                    );
                }
                continue;
            }
            "audit.operation" => {
                let input: Value = serde_json::from_slice(bytes).unwrap();
                let method = input["method"].as_str().unwrap();
                let path = input["path"].as_str().unwrap();
                let actual = if input["profile"] == "device" {
                    DeviceAccessOperation::from_route(method, path)
                        .map(|operation| operation.accepted_scopes()[0].as_str())
                } else {
                    AccountBrowserAccessOperation::from_route(method, path).and_then(|operation| {
                        match operation.requirement() {
                            AccountBrowserAccessRequirement::AnyScope(scopes) => {
                                Some(scopes[0].as_str())
                            }
                            AccountBrowserAccessRequirement::SelfSessionTermination => None,
                        }
                    })
                };
                assert_eq!(actual.unwrap_or("unmapped"), vector.expected, "{}", vector.id);
                continue;
            }
            "audit.checkpoint" => continue,
            other => panic!("unknown D-144 vector kind {other}"),
        };
        if vector.expected == "rejected" {
            assert!(decoded.is_err(), "{}", vector.id);
        } else {
            assert_eq!(decoded.expect(&vector.id), vector.expected.as_bytes(), "{}", vector.id);
        }
    }
    for kind in ["event", "page", "verification", "query", "range", "timestamp", "checkpoint"] {
        assert!(counts[&format!("audit.{kind}")] > 0, "unexercised {kind}");
    }
}

#[test]
fn original_checkpoint_payloads_and_signatures_preserve_each_millisecond() {
    for vector in vectors().vectors.into_iter().filter(|v| v.kind == "audit.checkpoint") {
        let input: Value = serde_json::from_str(&vector.input).unwrap();
        let organization = Uuid::parse_str(input["organization_id"].as_str().unwrap()).unwrap();
        let mut body: Value = serde_json::from_slice(&result().to_json().unwrap()).unwrap();
        body["checkpoint"] = input["checkpoint"].clone();
        let evidence = AuditVerification::from_json(&serde_json::to_vec(&body).unwrap())
            .unwrap()
            .checkpoint
            .unwrap();
        let payload = evidence.signed_payload(organization).unwrap();
        assert_eq!(payload, unhex(&vector.expected), "{}", vector.id);
        let key = unhex(input["public_key"].as_str().unwrap());
        ed25519_verify(&key, &payload, &evidence.signature).unwrap();
        let original = unhex(input["original_event_hex"].as_str().unwrap());
        let mut hasher = Sha256::new();
        hasher.update([0; 32]);
        hasher.update(&original);
        let computed: [u8; 32] = hasher.finalize().into();
        assert_eq!(computed, evidence.head_hash);
        let mut changed = evidence.clone();
        changed.signed_at =
            format_audit_timestamp(parse_audit_timestamp(&changed.signed_at).unwrap() + 1).unwrap();
        assert!(
            ed25519_verify(
                &key,
                &changed.signed_payload(organization).unwrap(),
                &evidence.signature
            )
            .is_err()
        );
        assert!(
            ed25519_verify(
                &key,
                &evidence.signed_payload(Uuid::from_u128(organization.as_u128() + 1)).unwrap(),
                &evidence.signature
            )
            .is_err()
        );
    }
}

#[test]
fn filters_and_pages_bind_exact_recorded_context() {
    let item = event();
    let all = format!(
        "occurred_at ge \"2026-11-17T00:00:00.001Z\" and occurred_at lt \"2026-11-17T00:00:00.01Z\" and actor_account_id eq \"{}\" and resource eq \"group:{}\" and event_class eq \"organization.groups_created\" and outcome eq \"success\"",
        item.actor_account_id.unwrap(),
        item.resource.as_ref().unwrap().id
    );
    let filter = AuditFilter::parse(&all).unwrap();
    assert!(filter.matches(&item).unwrap());
    for clause in all.split(" and ") {
        assert!(AuditFilter::parse(clause).unwrap().matches(&item).unwrap());
    }
    let query = AuditListQuery { limit: 1, cursor: Some(item.sequence + 1), filter };
    let page = AuditPage { items: vec![item.clone()], next_cursor: Some(item.sequence) };
    let bytes = page.to_json().unwrap();
    assert_eq!(AuditPage::from_json_for(&bytes, item.organization_id, &query).unwrap(), page);
    assert!(
        page.validate_for(Uuid::from_u128(item.organization_id.as_u128() + 1), &query).is_err()
    );
    let mut changed_query = query.clone();
    changed_query.cursor = Some(item.sequence);
    assert!(page.validate_for(item.organization_id, &changed_query).is_err());
    changed_query = query.clone();
    changed_query.filter.outcome = Some(AuditOutcome::Failure);
    assert!(page.validate_for(item.organization_id, &changed_query).is_err());
    changed_query = query.clone();
    changed_query.filter.event_class = Some("future.unclassified".into());
    assert!(!changed_query.filter.matches(&item).unwrap());
    let mut unknown = item.clone();
    unknown.actor_account_id = None;
    assert!(!query.filter.matches(&unknown).unwrap());
    unknown = item.clone();
    unknown.occurred_at = "2026-11-17T00:00:00.01Z".into();
    assert!(!query.filter.matches(&unknown).unwrap());
    let mut oversized_count = page.clone();
    oversized_count.items.push(AuditEvent { sequence: item.sequence - 1, ..item.clone() });
    oversized_count.next_cursor = None;
    assert!(oversized_count.validate_for(item.organization_id, &query).is_err());
}

#[test]
fn complete_byte_budgets_include_ignored_extensions_and_original_item_whitespace() {
    let base = String::from_utf8(event().to_json().unwrap()).unwrap();
    let prefix = format!("{},\"extension\":\"", &base[..base.len() - 1]);
    let exact = format!("{prefix}{}\"}}", "x".repeat(MAX_AUDIT_EVENT_BYTES - prefix.len() - 2));
    assert_eq!(exact.len(), MAX_AUDIT_EVENT_BYTES);
    assert!(AuditEvent::from_json(exact.as_bytes()).is_ok());
    let overflow = exact.replacen("\"extension\":\"", "\"extension\":\"x", 1);
    assert_eq!(AuditEvent::from_json(overflow.as_bytes()), Err(AuditCodecError::TooLarge));
    let page = format!("{{\"items\":[{overflow}],\"next_cursor\":null}}");
    assert_eq!(AuditPage::from_json(page.as_bytes()), Err(AuditCodecError::TooLarge));
    let empty = b"{\"items\":[],\"next_cursor\":null}";
    let mut complete = vec![b' '; MAX_AUDIT_PAGE_BYTES - empty.len()];
    complete.extend_from_slice(empty);
    assert!(AuditPage::from_json(&complete).is_ok());
    complete.push(b' ');
    assert_eq!(AuditPage::from_json(&complete), Err(AuditCodecError::TooLarge));
    let body = result().to_json().unwrap();
    let mut complete = vec![b' '; MAX_AUDIT_VERIFICATION_BYTES - body.len()];
    complete.extend_from_slice(&body);
    assert!(AuditVerification::from_json(&complete).is_ok());
    complete.push(b' ');
    assert_eq!(AuditVerification::from_json(&complete), Err(AuditCodecError::TooLarge));
    let mut invalid_utf8 = base.into_bytes();
    invalid_utf8[1] = 255;
    assert_eq!(AuditEvent::from_json(&invalid_utf8), Err(AuditCodecError::InvalidJson));
    for (cache, pragma) in
        [(None, None), (Some("no-store"), None), (Some("public"), Some("no-cache"))]
    {
        assert!(validate_audit_cache_headers(cache, pragma).is_err());
    }
    assert!(validate_audit_cache_headers(Some("no-store"), Some("no-cache")).is_ok());
}

#[test]
fn range_query_limits_and_calendar_arithmetic_never_wrap() {
    assert_eq!(AuditRange::new(1, 4096).unwrap().event_count().unwrap(), 4096);
    assert_eq!(AuditRange::new(1, 4097), Err(AuditCodecError::TooLarge));
    assert_eq!(AuditRange::new(1, u64::MAX), Err(AuditCodecError::TooLarge));
    assert_eq!(AuditRange::new(u64::MAX, u64::MAX).unwrap().event_count().unwrap(), 1);
    assert!(AuditListQuery::from_parameters([("filter", "x".repeat(2049).as_str())]).is_err());
    assert_eq!(
        AuditListQuery::from_parameters([("x", "x".repeat(4096).as_str())]),
        Err(AuditCodecError::TooLarge)
    );
    assert_eq!(
        AuditRange::from_parameters([
            ("from_sequence", "1"),
            ("to_sequence", "1"),
            ("x", "x".repeat(128).as_str())
        ]),
        Err(AuditCodecError::TooLarge)
    );
    assert_eq!(parse_audit_timestamp("0000-01-01T00:00:00Z").unwrap(), -62_167_219_200_000);
    assert_eq!(parse_audit_timestamp("9999-12-31T23:59:59.999Z").unwrap(), 253_402_300_799_999);
    for ms in [i64::MIN, -62_167_219_200_001, 253_402_300_800_000, i64::MAX] {
        assert!(format_audit_timestamp(ms).is_err());
    }
}

#[test]
fn reference_ranges_report_first_failure_and_only_join_adjacent_matching_successes() {
    let first = result();
    assert!(first.validate_for(first.organization_id, AuditRange::new(1, 1).unwrap()).is_ok());
    assert!(first.validate_for(first.organization_id, AuditRange::new(1, 2).unwrap()).is_err());
    let mut next = AuditVerification {
        from_sequence: 2,
        to_sequence: 4,
        checked_events: 3,
        previous_hash: first.head_hash,
        checkpoint: None,
        uncheckpointed_from_sequence: Some(2),
        ..first.clone()
    };
    assert!(first.can_join(&next));
    next.previous_hash = Some([99; 32]);
    assert!(!first.can_join(&next));
    next.previous_hash = first.head_hash;
    next.from_sequence = 3;
    next.checked_events = 2;
    next.uncheckpointed_from_sequence = Some(3);
    assert!(!first.can_join(&next));
    for failure in 2..=4 {
        let failed = AuditVerification {
            from_sequence: 2,
            to_sequence: 4,
            checked_events: failure - 2,
            valid: false,
            failure_sequence: Some(failure),
            previous_hash: None,
            head_hash: None,
            checkpoint: None,
            uncheckpointed_from_sequence: None,
            ..first.clone()
        };
        assert!(failed.validate().is_ok());
        assert!(!first.can_join(&failed));
        let mut forged = failed;
        forged.head_hash = first.head_hash;
        assert!(forged.to_json().is_err());
    }
    let newest = AuditVerification {
        from_sequence: u64::MAX,
        to_sequence: u64::MAX,
        checkpoint: None,
        uncheckpointed_from_sequence: Some(u64::MAX),
        ..first
    };
    assert!(newest.validate().is_ok());
    assert!(!newest.can_join(&newest));
    assert_eq!(AuditVerification::from_json(&newest.to_json().unwrap()).unwrap(), newest);
}

#[test]
fn audit_operations_are_exact_read_only_independent_profile_requirements() {
    let old_device = INITIAL_DEVICE_ACCESS_SCOPE.replace(" audit:read", "");
    let old_browser = INITIAL_ACCOUNT_BROWSER_ACCESS_SCOPE.replace(" audit:read", "");
    for path in ["/api/v1/orgs/{org}/audit-events", "/api/v1/orgs/{org}/audit-events/verify"] {
        let device = DeviceAccessOperation::from_route("GET", path).unwrap();
        assert_eq!(device.accepted_scopes(), &[DeviceAccessScope::AuditRead]);
        assert!(device.has_accepted_scope(INITIAL_DEVICE_ACCESS_SCOPE));
        assert!(!device.has_accepted_scope(&old_device));
        let browser = AccountBrowserAccessOperation::from_route("GET", path).unwrap();
        assert_eq!(
            browser.requirement(),
            AccountBrowserAccessRequirement::AnyScope(&[AccountBrowserAccessScope::AuditRead])
        );
        assert!(!AccountBrowserAccessScope::AuditRead.is_present_in(&old_browser));
        assert!(
            AccountBrowserAccessScope::AuditRead
                .is_present_in(INITIAL_ACCOUNT_BROWSER_ACCESS_SCOPE)
        );
        for method in ["POST", "PUT", "PATCH", "DELETE", "get", "CONNECT"] {
            assert!(DeviceAccessOperation::from_route(method, path).is_none());
            assert!(AccountBrowserAccessOperation::from_route(method, path).is_none());
        }
    }
    for path in [
        "/api/v1/orgs/{org}/audit-events/{id}",
        "/api/v1/admin/audit-events",
        "/api/v1/orgs/{org}/audit-events/",
    ] {
        assert!(DeviceAccessOperation::from_route("GET", path).is_none());
        assert!(AccountBrowserAccessOperation::from_route("GET", path).is_none());
    }
}
