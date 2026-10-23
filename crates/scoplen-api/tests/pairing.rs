// SPDX-License-Identifier: Apache-2.0

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use scoplen_api::{
    ERROR_CODES,
    auth::{DeviceAccessOperation, DeviceAccessScope},
    pairing::*,
    pairing_reference::{
        ReferencePairingActor as Actor, ReferencePairingError as PeerError,
        ReferencePairingFault as Fault, ReferencePairingPeer,
    },
};
use scoplen_crypto::{DeviceCertificate, SecretBytes};
use scoplen_test_vectors::VectorDocument;
use serde_json::{Value, json};
use uuid::Uuid;

fn id(last: u8) -> Uuid {
    Uuid::from_bytes([0, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, last])
}

fn context(claimed: bool) -> PairingContext {
    PairingContext {
        origin: "https://example.com".to_owned(),
        pairing_id: id(9),
        initiator_device_id: claimed.then(|| id(4)),
        responder_device_id: id(2),
        expires_at: "2026-10-24T12:05:00Z".to_owned(),
    }
}

fn old() -> Actor {
    Actor::Initiator { account_id: id(1), device_id: id(4), authorized: true }
}
fn new() -> Actor {
    Actor::Responder(SecretBytes::new([0; 32]))
}
fn peer() -> ReferencePairingPeer {
    ReferencePairingPeer::new(context(false), SecretBytes::new([0; 32]), 300_000).expect("fixture")
}

fn receipt() -> PairingReceipt {
    PairingReceipt { account_id: id(1), device_id: id(2), revision: 2 }
}
fn complete() -> PairingCompleteRequest {
    let vectors =
        VectorDocument::parse_str(include_str!("../../../vectors/pairing.json")).expect("vectors");
    let vector =
        vectors.vectors.iter().find(|v| v.id == "pairing-complete-v1").expect("approval vector");
    PairingCompleteRequest::from_json(vector.input.as_bytes()).expect("canonical fixture")
}
fn message(step: PairingStep) -> PairingMessageRequest {
    PairingMessageRequest {
        step,
        payload: vec![
            0;
            match step {
                PairingStep::NewDevice | PairingStep::Handoff => 41,
                _ => step.max_payload_bytes(),
            }
        ],
    }
}
fn ready() -> ReferencePairingPeer {
    let mut peer = peer();
    peer.claim(&old(), 1).expect("claim");
    for step in PairingStep::ALL {
        let actor = if step.role() == PairingRole::Initiator { old() } else { new() };
        peer.message(&actor, message(step), 2).expect("ordered relay");
    }
    peer
}

fn vector_codec(kind: &str, input: &[u8]) -> Result<Vec<u8>, PairingCodecError> {
    macro_rules! codec {
        ($ty:ty) => {
            <$ty>::from_json(input)?.to_json()
        };
    }
    match kind {
        "create.request" => codec!(PairingCreateRequest),
        "create.response" => codec!(PairingCreateResponse),
        "claim.request" => codec!(PairingClaimRequest),
        "claim.response" => codec!(PairingClaimResponse),
        "message" => codec!(PairingMessageRequest),
        "ack" => codec!(PairingMessageAck),
        "receipt" => codec!(PairingReceipt),
        "snapshot" => codec!(PairingSnapshot),
        "complete" => codec!(PairingCompleteRequest),
        _ => panic!("unrecognized vector kind"),
    }
}

#[test]
fn published_vectors_and_tracked_fuzz_seeds_use_public_exports() {
    let document = VectorDocument::parse_str(include_str!("../../../vectors/pairing.json"))
        .expect("D-114 vectors");
    assert!(document.vectors.len() >= 25);
    for vector in document.vectors {
        let kind = vector.kind.strip_prefix("pairing.").expect("kind");
        if let Some(kind) = kind.strip_suffix(".json") {
            let canonical = vector_codec(kind, vector.input.as_bytes()).expect(&vector.id);
            assert_eq!(canonical, vector.expected.as_bytes(), "{}", vector.id);
            assert_eq!(vector_codec(kind, &canonical), Ok(canonical), "{}", vector.id);
        } else {
            let kind = kind.strip_suffix(".invalid").expect("invalid kind");
            assert_eq!(
                format!("{:?}", vector_codec(kind, vector.input.as_bytes()).expect_err(&vector.id)),
                vector.expected,
                "{}",
                vector.id
            );
        }
        let seed = std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../fuzz/corpus/api_json")
                .join(format!("seed-{}", vector.id)),
        )
        .expect("tracked seed");
        assert_eq!(seed, vector.input.as_bytes());
    }
}

#[test]
fn relay_sizes_are_exact_and_mutable_fields_are_rechecked() {
    for step in PairingStep::ALL {
        let minimum = if matches!(step, PairingStep::NewDevice | PairingStep::Handoff) {
            41
        } else {
            step.max_payload_bytes()
        };
        for size in [minimum, step.max_payload_bytes()] {
            let request = PairingMessageRequest { step, payload: vec![0; size] };
            let encoded = request.to_json().expect("accepted endpoint");
            assert!(encoded.len() <= step.request_body_limit());
            assert_eq!(PairingMessageRequest::from_json(&encoded), Ok(request));
        }
        let mut request = message(step);
        request.payload.resize(step.max_payload_bytes() + 1, 0);
        assert_eq!(request.to_json(), Err(PairingCodecError::TooLarge(step.max_payload_bytes())));
        request.payload.resize(minimum - 1, 0);
        assert_eq!(request.to_json(), Err(PairingCodecError::InvalidField("payload")));
    }
    let mut small = message(PairingStep::InitiatorShare).to_json().expect("small message");
    small.resize(257, b' ');
    assert_eq!(PairingMessageRequest::from_json(&small), Err(PairingCodecError::TooLarge(256)));
}

#[test]
fn all_complete_body_limits_include_whitespace_and_extensions() {
    assert_eq!(
        PairingCreateRequest::from_json(&vec![b' '; 257]),
        Err(PairingCodecError::TooLarge(256))
    );
    assert_eq!(
        PairingClaimResponse::from_json(&vec![b' '; 4097]),
        Err(PairingCodecError::TooLarge(4096))
    );
    assert_eq!(
        PairingCompleteRequest::from_json(&vec![b' '; MAX_PAIRING_LARGE_REQUEST_BYTES + 1]),
        Err(PairingCodecError::TooLarge(MAX_PAIRING_LARGE_REQUEST_BYTES))
    );
    assert_eq!(
        PairingSnapshot::from_json(&vec![b' '; MAX_PAIRING_SNAPSHOT_BYTES + 1]),
        Err(PairingCodecError::TooLarge(MAX_PAIRING_SNAPSHOT_BYTES))
    );
    let mut receipt: Value =
        serde_json::from_slice(&receipt().to_json().expect("receipt")).expect("JSON");
    receipt["extension"] = json!(" ".repeat(300));
    assert_eq!(
        PairingReceipt::from_json(&serde_json::to_vec(&receipt).expect("JSON")),
        Err(PairingCodecError::TooLarge(256))
    );
}

#[test]
fn canonical_ids_origins_times_and_duplicate_names_are_required() {
    let good = PairingClaimResponse { context: context(true) }.to_json().expect("context");
    let base: Value = serde_json::from_slice(&good).expect("JSON");
    for value in [
        "http://example.com",
        "https://EXAMPLE.com",
        "https://example.com/",
        "https://example.com?q=1",
        "https://user@example.com",
    ] {
        let mut body = base.clone();
        body["context"]["origin"] = json!(value);
        assert!(
            PairingClaimResponse::from_json(&serde_json::to_vec(&body).expect("JSON")).is_err()
        );
    }
    for value in ["2026-02-30T12:00:00Z", "2026-10-24T12:00:60Z", "2026-10-24T12:00:00+00:00"] {
        let mut body = base.clone();
        body["context"]["expires_at"] = json!(value);
        assert!(
            PairingClaimResponse::from_json(&serde_json::to_vec(&body).expect("JSON")).is_err()
        );
    }
    for value in [
        id(2).to_string().replace('-', ""),
        "00000000-0000-4000-8000-000000000002".to_owned(),
        "00000000-0000-7000-0000-000000000002".to_owned(),
    ] {
        let body = json!({"device_id":value});
        assert!(
            PairingCreateRequest::from_json(&serde_json::to_vec(&body).expect("JSON")).is_err()
        );
    }
    for body in [
        br#"{"device_id":"x","device_id":"y"}"#.as_slice(),
        br#"{"extra":{"x":1,"x":2}}"#.as_slice(),
        b"{} {}",
    ] {
        assert_eq!(PairingClaimRequest::from_json(body), Err(PairingCodecError::InvalidJson));
    }
}

#[test]
fn response_extensions_are_ignored_but_request_extensions_fail() {
    let body = PairingClaimResponse { context: context(true) }.to_json().expect("context");
    let mut extended: Value = serde_json::from_slice(&body).expect("JSON");
    extended["extra"] = json!({"ok":true});
    extended["context"]["extra"] = json!([true]);
    assert_eq!(
        PairingClaimResponse::from_json(&serde_json::to_vec(&extended).expect("JSON"))
            .expect("extensions")
            .to_json(),
        Ok(body)
    );
    assert!(PairingClaimRequest::from_json(br#"{"extra":null}"#).is_err());
    assert!(
        PairingMessageRequest::from_json(br#"{"step":"acceptance","payload":"AA","extra":null}"#)
            .is_err()
    );
}

#[test]
fn prefix_and_receipt_validation_is_all_or_nothing() {
    let valid = PairingSnapshot {
        context: context(true),
        state: PairingState::Ready,
        messages: PairingStep::ALL.into_iter().map(message).collect(),
        receipt: None,
    };
    valid.validate().expect("ready prefix");
    let mut changed = valid.clone();
    changed.messages.swap(0, 1);
    assert!(changed.to_json().is_err());
    let mut changed = valid.clone();
    changed.messages.push(message(PairingStep::Acceptance));
    assert!(changed.to_json().is_err());
    for state in [
        PairingState::Waiting,
        PairingState::Exchanging,
        PairingState::Completed,
        PairingState::Cancelled,
        PairingState::Expired,
    ] {
        let mut changed = valid.clone();
        changed.state = state;
        assert!(changed.to_json().is_err());
    }
    let mut terminal = PairingSnapshot {
        context: context(true),
        state: PairingState::Completed,
        messages: vec![],
        receipt: Some(receipt()),
    };
    terminal.validate().expect("receipt");
    terminal.receipt.as_mut().expect("receipt").device_id = id(99);
    assert_eq!(terminal.validate(), Err(PairingCodecError::InvalidState));
}

#[test]
fn approval_retains_exact_artifacts_and_delegates_fingerprint() {
    let request = complete();
    let encoded = request.to_json().expect("approval");
    assert_eq!(PairingCompleteRequest::from_json(&encoded), Ok(request.clone()));
    assert_eq!(
        request.approval_fingerprint().expect("hash"),
        scoplen_crypto::pairing_approval_fingerprint(
            &request.device_certificate,
            &request.key_bundle_update,
            &request.new_device_signature
        )
        .expect("shared hash")
    );
    for field in ["device_certificate", "key_bundle_update"] {
        let mut invalid: Value = serde_json::from_slice(&encoded).expect("JSON");
        invalid[field] = json!("AA");
        assert_eq!(
            PairingCompleteRequest::from_json(&serde_json::to_vec(&invalid).expect("JSON")),
            Err(PairingCodecError::InvalidField(field))
        );
    }
    let mut invalid = request.clone();
    invalid.device_certificate.push(0);
    assert_eq!(invalid.to_json(), Err(PairingCodecError::InvalidField("device_certificate")));
    let mut invalid = request;
    invalid.key_bundle_update.push(0);
    assert_eq!(invalid.to_json(), Err(PairingCodecError::InvalidField("key_bundle_update")));
}

#[test]
fn metadata_scopes_and_redaction_preserve_security_boundaries() {
    for read in [false, true] {
        for delay in [1, 300] {
            let headers = PairingRateLimitHeaders::new(delay, read).expect("bounded delay");
            assert_eq!(headers.retry_after_seconds(), delay);
            assert_eq!(headers.rate_limit(), format!("\"pairing\";r=0;t={delay}"));
            assert_eq!(
                headers.rate_limit_policy(),
                if read { "\"pairing\";q=120;w=60" } else { "\"pairing\";q=30;w=60" }
            );
        }
        for delay in [0, 301, u16::MAX] {
            assert_eq!(
                PairingRateLimitHeaders::new(delay, read),
                Err(PairingCodecError::InvalidField("retry_after_seconds"))
            );
        }
    }
    let capability = SecretBytes::new([0; 32]);
    let authorization = encode_pairing_authorization(&capability);
    assert_eq!(decode_pairing_authorization(&authorization), Ok(capability));
    for value in [
        format!(" {authorization}"),
        format!("{authorization} "),
        format!("{authorization}="),
        authorization.to_lowercase(),
        "Pairing AA".to_owned(),
    ] {
        assert_eq!(decode_pairing_authorization(&value), Err(PairingCodecError::HttpMetadata));
    }
    assert!(validate_pairing_request_metadata(None, b"", false, false, false).is_ok());
    assert!(validate_pairing_request_metadata(Some(""), b"", false, false, false).is_err());
    assert!(validate_pairing_request_metadata(None, b"{}", false, false, false).is_err());
    for flags in [(true, false), (false, true)] {
        assert!(validate_pairing_request_metadata(None, b"", false, flags.0, flags.1).is_err());
    }
    assert!(
        validate_pairing_response_metadata(
            Some("no-store"),
            Some("no-cache"),
            Some("no-referrer"),
            false
        )
        .is_ok()
    );
    assert!(
        validate_pairing_response_metadata(
            Some("no-store"),
            Some("no-cache"),
            Some("no-referrer"),
            true
        )
        .is_err()
    );
    for op in [
        DeviceAccessOperation::PairingRead,
        DeviceAccessOperation::PairingClaim,
        DeviceAccessOperation::PairingMessage,
        DeviceAccessOperation::PairingComplete,
        DeviceAccessOperation::PairingCancel,
    ] {
        assert_eq!(op.required_scope(), DeviceAccessScope::KeysWrite);
        assert_eq!(
            DeviceAccessOperation::from_route(op.http_method(), op.route_template()),
            Some(op)
        );
    }
    assert!(
        ERROR_CODES.contains(&"auth.pairing_denied")
            && ERROR_CODES.contains(&"auth.pairing_conflict")
    );
    let response = PairingCreateResponse {
        context: context(false),
        new_device_token: SecretBytes::new([123; 32]),
    };
    let debug = format!("{response:?} {:?} {:?}", complete(), message(PairingStep::Handoff));
    assert!(
        !debug.contains("example.com")
            && !debug.contains("device_certificate")
            && !debug.contains(&URL_SAFE_NO_PAD.encode([123; 32]))
    );
}

#[test]
fn reference_peer_enforces_claim_role_order_and_exact_slot_replay() {
    let mut peer = peer();
    assert_eq!(peer.read(&old(), 0), Err(PeerError::Denied));
    assert_eq!(peer.claim(&new(), 0), Err(PeerError::Denied));
    assert_eq!(peer.claim(&old(), 1), Ok(context(true)));
    assert_eq!(peer.claim(&old(), 2), Ok(context(true)));
    let other = Actor::Initiator { account_id: id(1), device_id: id(8), authorized: true };
    assert_eq!(peer.claim(&other, 3), Err(PeerError::Denied));
    assert_eq!(
        peer.message(&new(), message(PairingStep::InitiatorShare), 4),
        Err(PeerError::Denied)
    );
    assert_eq!(
        peer.message(&new(), message(PairingStep::ResponderShare), 4),
        Err(PeerError::Conflict)
    );
    peer.message(&old(), message(PairingStep::InitiatorShare), 5).expect("slot");
    peer.message(&old(), message(PairingStep::InitiatorShare), 6).expect("exact replay");
    let mut different = message(PairingStep::InitiatorShare);
    different.payload[0] = 1;
    assert_eq!(peer.message(&old(), different, 7), Err(PeerError::Conflict));
    assert_eq!(peer.read(&new(), 8).expect("snapshot").messages.len(), 1);
}

#[test]
fn reference_peer_unknown_commit_recovers_exact_receipt_and_rechecks_authorization() {
    let mut peer = ready();
    let request = complete();
    peer.inject_fault(Fault::AfterCommit);
    assert_eq!(
        peer.complete(&old(), &request, 3, |_, _, _| Ok(receipt())),
        Err(PeerError::CommitOutcomeUnknown)
    );
    let snapshot = peer.read(&new(), 4).expect("committed snapshot");
    assert_eq!(snapshot.state, PairingState::Completed);
    assert_eq!(snapshot.messages, [] as [PairingMessageRequest; 0]);
    assert_eq!(snapshot.receipt, Some(receipt()));
    assert_eq!(
        peer.complete(&old(), &request, 300_001, |_, _, _| panic!("replay must not readmit")),
        Ok(receipt())
    );
    let revoked = Actor::Initiator { account_id: id(1), device_id: id(4), authorized: false };
    assert_eq!(
        peer.complete(&revoked, &request, 5, |_, _, _| panic!("must reauthorize")),
        Err(PeerError::Denied)
    );
    let mut other = request;
    other.new_device_signature[0] = 1;
    assert_eq!(
        peer.complete(&old(), &other, 5, |_, _, _| panic!("different plan")),
        Err(PeerError::Conflict)
    );
    assert_eq!(peer.cancel(&new(), 5), Err(PeerError::Conflict));
    assert_eq!(
        peer.message(&new(), message(PairingStep::InitiatorShare), 5),
        Err(PeerError::Denied)
    );
    assert_eq!(peer.read(&new(), 86_400_003), Err(PeerError::Denied));
}

#[test]
fn reference_peer_denial_and_known_rollback_preserve_ready_state() {
    let mut peer = ready();
    let request = complete();
    let before = peer.read(&new(), 3).expect("before");
    assert_eq!(
        peer.complete(&old(), &request, 4, |_, _, _| Err(PeerError::Conflict)),
        Err(PeerError::Conflict)
    );
    assert_eq!(peer.read(&new(), 5), Ok(before.clone()));
    assert_eq!(
        peer.complete(&old(), &request, 5, |_, _, _| {
            Ok(PairingReceipt { revision: 99, ..receipt() })
        }),
        Err(PeerError::InvalidRequest)
    );
    let mut foreign = request.clone();
    let mut certificate =
        DeviceCertificate::decode(&foreign.device_certificate).expect("certificate");
    certificate.device_id = id(99);
    foreign.device_certificate = certificate.encode().expect("canonical foreign certificate");
    assert_eq!(
        peer.complete(&old(), &foreign, 5, |_, _, _| panic!("wrong identity")),
        Err(PeerError::InvalidRequest)
    );
    peer.inject_fault(Fault::BeforeMutation);
    assert_eq!(
        peer.complete(&old(), &request, 6, |_, _, _| Ok(receipt())),
        Err(PeerError::StorageUnavailable)
    );
    assert_eq!(peer.read(&new(), 7), Ok(before));
    peer.complete(&old(), &request, 8, |context, handoff, request| {
        assert_eq!(context.responder_device_id, id(2));
        assert_eq!(handoff.len(), 41);
        let cert = DeviceCertificate::decode(&request.device_certificate).expect("canonical cert");
        assert_eq!(cert.device_id, id(2));
        Ok(receipt())
    })
    .expect("admission boundary");
}

#[test]
fn reference_peer_expiry_cancel_and_lost_message_do_not_restart_cpace() {
    let mut peer = peer();
    peer.claim(&old(), 1).expect("claim");
    peer.inject_fault(Fault::AfterCommit);
    assert_eq!(
        peer.message(&old(), message(PairingStep::InitiatorShare), 2),
        Err(PeerError::CommitOutcomeUnknown)
    );
    assert_eq!(peer.read(&new(), 3).expect("read").messages.len(), 1);
    peer.message(&old(), message(PairingStep::InitiatorShare), 4).expect("exact saved bytes");
    assert_eq!(peer.read(&new(), 300_000).expect("expired").state, PairingState::Expired);
    assert_eq!(peer.cancel(&new(), 300_000), Err(PeerError::Denied));
    assert_eq!(
        peer.message(&old(), message(PairingStep::InitiatorShare), 300_000),
        Err(PeerError::Denied)
    );
    assert_eq!(
        peer.complete(&old(), &complete(), 300_000, |_, _, _| panic!("expired")),
        Err(PeerError::Denied)
    );
    let mut peer = ready();
    peer.cancel(&new(), 3).expect("cancel");
    peer.cancel(&new(), 400_000).expect("repeat cancelled");
    assert_eq!(
        peer.complete(&old(), &complete(), 4, |_, _, _| panic!("cancelled")),
        Err(PeerError::Conflict)
    );
    assert_eq!(
        peer.read(&new(), 86_699_999).expect("last retained millisecond").state,
        PairingState::Cancelled
    );
    assert_eq!(peer.read(&new(), 86_700_000), Err(PeerError::Denied));
    for (error, code, changed, retryable) in [
        (PeerError::StorageUnavailable, "auth.storage_unavailable", false, true),
        (PeerError::CommitOutcomeUnknown, "auth.commit_outcome_unknown", true, false),
    ] {
        let problem = error.problem("test-request").expect("problem");
        assert_eq!(problem.code.as_str(), code);
        assert_eq!((problem.changed, problem.retryable), (changed, retryable));
    }
}
