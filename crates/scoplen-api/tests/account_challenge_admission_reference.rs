// SPDX-License-Identifier: Apache-2.0
use std::{
    cell::Cell,
    collections::BTreeSet,
    net::{IpAddr, Ipv4Addr},
};

use scoplen_api::{
    account_admission::{
        AccountRegistrationPayload, AccountRegistrationRequest, AccountRequestChallengeRequest,
        AccountRequestIntent as Intent, AccountRequestKind as Kind,
    },
    account_rate_reference::{
        ReferenceAccountRateError as RateError, ReferenceAccountRateFault as RateFault,
        ReferenceAccountRatePeer as Rates,
    },
    account_registration_reference::{
        DEFAULT_USED_ACCOUNT_ID_CEILING, ReferenceAccountRegistrationPeer as Peer,
        ReferenceChallengeAdmissionError as Error, ReferenceRegistrationError as ChallengeError,
    },
};
use scoplen_crypto::{
    AccountRequestProof, AccountRequestSignatureInput, P256SigningKey, account_capability_digest,
};
use scoplen_test_vectors::VectorDocument;
use uuid::Uuid;

const ORIGIN: &str = "https://control.example.com";
const NOW: u64 = 1_800_000_000_000;

fn fixture() -> (Peer, Rates) {
    (Peer::new(ORIGIN).unwrap(), Rates::new(ORIGIN, &[7; 32]).unwrap())
}
fn source(n: u32) -> IpAddr {
    IpAddr::V4(Ipv4Addr::from(n))
}
fn id(n: u64) -> Uuid {
    Uuid::parse_str(&format!("019bdad6-b800-7000-8000-{n:012x}")).unwrap()
}
fn challenge_body(operation: Uuid, device: Uuid) -> Vec<u8> {
    AccountRequestChallengeRequest {
        kind: Kind::Register,
        intent: Intent::Submit,
        operation_id: operation,
        device_id: device,
    }
    .to_json()
    .unwrap()
}
fn body() -> Vec<u8> {
    challenge_body(id(1), id(2))
}
fn delay(error: Error) -> u16 {
    let Error::Admission(RateError::RateLimited(headers)) = error else {
        panic!("expected rate denial: {error:?}");
    };
    assert_eq!(headers.rate_limit_policy(), "\"authentication\";q=30;w=60");
    assert_eq!(
        headers.rate_limit(),
        format!("\"authentication\";r=0;t={}", headers.retry_after_seconds())
    );
    headers.retry_after_seconds()
}

#[test]
fn source_rejection_precedes_lazy_body_collection_and_any_nonce_creation() {
    let (peer, rates) = fixture();
    let calls = Cell::new(0);
    for _ in 0..30 {
        assert_eq!(
            peer.challenge_with_admission(
                &rates,
                source(1),
                || {
                    calls.set(calls.get() + 1);
                    Ok(b"{".to_vec())
                },
                || NOW
            )
            .unwrap_err(),
            Error::Challenge(ChallengeError::InvalidRequest)
        );
    }
    let before = peer.summary().unwrap();
    assert_eq!(
        delay(
            peer.challenge_with_admission(
                &rates,
                source(1),
                || {
                    calls.set(calls.get() + 1);
                    Ok(body())
                },
                || NOW
            )
            .unwrap_err()
        ),
        60
    );
    assert_eq!(calls.get(), 30);
    assert_eq!(before.challenges, 0);
    assert_eq!(peer.summary().unwrap(), before);
    assert_eq!(rates.summary().unwrap().rows, 1);
}

#[test]
fn strict_complete_structure_precedes_device_admission() {
    let (peer, rates) = fixture();
    let valid = String::from_utf8(body()).unwrap();
    let duplicate = format!("{},\"device_id\":\"{}\"}}", &valid[..valid.len() - 1], id(2));
    let nil = valid.replace(&id(2).to_string(), &Uuid::nil().to_string());
    let mut oversized = body();
    oversized.resize(513, b' ');
    for (index, (input, expected)) in [
        (b"{}".to_vec(), ChallengeError::InvalidRequest),
        (duplicate.into_bytes(), ChallengeError::InvalidRequest),
        (nil.into_bytes(), ChallengeError::InvalidRequest),
        (oversized, ChallengeError::TooLarge),
    ]
    .into_iter()
    .enumerate()
    {
        assert_eq!(
            peer.challenge_with_admission(
                &rates,
                source(u32::try_from(index).unwrap()),
                || Ok(input),
                || NOW
            )
            .unwrap_err(),
            Error::Challenge(expected)
        );
    }
    assert_eq!(peer.summary().unwrap().challenges, 0);
    assert_eq!(rates.summary().unwrap().rows, 4);
    for index in 0..10 {
        peer.challenge_with_admission(&rates, source(index + 100), || Ok(body()), || NOW).unwrap();
    }
    assert_eq!(peer.summary().unwrap().challenges, 10);
    assert_eq!(
        delay(
            peer.challenge_with_admission(&rates, source(200), || Ok(body()), || NOW).unwrap_err()
        ),
        60
    );
}

#[test]
fn device_rejection_preserves_challenges_and_does_not_refund_source() {
    let (peer, rates) = fixture();
    let mut attempts = BTreeSet::new();
    let mut nonces = BTreeSet::new();
    for index in 0..10 {
        let response = peer
            .challenge_with_admission(&rates, source(index + 1), || Ok(body()), || NOW)
            .unwrap();
        assert_eq!(response.expires_at_ms, NOW + 120_000);
        assert!(attempts.insert(account_capability_digest(response.attempt_id.as_bytes())));
        assert!(nonces.insert(account_capability_digest(response.nonce.as_bytes())));
    }
    let before = peer.summary().unwrap();
    assert_eq!(
        delay(
            peer.challenge_with_admission(&rates, source(100), || Ok(body()), || NOW).unwrap_err()
        ),
        60
    );
    assert_eq!(peer.summary().unwrap(), before);
    for _ in 0..29 {
        assert_eq!(
            peer.challenge_with_admission(&rates, source(100), || Ok(b"{".to_vec()), || NOW)
                .unwrap_err(),
            Error::Challenge(ChallengeError::InvalidRequest)
        );
    }
    let called = Cell::new(false);
    assert_eq!(
        delay(
            peer.challenge_with_admission(
                &rates,
                source(100),
                || {
                    called.set(true);
                    Ok(body())
                },
                || NOW
            )
            .unwrap_err()
        ),
        60
    );
    assert!(!called.get());
    assert_eq!(peer.summary().unwrap(), before);
}

#[test]
fn returned_nonce_accepts_a_real_fresh_device_proof_in_the_existing_registration_peer() {
    let (peer, rates) = fixture();
    let vectors =
        VectorDocument::parse_str(include_str!("../../../vectors/account-admission.json")).unwrap();
    let vector = vectors
        .vectors
        .iter()
        .find(|vector| vector.id == "account-admission-register-submit")
        .unwrap();
    let mut request = AccountRegistrationRequest::from_json(vector.input.as_bytes()).unwrap();
    let payload = AccountRegistrationPayload::from_cbor(request.payload.as_bytes()).unwrap();
    let calls = Cell::new(0);
    let response = peer
        .challenge_with_admission(
            &rates,
            source(1),
            || {
                calls.set(calls.get() + 1);
                Ok(challenge_body(payload.operation_id, payload.device_id))
            },
            || NOW,
        )
        .unwrap();
    request.attempt_id = response.attempt_id;
    request.nonce = response.nonce;
    let digest = AccountRequestSignatureInput::new(Kind::Register, request.payload.as_bytes())
        .unwrap()
        .request_digest(&request.account_signature);
    request.device_proof = AccountRequestProof::new(
        Kind::Register,
        Intent::Submit,
        ORIGIN,
        request.attempt_id.as_bytes(),
        request.nonce.as_bytes(),
        payload.operation_id,
        payload.device_id,
        &digest,
    )
    .unwrap()
    .sign(&P256SigningKey::from_bytes(&[2; 32]).unwrap())
    .unwrap();
    // Registration remains the explicitly admitted-only fixture operation; only its challenge
    // was connected to rate admission by this outcome.
    assert_eq!(peer.register(&request.to_json().unwrap(), || NOW).unwrap().status, 201);
    assert_eq!(calls.get(), 1);
    let summary = peer.summary().unwrap();
    assert_eq!(summary.accounts, 1);
    assert_eq!(summary.devices, 1);
    assert_eq!(summary.receipts, 1);
    assert_eq!(summary.registrations, 1);
    assert_eq!(summary.challenges, 0);
    assert_eq!(rates.summary().unwrap().rows, 2);
}

#[test]
fn body_collection_failure_preserves_its_earlier_source_count() {
    let (peer, rates) = fixture();
    assert_eq!(
        peer.challenge_with_admission(
            &rates,
            source(1),
            || Err(ChallengeError::StorageUnavailable),
            || NOW
        )
        .unwrap_err(),
        Error::Challenge(ChallengeError::StorageUnavailable)
    );
    assert_eq!(rates.summary().unwrap().rows, 1);
    for _ in 0..29 {
        assert_eq!(
            peer.challenge_with_admission(&rates, source(1), || Ok(b"{".to_vec()), || NOW)
                .unwrap_err(),
            Error::Challenge(ChallengeError::InvalidRequest)
        );
    }
    assert_eq!(
        delay(peer.challenge_with_admission(&rates, source(1), || Ok(body()), || NOW).unwrap_err()),
        60
    );
    assert_eq!(peer.summary().unwrap().challenges, 0);
}

#[test]
fn admission_storage_and_private_capacity_failure_never_generate_a_nonce() {
    let (peer, rates) = fixture();
    rates.set_fault(RateFault::BeforeCommit).unwrap();
    let called = Cell::new(false);
    assert_eq!(
        peer.challenge_with_admission(
            &rates,
            source(1),
            || {
                called.set(true);
                Ok(body())
            },
            || NOW
        )
        .unwrap_err(),
        Error::Admission(RateError::StorageUnavailable)
    );
    assert!(!called.get());
    assert_eq!(rates.summary().unwrap().rows, 0);
    let rates = Rates::with_ceiling(ORIGIN, &[7; 32], 1).unwrap();
    assert_eq!(
        delay(
            peer.challenge_with_admission(
                &rates,
                source(1),
                || {
                    called.set(true);
                    Ok(body())
                },
                || NOW
            )
            .unwrap_err()
        ),
        1
    );
    assert!(called.get());
    assert_eq!(rates.summary().unwrap().rows, 1);
    assert_eq!(peer.summary().unwrap().challenges, 0);
}

#[test]
fn business_expiry_failure_leaves_no_nonce_and_keeps_admitted_device_debt() {
    let (peer, rates) = fixture();
    let calls = Cell::new(0);
    assert_eq!(
        peer.challenge_with_admission(
            &rates,
            source(1),
            || Ok(body()),
            || {
                calls.set(calls.get() + 1);
                if calls.get() < 4 { NOW } else { NOW + 120_000 }
            }
        )
        .unwrap_err(),
        Error::Challenge(ChallengeError::StorageUnavailable)
    );
    assert_eq!(peer.summary().unwrap().challenges, 0);
    assert_eq!(rates.summary().unwrap().rows, 2);
}

#[test]
fn independently_restored_images_preserve_device_debt_and_issued_challenges() {
    let (peer, rates) = fixture();
    for index in 0..10 {
        peer.challenge_with_admission(&rates, source(index + 1), || Ok(body()), || NOW).unwrap();
    }
    // The caller is quiescent while these two independent images are taken. The entry does
    // not provide an atomic combined checkpoint or a shared business/admission transaction.
    let business_image = peer.checkpoint().unwrap();
    let rate_image = rates.checkpoint().unwrap();
    let peer = Peer::restore(business_image, ORIGIN, DEFAULT_USED_ACCOUNT_ID_CEILING).unwrap();
    let rates = Rates::restore(rate_image);
    let before = peer.summary().unwrap();
    assert_eq!(before.challenges, 10);
    assert_eq!(
        delay(
            peer.challenge_with_admission(&rates, source(100), || Ok(body()), || NOW - 1)
                .unwrap_err()
        ),
        60
    );
    assert_eq!(peer.summary().unwrap(), before);
    assert_eq!(rates.summary().unwrap().high_water_ms, NOW);
}
