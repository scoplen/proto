// SPDX-License-Identifier: Apache-2.0
use std::{
    cell::Cell,
    net::{IpAddr, Ipv4Addr},
    sync::{Arc, Barrier},
};

use scoplen_api::{
    account_admission::{AccountEntryOperation as Operation, AccountRequestIntent as Intent},
    account_rate_reference::{
        ACCOUNT_RATE_BUCKET_CEILING, ReferenceAccountRateError as Error,
        ReferenceAccountRateFault as Fault, ReferenceAccountRateOutcome as Outcome,
        ReferenceAccountRatePeer as Peer, ReferenceAccountRateRequest as Request,
        ReferenceAccountRateSubject as Subject,
    },
    account_registration_reference::ReferencePasswordAttempt,
};
use uuid::Uuid;

const ORIGIN: &str = "https://control.example.com";
const NOW: u64 = 1_800_000_000_000;
const OPERATIONS: [Operation; 5] = [
    Operation::RequestChallenge,
    Operation::Register,
    Operation::PasswordOptions,
    Operation::PasswordLogin,
    Operation::DeviceAdmission,
];

fn peer() -> Peer {
    Peer::new(ORIGIN, &[7; 32]).unwrap()
}
fn source(n: u32) -> IpAddr {
    IpAddr::V4(Ipv4Addr::from(n))
}
fn id(n: u64) -> Uuid {
    Uuid::parse_str(&format!("019bdad6-b800-7000-8000-{n:012x}")).unwrap()
}
fn delay(error: Error) -> u16 {
    let Error::RateLimited(headers) = error else {
        panic!("expected common rate denial: {error:?}");
    };
    assert_eq!(headers.rate_limit_policy(), "\"authentication\";q=30;w=60");
    assert_eq!(
        headers.rate_limit(),
        format!("\"authentication\";r=0;t={}", headers.retry_after_seconds())
    );
    headers.retry_after_seconds()
}
fn attempt(username: &str) -> ReferencePasswordAttempt {
    ReferencePasswordAttempt {
        username: username.into(),
        profile: 1,
        salt: [1; 16],
        expires_at_ms: NOW + 120_000,
    }
}
fn device(request: &mut Request, n: u64, intent: Intent, now: u64) -> Result<(), Error> {
    request.admit_private(Subject::DecodedDevice { device_id: id(n), intent }, || now)
}
fn registration(peer: &Peer, address: u32, n: u64, now: u64) -> Request {
    let mut request = peer.begin(Operation::Register, source(address), || now).unwrap();
    device(&mut request, n, Intent::Submit, now).unwrap();
    request
}

#[test]
fn each_post_has_an_independent_exact_source_window() {
    let peer = peer();
    for operation in OPERATIONS {
        for _ in 0..30 {
            drop(peer.begin(operation, source(1), || NOW).unwrap());
        }
        assert_eq!(delay(peer.begin(operation, source(1), || NOW).unwrap_err()), 60);
    }
    assert_eq!(peer.summary().unwrap().rows, 5);
    for operation in OPERATIONS {
        assert_eq!(delay(peer.begin(operation, source(1), || NOW + 59_999).unwrap_err()), 1);
    }
    for operation in OPERATIONS {
        drop(peer.begin(operation, source(1), || NOW + 60_000).unwrap());
    }
}

#[test]
fn mapped_ipv6_uses_the_actual_ipv4_peer_bucket() {
    let peer = peer();
    let ipv4 = "192.0.2.1".parse().unwrap();
    let mapped = "::ffff:192.0.2.1".parse().unwrap();
    for _ in 0..15 {
        drop(peer.begin(Operation::Register, ipv4, || NOW).unwrap());
        drop(peer.begin(Operation::Register, mapped, || NOW).unwrap());
    }
    assert_eq!(delay(peer.begin(Operation::Register, mapped, || NOW).unwrap_err()), 60);
    drop(peer.begin(Operation::Register, "2001:db8::1".parse().unwrap(), || NOW).unwrap());
    assert_eq!(peer.summary().unwrap().rows, 2);
}

#[test]
fn private_rejections_and_malformed_bodies_do_not_refund_source() {
    let peer = peer();
    for index in 0..30 {
        let mut request = peer.begin(Operation::PasswordOptions, source(1), || NOW).unwrap();
        let result = request.admit_private(Subject::OptionsUsername("fixture.user"), || NOW);
        if index < 10 {
            result.unwrap();
            request.finish(Outcome::Other, || NOW).unwrap();
        } else {
            assert_eq!(delay(result.unwrap_err()), 60);
        }
    }
    assert_eq!(delay(peer.begin(Operation::PasswordOptions, source(1), || NOW).unwrap_err()), 60);
    for _ in 0..30 {
        let request = peer.begin(Operation::Register, source(2), || NOW).unwrap();
        request.finish(Outcome::Other, || NOW).unwrap();
    }
    assert_eq!(delay(peer.begin(Operation::Register, source(2), || NOW).unwrap_err()), 60);
    assert_eq!(peer.summary().unwrap().rows, 3);
}

#[test]
fn username_windows_use_bound_attempts_and_have_no_existence_branch() {
    let peer = peer();
    // These labels deliberately carry no Account lookup or status into the admission model.
    for username in ["current.user", "unknown.user", "inactive.user"] {
        for index in 0..10 {
            let mut request =
                peer.begin(Operation::PasswordOptions, source(index + 1), || NOW).unwrap();
            request.admit_private(Subject::OptionsUsername(username), || NOW).unwrap();
        }
        let mut request = peer.begin(Operation::PasswordOptions, source(20), || NOW).unwrap();
        assert_eq!(
            delay(request.admit_private(Subject::OptionsUsername(username), || NOW).unwrap_err()),
            60
        );
        // Login has its own endpoint bucket and takes the attempt's original username.
        let bound = attempt(username);
        for index in 0..10 {
            let mut request =
                peer.begin(Operation::PasswordLogin, source(index + 1), || NOW).unwrap();
            request.admit_private(Subject::PasswordAttempt(Some(&bound)), || NOW).unwrap();
        }
        let mut request = peer.begin(Operation::PasswordLogin, source(20), || NOW).unwrap();
        assert_eq!(
            delay(
                request.admit_private(Subject::PasswordAttempt(Some(&bound)), || NOW).unwrap_err()
            ),
            60
        );
    }
}

#[test]
fn decoded_device_quota_is_per_endpoint_without_existence_lookup() {
    let peer = peer();
    for operation in [Operation::RequestChallenge, Operation::Register, Operation::DeviceAdmission]
    {
        for index in 0..10 {
            let mut request = peer.begin(operation, source(index + 1), || NOW).unwrap();
            device(&mut request, 1, Intent::Submit, NOW).unwrap();
        }
        let mut request = peer.begin(operation, source(20), || NOW).unwrap();
        assert_eq!(delay(device(&mut request, 1, Intent::Confirm, NOW).unwrap_err()), 60);
        let mut request = peer.begin(operation, source(21), || NOW).unwrap();
        device(&mut request, 2, Intent::Submit, NOW).unwrap();
    }
}

#[test]
fn stages_reject_unverified_account_selection_and_repeated_admission() {
    let peer = peer();
    let called = Cell::new(false);
    let mut request = peer.begin(Operation::PasswordLogin, source(1), || NOW).unwrap();
    assert_eq!(
        request.verify_account(
            || {
                called.set(true);
                Some(id(1))
            },
            || NOW
        ),
        Err(Error::InvalidRequest)
    );
    assert!(!called.get());
    assert_eq!(peer.summary().unwrap().rows, 1);
    let bound = attempt("fixture.user");
    let mut request = peer.begin(Operation::PasswordLogin, source(2), || NOW).unwrap();
    request.admit_private(Subject::PasswordAttempt(Some(&bound)), || NOW).unwrap();
    assert!(!request.verify_account(|| None, || NOW).unwrap());
    assert_eq!(peer.summary().unwrap().rows, 3);
    assert_eq!(request.finish(Outcome::Authenticated, || NOW), Err(Error::InvalidRequest));
    let mut request = peer.begin(Operation::PasswordOptions, source(3), || NOW).unwrap();
    request.admit_private(Subject::OptionsUsername("fixture.user"), || NOW).unwrap();
    assert_eq!(
        request.admit_private(Subject::OptionsUsername("other.user"), || NOW),
        Err(Error::InvalidRequest)
    );
    let mut request = registration(&peer, 4, 4, NOW);
    assert_eq!(request.verify_account(|| Some(id(1)), || NOW), Err(Error::InvalidRequest));
}

#[test]
fn only_verified_login_admission_and_confirmation_charge_account() {
    let peer = peer();
    for operation in [Operation::PasswordLogin, Operation::DeviceAdmission, Operation::Register] {
        for index in 0..11_u32 {
            let mut request = peer.begin(operation, source(index + 1), || NOW).unwrap();
            if operation == Operation::PasswordLogin {
                let bound = attempt(&format!("fixture.user{index}"));
                request.admit_private(Subject::PasswordAttempt(Some(&bound)), || NOW).unwrap();
            } else {
                device(&mut request, u64::from(index + 1), Intent::Confirm, NOW).unwrap();
            }
            let verified = request.verify_account(|| Some(id(100)), || NOW);
            if index < 10 {
                assert!(verified.unwrap());
                request.finish(Outcome::Authenticated, || NOW).unwrap();
            } else {
                assert_eq!(delay(verified.unwrap_err()), 60);
            }
        }
    }
    // A submitted Account id is absent from every private subject variant. The trusted callback
    // above scripts successful verification; it does not prove actual password/signature checks.
}

#[test]
fn unusable_password_attempt_establishes_only_the_source() {
    let peer = peer();
    let mut request = peer.begin(Operation::PasswordLogin, source(1), || NOW).unwrap();
    request.admit_private(Subject::PasswordAttempt(None), || NOW).unwrap();
    request.finish(Outcome::AuthenticationDenied, || NOW).unwrap();
    assert_eq!(peer.summary().unwrap().rows, 1);
    assert_eq!(peer.summary().unwrap().denials, 1);
    assert_eq!(delay(peer.begin(Operation::PasswordLogin, source(1), || NOW).unwrap_err()), 1);
}

#[test]
fn exponential_cooldown_caps_at_300_and_rejections_do_not_extend_it() {
    let peer = peer();
    let mut now = NOW;
    for expected in [1, 2, 4, 8, 16, 32, 64, 128, 256, 300, 300] {
        registration(&peer, 1, 1, now).finish(Outcome::AuthenticationDenied, || now).unwrap();
        assert_eq!(
            delay(peer.begin(Operation::Register, source(1), || now).unwrap_err()),
            expected
        );
        assert_eq!(
            delay(peer.begin(Operation::Register, source(1), || now + 1).unwrap_err()),
            expected
        );
        let end = now + u64::from(expected) * 1_000;
        assert_eq!(delay(peer.begin(Operation::Register, source(1), || end - 1).unwrap_err()), 1);
        now = end;
    }
    let mut request = peer.begin(Operation::Register, source(2), || now).unwrap();
    // A fresh source still meets the established Device cooldown, with no identity in headers.
    device(&mut request, 1, Intent::Submit, now).unwrap();
    request.finish(Outcome::Other, || now).unwrap();
    assert_eq!(peer.summary().unwrap().denials, 11);
}

#[test]
fn private_cooldown_survives_source_changes_and_uses_greatest_wait() {
    let peer = peer();
    registration(&peer, 1, 1, NOW).finish(Outcome::AuthenticationDenied, || NOW).unwrap();
    let mut request = peer.begin(Operation::Register, source(2), || NOW).unwrap();
    assert_eq!(delay(device(&mut request, 1, Intent::Submit, NOW).unwrap_err()), 1);
    // Bring this new source to its final admitted slot without refunding the rejected private
    // stage. The private cooldown is 1 second; retrying this source needs the full window.
    for _ in 0..28 {
        drop(peer.begin(Operation::Register, source(2), || NOW).unwrap());
    }
    let mut request = peer.begin(Operation::Register, source(2), || NOW).unwrap();
    assert_eq!(delay(device(&mut request, 1, Intent::Submit, NOW).unwrap_err()), 60);
}

#[test]
fn authenticated_success_clears_streak_but_preserves_window_counts() {
    let peer = peer();
    registration(&peer, 1, 1, NOW).finish(Outcome::AuthenticationDenied, || NOW).unwrap();
    registration(&peer, 1, 1, NOW + 1_000).finish(Outcome::Authenticated, || NOW + 1_000).unwrap();
    registration(&peer, 1, 1, NOW + 1_000)
        .finish(Outcome::AuthenticationDenied, || NOW + 1_000)
        .unwrap();
    assert_eq!(delay(peer.begin(Operation::Register, source(1), || NOW + 1_000).unwrap_err()), 1);
    for _ in 0..27 {
        drop(peer.begin(Operation::Register, source(1), || NOW + 2_000).unwrap());
    }
    assert_eq!(delay(peer.begin(Operation::Register, source(1), || NOW + 2_000).unwrap_err()), 58);
}

#[test]
fn issuance_and_other_outcomes_do_not_clear_failure_streaks() {
    let peer = peer();
    registration(&peer, 1, 1, NOW).finish(Outcome::AuthenticationDenied, || NOW).unwrap();
    registration(&peer, 1, 1, NOW + 1_000).finish(Outcome::Other, || NOW + 1_000).unwrap();
    registration(&peer, 1, 1, NOW + 1_000)
        .finish(Outcome::AuthenticationDenied, || NOW + 1_000)
        .unwrap();
    assert_eq!(delay(peer.begin(Operation::Register, source(1), || NOW + 1_000).unwrap_err()), 2);
    for operation in [Operation::RequestChallenge, Operation::PasswordOptions] {
        let mut request = peer.begin(operation, source(1), || NOW + 3_000).unwrap();
        if operation == Operation::PasswordOptions {
            request
                .admit_private(Subject::OptionsUsername("fixture.user"), || NOW + 3_000)
                .unwrap();
        } else {
            device(&mut request, 1, Intent::Submit, NOW + 3_000).unwrap();
        }
        assert_eq!(
            request.finish(Outcome::Authenticated, || NOW + 3_000),
            Err(Error::InvalidRequest)
        );
    }
}

#[test]
fn ten_quiet_minutes_clear_streak_without_needing_row_retirement() {
    let peer = peer();
    registration(&peer, 1, 1, NOW).finish(Outcome::AuthenticationDenied, || NOW).unwrap();
    registration(&peer, 1, 1, NOW + 1_000)
        .finish(Outcome::AuthenticationDenied, || NOW + 1_000)
        .unwrap();
    registration(&peer, 1, 1, NOW + 500_000).finish(Outcome::Other, || NOW + 500_000).unwrap();
    registration(&peer, 1, 1, NOW + 601_000)
        .finish(Outcome::AuthenticationDenied, || NOW + 601_000)
        .unwrap();
    assert_eq!(peer.summary().unwrap().rows, 2);
    assert_eq!(delay(peer.begin(Operation::Register, source(1), || NOW + 601_000).unwrap_err()), 1);
}

#[test]
fn complete_restart_preserves_username_debt_cooldown_and_time_high_water() {
    let peer = peer();
    for index in 0..10 {
        let mut request =
            peer.begin(Operation::PasswordOptions, source(index + 1), || NOW).unwrap();
        request.admit_private(Subject::OptionsUsername("fixture.user"), || NOW).unwrap();
    }
    registration(&peer, 1, 1, NOW).finish(Outcome::AuthenticationDenied, || NOW).unwrap();
    let restored = Peer::restore(peer.checkpoint().unwrap());
    assert_eq!(
        delay(restored.begin(Operation::Register, source(1), || NOW - 60_000).unwrap_err()),
        1
    );
    assert_eq!(restored.summary().unwrap().high_water_ms, NOW);
    let mut request =
        restored.begin(Operation::PasswordOptions, source(100), || NOW - 60_000).unwrap();
    assert_eq!(
        delay(
            request
                .admit_private(Subject::OptionsUsername("fixture.user"), || NOW - 60_000)
                .unwrap_err()
        ),
        60
    );
    registration(&restored, 1, 1, NOW + 1_000)
        .finish(Outcome::AuthenticationDenied, || NOW + 1_000)
        .unwrap();
    assert_eq!(
        delay(restored.begin(Operation::Register, source(1), || NOW + 1_000).unwrap_err()),
        2
    );
}

#[test]
fn actual_global_row_ceiling_preserves_existing_debt_and_indexed_bounded_retirement() {
    let peer = peer();
    for index in 0..u32::try_from(ACCOUNT_RATE_BUCKET_CEILING).unwrap() {
        drop(peer.begin(Operation::Register, source(index), || NOW).unwrap());
    }
    assert_eq!(peer.summary().unwrap().rows, ACCOUNT_RATE_BUCKET_CEILING);
    assert_eq!(delay(peer.begin(Operation::PasswordOptions, source(0), || NOW).unwrap_err()), 1);
    for _ in 1..30 {
        drop(peer.begin(Operation::Register, source(0), || NOW).unwrap());
    }
    assert_eq!(delay(peer.begin(Operation::Register, source(0), || NOW).unwrap_err()), 60);
    assert_eq!(peer.maintain(|| NOW + 599_000).unwrap(), 0);
    assert_eq!(peer.maintain(|| NOW + 600_000).unwrap(), 100);
    assert_eq!(peer.maintain(|| NOW + 600_000).unwrap(), 0);
    assert_eq!(peer.maintain(|| NOW - 1).unwrap(), 0);
    assert_eq!(peer.maintain(|| NOW + 601_000).unwrap(), 100);
    assert_eq!(peer.summary().unwrap().rows, ACCOUNT_RATE_BUCKET_CEILING - 200);
    assert_eq!(peer.summary().unwrap().indexed_rows, ACCOUNT_RATE_BUCKET_CEILING - 200);
    drop(peer.begin(Operation::PasswordOptions, source(0), || NOW + 601_000).unwrap());
}

#[test]
fn an_admitted_attempt_updates_the_single_expiry_index() {
    let peer = peer();
    drop(peer.begin(Operation::Register, source(1), || NOW).unwrap());
    drop(peer.begin(Operation::Register, source(1), || NOW + 500_000).unwrap());
    assert_eq!(peer.summary().unwrap().indexed_rows, 1);
    assert_eq!(peer.maintain(|| NOW + 600_000).unwrap(), 0);
    assert_eq!(peer.maintain(|| NOW + 1_100_000).unwrap(), 1);
    assert_eq!(peer.summary().unwrap().rows, 0);
    assert_eq!(peer.summary().unwrap().indexed_rows, 0);
}

#[test]
fn cloned_instances_serialize_new_bucket_capacity_and_source_counts() {
    let peer = Peer::with_ceiling(ORIGIN, &[7; 32], 2).unwrap();
    let barrier = Arc::new(Barrier::new(4));
    let workers: Vec<_> = (0..4)
        .map(|index| {
            let peer = peer.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                peer.begin(Operation::Register, source(index), || NOW).map(drop)
            })
        })
        .collect();
    let results: Vec<_> = workers.into_iter().map(|worker| worker.join().unwrap()).collect();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 2);
    assert!(
        results.iter().filter_map(|result| result.as_ref().err()).all(|error| delay(*error) == 1)
    );
    assert_eq!(peer.summary().unwrap().rows, 2);
    let peer = Peer::new(ORIGIN, &[7; 32]).unwrap();
    let barrier = Arc::new(Barrier::new(40));
    let workers: Vec<_> = (0..40)
        .map(|_| {
            let peer = peer.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                peer.begin(Operation::Register, source(1), || NOW).map(drop)
            })
        })
        .collect();
    let results: Vec<_> = workers.into_iter().map(|worker| worker.join().unwrap()).collect();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 30);
    assert!(
        results.iter().filter_map(|result| result.as_ref().err()).all(|error| delay(*error) == 60)
    );
}

#[test]
fn denial_audit_failure_rolls_back_all_cooldowns_but_not_earlier_counts() {
    let peer = peer();
    let request = registration(&peer, 1, 1, NOW);
    peer.set_fault(Fault::DenialAudit).unwrap();
    assert_eq!(
        request.finish(Outcome::AuthenticationDenied, || NOW),
        Err(Error::StorageUnavailable)
    );
    assert_eq!(peer.summary().unwrap().denials, 0);
    for _ in 1..10 {
        registration(&peer, 1, 1, NOW).finish(Outcome::Other, || NOW).unwrap();
    }
    let mut request = peer.begin(Operation::Register, source(1), || NOW).unwrap();
    assert_eq!(delay(device(&mut request, 1, Intent::Submit, NOW).unwrap_err()), 60);
    assert_eq!(peer.summary().unwrap().rows, 2);
}

#[test]
fn admission_storage_failure_never_partially_charges_its_stage() {
    let peer = peer();
    peer.set_fault(Fault::BeforeCommit).unwrap();
    assert_eq!(
        peer.begin(Operation::Register, source(1), || NOW).unwrap_err(),
        Error::StorageUnavailable
    );
    assert_eq!(peer.summary().unwrap().rows, 0);
    let mut request = peer.begin(Operation::Register, source(1), || NOW).unwrap();
    peer.set_fault(Fault::BeforeCommit).unwrap();
    assert_eq!(device(&mut request, 1, Intent::Submit, NOW), Err(Error::StorageUnavailable));
    assert_eq!(peer.summary().unwrap().rows, 1);
    for _ in 1..30 {
        drop(peer.begin(Operation::Register, source(1), || NOW).unwrap());
    }
    assert_eq!(delay(peer.begin(Operation::Register, source(1), || NOW).unwrap_err()), 60);
}

#[test]
fn invalid_identities_stages_and_configuration_fail_without_private_rows() {
    assert!(matches!(
        Peer::new("http://control.example.com", &[7; 32]),
        Err(Error::InvalidRequest)
    ));
    assert!(matches!(Peer::new(ORIGIN, &[7; 31]), Err(Error::InvalidRequest)));
    for ceiling in [0, ACCOUNT_RATE_BUCKET_CEILING + 1] {
        assert!(matches!(
            Peer::with_ceiling(ORIGIN, &[7; 32], ceiling),
            Err(Error::InvalidRequest)
        ));
    }
    let peer = peer();
    let mut request = peer.begin(Operation::PasswordOptions, source(1), || NOW).unwrap();
    assert_eq!(
        request.admit_private(Subject::OptionsUsername("NotCanonical"), || NOW),
        Err(Error::InvalidRequest)
    );
    let mut request = peer.begin(Operation::Register, source(1), || NOW).unwrap();
    assert_eq!(
        request.admit_private(
            Subject::DecodedDevice { device_id: Uuid::nil(), intent: Intent::Submit },
            || NOW
        ),
        Err(Error::InvalidRequest)
    );
    let mut request = peer.begin(Operation::PasswordLogin, source(1), || NOW).unwrap();
    assert_eq!(
        request.admit_private(Subject::OptionsUsername("fixture.user"), || NOW),
        Err(Error::InvalidRequest)
    );
    assert_eq!(peer.summary().unwrap().rows, 3);
}

#[test]
fn debug_surfaces_redact_identities_probe_key_and_restart_image() {
    let peer = peer();
    let mut request = peer.begin(Operation::PasswordOptions, source(1), || NOW).unwrap();
    let subject = Subject::OptionsUsername("fixture.user");
    assert_eq!(format!("{subject:?}"), "ReferenceAccountRateSubject([REDACTED])");
    request.admit_private(subject, || NOW).unwrap();
    assert_eq!(format!("{request:?}"), "ReferenceAccountRateRequest([REDACTED])");
    assert_eq!(format!("{peer:?}"), "ReferenceAccountRatePeer([REDACTED])");
    assert_eq!(
        format!("{:?}", peer.checkpoint().unwrap()),
        "ReferenceAccountRateImage([REDACTED])"
    );
}

#[test]
fn each_rejected_stage_stops_later_work_without_consuming_business_challenges() {
    use scoplen_api::{
        account_admission::{AccountRequestChallengeRequest, AccountRequestKind},
        account_registration_reference::ReferenceAccountRegistrationPeer,
    };
    let business_peer = ReferenceAccountRegistrationPeer::new(ORIGIN).unwrap();
    business_peer
        .challenge(
            &AccountRequestChallengeRequest {
                kind: AccountRequestKind::Register,
                intent: Intent::Submit,
                operation_id: id(1),
                device_id: id(2),
            }
            .to_json()
            .unwrap(),
            || NOW,
        )
        .unwrap();
    let before = business_peer.summary().unwrap();
    let bound = attempt("fixture.user");
    for blocked_stage in 0..3 {
        let peer = peer();
        match blocked_stage {
            0 => {
                for _ in 0..30 {
                    drop(peer.begin(Operation::PasswordLogin, source(100), || NOW).unwrap());
                }
            }
            1 => {
                for index in 0..10 {
                    let mut request =
                        peer.begin(Operation::PasswordLogin, source(index + 1), || NOW).unwrap();
                    request.admit_private(Subject::PasswordAttempt(Some(&bound)), || NOW).unwrap();
                }
            }
            _ => {
                for index in 0..10 {
                    let mut request =
                        peer.begin(Operation::PasswordLogin, source(index + 1), || NOW).unwrap();
                    let other = attempt(&format!("fixture.other{index}"));
                    request.admit_private(Subject::PasswordAttempt(Some(&other)), || NOW).unwrap();
                    request.verify_account(|| Some(id(50)), || NOW).unwrap();
                }
            }
        }
        let decoded = Cell::new(0);
        let verified = Cell::new(0);
        let dispatched = Cell::new(0);
        let result =
            peer.begin(Operation::PasswordLogin, source(100), || NOW).and_then(|mut request| {
                decoded.set(decoded.get() + 1);
                request.admit_private(Subject::PasswordAttempt(Some(&bound)), || NOW)?;
                request.verify_account(
                    || {
                        verified.set(verified.get() + 1);
                        Some(id(50))
                    },
                    || NOW,
                )?;
                dispatched.set(dispatched.get() + 1);
                request.finish(Outcome::Authenticated, || NOW)
            });
        assert_eq!(delay(result.unwrap_err()), 60);
        assert_eq!(decoded.get(), u32::from(blocked_stage > 0));
        assert_eq!(verified.get(), u32::from(blocked_stage > 1));
        assert_eq!(dispatched.get(), 0);
        assert_eq!(business_peer.summary().unwrap(), before);
    }
    // This is an explicit staged-fixture boundary, not an integrated HTTP or Account adapter.
}
