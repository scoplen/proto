// SPDX-License-Identifier: Apache-2.0
use scoplen_api::{
    certificate::{CertificateIssuanceRequest, CertificateTargets},
    certificate_reference::{
        CERTIFICATE_REFERENCE_ISSUANCE_LIMIT, CertificateReferenceActor as Actor,
        CertificateReferenceDissolutionError as DissolutionError,
        CertificateReferenceError as Error, CertificateReferenceFault as Fault,
        CertificateReferenceIssued as Issued, CertificateReferenceMemberStatus as Status,
        CertificateReferencePeer as Peer,
    },
};
use uuid::Uuid;

const ORIGIN: &str = "https://control.example.com";
const ED25519: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINdamAGCsQq31Uv+08lkBzoO4XLz2qYjJa8CGmj3B1Ea";

fn id(n: u64) -> Uuid {
    Uuid::parse_str(&format!("019bdad6-b800-7000-8000-{n:012x}")).unwrap()
}

fn actor(n: u64) -> Actor {
    Actor {
        origin: ORIGIN.into(),
        account: id(n),
        device: id(n + 1),
        current_identity: true,
        issue_scope: true,
        ca_read_scope: true,
        targets_authorized: true,
    }
}

fn request() -> CertificateIssuanceRequest {
    CertificateIssuanceRequest::new(
        ED25519,
        CertificateTargets::Hosts(vec![id(500)]),
        "deploy",
        300,
    )
    .unwrap()
}

fn fixture() -> (Peer, Actor, Actor) {
    let member = actor(1);
    let manager = actor(20);
    let mut peer = Peer::new(ORIGIN);
    peer.add_ca(id(100), id(200), 100).unwrap();
    for account in [member.account, manager.account] {
        peer.set_initial_member(id(100), account, Status::Active).unwrap();
    }
    (peer, member, manager)
}

fn issue(peer: &mut Peer, actor: &Actor, key: u64, now: u64) -> Result<Issued, Error> {
    peer.issue(actor, id(100), id(200), id(key), &request(), now)
}

#[test]
fn initial_snapshot_is_ca_bound_persisted_and_requires_current_native_authority() {
    let (peer, member, _) = fixture();
    let snapshot = peer.snapshot(&member, id(100), id(200)).unwrap();
    assert_eq!(snapshot.organization, id(100));
    assert_eq!(snapshot.authority, id(200));
    assert_eq!(snapshot.version, 1);
    assert_eq!(snapshot.generated_at, 100);
    assert_eq!(snapshot.revoked_serials, [] as [u64; 0]);
    for _ in 0..2 {
        assert_eq!(peer.snapshot(&member, id(100), id(200)), Ok(snapshot.clone()));
    }
    let reopened = Peer::from_image(peer.image());
    assert_eq!(reopened.snapshot(&member, id(100), id(200)), Ok(snapshot));
    assert_eq!(reopened.audit_events(), 0);

    let mut wrong = member.clone();
    wrong.current_identity = false;
    assert_eq!(peer.snapshot(&wrong, id(100), id(200)), Err(Error::AuthenticationRequired));
    wrong = member.clone();
    wrong.origin = "https://other.example.com".into();
    assert_eq!(peer.snapshot(&wrong, id(100), id(200)), Err(Error::Denied));
    wrong = member.clone();
    wrong.ca_read_scope = false;
    assert_eq!(peer.snapshot(&wrong, id(100), id(200)), Err(Error::Denied));
    for (caller, organization, authority) in [
        (actor(40), id(100), id(200)),
        (member.clone(), id(999), id(200)),
        (member, id(100), id(201)),
    ] {
        assert_eq!(peer.snapshot(&caller, organization, authority), Err(Error::NotFound));
    }
}

#[test]
fn exact_receipt_binds_account_device_origin_team_ca_and_canonical_body() {
    let (mut peer, member, manager) = fixture();
    let original = issue(&mut peer, &member, 300, 100).unwrap();
    let wire = format!(
        "{{\"ttl_seconds\":300, \"remote_user\":\"deploy\", \"hosts\":[\"{}\"], \"public_key\":\"{ED25519}\"}}",
        id(500)
    );
    let canonical = CertificateIssuanceRequest::from_json(wire.as_bytes()).unwrap();
    assert_eq!(
        peer.issue(&member, id(100), id(200), id(300), &canonical, 101),
        Ok(original.clone())
    );
    let before = peer.counters(id(100));
    let mut wrong = member.clone();
    wrong.device = id(3);
    assert_eq!(issue(&mut peer, &wrong, 300, 101), Err(Error::Conflict));
    wrong = member.clone();
    wrong.origin = "https://other.example.com".into();
    assert_eq!(issue(&mut peer, &wrong, 300, 101), Err(Error::Denied));
    let mut changed = request();
    changed.remote_user = "other".into();
    assert_eq!(peer.issue(&member, id(100), id(200), id(300), &changed, 101), Err(Error::Conflict));
    peer.add_ca(id(101), id(201), 100).unwrap();
    peer.set_initial_member(id(101), member.account, Status::Active).unwrap();
    assert_eq!(
        peer.issue(&member, id(101), id(201), id(300), &request(), 101),
        Err(Error::Conflict)
    );
    assert_eq!(
        peer.issue(&member, id(100), id(201), id(300), &request(), 101),
        Err(Error::NotFound)
    );
    assert_eq!(peer.counters(id(100)), before);
    assert_eq!(peer.counters(id(101)), Some((0, 1, 0)));
    assert_eq!(peer.audit_events(), 1);

    let independent = issue(&mut peer, &manager, 300, 101).unwrap();
    assert_eq!(independent.account, manager.account);
    assert_eq!(independent.serial, original.serial + 1);
    assert_eq!(issue(&mut peer, &member, 300, 102), Ok(original));
    assert_eq!(peer.audit_events(), 2);
}

#[test]
fn current_authority_precedes_mismatched_and_revoked_receipts() {
    let (mut peer, member, manager) = fixture();
    issue(&mut peer, &member, 300, 100).unwrap();
    peer.change_member(&manager, id(100), id(200), member.account, Status::Suspended, true, 101)
        .unwrap();
    assert_eq!(issue(&mut peer, &member, 300, 102), Err(Error::NotFound));
    peer.change_member(&manager, id(100), id(200), member.account, Status::Active, true, 103)
        .unwrap();
    assert_eq!(issue(&mut peer, &member, 300, 104), Err(Error::Revoked));

    for (identity, scope, targets, expected) in [
        (false, true, true, Error::AuthenticationRequired),
        (true, false, true, Error::Denied),
        (true, true, false, Error::Denied),
    ] {
        let mut wrong = member.clone();
        wrong.current_identity = identity;
        wrong.issue_scope = scope;
        wrong.targets_authorized = targets;
        assert_eq!(issue(&mut peer, &wrong, 300, 104), Err(expected));
    }
    let mut wrong = member.clone();
    wrong.targets_authorized = false;
    wrong.device = id(3);
    assert_eq!(issue(&mut peer, &wrong, 300, 104), Err(Error::Denied));
    wrong = member.clone();
    wrong.device = id(3);
    assert_eq!(issue(&mut peer, &wrong, 300, 104), Err(Error::Conflict));
    assert_eq!(peer.audit_events(), 3);
}

#[test]
fn suspend_remove_and_self_leave_preserve_revoked_serials_after_restore_or_rejoin() {
    for status in [Status::Suspended, Status::Removed] {
        for self_leave in [false, true] {
            if self_leave && status != Status::Removed {
                continue;
            }
            let (mut peer, member, manager) = fixture();
            let original = issue(&mut peer, &member, 300, 100).unwrap();
            let actor = if self_leave { &member } else { &manager };
            peer.change_member(actor, id(100), id(200), member.account, status, true, 101).unwrap();
            assert_eq!(issue(&mut peer, &member, 300, 102), Err(Error::NotFound));
            assert_eq!(peer.snapshot(&member, id(100), id(200)), Err(Error::NotFound));
            let revoked = peer.snapshot(&manager, id(100), id(200)).unwrap();
            assert_eq!(revoked.revoked_serials, [original.serial]);
            assert_eq!(revoked.version, 2);
            assert_eq!(revoked.generated_at, 101);
            peer.change_member(
                &manager,
                id(100),
                id(200),
                member.account,
                Status::Active,
                true,
                103,
            )
            .unwrap();
            assert_eq!(peer.snapshot(&member, id(100), id(200)), Ok(revoked.clone()));
            let fresh = issue(&mut peer, &member, 301, 104).unwrap();
            assert_eq!(fresh.serial, original.serial + 1);
            assert_eq!(issue(&mut peer, &member, 300, 104), Err(Error::Revoked));
            let mut reopened = Peer::from_image(peer.image());
            assert_eq!(issue(&mut reopened, &member, 300, 105), Err(Error::Revoked));
            assert_eq!(issue(&mut reopened, &member, 301, 105), Ok(fresh));
            assert_eq!(reopened.snapshot(&member, id(100), id(200)), Ok(revoked));
        }
    }
}

#[test]
fn revocation_is_account_and_ca_isolated_even_when_serials_and_keys_match() {
    let (mut peer, member, manager) = fixture();
    let affected = issue(&mut peer, &member, 300, 100).unwrap();
    let unaffected = issue(&mut peer, &manager, 300, 100).unwrap();
    peer.add_ca(id(101), id(201), 100).unwrap();
    peer.set_initial_member(id(101), member.account, Status::Active).unwrap();
    let other_team = peer.issue(&member, id(101), id(201), id(301), &request(), 100).unwrap();
    assert_eq!(other_team.serial, affected.serial);
    peer.change_member(&manager, id(100), id(200), member.account, Status::Removed, true, 101)
        .unwrap();
    assert_eq!(
        peer.snapshot(&manager, id(100), id(200)).unwrap().revoked_serials,
        [affected.serial]
    );
    assert_eq!(issue(&mut peer, &manager, 300, 102), Ok(unaffected));
    assert_eq!(peer.issue(&member, id(101), id(201), id(301), &request(), 102), Ok(other_team));
    let other_snapshot = peer.snapshot(&member, id(101), id(201)).unwrap();
    assert_eq!(other_snapshot.version, 1);
    assert_eq!(other_snapshot.revoked_serials, [] as [u64; 0]);
}

#[test]
fn actual_cap_counts_revoked_unexpired_rows_but_exact_receipt_precedes_it() {
    let (mut peer, member, manager) = fixture();
    let original = issue(&mut peer, &member, 300, 100).unwrap();
    for serial in 2..=u64::try_from(CERTIFICATE_REFERENCE_ISSUANCE_LIMIT).unwrap() {
        peer.seed_issued(Issued { serial, ..original.clone() }).unwrap();
    }
    let full = peer.counters(id(100));
    assert_eq!(full, Some((100_000, 1, 100_000)));
    assert_eq!(issue(&mut peer, &member, 300, 101), Ok(original));
    assert_eq!(issue(&mut peer, &member, 301, 101), Err(Error::QuotaExceeded));
    assert_eq!(peer.counters(id(100)), full);
    assert_eq!(peer.audit_events(), 1);

    peer.change_member(&manager, id(100), id(200), member.account, Status::Suspended, true, 102)
        .unwrap();
    let snapshot = peer.snapshot(&manager, id(100), id(200)).unwrap();
    assert_eq!(snapshot.revoked_serials, (1..=100_000).collect::<Vec<_>>());
    assert_eq!(snapshot.version, 2);
    peer.change_member(&manager, id(100), id(200), member.account, Status::Active, true, 103)
        .unwrap();
    assert_eq!(issue(&mut peer, &member, 300, 104), Err(Error::Revoked));
    assert_eq!(issue(&mut peer, &member, 301, 104), Err(Error::QuotaExceeded));
    assert_eq!(peer.counters(id(100)), Some((100_000, 3, 100_000)));
    assert_eq!(peer.audit_events(), 3);

    peer.change_member(&manager, id(100), id(200), member.account, Status::Removed, true, 400)
        .unwrap();
    let pruned = peer.snapshot(&manager, id(100), id(200)).unwrap();
    assert_eq!(pruned.revoked_serials, [] as [u64; 0]);
    assert_eq!(pruned.version, 3);
    assert_eq!(pruned.generated_at, 400);
    peer.change_member(&manager, id(100), id(200), member.account, Status::Active, true, 401)
        .unwrap();
    let mut reopened = Peer::from_image(peer.image());
    assert_eq!(issue(&mut reopened, &member, 300, 402), Err(Error::Revoked));
    let fresh = issue(&mut reopened, &member, 301, 402).unwrap();
    assert_eq!(fresh.serial, 100_001);
    assert_eq!(reopened.snapshot(&member, id(100), id(200)), Ok(pruned));
}

#[test]
fn denied_and_noop_membership_changes_preserve_snapshot_counters_audit_and_fault() {
    let (mut peer, member, manager) = fixture();
    let snapshot = peer.snapshot(&member, id(100), id(200)).unwrap();
    let counters = peer.counters(id(100));
    peer.set_fault(Fault::Rollback);
    assert_eq!(
        peer.change_member(&manager, id(100), id(200), member.account, Status::Removed, false, 101),
        Err(Error::Denied)
    );
    peer.change_member(&manager, id(100), id(200), member.account, Status::Active, true, 101)
        .unwrap();
    assert_eq!(peer.snapshot(&member, id(100), id(200)), Ok(snapshot));
    assert_eq!(peer.counters(id(100)), counters);
    assert_eq!(peer.audit_events(), 0);
    assert_eq!(issue(&mut peer, &member, 300, 102), Err(Error::StorageUnavailable));
    assert_eq!(peer.counters(id(100)), counters);
    assert_eq!(peer.audit_events(), 0);
}

#[test]
fn issuance_faults_publish_certificate_receipt_serial_and_audit_atomically_across_restart() {
    for (fault, expected, committed) in [
        (Fault::Rollback, Error::StorageUnavailable, false),
        (Fault::UnknownRollback, Error::CommitOutcomeUnknown, false),
        (Fault::UnknownCommitted, Error::CommitOutcomeUnknown, true),
        (Fault::LostResponse, Error::ResponseLost, true),
    ] {
        let (mut peer, member, _) = fixture();
        peer.set_fault(fault);
        assert_eq!(issue(&mut peer, &member, 300, 100), Err(expected));
        let count = u64::from(committed);
        assert_eq!(peer.counters(id(100)), Some((count, 1, usize::from(committed))));
        assert_eq!(peer.audit_events(), count);
        let mut reopened = Peer::from_image(peer.image());
        let confirmed = issue(&mut reopened, &member, 300, 101).unwrap();
        assert_eq!(confirmed.serial, 1);
        assert_eq!(confirmed.valid_before, if committed { 400 } else { 401 });
        assert_eq!(issue(&mut reopened, &member, 300, 102), Ok(confirmed));
        assert_eq!(reopened.counters(id(100)), Some((1, 1, 1)));
        assert_eq!(reopened.audit_events(), 1);
    }
}

#[test]
fn member_faults_publish_status_revocation_snapshot_revision_and_audit_atomically() {
    for (fault, expected, committed) in [
        (Fault::Rollback, Error::StorageUnavailable, false),
        (Fault::UnknownRollback, Error::UpdateCommitOutcomeUnknown, false),
        (Fault::UnknownCommitted, Error::UpdateCommitOutcomeUnknown, true),
        (Fault::LostResponse, Error::ResponseLost, true),
    ] {
        let (mut peer, member, manager) = fixture();
        let original = issue(&mut peer, &member, 300, 100).unwrap();
        peer.set_fault(fault);
        assert_eq!(
            peer.change_member(
                &manager,
                id(100),
                id(200),
                member.account,
                Status::Suspended,
                true,
                101
            ),
            Err(expected)
        );
        let mut reopened = Peer::from_image(peer.image());
        let snapshot = reopened.snapshot(&manager, id(100), id(200)).unwrap();
        assert_eq!(snapshot.version, if committed { 2 } else { 1 });
        assert_eq!(snapshot.generated_at, if committed { 101 } else { 100 });
        assert_eq!(snapshot.revoked_serials, if committed { vec![1] } else { vec![] });
        assert_eq!(reopened.counters(id(100)), Some((1, if committed { 2 } else { 1 }, 1)));
        assert_eq!(reopened.audit_events(), if committed { 2 } else { 1 });
        assert_eq!(
            issue(&mut reopened, &member, 300, 102),
            if committed { Err(Error::NotFound) } else { Ok(original) }
        );
        if committed {
            reopened
                .change_member(
                    &manager,
                    id(100),
                    id(200),
                    member.account,
                    Status::Active,
                    true,
                    103,
                )
                .unwrap();
            assert_eq!(issue(&mut reopened, &member, 300, 104), Err(Error::Revoked));
        }
    }
}

#[test]
fn dissolution_hook_is_atomic_and_grants_no_historical_snapshot_access() {
    for (fault, expected, committed) in [
        (Fault::Rollback, DissolutionError::RolledBack, false),
        (Fault::UnknownRollback, DissolutionError::CommitOutcomeUnknown, false),
        (Fault::UnknownCommitted, DissolutionError::CommitOutcomeUnknown, true),
        (Fault::LostResponse, DissolutionError::ResponseLost, true),
    ] {
        let (mut peer, member, manager) = fixture();
        issue(&mut peer, &member, 300, 100).unwrap();
        issue(&mut peer, &manager, 300, 100).unwrap();
        peer.set_fault(fault);
        assert_eq!(peer.dissolve(&manager, id(100), id(200), true, 101), Err(expected));
        let mut reopened = Peer::from_image(peer.image());
        assert_eq!(reopened.counters(id(100)), Some((2, if committed { 2 } else { 1 }, 2)));
        assert_eq!(reopened.audit_events(), if committed { 3 } else { 2 });
        let persisted = reopened.inspect_snapshot(id(100)).unwrap();
        assert_eq!(persisted.revoked_serials, if committed { vec![1, 2] } else { vec![] });
        assert_eq!(persisted.version, if committed { 2 } else { 1 });
        assert_eq!(persisted.generated_at, if committed { 101 } else { 100 });
        for caller in [&member, &manager] {
            if committed {
                assert_eq!(reopened.snapshot(caller, id(100), id(200)), Err(Error::NotFound));
                assert_eq!(issue(&mut reopened, caller, 300, 102), Err(Error::NotFound));
            } else {
                assert_eq!(
                    reopened.snapshot(caller, id(100), id(200)).unwrap().revoked_serials,
                    [] as [u64; 0]
                );
                assert!(issue(&mut reopened, caller, 300, 102).is_ok());
            }
        }
    }
    let (mut peer, member, manager) = fixture();
    assert_eq!(
        peer.dissolve(&manager, id(100), id(200), false, 101),
        Err(DissolutionError::Rejected(Error::Denied))
    );
    peer.dissolve(&manager, id(100), id(200), true, 101).unwrap();
    assert_eq!(peer.snapshot(&member, id(100), id(200)), Err(Error::NotFound));
}

#[test]
fn replay_and_validation_do_not_consume_the_next_transaction_fault() {
    let (mut peer, member, _) = fixture();
    let original = issue(&mut peer, &member, 300, 100).unwrap();
    peer.set_fault(Fault::Rollback);
    assert_eq!(issue(&mut peer, &member, 300, 101), Ok(original));
    let mut invalid = request();
    invalid.ttl_seconds = 0;
    assert_eq!(
        peer.issue(&member, id(100), id(200), id(301), &invalid, 101),
        Err(Error::InvalidRequest)
    );
    assert_eq!(issue(&mut peer, &member, 301, 101), Err(Error::StorageUnavailable));
    assert_eq!(peer.counters(id(100)), Some((1, 1, 1)));
    assert_eq!(peer.audit_events(), 1);
    assert_eq!(issue(&mut peer, &member, 301, 102).unwrap().serial, 2);
}

#[test]
fn receipt_lifetime_is_exact_and_expired_issuance_never_reuses_a_serial() {
    let (mut peer, member, _) = fixture();
    let original = issue(&mut peer, &member, 300, 100).unwrap();
    assert_eq!(issue(&mut peer, &member, 300, 86_499), Ok(original));
    let next = issue(&mut peer, &member, 300, 86_500).unwrap();
    assert_eq!(next.serial, 2);
    assert_eq!(next.valid_before, 86_800);
    assert_eq!(peer.audit_events(), 2);
}

#[test]
fn invalid_fixture_inputs_and_overflow_fail_without_business_mutation() {
    let (mut peer, member, manager) = fixture();
    assert_eq!(peer.add_ca(id(100), id(200), 100), Err(Error::InvalidRequest));
    assert_eq!(peer.add_ca(Uuid::nil(), id(200), 100), Err(Error::InvalidRequest));
    assert_eq!(peer.add_ca(id(101), id(201), 0), Err(Error::InvalidRequest));
    assert_eq!(
        peer.set_initial_member(id(100), member.account, Status::Removed),
        Err(Error::InvalidRequest)
    );
    assert_eq!(
        peer.change_member(&manager, id(100), id(200), member.account, Status::Removed, true, 0),
        Err(Error::InvalidRequest)
    );
    assert_eq!(issue(&mut peer, &member, 300, 0), Err(Error::InvalidRequest));
    assert_eq!(issue(&mut peer, &member, 300, u64::MAX), Err(Error::InvalidRequest));
    assert_eq!(
        peer.issue(&member, id(100), id(200), Uuid::nil(), &request(), 101),
        Err(Error::InvalidRequest)
    );
    let row = Issued {
        organization: id(100),
        authority: id(200),
        account: member.account,
        device: member.device,
        serial: u64::MAX,
        valid_before: 400,
    };
    peer.seed_issued(row.clone()).unwrap();
    assert_eq!(peer.seed_issued(row.clone()), Err(Error::InvalidRequest));
    assert_eq!(peer.seed_issued(Issued { authority: id(201), ..row }), Err(Error::InvalidRequest));
    assert_eq!(issue(&mut peer, &member, 300, 101), Err(Error::StorageUnavailable));
    assert_eq!(peer.counters(id(100)), Some((u64::MAX, 1, 1)));
    assert_eq!(peer.audit_events(), 0);
}

#[test]
fn definite_problem_classifications_are_content_free_and_uncertainty_stays_distinct() {
    for (error, status, code, changed, retryable) in [
        (Error::Revoked, 409, "certificate.revoked", false, false),
        (Error::QuotaExceeded, 413, "certificate.quota_exceeded", false, false),
        (Error::Conflict, 409, "organization.conflict", false, false),
        (Error::StorageUnavailable, 503, "organization.storage_unavailable", false, true),
        (Error::CommitOutcomeUnknown, 503, "organization.commit_outcome_unknown", true, true),
        (
            Error::UpdateCommitOutcomeUnknown,
            503,
            "organization.commit_outcome_unknown",
            true,
            false,
        ),
    ] {
        let problem = error.problem("fixture-request").unwrap().unwrap();
        assert_eq!((problem.status, problem.code.as_str()), (status, code));
        assert_eq!((problem.changed, problem.retryable), (changed, retryable));
        let encoded = serde_json::to_string(&problem).unwrap();
        for submitted in [ED25519, "deploy", "019bdad6-b800-7000-8000"] {
            assert!(!encoded.contains(submitted));
            assert!(!error.to_string().contains(submitted));
        }
        assert!(error.problem("").is_err());
    }
    assert_eq!(Error::ResponseLost.problem("fixture-request").unwrap(), None);
}
