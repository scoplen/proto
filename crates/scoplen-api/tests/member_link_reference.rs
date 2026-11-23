// SPDX-License-Identifier: Apache-2.0
use cedar_policy::PolicySet;
use scoplen_api::{
    account_browser::{AccountBrowserWriter, INITIAL_ACCOUNT_BROWSER_ACCESS_SCOPE},
    auth_connection::ConnectionTarget,
    auth_connection_draft::test_login::DraftLoginStatus,
    member_link::{LinkConnection, reference::*},
    organization::{OrganizationMembership, OrganizationResource},
    organization_reference::{
        OrganizationReferenceError as Error, OrganizationReferenceFault as Fault,
    },
};
use scoplen_crypto::SecretVec;
use uuid::Uuid;

const NOW: u64 = 1_700_000_000;
const ISSUER: &str = "https://login.example.test";
const TIME: &str = "2023-11-14T22:13:20Z";

fn id(n: u8) -> Uuid {
    format!("019bdad6-b800-7000-8000-{n:012}").parse().unwrap()
}

fn writer(account: u8, family: u8) -> AccountBrowserWriter {
    AccountBrowserWriter::new(id(account), id(family)).unwrap()
}

fn membership(organization: u8, member: u8, account: u8, role: &str) -> OrganizationResource {
    OrganizationResource {
        id: id(organization),
        etag: format!("\"{}\"", id(organization)),
        created_at: TIME.into(),
        updated_at: TIME.into(),
        name: "Example".into(),
        membership: OrganizationMembership {
            id: id(member),
            account_id: id(account),
            roles: vec![role.into()],
        },
    }
}

fn connection(revision: u8, space: &str) -> LinkConnection {
    LinkConnection {
        id: id(revision),
        target: ConnectionTarget {
            issuer: ISSUER.into(),
            client_id: "client".into(),
            space_id: space.into(),
        },
    }
}

fn context(account: u8, family: u8, organization: u8, elapsed: u64) -> LinkContext {
    LinkContext {
        writer: writer(account, family),
        organization: id(organization),
        now: NOW + elapsed,
    }
}

fn navigation() -> SecretVec {
    SecretVec::new(format!("{ISSUER}/authorize?state=fixture").into_bytes())
}

fn peer() -> MemberLinkReferencePeer {
    let mut peer = MemberLinkReferencePeer::default();
    for (account, family) in [(1, 11), (1, 12), (2, 21), (3, 31)] {
        peer.set_browser(
            writer(account, family),
            INITIAL_ACCOUNT_BROWSER_ACCESS_SCOPE,
            NOW,
            NOW + 3600,
        );
    }
    for member in [
        membership(100, 101, 1, "member"),
        membership(100, 102, 2, "owner"),
        membership(100, 103, 3, "administrator"),
        membership(110, 111, 1, "owner"),
        membership(110, 112, 2, "member"),
    ] {
        peer.set_membership(member, true).unwrap();
    }
    peer.activate(id(100), connection(130, "spc_a")).unwrap();
    peer.activate(id(110), connection(131, "spc_b")).unwrap();
    peer
}

fn verify(
    peer: &mut MemberLinkReferencePeer,
    ctx: LinkContext,
    revision: u8,
    attempt: u8,
    comparison: u8,
) {
    peer.start(ctx, id(revision), id(attempt), navigation()).unwrap();
    peer.claim(ctx, id(attempt), id(revision)).unwrap();
    assert_eq!(peer.read_attempt(ctx, id(attempt)).unwrap().status, DraftLoginStatus::Pending);
    assert_eq!(peer.claim(ctx, id(attempt), id(revision)), Err(Error::NotFound));
    peer.finish(ctx, id(attempt), id(revision), LinkProof::Verified([comparison; 32])).unwrap();
}

#[test]
fn named_withdrawal_checks_distinct_scope_current_owner_cedar_and_target() {
    let mut peer = peer();
    let member = context(1, 11, 100, 10);
    let owner = context(2, 21, 100, 10);
    let admin = context(3, 31, 100, 10);
    verify(&mut peer, member, 130, 41, 7);
    let link = peer.confirm(member, id(41), id(130), id(51), id(61)).unwrap();
    assert_eq!(peer.read_named(owner, id(101)).unwrap().link, Some(link));
    assert_eq!(peer.read_named(member, id(101)), Err(Error::Denied));
    assert_eq!(peer.withdraw_named(admin, id(101), id(61)), Err(Error::Denied));
    assert_eq!(peer.withdraw_named(owner, id(111), id(61)), Err(Error::NotFound));
    assert_eq!(peer.withdraw_named(owner, id(101), id(62)), Err(Error::PreconditionFailed));
    peer.set_browser(owner.writer, "auth-links:self", NOW, NOW + 3600);
    assert_eq!(peer.read_named(owner, id(101)), Err(Error::Denied));
    peer.set_browser(owner.writer, "auth-links:withdraw", NOW, NOW + 3600);
    assert_eq!(peer.start(owner, id(130), id(42), navigation()), Err(Error::Denied));
    let policy = "forbid(principal, action == Action::\"manage_members\", resource);"
        .parse::<PolicySet>()
        .unwrap();
    peer.set_policies(id(100), policy).unwrap();
    assert_eq!(peer.withdraw_named(owner, id(101), id(61)), Err(Error::Denied));
    assert!(peer.read_self(member).unwrap().status.link.is_some());
    peer.set_policies(id(100), PolicySet::new()).unwrap();
    peer.withdraw_named(owner, id(101), id(61)).unwrap();
    assert!(peer.read_self(member).unwrap().status.link.is_none());
    assert_eq!(peer.audit().last().unwrap().event, LinkEvent::Withdrawn);
    assert_eq!(peer.audit().last().unwrap().writer, owner.writer);
    assert_eq!(peer.audit().last().unwrap().membership.membership_id, id(101));
}

#[test]
fn link_generation_prevents_other_family_resurrection_after_withdrawal() {
    let mut peer = peer();
    let first = context(1, 11, 100, 10);
    let second = context(1, 12, 100, 10);
    verify(&mut peer, first, 130, 41, 7);
    verify(&mut peer, second, 130, 42, 8);
    let installed = peer.confirm(first, id(41), id(130), id(51), id(61)).unwrap();
    assert_eq!(peer.confirm(second, id(41), id(130), id(51), id(64)), Err(Error::Conflict));
    peer.unlink_self(first, installed.id).unwrap();
    assert_eq!(peer.confirm(second, id(42), id(130), id(52), id(62)), Err(Error::NotFound));
    assert_eq!(peer.confirm(first, id(42), id(130), id(51), id(62)), Err(Error::Conflict));
    let original = peer.confirm(first, id(41), id(130), id(51), id(63)).unwrap();
    assert_eq!(original.to_json().unwrap(), installed.to_json().unwrap());
    assert!(peer.read_self(first).unwrap().status.link.is_none());
    assert_eq!(peer.audit().iter().filter(|entry| entry.event == LinkEvent::Confirmed).count(), 1);
    assert_eq!(
        peer.confirm(context(1, 11, 100, 300), id(41), id(130), id(51), id(63)),
        Err(Error::Denied)
    );
}

#[test]
fn simultaneous_verified_subjects_cannot_cross_memberships_or_organizations() {
    let mut peer = peer();
    let first = context(1, 11, 100, 10);
    let second = context(2, 21, 100, 10);
    let other_org = context(1, 12, 110, 10);
    verify(&mut peer, first, 130, 41, 7);
    verify(&mut peer, second, 130, 42, 7);
    verify(&mut peer, other_org, 131, 43, 7);
    assert_eq!(peer.start(first, id(130), id(44), navigation()), Err(Error::Conflict));
    assert_eq!(
        peer.start(context(1, 11, 110, 10), id(131), id(44), navigation()),
        Err(Error::Conflict)
    );
    let link = peer.confirm(first, id(41), id(130), id(51), id(61)).unwrap();
    assert_eq!(peer.confirm(second, id(42), id(130), id(52), id(62)), Err(Error::Conflict));
    peer.confirm(other_org, id(43), id(131), id(53), id(63)).unwrap();
    assert!(peer.read_self(second).unwrap().status.link.is_none());
    peer.unlink_self(first, link.id).unwrap();
    peer.confirm(second, id(42), id(130), id(52), id(62)).unwrap();
    assert!(peer.read_self(other_org).unwrap().status.link.is_some());
}

#[test]
fn callbacks_cannot_finish_after_switch_abandonment_trust_loss_or_membership_loss() {
    let original = context(1, 11, 100, 10);
    for change in [0, 1, 2, 3, 4, 5] {
        let mut peer = peer();
        let attempt = peer.start(original, id(130), id(41), navigation()).unwrap();
        assert_eq!(attempt.attempt.expires_at, "2023-11-14T22:18:20Z");
        assert_eq!(peer.claim(context(1, 12, 100, 10), id(41), id(130)), Err(Error::NotFound));
        assert_eq!(peer.claim(context(1, 11, 110, 10), id(41), id(130)), Err(Error::NotFound));
        assert_eq!(peer.claim(original, id(41), id(131)), Err(Error::NotFound));
        peer.claim(original, id(41), id(130)).unwrap();
        match change {
            0 => peer.activate(id(100), connection(132, "spc_a")).unwrap(),
            1 => peer.abandon(original, id(41)).unwrap(),
            2 => peer.withdraw_trust(id(100)),
            3 => peer.set_membership(membership(100, 101, 1, "member"), false).unwrap(),
            4 => peer.suspend(id(100)),
            5 => peer.revoke_browser(original.writer.family_id()),
            _ => unreachable!(),
        }
        let expected = if change == 5 { Error::AuthenticationRequired } else { Error::NotFound };
        assert_eq!(
            peer.finish(original, id(41), id(130), LinkProof::Verified([7; 32])),
            Err(expected)
        );
        assert!(peer.audit().iter().all(|entry| !matches!(entry.event, LinkEvent::Finished(_))));
    }
}

#[test]
fn failed_audit_and_unknown_outcomes_preserve_original_writer_semantics() {
    let mut peer = peer();
    let original = context(1, 11, 100, 10);
    peer.set_fault(Fault::UnknownCommitted);
    assert_eq!(
        peer.start(original, id(130), id(41), navigation()),
        Err(Error::UpdateCommitOutcomeUnknown)
    );
    assert_eq!(peer.start(original, id(130), id(42), navigation()), Err(Error::Conflict));
    peer.abandon(original, id(41)).unwrap();
    peer.start(original, id(130), id(42), navigation()).unwrap();
    peer.claim(original, id(42), id(130)).unwrap();
    peer.set_fault(Fault::Rollback);
    assert_eq!(
        peer.finish(original, id(42), id(130), LinkProof::Verified([7; 32])),
        Err(Error::StorageUnavailable)
    );
    assert_eq!(peer.read_attempt(original, id(42)).unwrap().status, DraftLoginStatus::Pending);
    assert_eq!(peer.claim(original, id(42), id(130)), Err(Error::NotFound));
    peer.abandon(original, id(42)).unwrap();
    verify(&mut peer, original, 130, 43, 7);
    peer.set_fault(Fault::Rollback);
    assert_eq!(
        peer.confirm(original, id(43), id(130), id(51), id(61)),
        Err(Error::StorageUnavailable)
    );
    assert!(peer.read_self(original).unwrap().status.link.is_none());
    peer.set_fault(Fault::UnknownCommitted);
    assert_eq!(
        peer.confirm(original, id(43), id(130), id(51), id(61)),
        Err(Error::CommitOutcomeUnknown)
    );
    assert_eq!(peer.confirm(original, id(43), id(130), id(52), id(61)), Err(Error::NotFound));
    let result = peer.confirm(original, id(43), id(130), id(51), id(62)).unwrap();
    let status = peer.read_self(original).unwrap().status;
    assert_eq!(status.link, Some(result));
    peer.set_fault(Fault::Rollback);
    assert_eq!(peer.unlink_self(original, id(61)), Err(Error::StorageUnavailable));
    assert_eq!(peer.read_self(original).unwrap().status, status);
    assert_eq!(peer.audit().iter().filter(|entry| entry.event == LinkEvent::Confirmed).count(), 1);
    assert!(peer.audit().iter().all(|entry| entry.event != LinkEvent::Withdrawn));
}

#[test]
fn exact_context_replacement_retains_links_and_different_context_retires_them() {
    let mut peer = peer();
    let member = context(1, 11, 100, 10);
    verify(&mut peer, member, 130, 41, 7);
    let link = peer.confirm(member, id(41), id(130), id(51), id(61)).unwrap();
    peer.suspend(id(100));
    let suspended = peer.read_self(member).unwrap();
    assert!(suspended.connection.is_none());
    assert_eq!(suspended.status.link, Some(link.clone()));
    peer.activate(id(100), connection(132, "spc_a")).unwrap();
    assert_eq!(peer.read_self(member).unwrap().status.link, Some(link));
    assert_eq!(
        peer.confirm(member, id(41), id(130), id(51), id(62)),
        Err(Error::PreconditionFailed)
    );
    peer.activate(id(100), connection(133, "spc_b")).unwrap();
    assert!(peer.read_self(member).unwrap().status.link.is_none());
    peer.activate(id(100), connection(134, "spc_a")).unwrap();
    assert!(peer.read_self(member).unwrap().status.link.is_none());
    assert_eq!(peer.activate(id(100), connection(130, "spc_a")), Err(Error::Conflict));
    verify(&mut peer, member, 134, 42, 7);
    assert_eq!(peer.confirm(member, id(42), id(134), id(52), id(61)), Err(Error::Conflict));
    peer.confirm(member, id(42), id(134), id(52), id(62)).unwrap();
}
