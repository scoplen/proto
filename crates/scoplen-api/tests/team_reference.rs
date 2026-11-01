// SPDX-License-Identifier: Apache-2.0
use std::str::FromStr as _;

use cedar_policy::PolicySet;
use scoplen_api::{
    auth::INITIAL_DEVICE_ACCESS_SCOPE,
    organization::{OrganizationCreateRequest, OrganizationListQuery},
    organization_reference::{
        OrganizationReferenceError as Error, OrganizationReferenceFault as Fault,
        OrganizationReferencePeer,
    },
    team::{
        TeamAcceptanceReceipt, TeamDissolveRequest, TeamInvitationAcceptRequest,
        TeamInvitationCreateRequest, TeamInvitationStatus, TeamMemberStatus,
        TeamMemberUpdateRequest, TeamRole,
    },
    team_reference::{TeamReferencePeer, TeamReferenceTime},
};
use scoplen_crypto::{DeviceAccessTokenClaims, TeamInvitationPassword};
use uuid::Uuid;

const ORIGIN: &str = "https://control.example.com";

fn id(n: u64) -> Uuid {
    Uuid::parse_str(&format!("019bdad6-b800-7000-8000-{n:012x}")).unwrap()
}

fn claims(n: u64) -> DeviceAccessTokenClaims {
    DeviceAccessTokenClaims {
        iss: ORIGIN.into(),
        sub: id(n),
        did: id(n + 1),
        jti: id(n + 2),
        cnf_jkt: format!("fixture-proof-key-{n}"),
        org: vec![],
        scope: INITIAL_DEVICE_ACCESS_SCOPE.into(),
        iat: 1,
        exp: 1_000_000,
    }
}

fn clock(now: u64) -> TeamReferenceTime {
    TeamReferenceTime {
        now,
        timestamp: "2026-11-01T00:00:00Z".into(),
        invitation_expires_at: "2026-11-02T00:00:00Z".into(),
    }
}

struct Fixture {
    peer: TeamReferencePeer,
    owner: DeviceAccessTokenClaims,
    recipient: DeviceAccessTokenClaims,
    outsider: DeviceAccessTokenClaims,
    organization: Uuid,
    other_team: Uuid,
}

fn fixture() -> Fixture {
    let owner = claims(1);
    let recipient = claims(11);
    let outsider = claims(21);
    let mut peer = TeamReferencePeer::new(ORIGIN).unwrap();
    for (principal, name) in [(&owner, "owner"), (&recipient, "member"), (&outsider, "other")] {
        peer.set_principal(principal, name, true).unwrap();
    }
    let mut creator = OrganizationReferencePeer::default();
    creator.set_principal(&owner, true);
    creator.set_allow_creation(true);
    let request = OrganizationCreateRequest::new("Operations").unwrap().to_json().unwrap();
    let team = creator.create(&owner, id(300), &request, 100, &clock(100).timestamp).unwrap();
    let other = creator.create(&owner, id(301), &request, 100, &clock(100).timestamp).unwrap();
    let organization = team.id;
    let other_team = other.id;
    peer.seed_organization(team).unwrap();
    peer.seed_organization(other).unwrap();
    Fixture { peer, owner, recipient, outsider, organization, other_team }
}

fn invitation_body(
    organization: Uuid,
    invitation: Uuid,
    recipient: &str,
    roles: Vec<TeamRole>,
) -> Vec<u8> {
    TeamInvitationCreateRequest {
        invitation_id: invitation,
        recipient_username: recipient.into(),
        roles,
        password_verifier: password().verifier(ORIGIN, &organization, &invitation).unwrap(),
    }
    .to_json()
    .unwrap()
    .as_bytes()
    .to_vec()
}

fn password() -> TeamInvitationPassword {
    TeamInvitationPassword::parse(b"01234567").unwrap()
}

fn acceptance() -> Vec<u8> {
    TeamInvitationAcceptRequest { password: password() }.to_json().unwrap().as_bytes().to_vec()
}

fn wrong_password() -> Vec<u8> {
    TeamInvitationAcceptRequest { password: TeamInvitationPassword::parse(b"ABCDEFGH").unwrap() }
        .to_json()
        .unwrap()
        .as_bytes()
        .to_vec()
}

fn issue(f: &mut Fixture, invitation: u64, roles: Vec<TeamRole>) -> Uuid {
    let invitation = id(invitation);
    f.peer
        .create_invitation(
            &f.owner,
            f.organization,
            id(400),
            &invitation_body(f.organization, invitation, "member", roles),
            &clock(100),
        )
        .unwrap();
    invitation
}

fn join(f: &mut Fixture, roles: Vec<TeamRole>) -> TeamAcceptanceReceipt {
    let invitation = issue(f, 500, roles);
    f.peer
        .accept_invitation(
            &f.recipient,
            f.organization,
            invitation,
            id(600),
            &acceptance(),
            &clock(101),
        )
        .unwrap()
}

#[test]
fn designated_account_joins_with_real_verifier_and_wrong_accounts_do_not_consume_attempts() {
    let mut f = fixture();
    let invitation = issue(&mut f, 500, vec![TeamRole::Member]);
    assert_eq!(
        f.peer.invitation(&f.outsider, f.organization, invitation, 101),
        Err(Error::NotFound)
    );
    for n in 0..8 {
        assert_eq!(
            f.peer.accept_invitation(
                &f.outsider,
                f.organization,
                invitation,
                id(700 + n),
                &wrong_password(),
                &clock(101)
            ),
            Err(Error::NotFound)
        );
    }
    assert_eq!(f.peer.audit_events(), 1);
    let preview = f.peer.invitation(&f.recipient, f.organization, invitation, 101).unwrap();
    assert_eq!(preview.organization_name, "Operations");
    assert_eq!(preview.recipient_account_id, f.recipient.sub);
    assert_eq!(preview.status, TeamInvitationStatus::Pending);
    let accepted = f
        .peer
        .accept_invitation(
            &f.recipient,
            f.organization,
            invitation,
            id(600),
            &acceptance(),
            &clock(102),
        )
        .unwrap();
    assert_eq!(accepted.account_id, f.recipient.sub);
    assert_eq!(
        f.peer.organization(&f.recipient, f.organization, 103).unwrap().membership.id,
        accepted.membership_id
    );
    assert_eq!(f.peer.audit_events(), 2);
    assert_eq!(
        f.peer.member(&f.recipient, f.organization, accepted.membership_id, 103),
        Err(Error::Denied)
    );
}

#[test]
fn five_wrong_passwords_lock_and_only_authorized_revoke_can_change_locked_invitation() {
    let mut f = fixture();
    let invitation = issue(&mut f, 500, vec![TeamRole::Member]);
    for n in 0..5 {
        assert_eq!(
            f.peer.accept_invitation(
                &f.recipient,
                f.organization,
                invitation,
                id(700 + n),
                &wrong_password(),
                &clock(101)
            ),
            Err(Error::InvitationDenied)
        );
    }
    let locked = f.peer.invitation(&f.owner, f.organization, invitation, 102).unwrap();
    assert_eq!(locked.status, TeamInvitationStatus::Locked);
    assert_eq!(
        f.peer.accept_invitation(
            &f.recipient,
            f.organization,
            invitation,
            id(600),
            &acceptance(),
            &clock(102)
        ),
        Err(Error::InvitationDenied)
    );
    assert_eq!(f.peer.audit_events(), 6);
    assert_eq!(
        f.peer.revoke_invitation(
            &f.recipient,
            f.organization,
            invitation,
            Some(&locked.etag),
            &clock(103)
        ),
        Err(Error::NotFound)
    );
    f.peer
        .revoke_invitation(&f.owner, f.organization, invitation, Some(&locked.etag), &clock(103))
        .unwrap();
    let revoked = f.peer.invitation(&f.owner, f.organization, invitation, 103).unwrap();
    assert_eq!(revoked.status, TeamInvitationStatus::Revoked);
    f.peer
        .revoke_invitation(&f.owner, f.organization, invitation, Some(&revoked.etag), &clock(104))
        .unwrap();
    assert_eq!(f.peer.audit_events(), 7);
}

#[test]
fn acceptance_confirmation_precedes_issuer_membership_and_team_state_without_restoring_access() {
    let mut f = fixture();
    let accepted = join(&mut f, vec![TeamRole::Member]);
    let projection = f.peer.organization(&f.recipient, f.organization, 102).unwrap();
    let mut self_only = f.recipient.clone();
    self_only.scope = "orgs:read teams:join".into();
    f.peer
        .remove_member(
            &self_only,
            f.organization,
            accepted.membership_id,
            Some(&projection.etag),
            &clock(103),
        )
        .unwrap();
    let before = f.peer.audit_events();
    let mut reopened = f.peer.clone();
    assert_eq!(
        reopened.accept_invitation(
            &f.recipient,
            f.organization,
            accepted.invitation_id,
            id(600),
            &acceptance(),
            &clock(104)
        ),
        Ok(accepted.clone())
    );
    assert_eq!(reopened.audit_events(), before);
    assert_eq!(reopened.organization(&f.recipient, f.organization, 104), Err(Error::NotFound));
    assert_eq!(
        reopened.accept_invitation(
            &f.recipient,
            f.organization,
            accepted.invitation_id,
            id(601),
            &acceptance(),
            &clock(104)
        ),
        Err(Error::InvitationDenied)
    );
    assert_eq!(
        reopened.accept_invitation(
            &f.recipient,
            f.organization,
            accepted.invitation_id,
            id(600),
            &wrong_password(),
            &clock(104)
        ),
        Err(Error::Conflict)
    );
    let owner = reopened.organization(&f.owner, f.organization, 104).unwrap();
    let body = TeamDissolveRequest { organization_id: f.organization }.to_json().unwrap();
    reopened
        .dissolve(&f.owner, f.organization, id(800), Some(&owner.etag), &body, &clock(105))
        .unwrap();
    assert_eq!(
        reopened.accept_invitation(
            &f.recipient,
            f.organization,
            accepted.invitation_id,
            id(600),
            &acceptance(),
            &clock(106)
        ),
        Ok(accepted)
    );
    assert!(reopened.organization(&f.owner, f.other_team, 106).is_ok());
}

#[test]
fn removed_members_rejoin_only_through_new_invitation_while_suspended_members_need_update() {
    let mut f = fixture();
    let accepted = join(&mut f, vec![TeamRole::Member]);
    let member = f.peer.member(&f.owner, f.organization, accepted.membership_id, 102).unwrap();
    let suspend = TeamMemberUpdateRequest {
        roles: vec![TeamRole::Member],
        status: TeamMemberStatus::Suspended,
    }
    .to_json()
    .unwrap();
    let suspended = f
        .peer
        .update_member(
            &f.owner,
            f.organization,
            member.id,
            Some(&member.etag),
            &suspend,
            &clock(103),
        )
        .unwrap();
    assert_eq!(
        f.peer.create_invitation(
            &f.owner,
            f.organization,
            id(401),
            &invitation_body(f.organization, id(501), "member", vec![TeamRole::Member]),
            &clock(104)
        ),
        Err(Error::InvitationDenied)
    );
    let restore =
        TeamMemberUpdateRequest { roles: vec![TeamRole::Member], status: TeamMemberStatus::Active }
            .to_json()
            .unwrap();
    let active = f
        .peer
        .update_member(
            &f.owner,
            f.organization,
            member.id,
            Some(&suspended.etag),
            &restore,
            &clock(105),
        )
        .unwrap();
    f.peer
        .remove_member(&f.owner, f.organization, active.id, Some(&active.etag), &clock(106))
        .unwrap();
    let removed = f.peer.member(&f.owner, f.organization, member.id, 106).unwrap();
    let audits = f.peer.audit_events();
    f.peer
        .remove_member(&f.owner, f.organization, removed.id, Some(&removed.etag), &clock(107))
        .unwrap();
    assert_eq!(f.peer.audit_events(), audits);
    assert_eq!(
        f.peer.update_member(
            &f.owner,
            f.organization,
            member.id,
            Some(&removed.etag),
            &restore,
            &clock(107)
        ),
        Err(Error::Conflict)
    );
    f.peer
        .create_invitation(
            &f.owner,
            f.organization,
            id(401),
            &invitation_body(f.organization, id(501), "member", vec![TeamRole::Approver]),
            &clock(108),
        )
        .unwrap();
    let rejoined = f
        .peer
        .accept_invitation(
            &f.recipient,
            f.organization,
            id(501),
            id(601),
            &acceptance(),
            &clock(109),
        )
        .unwrap();
    assert_eq!(rejoined.membership_id, accepted.membership_id);
    assert_eq!(
        f.peer.member(&f.owner, f.organization, member.id, 110).unwrap().roles,
        [TeamRole::Approver]
    );
}

#[test]
fn failed_password_attempt_audit_rolls_back_its_lock_state() {
    let mut f = fixture();
    let invitation = issue(&mut f, 500, vec![TeamRole::Member]);
    for n in 0..4 {
        assert_eq!(
            f.peer.accept_invitation(
                &f.recipient,
                f.organization,
                invitation,
                id(700 + n),
                &wrong_password(),
                &clock(101)
            ),
            Err(Error::InvitationDenied)
        );
    }
    f.peer.set_fault(Fault::Rollback);
    assert_eq!(
        f.peer.accept_invitation(
            &f.recipient,
            f.organization,
            invitation,
            id(704),
            &wrong_password(),
            &clock(102)
        ),
        Err(Error::StorageUnavailable)
    );
    assert_eq!(f.peer.audit_events(), 5);
    assert_eq!(
        f.peer.invitation(&f.recipient, f.organization, invitation, 103).unwrap().status,
        TeamInvitationStatus::Pending
    );
    f.peer
        .accept_invitation(
            &f.recipient,
            f.organization,
            invitation,
            id(600),
            &acceptance(),
            &clock(103),
        )
        .unwrap();
    assert_eq!(f.peer.audit_events(), 6);
}

#[test]
fn current_issuer_and_expiry_are_checked_before_first_acceptance() {
    let mut f = fixture();
    let invitation = issue(&mut f, 500, vec![TeamRole::Member]);
    let owner = f.peer.organization(&f.owner, f.organization, 101).unwrap();
    let deny =
        PolicySet::from_str("forbid(principal, action == Action::\"manage_members\", resource);")
            .unwrap();
    f.peer.set_policies(f.organization, deny).unwrap();
    assert_eq!(
        f.peer.accept_invitation(
            &f.recipient,
            f.organization,
            invitation,
            id(600),
            &acceptance(),
            &clock(102)
        ),
        Err(Error::InvitationDenied)
    );
    f.peer.set_policies(f.organization, PolicySet::new()).unwrap();
    assert_eq!(
        f.peer.accept_invitation(
            &f.recipient,
            f.organization,
            invitation,
            id(600),
            &acceptance(),
            &clock(86_500)
        ),
        Err(Error::InvitationDenied)
    );
    assert_eq!(
        f.peer.invitation(&f.owner, f.organization, invitation, 86_500).unwrap().status,
        TeamInvitationStatus::Expired
    );
    assert_eq!(
        f.peer.organization(&f.owner, f.organization, 103).unwrap().membership.id,
        owner.membership.id
    );
    assert_eq!(f.peer.audit_events(), 1);
}

#[test]
fn owner_grant_and_last_active_owner_rules_survive_custom_permit_all() {
    let mut f = fixture();
    let accepted = join(&mut f, vec![TeamRole::Administrator]);
    let all = PolicySet::from_str("permit(principal, action, resource);").unwrap();
    f.peer.set_policies(f.organization, all).unwrap();
    let owner = f.peer.organization(&f.owner, f.organization, 102).unwrap();
    let owner_member = f.peer.member(&f.owner, f.organization, owner.membership.id, 102).unwrap();
    let downgrade =
        TeamMemberUpdateRequest { roles: vec![TeamRole::Member], status: TeamMemberStatus::Active }
            .to_json()
            .unwrap();
    assert_eq!(
        f.peer.update_member(
            &f.recipient,
            f.organization,
            owner_member.id,
            Some(&owner_member.etag),
            &downgrade,
            &clock(103)
        ),
        Err(Error::Denied)
    );
    assert_eq!(
        f.peer.create_invitation(
            &f.recipient,
            f.organization,
            id(402),
            &invitation_body(f.organization, id(502), "other", vec![TeamRole::Owner]),
            &clock(103)
        ),
        Err(Error::Denied)
    );
    assert_eq!(
        f.peer.update_member(
            &f.owner,
            f.organization,
            owner_member.id,
            Some(&owner_member.etag),
            &downgrade,
            &clock(103)
        ),
        Err(Error::Conflict)
    );
    assert_eq!(
        f.peer.remove_member(
            &f.owner,
            f.organization,
            owner_member.id,
            Some(&owner.etag),
            &clock(103)
        ),
        Err(Error::Conflict)
    );
    let suspend_owner = TeamMemberUpdateRequest {
        roles: vec![TeamRole::Owner],
        status: TeamMemberStatus::Suspended,
    }
    .to_json()
    .unwrap();
    assert_eq!(
        f.peer.update_member(
            &f.owner,
            f.organization,
            owner_member.id,
            Some(&owner_member.etag),
            &suspend_owner,
            &clock(103)
        ),
        Err(Error::Conflict)
    );
    let administrator =
        f.peer.member(&f.owner, f.organization, accepted.membership_id, 104).unwrap();
    let promote =
        TeamMemberUpdateRequest { roles: vec![TeamRole::Owner], status: TeamMemberStatus::Active }
            .to_json()
            .unwrap();
    f.peer
        .update_member(
            &f.owner,
            f.organization,
            administrator.id,
            Some(&administrator.etag),
            &promote,
            &clock(104),
        )
        .unwrap();
    f.peer
        .remove_member(&f.owner, f.organization, owner_member.id, Some(&owner.etag), &clock(105))
        .unwrap();
    assert_eq!(f.peer.organization(&f.owner, f.organization, 106), Err(Error::NotFound));
    assert_eq!(
        f.peer.organization(&f.recipient, f.organization, 106).unwrap().membership.roles,
        ["owner"]
    );
    assert_eq!(f.peer.organization(&f.recipient, f.other_team, 106), Err(Error::NotFound));
}

#[test]
fn receipt_backed_transactions_are_atomic_under_faults_and_restart() {
    for (fault, error, committed) in [
        (Fault::Rollback, Error::StorageUnavailable, false),
        (Fault::UnknownRollback, Error::CommitOutcomeUnknown, false),
        (Fault::UnknownCommitted, Error::CommitOutcomeUnknown, true),
        (Fault::LostResponse, Error::ResponseLost, true),
    ] {
        let mut f = fixture();
        let invitation = issue(&mut f, 500, vec![TeamRole::Member]);
        f.peer.set_fault(fault);
        assert_eq!(
            f.peer.accept_invitation(
                &f.recipient,
                f.organization,
                invitation,
                id(600),
                &acceptance(),
                &clock(101)
            ),
            Err(error)
        );
        assert_eq!(f.peer.audit_events(), if committed { 2 } else { 1 });
        let mut reopened = f.peer.clone();
        let accepted = reopened
            .accept_invitation(
                &f.recipient,
                f.organization,
                invitation,
                id(600),
                &acceptance(),
                &clock(102),
            )
            .unwrap();
        assert_eq!(reopened.audit_events(), 2);
        assert_eq!(
            reopened.organization(&f.recipient, f.organization, 103).unwrap().membership.id,
            accepted.membership_id
        );
    }
}

#[test]
fn creation_receipt_preserves_expiry_and_conflicts_on_changed_payload() {
    let mut f = fixture();
    let body = invitation_body(f.organization, id(500), "member", vec![TeamRole::Member]);
    f.peer.set_fault(Fault::LostResponse);
    assert_eq!(
        f.peer.create_invitation(&f.owner, f.organization, id(400), &body, &clock(100)),
        Err(Error::ResponseLost)
    );
    let created =
        f.peer.create_invitation(&f.owner, f.organization, id(400), &body, &clock(200)).unwrap();
    assert_eq!(created.expires_at, "2026-11-02T00:00:00Z");
    assert_eq!(f.peer.audit_events(), 1);
    assert_eq!(
        f.peer.create_invitation(
            &f.owner,
            f.organization,
            id(400),
            &invitation_body(f.organization, id(500), "other", vec![TeamRole::Member]),
            &clock(201)
        ),
        Err(Error::Conflict)
    );
    assert_eq!(
        f.peer.create_invitation(&f.owner, f.organization, id(400), &body, &clock(86_500)),
        Err(Error::Conflict)
    );
}

#[test]
fn dissolution_confirmation_precedes_inactive_org_and_binds_original_if_match() {
    for (fault, error) in [
        (Fault::UnknownCommitted, Error::CommitOutcomeUnknown),
        (Fault::LostResponse, Error::ResponseLost),
    ] {
        let mut f = fixture();
        let owner = f.peer.organization(&f.owner, f.organization, 101).unwrap();
        let body = TeamDissolveRequest { organization_id: f.organization }.to_json().unwrap();
        f.peer.set_fault(fault);
        assert_eq!(
            f.peer.dissolve(
                &f.owner,
                f.organization,
                id(800),
                Some(&owner.etag),
                &body,
                &clock(102)
            ),
            Err(error)
        );
        assert_eq!(f.peer.organization(&f.owner, f.organization, 103), Err(Error::NotFound));
        let receipt = f
            .peer
            .dissolve(&f.owner, f.organization, id(800), Some(&owner.etag), &body, &clock(103))
            .unwrap();
        assert_eq!(receipt.organization_id, f.organization);
        assert_eq!(f.peer.audit_events(), 1);
        assert_eq!(
            f.peer.dissolve(
                &f.owner,
                f.organization,
                id(800),
                Some("\"different\""),
                &body,
                &clock(104)
            ),
            Err(Error::Conflict)
        );
        assert_eq!(
            f.peer.dissolve(
                &f.owner,
                f.organization,
                id(801),
                Some(&owner.etag),
                &body,
                &clock(104)
            ),
            Err(Error::NotFound)
        );
        assert!(f.peer.organization(&f.owner, f.other_team, 104).is_ok());
    }
}

#[test]
fn suspended_members_can_leave_with_their_member_etag_without_regaining_team_reads() {
    let mut f = fixture();
    let accepted = join(&mut f, vec![TeamRole::Member]);
    let projection = f.peer.organization(&f.recipient, f.organization, 102).unwrap();
    let owner = f.peer.organization(&f.owner, f.organization, 102).unwrap();
    let member = f.peer.member(&f.owner, f.organization, accepted.membership_id, 102).unwrap();
    let body = TeamMemberUpdateRequest {
        roles: vec![TeamRole::Member],
        status: TeamMemberStatus::Suspended,
    }
    .to_json()
    .unwrap();
    let suspended = f
        .peer
        .update_member(&f.owner, f.organization, member.id, Some(&member.etag), &body, &clock(103))
        .unwrap();
    let mut caller = f.recipient.clone();
    caller.scope = "orgs:read teams:join".into();
    let before = f.peer.audit_events();
    assert_eq!(f.peer.organization(&caller, f.organization, 104), Err(Error::NotFound));
    assert_eq!(f.peer.member(&caller, f.organization, member.id, 104), Err(Error::Denied));
    assert_eq!(
        f.peer.remove_member(
            &caller,
            f.organization,
            owner.membership.id,
            Some(&owner.etag),
            &clock(104)
        ),
        Err(Error::NotFound)
    );
    for etag in [projection.etag.as_str(), member.etag.as_str(), "\"stale\""] {
        assert_eq!(
            f.peer.remove_member(&caller, f.organization, member.id, Some(etag), &clock(104)),
            Err(Error::PreconditionFailed)
        );
    }
    assert_eq!(
        f.peer.remove_member(&caller, f.organization, member.id, None, &clock(104)),
        Err(Error::PreconditionRequired)
    );
    let mut dissolved = f.peer.clone();
    let body = TeamDissolveRequest { organization_id: f.organization }.to_json().unwrap();
    dissolved
        .dissolve(&f.owner, f.organization, id(800), Some(&owner.etag), &body, &clock(104))
        .unwrap();
    assert_eq!(
        dissolved.remove_member(
            &caller,
            f.organization,
            member.id,
            Some(&suspended.etag),
            &clock(105)
        ),
        Err(Error::NotFound)
    );
    assert_eq!(f.peer.audit_events(), before);
    f.peer
        .remove_member(&caller, f.organization, member.id, Some(&suspended.etag), &clock(105))
        .unwrap();
    assert_eq!(f.peer.audit_events(), before + 1);
    let removed = f.peer.member(&f.owner, f.organization, member.id, 106).unwrap();
    assert_eq!(removed.status, TeamMemberStatus::Removed);
    assert_eq!(
        f.peer.remove_member(&caller, f.organization, member.id, Some(&removed.etag), &clock(106)),
        Err(Error::NotFound)
    );
    assert!(f.peer.organization(&f.owner, f.other_team, 106).is_ok());
}

#[test]
fn current_device_scope_foreign_targets_and_noop_boundaries_are_enforced() {
    let mut f = fixture();
    let accepted = join(&mut f, vec![TeamRole::Member]);
    let member = f.peer.member(&f.owner, f.organization, accepted.membership_id, 102).unwrap();
    let unchanged =
        TeamMemberUpdateRequest { roles: vec![TeamRole::Member], status: TeamMemberStatus::Active }
            .to_json()
            .unwrap();
    assert_eq!(
        f.peer.update_member(&f.owner, f.organization, member.id, None, &unchanged, &clock(103)),
        Err(Error::PreconditionRequired)
    );
    assert_eq!(
        f.peer.update_member(
            &f.owner,
            f.organization,
            member.id,
            Some("\"stale\""),
            &unchanged,
            &clock(103)
        ),
        Err(Error::PreconditionFailed)
    );
    assert_eq!(
        f.peer.update_member(
            &f.owner,
            f.organization,
            member.id,
            Some(&member.etag),
            &unchanged,
            &clock(103)
        ),
        Ok(member.clone())
    );
    assert_eq!(f.peer.audit_events(), 2);
    assert_eq!(f.peer.member(&f.owner, f.other_team, member.id, 103), Err(Error::NotFound));
    let mut scoped = f.owner.clone();
    scoped.scope = "orgs:read".into();
    assert_eq!(f.peer.member(&scoped, f.organization, member.id, 103), Err(Error::Denied));
    let mut wrong = f.owner.clone();
    wrong.cnf_jkt = "wrong-key".into();
    assert_eq!(
        f.peer.members(&wrong, f.organization, OrganizationListQuery::default(), 103),
        Err(Error::AuthenticationRequired)
    );
    let page = f
        .peer
        .members(&f.owner, f.organization, OrganizationListQuery { limit: 1, cursor: None }, 103)
        .unwrap();
    assert_eq!(page.items.len(), 1);
    assert!(page.next_cursor.is_some());
    let second = f
        .peer
        .members(
            &f.owner,
            f.organization,
            OrganizationListQuery { limit: 1, cursor: page.next_cursor },
            103,
        )
        .unwrap();
    assert_eq!(second.items.len(), 1);
    assert_eq!(second.next_cursor, None);
    f.peer.set_principal(&f.recipient, "member", false).unwrap();
    assert_eq!(
        f.peer.accept_invitation(
            &f.recipient,
            f.organization,
            accepted.invitation_id,
            id(600),
            &acceptance(),
            &clock(104)
        ),
        Err(Error::AuthenticationRequired)
    );
    f.peer.set_principal(&f.recipient, "member", true).unwrap();
    f.peer.set_account_active(f.recipient.sub, false).unwrap();
    assert_eq!(
        f.peer.organization(&f.recipient, f.organization, 104),
        Err(Error::AuthenticationRequired)
    );
}
