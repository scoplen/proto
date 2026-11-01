// SPDX-License-Identifier: Apache-2.0
//! Bounded D-136 fixture peer for invitation and membership transaction semantics.
//!
//! Uses the real shared codecs, invitation verifier and Cedar Organization authorizer.
//! Fixture setters supply already-verified current Account/Device and clock state. This peer
//! supplies no HTTP, token/proof verification, rate admission, durable store or audit chain.

use std::collections::BTreeMap;

use cedar_policy::PolicySet;
use scoplen_crypto::{DeviceAccessTokenClaims, PasswordKdfContext, TeamInvitationVerifier};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use crate::{
    auth::DeviceAccessScope,
    certificate::valid_utc_timestamp,
    organization::{
        OrganizationListQuery, OrganizationMembership, OrganizationPreconditionError,
        OrganizationResource, parse_organization_if_match, valid_uuid,
    },
    organization_reference::{
        OrganizationReferenceError as Error, OrganizationReferenceFault as Fault,
        authorize_organization_action,
    },
    team::{
        TEAM_RECEIPT_LIFETIME_SECONDS, TeamAcceptanceReceipt, TeamDissolutionReceipt,
        TeamDissolveRequest, TeamInvitationAcceptRequest, TeamInvitationCreateRequest,
        TeamInvitationPage, TeamInvitationResource, TeamInvitationStatus, TeamMemberPage,
        TeamMemberResource, TeamMemberStatus, TeamMemberUpdateRequest, TeamRole,
    },
};

const FIXTURE_CAPACITY: usize = 1_024;

/// Trusted synthetic clock projection, matching the existing Organization reference fixture.
///
/// `now` drives expiry. The fixture supplies its UTC rendering and the UTC rendering exactly
/// 24 hours later; this adapter is not a production clock or a timestamp arithmetic service.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TeamReferenceTime {
    /// Trusted Unix seconds used for token and operation lifetime checks.
    pub now: u64,
    /// UTC rendering of `now`.
    pub timestamp: String,
    /// UTC rendering of `now + 86_400`, used only for newly created invitations.
    pub invitation_expires_at: String,
}

impl TeamReferenceTime {
    fn validate(&self) -> Result<(), Error> {
        if !valid_utc_timestamp(&self.timestamp)
            || !valid_utc_timestamp(&self.invitation_expires_at)
            || self.now.checked_add(TEAM_RECEIPT_LIFETIME_SECONDS).is_none()
        {
            return Err(Error::InvalidRequest);
        }
        Ok(())
    }
}

#[derive(Clone)]
struct Account {
    username: String,
    active: bool,
}

#[derive(Clone)]
struct Principal {
    account: Uuid,
    key: String,
    active: bool,
}

#[derive(Clone)]
struct Team {
    resource: OrganizationResource,
    active: bool,
    policies: PolicySet,
}

#[derive(Clone)]
struct Invitation {
    resource: TeamInvitationResource,
    verifier: TeamInvitationVerifier,
    failures: u8,
    expires_at: u64,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Operation {
    Create(Uuid),
    Accept(Uuid),
    Dissolve,
}

#[derive(Clone)]
enum Confirmation {
    Created(Uuid),
    Accepted(TeamAcceptanceReceipt),
    Dissolved(TeamDissolutionReceipt),
}

#[derive(Clone)]
struct Receipt {
    device: Uuid,
    organization: Uuid,
    operation: Operation,
    digest: [u8; 32],
    if_match: Option<String>,
    expires_at: u64,
    confirmation: Confirmation,
}

/// Independent bounded fixture state; cloning models reopening an already committed image.
#[derive(Clone)]
pub struct TeamReferencePeer {
    origin: String,
    accounts: BTreeMap<Uuid, Account>,
    principals: BTreeMap<Uuid, Principal>,
    teams: BTreeMap<Uuid, Team>,
    members: BTreeMap<(Uuid, Uuid), TeamMemberResource>,
    invitations: BTreeMap<(Uuid, Uuid), Invitation>,
    receipts: BTreeMap<(Uuid, Uuid), Receipt>,
    audit_events: u64,
    fault: Option<Fault>,
}

impl std::fmt::Debug for TeamReferencePeer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TeamReferencePeer")
            .field("organizations", &self.teams.len())
            .field("invitations", &self.invitations.len())
            .finish_non_exhaustive()
    }
}

impl TeamReferencePeer {
    /// Create an independent fixture for one canonical deployment origin.
    /// # Errors
    /// Rejects a malformed origin.
    pub fn new(origin: &str) -> Result<Self, Error> {
        scoplen_crypto::validate_server_origin(origin).map_err(|_| Error::InvalidRequest)?;
        Ok(Self {
            origin: origin.into(),
            accounts: BTreeMap::new(),
            principals: BTreeMap::new(),
            teams: BTreeMap::new(),
            members: BTreeMap::new(),
            invitations: BTreeMap::new(),
            receipts: BTreeMap::new(),
            audit_events: 0,
            fault: None,
        })
    }

    /// Install one already-verified current Device and its canonical Account username.
    /// # Errors
    /// Rejects invalid ids/usernames, inconsistent identity or bounded fixture capacity.
    pub fn set_principal(
        &mut self,
        claims: &DeviceAccessTokenClaims,
        username: &str,
        active: bool,
    ) -> Result<(), Error> {
        valid_uuid(claims.sub, "account").map_err(|_| Error::InvalidRequest)?;
        valid_uuid(claims.did, "device").map_err(|_| Error::InvalidRequest)?;
        PasswordKdfContext::new(&self.origin, username, 1, &[0; 16])
            .map_err(|_| Error::InvalidRequest)?;
        if claims.iss != self.origin
            || self.accounts.iter().any(|(id, account)| {
                (*id != claims.sub && account.username == username)
                    || (*id == claims.sub && account.username != username)
            })
        {
            return Err(Error::InvalidRequest);
        }
        capacity(&self.accounts, &claims.sub)?;
        capacity(&self.principals, &claims.did)?;
        self.accounts
            .entry(claims.sub)
            .or_insert_with(|| Account { username: username.into(), active: true });
        self.principals.insert(
            claims.did,
            Principal { account: claims.sub, key: claims.cnf_jkt.clone(), active },
        );
        Ok(())
    }

    /// Set trusted current Account state independently of any one Device or team.
    /// # Errors
    /// Rejects an absent fixture Account.
    pub fn set_account_active(&mut self, account: Uuid, active: bool) -> Result<(), Error> {
        self.accounts.get_mut(&account).ok_or(Error::NotFound)?.active = active;
        Ok(())
    }

    /// Seed a team from the D-130 creator's already-validated caller projection.
    /// # Errors
    /// Rejects unknown Accounts, invalid metadata/roles or capacity, without partial state.
    pub fn seed_organization(&mut self, resource: OrganizationResource) -> Result<(), Error> {
        resource.to_json().map_err(|_| Error::InvalidRequest)?;
        let account = self.accounts.get(&resource.membership.account_id).ok_or(Error::NotFound)?;
        let member = TeamMemberResource {
            id: resource.membership.id,
            etag: tag(),
            created_at: resource.created_at.clone(),
            updated_at: resource.updated_at.clone(),
            organization_id: resource.id,
            account_id: resource.membership.account_id,
            username: account.username.clone(),
            roles: resource
                .membership
                .roles
                .iter()
                .map(|role| role_from_str(role))
                .collect::<Result<_, _>>()?,
            status: TeamMemberStatus::Active,
        };
        member.validate().map_err(|_| Error::InvalidRequest)?;
        if self.teams.contains_key(&resource.id) {
            return Err(Error::Conflict);
        }
        capacity(&self.teams, &resource.id)?;
        capacity(&self.members, &(resource.id, member.account_id))?;
        self.members.insert((resource.id, member.account_id), member);
        self.teams.insert(resource.id, Team { resource, active: true, policies: PolicySet::new() });
        Ok(())
    }

    /// Supply trusted custom Cedar policies for a fixture; mandatory shared guards remain.
    /// # Errors
    /// Rejects an absent fixture Organization.
    pub fn set_policies(&mut self, organization: Uuid, policies: PolicySet) -> Result<(), Error> {
        self.teams.get_mut(&organization).ok_or(Error::NotFound)?.policies = policies;
        Ok(())
    }

    /// Script one eligible mutation/audit/response fault.
    pub fn set_fault(&mut self, fault: Fault) {
        self.fault = Some(fault);
    }

    /// Number of fixture mutation/attempt audit events, excluding trusted setup.
    #[must_use]
    pub const fn audit_events(&self) -> u64 {
        self.audit_events
    }

    /// Current caller-only D-130 projection, also providing self-leave's allowed `ETag`.
    /// # Errors
    /// Requires current Device, exact orgs:read and this Account's active membership.
    pub fn organization(
        &self,
        claims: &DeviceAccessTokenClaims,
        organization: Uuid,
        now: u64,
    ) -> Result<OrganizationResource, Error> {
        self.authenticate(claims, DeviceAccessScope::OrganizationRead, now)?;
        self.projection(organization, claims.sub)
    }

    /// Create or confirm an original named-account invitation using the real typed codec.
    /// # Errors
    /// Enforces current management/Owner grant authority, eligibility, receipts and faults.
    pub fn create_invitation(
        &mut self,
        claims: &DeviceAccessTokenClaims,
        organization: Uuid,
        key: Uuid,
        body: &[u8],
        clock: &TeamReferenceTime,
    ) -> Result<TeamInvitationResource, Error> {
        self.authenticate(claims, DeviceAccessScope::TeamsManage, clock.now)?;
        clock.validate()?;
        valid_uuid(key, "key").map_err(|_| Error::InvalidRequest)?;
        let request =
            TeamInvitationCreateRequest::from_json(body).map_err(|_| Error::InvalidRequest)?;
        let canonical = request.to_json().map_err(|_| Error::InvalidRequest)?;
        let digest = digest(canonical.as_bytes());
        let actor = self.authorize(organization, claims.sub, "manage_members", clock.now)?;
        let operation = Operation::Create(request.invitation_id);
        if let Some(receipt) =
            self.receipt(claims, organization, key, operation, digest, None, clock.now)?
        {
            let Confirmation::Created(id) = receipt else {
                return Err(Error::Conflict);
            };
            return self.render_invitation(organization, id, clock.now);
        }
        Self::check_grant(&actor, &request.roles)?;
        let recipient = self
            .accounts
            .iter()
            .find(|(_, account)| account.active && account.username == request.recipient_username)
            .map(|(id, _)| *id)
            .ok_or(Error::InvitationDenied)?;
        if self
            .members
            .get(&(organization, recipient))
            .is_some_and(|member| member.status != TeamMemberStatus::Removed)
        {
            return Err(Error::InvitationDenied);
        }
        if self.invitations.contains_key(&(organization, request.invitation_id)) {
            return Err(Error::Conflict);
        }
        capacity(&self.invitations, &(organization, request.invitation_id))?;
        let resource = TeamInvitationResource {
            id: request.invitation_id,
            etag: tag(),
            created_at: clock.timestamp.clone(),
            updated_at: clock.timestamp.clone(),
            organization_id: organization,
            organization_name: self.teams[&organization].resource.name.clone(),
            recipient_account_id: recipient,
            recipient_username: request.recipient_username,
            roles: request.roles,
            issuer_account_id: claims.sub,
            expires_at: clock.invitation_expires_at.clone(),
            status: TeamInvitationStatus::Pending,
            membership_id: None,
        };
        resource.to_json().map_err(|_| Error::InvalidRequest)?;
        let mut next = self.clone();
        next.invitations.insert(
            (organization, resource.id),
            Invitation {
                resource: resource.clone(),
                verifier: request.password_verifier,
                failures: 0,
                expires_at: deadline(clock.now)?,
            },
        );
        next.store_receipt(
            claims,
            key,
            Receipt {
                device: claims.did,
                organization,
                operation,
                digest,
                if_match: None,
                expires_at: deadline(clock.now)?,
                confirmation: Confirmation::Created(resource.id),
            },
            clock.now,
        )?;
        next.record_audit()?;
        self.commit(next, resource, true)
    }

    /// Preview an invitation as the fixed recipient or a current authorized administrator.
    /// # Errors
    /// Wrong Account, inactive team and missing id share the same not-found result.
    pub fn invitation(
        &self,
        claims: &DeviceAccessTokenClaims,
        organization: Uuid,
        invitation: Uuid,
        now: u64,
    ) -> Result<TeamInvitationResource, Error> {
        self.authenticate_identity(claims, now)?;
        if !DeviceAccessScope::TeamsJoin.is_present_in(&claims.scope)
            && !DeviceAccessScope::TeamsManage.is_present_in(&claims.scope)
        {
            return Err(Error::Denied);
        }
        let resource = self.render_invitation(organization, invitation, now)?;
        if DeviceAccessScope::TeamsJoin.is_present_in(&claims.scope)
            && resource.recipient_account_id == claims.sub
        {
            return Ok(resource);
        }
        if DeviceAccessScope::TeamsManage.is_present_in(&claims.scope)
            && self.authorize(organization, claims.sub, "manage_members", now).is_ok()
        {
            return Ok(resource);
        }
        Err(Error::NotFound)
    }

    /// List only this Organization's invitation Resources under current administration.
    /// # Errors
    /// Requires exact scope/Cedar authority and valid bounded live pagination.
    pub fn invitations(
        &self,
        claims: &DeviceAccessTokenClaims,
        organization: Uuid,
        query: OrganizationListQuery,
        now: u64,
    ) -> Result<TeamInvitationPage, Error> {
        self.authenticate(claims, DeviceAccessScope::TeamsManage, now)?;
        self.authorize(organization, claims.sub, "manage_members", now)?;
        query.validate().map_err(|_| Error::InvalidRequest)?;
        let ids: Vec<_> = self
            .invitations
            .keys()
            .filter(|(org, id)| {
                *org == organization && query.cursor.is_none_or(|cursor| *id > cursor)
            })
            .map(|(_, id)| *id)
            .take(usize::from(query.limit) + 1)
            .collect();
        let more = ids.len() > usize::from(query.limit);
        let items = ids
            .into_iter()
            .take(usize::from(query.limit))
            .map(|id| self.render_invitation(organization, id, now))
            .collect::<Result<Vec<_>, _>>()?;
        let next_cursor = if more { items.last().map(|item| item.id) } else { None };
        let page = TeamInvitationPage { items, next_cursor };
        page.to_json().map_err(|_| Error::InvalidRequest)?;
        Ok(page)
    }

    /// Accept or confirm one exact original invitation operation.
    /// # Errors
    /// Requires fixed recipient, real password verification, current issuer and atomic success.
    #[allow(clippy::too_many_arguments)]
    pub fn accept_invitation(
        &mut self,
        claims: &DeviceAccessTokenClaims,
        organization: Uuid,
        invitation: Uuid,
        key: Uuid,
        body: &[u8],
        clock: &TeamReferenceTime,
    ) -> Result<TeamAcceptanceReceipt, Error> {
        self.authenticate(claims, DeviceAccessScope::TeamsJoin, clock.now)?;
        clock.validate()?;
        valid_uuid(key, "key").map_err(|_| Error::InvalidRequest)?;
        let request =
            TeamInvitationAcceptRequest::from_json(body).map_err(|_| Error::InvalidRequest)?;
        let canonical = request.to_json().map_err(|_| Error::InvalidRequest)?;
        let digest = digest(canonical.as_bytes());
        if let Some(receipt) = self.receipt(
            claims,
            organization,
            key,
            Operation::Accept(invitation),
            digest,
            None,
            clock.now,
        )? {
            let Confirmation::Accepted(value) = receipt else {
                return Err(Error::Conflict);
            };
            return Ok(value);
        }
        let resource = self.render_invitation(organization, invitation, clock.now)?;
        if resource.recipient_account_id != claims.sub {
            return Err(Error::NotFound);
        }
        if resource.status != TeamInvitationStatus::Pending {
            return Err(Error::InvitationDenied);
        }
        let actor = self
            .authorize(organization, resource.issuer_account_id, "manage_members", clock.now)
            .map_err(|_| Error::InvitationDenied)?;
        Self::check_grant(&actor, &resource.roles).map_err(|_| Error::InvitationDenied)?;
        if self
            .members
            .get(&(organization, claims.sub))
            .is_some_and(|member| member.status != TeamMemberStatus::Removed)
        {
            return Err(Error::InvitationDenied);
        }
        let verifier = request
            .password
            .verifier(&self.origin, &organization, &invitation)
            .map_err(|_| Error::InvalidRequest)?;
        if verifier != self.invitations[&(organization, invitation)].verifier {
            self.record_failed_password(organization, invitation, clock)?;
            return Err(Error::InvitationDenied);
        }
        let mut next = self.clone();
        let account = &next.accounts[&claims.sub];
        let old = next.members.get(&(organization, claims.sub));
        let membership = old.map_or_else(Uuid::now_v7, |member| member.id);
        let member = TeamMemberResource {
            id: membership,
            etag: tag(),
            created_at: old
                .map_or_else(|| clock.timestamp.clone(), |member| member.created_at.clone()),
            updated_at: clock.timestamp.clone(),
            organization_id: organization,
            account_id: claims.sub,
            username: account.username.clone(),
            roles: resource.roles,
            status: TeamMemberStatus::Active,
        };
        member.to_json().map_err(|_| Error::InvalidRequest)?;
        capacity(&next.members, &(organization, claims.sub))?;
        next.members.insert((organization, claims.sub), member);
        let stored =
            next.invitations.get_mut(&(organization, invitation)).ok_or(Error::NotFound)?;
        stored.resource.status = TeamInvitationStatus::Accepted;
        stored.resource.membership_id = Some(membership);
        stored.resource.updated_at.clone_from(&clock.timestamp);
        stored.resource.etag = tag();
        let receipt = TeamAcceptanceReceipt {
            invitation_id: invitation,
            organization_id: organization,
            account_id: claims.sub,
            membership_id: membership,
            accepted_at: clock.timestamp.clone(),
        };
        receipt.to_json().map_err(|_| Error::InvalidRequest)?;
        next.store_receipt(
            claims,
            key,
            Receipt {
                device: claims.did,
                organization,
                operation: Operation::Accept(invitation),
                digest,
                if_match: None,
                expires_at: deadline(clock.now)?,
                confirmation: Confirmation::Accepted(receipt.clone()),
            },
            clock.now,
        )?;
        next.record_audit()?;
        self.commit(next, receipt, true)
    }

    /// Revoke a pending/locked invitation or confirm a matching already-revoked no-op.
    /// # Errors
    /// Current authorization precedes the original strong precondition comparison.
    pub fn revoke_invitation(
        &mut self,
        claims: &DeviceAccessTokenClaims,
        organization: Uuid,
        invitation: Uuid,
        if_match: Option<&str>,
        clock: &TeamReferenceTime,
    ) -> Result<(), Error> {
        self.authenticate(claims, DeviceAccessScope::TeamsManage, clock.now)?;
        clock.validate()?;
        self.authorize(organization, claims.sub, "manage_members", clock.now)?;
        let resource = self.render_invitation(organization, invitation, clock.now)?;
        precondition(if_match, &resource.etag)?;
        if resource.status == TeamInvitationStatus::Revoked {
            return Ok(());
        }
        if !matches!(resource.status, TeamInvitationStatus::Pending | TeamInvitationStatus::Locked)
        {
            return Err(Error::Conflict);
        }
        let mut next = self.clone();
        let stored =
            next.invitations.get_mut(&(organization, invitation)).ok_or(Error::NotFound)?;
        stored.resource.status = TeamInvitationStatus::Revoked;
        stored.resource.etag = tag();
        stored.resource.updated_at.clone_from(&clock.timestamp);
        next.record_audit()?;
        self.commit(next, (), false)
    }

    /// Read one current administrative Member projection.
    /// # Errors
    /// Requires current management scope/Cedar authority and same-team target membership.
    pub fn member(
        &self,
        claims: &DeviceAccessTokenClaims,
        organization: Uuid,
        membership: Uuid,
        now: u64,
    ) -> Result<TeamMemberResource, Error> {
        self.authenticate(claims, DeviceAccessScope::TeamsManage, now)?;
        self.authorize(organization, claims.sub, "manage_members", now)?;
        self.member_by_id(organization, membership).cloned()
    }

    /// List the current administrative directory with standard ascending membership ids.
    /// # Errors
    /// Requires current authority and valid bounded live pagination.
    pub fn members(
        &self,
        claims: &DeviceAccessTokenClaims,
        organization: Uuid,
        query: OrganizationListQuery,
        now: u64,
    ) -> Result<TeamMemberPage, Error> {
        self.authenticate(claims, DeviceAccessScope::TeamsManage, now)?;
        self.authorize(organization, claims.sub, "manage_members", now)?;
        query.validate().map_err(|_| Error::InvalidRequest)?;
        let mut items: Vec<_> = self
            .members
            .values()
            .filter(|member| {
                member.organization_id == organization
                    && query.cursor.is_none_or(|cursor| member.id > cursor)
            })
            .cloned()
            .collect();
        items.sort_by_key(|member| member.id);
        let more = items.len() > usize::from(query.limit);
        items.truncate(usize::from(query.limit));
        let next_cursor = if more { items.last().map(|item| item.id) } else { None };
        let page = TeamMemberPage { items, next_cursor };
        page.to_json().map_err(|_| Error::InvalidRequest)?;
        Ok(page)
    }

    /// Update roles/status under current administrative authority and last-Owner rules.
    /// # Errors
    /// Refuses removed-state reactivation, stale preconditions and Owner-boundary violations.
    #[allow(clippy::too_many_arguments)]
    pub fn update_member(
        &mut self,
        claims: &DeviceAccessTokenClaims,
        organization: Uuid,
        membership: Uuid,
        if_match: Option<&str>,
        body: &[u8],
        clock: &TeamReferenceTime,
    ) -> Result<TeamMemberResource, Error> {
        self.authenticate(claims, DeviceAccessScope::TeamsManage, clock.now)?;
        clock.validate()?;
        let request =
            TeamMemberUpdateRequest::from_json(body).map_err(|_| Error::InvalidRequest)?;
        let actor = self.authorize(organization, claims.sub, "manage_members", clock.now)?;
        let current = self.member_by_id(organization, membership)?.clone();
        Self::check_owner_change(&actor, &current, &request.roles)?;
        precondition(if_match, &current.etag)?;
        if current.status == TeamMemberStatus::Removed {
            return Err(Error::Conflict);
        }
        let mut desired = current.clone();
        desired.roles = request.roles;
        desired.roles.sort_unstable();
        desired.status = request.status;
        if desired.roles == current.roles && desired.status == current.status {
            return Ok(current);
        }
        self.preserve_owner(organization, &desired)?;
        desired.updated_at.clone_from(&clock.timestamp);
        desired.etag = tag();
        desired.to_json().map_err(|_| Error::InvalidRequest)?;
        let mut next = self.clone();
        next.members.insert((organization, desired.account_id), desired.clone());
        next.record_audit()?;
        self.commit(next, desired, false)
    }

    /// Remove a member or leave this caller's exact team using its own projection `ETag`.
    /// # Errors
    /// Refuses foreign targets, missing current authority, stale `ETags` and last Owner removal.
    pub fn remove_member(
        &mut self,
        claims: &DeviceAccessTokenClaims,
        organization: Uuid,
        membership: Uuid,
        if_match: Option<&str>,
        clock: &TeamReferenceTime,
    ) -> Result<(), Error> {
        self.authenticate_identity(claims, clock.now)?;
        clock.validate()?;
        let join_scope = DeviceAccessScope::TeamsJoin.is_present_in(&claims.scope);
        let manage_scope = DeviceAccessScope::TeamsManage.is_present_in(&claims.scope);
        if !join_scope && !manage_scope {
            return Err(Error::Denied);
        }
        let current = self.member_by_id(organization, membership)?.clone();
        let own = current.account_id == claims.sub && join_scope;
        let actor = self.member_projection(organization, claims.sub, own)?;
        if !manage_scope && actor.membership.id != membership {
            return Err(Error::NotFound);
        }
        if !own {
            if !manage_scope {
                return Err(Error::Denied);
            }
            self.authorize(organization, claims.sub, "manage_members", clock.now)?;
        }
        Self::check_owner_change(&actor, &current, &current.roles)?;
        if own
            && current.status == TeamMemberStatus::Active
            && if_match == Some(actor.etag.as_str())
        {
            precondition(if_match, &actor.etag)?;
        } else {
            precondition(if_match, &current.etag)?;
        }
        if current.status == TeamMemberStatus::Removed {
            return Ok(());
        }
        let mut desired = current;
        desired.status = TeamMemberStatus::Removed;
        self.preserve_owner(organization, &desired)?;
        desired.updated_at.clone_from(&clock.timestamp);
        desired.etag = tag();
        let mut next = self.clone();
        next.members.insert((organization, desired.account_id), desired);
        next.record_audit()?;
        self.commit(next, (), false)
    }

    /// Dissolve or confirm the exact original Owner operation, preserving unrelated teams.
    /// # Errors
    /// Current Account/Device and exact receipt binding precede inactive-team/Owner checks.
    #[allow(clippy::too_many_arguments)]
    pub fn dissolve(
        &mut self,
        claims: &DeviceAccessTokenClaims,
        organization: Uuid,
        key: Uuid,
        if_match: Option<&str>,
        body: &[u8],
        clock: &TeamReferenceTime,
    ) -> Result<TeamDissolutionReceipt, Error> {
        self.authenticate(claims, DeviceAccessScope::TeamsManage, clock.now)?;
        clock.validate()?;
        valid_uuid(key, "key").map_err(|_| Error::InvalidRequest)?;
        let request = TeamDissolveRequest::from_json(body).map_err(|_| Error::InvalidRequest)?;
        request.validate_for_organization(organization).map_err(|_| Error::InvalidRequest)?;
        let parsed = parse_organization_if_match(if_match).map_err(precondition_error)?;
        let digest = digest(&request.to_json().map_err(|_| Error::InvalidRequest)?);
        if let Some(receipt) = self.receipt(
            claims,
            organization,
            key,
            Operation::Dissolve,
            digest,
            Some(parsed),
            clock.now,
        )? {
            let Confirmation::Dissolved(value) = receipt else {
                return Err(Error::Conflict);
            };
            return Ok(value);
        }
        let actor = self.authorize(organization, claims.sub, "manage_organization", clock.now)?;
        if !actor.membership.roles.iter().any(|role| role == "owner") {
            return Err(Error::Denied);
        }
        precondition(if_match, &actor.etag)?;
        let mut next = self.clone();
        next.teams.get_mut(&organization).ok_or(Error::NotFound)?.active = false;
        for member in
            next.members.values_mut().filter(|member| member.organization_id == organization)
        {
            member.status = TeamMemberStatus::Removed;
            member.etag = tag();
            member.updated_at.clone_from(&clock.timestamp);
        }
        for invitation in next.invitations.values_mut().filter(|invitation| {
            invitation.resource.organization_id == organization
                && matches!(
                    invitation.resource.status,
                    TeamInvitationStatus::Pending | TeamInvitationStatus::Locked
                )
        }) {
            invitation.resource.status = TeamInvitationStatus::Revoked;
            invitation.resource.etag = tag();
            invitation.resource.updated_at.clone_from(&clock.timestamp);
        }
        let receipt = TeamDissolutionReceipt {
            organization_id: organization,
            dissolved_at: clock.timestamp.clone(),
        };
        receipt.to_json().map_err(|_| Error::InvalidRequest)?;
        next.store_receipt(
            claims,
            key,
            Receipt {
                device: claims.did,
                organization,
                operation: Operation::Dissolve,
                digest,
                if_match: Some(parsed.into()),
                expires_at: deadline(clock.now)?,
                confirmation: Confirmation::Dissolved(receipt.clone()),
            },
            clock.now,
        )?;
        next.record_audit()?;
        self.commit(next, receipt, true)
    }

    fn authenticate_identity(
        &self,
        claims: &DeviceAccessTokenClaims,
        now: u64,
    ) -> Result<(), Error> {
        if claims.iss != self.origin
            || now < claims.iat
            || now >= claims.exp
            || !self.accounts.get(&claims.sub).is_some_and(|account| account.active)
            || !self.principals.get(&claims.did).is_some_and(|principal| {
                principal.active
                    && principal.account == claims.sub
                    && principal.key == claims.cnf_jkt
            })
        {
            return Err(Error::AuthenticationRequired);
        }
        Ok(())
    }

    fn authenticate(
        &self,
        claims: &DeviceAccessTokenClaims,
        scope: DeviceAccessScope,
        now: u64,
    ) -> Result<(), Error> {
        self.authenticate_identity(claims, now)?;
        if !scope.is_present_in(&claims.scope) {
            return Err(Error::Denied);
        }
        Ok(())
    }

    fn projection(&self, organization: Uuid, account: Uuid) -> Result<OrganizationResource, Error> {
        self.member_projection(organization, account, false)
    }

    fn member_projection(
        &self,
        organization: Uuid,
        account: Uuid,
        allow_suspended: bool,
    ) -> Result<OrganizationResource, Error> {
        let team =
            self.teams.get(&organization).filter(|team| team.active).ok_or(Error::NotFound)?;
        let member = self
            .members
            .get(&(organization, account))
            .filter(|member| {
                member.status == TeamMemberStatus::Active
                    || (allow_suspended && member.status == TeamMemberStatus::Suspended)
            })
            .ok_or(Error::NotFound)?;
        let mut resource = team.resource.clone();
        resource.membership = OrganizationMembership {
            id: member.id,
            account_id: account,
            roles: member.roles.iter().map(|role| role.as_str().into()).collect(),
        };
        resource.updated_at = later_timestamp(&resource.updated_at, &member.updated_at).into();
        resource.etag = format!(
            "\"{}:{}\"",
            team.resource.etag.trim_matches('"'),
            member.etag.trim_matches('"')
        );
        Ok(resource)
    }

    fn authorize(
        &self,
        organization: Uuid,
        account: Uuid,
        action: &str,
        now: u64,
    ) -> Result<OrganizationResource, Error> {
        if !self.accounts.get(&account).is_some_and(|account| account.active) {
            return Err(Error::NotFound);
        }
        let resource = self.projection(organization, account)?;
        authorize_organization_action(&resource, action, &self.teams[&organization].policies, now)?;
        Ok(resource)
    }

    fn check_grant(actor: &OrganizationResource, roles: &[TeamRole]) -> Result<(), Error> {
        if roles.contains(&TeamRole::Owner)
            && !actor.membership.roles.iter().any(|role| role == "owner")
        {
            return Err(Error::Denied);
        }
        Ok(())
    }

    fn check_owner_change(
        actor: &OrganizationResource,
        current: &TeamMemberResource,
        roles: &[TeamRole],
    ) -> Result<(), Error> {
        if current.roles.contains(&TeamRole::Owner) || roles.contains(&TeamRole::Owner) {
            Self::check_grant(actor, &[TeamRole::Owner])?;
        }
        Ok(())
    }

    fn preserve_owner(
        &self,
        organization: Uuid,
        desired: &TeamMemberResource,
    ) -> Result<(), Error> {
        if !self.members.values().any(|member| {
            member.organization_id == organization
                && if member.id == desired.id {
                    desired.status == TeamMemberStatus::Active
                        && desired.roles.contains(&TeamRole::Owner)
                } else {
                    member.status == TeamMemberStatus::Active
                        && member.roles.contains(&TeamRole::Owner)
                }
        }) {
            return Err(Error::Conflict);
        }
        Ok(())
    }

    fn member_by_id(
        &self,
        organization: Uuid,
        membership: Uuid,
    ) -> Result<&TeamMemberResource, Error> {
        self.teams.get(&organization).filter(|team| team.active).ok_or(Error::NotFound)?;
        self.members
            .values()
            .find(|member| member.organization_id == organization && member.id == membership)
            .ok_or(Error::NotFound)
    }

    fn render_invitation(
        &self,
        organization: Uuid,
        invitation: Uuid,
        now: u64,
    ) -> Result<TeamInvitationResource, Error> {
        let team =
            self.teams.get(&organization).filter(|team| team.active).ok_or(Error::NotFound)?;
        let invitation =
            self.invitations.get(&(organization, invitation)).ok_or(Error::NotFound)?;
        let mut resource = invitation.resource.clone();
        resource.organization_name.clone_from(&team.resource.name);
        if matches!(resource.status, TeamInvitationStatus::Pending | TeamInvitationStatus::Locked)
            && now >= invitation.expires_at
        {
            resource.status = TeamInvitationStatus::Expired;
            resource.etag = format!("\"{}:expired\"", resource.etag.trim_matches('"'));
            resource.updated_at.clone_from(&resource.expires_at);
        }
        resource.to_json().map_err(|_| Error::InvalidRequest)?;
        Ok(resource)
    }

    #[allow(clippy::too_many_arguments)]
    fn receipt(
        &self,
        claims: &DeviceAccessTokenClaims,
        organization: Uuid,
        key: Uuid,
        operation: Operation,
        digest: [u8; 32],
        if_match: Option<&str>,
        now: u64,
    ) -> Result<Option<Confirmation>, Error> {
        let Some(receipt) =
            self.receipts.get(&(claims.sub, key)).filter(|receipt| now < receipt.expires_at)
        else {
            return Ok(None);
        };
        if receipt.device != claims.did
            || receipt.organization != organization
            || receipt.operation != operation
            || receipt.digest != digest
            || receipt.if_match.as_deref() != if_match
        {
            return Err(Error::Conflict);
        }
        Ok(Some(receipt.confirmation.clone()))
    }

    fn store_receipt(
        &mut self,
        claims: &DeviceAccessTokenClaims,
        key: Uuid,
        receipt: Receipt,
        now: u64,
    ) -> Result<(), Error> {
        self.receipts.retain(|_, receipt| now < receipt.expires_at);
        capacity(&self.receipts, &(claims.sub, key))?;
        self.receipts.insert((claims.sub, key), receipt);
        Ok(())
    }

    fn record_failed_password(
        &mut self,
        organization: Uuid,
        invitation: Uuid,
        clock: &TeamReferenceTime,
    ) -> Result<(), Error> {
        let mut next = self.clone();
        let attempt =
            next.invitations.get_mut(&(organization, invitation)).ok_or(Error::NotFound)?;
        attempt.failures += 1;
        if attempt.failures >= 5 {
            attempt.resource.status = TeamInvitationStatus::Locked;
        }
        attempt.resource.etag = tag();
        attempt.resource.updated_at.clone_from(&clock.timestamp);
        next.record_audit()?;
        self.commit(next, (), false)
    }

    fn record_audit(&mut self) -> Result<(), Error> {
        self.audit_events = self.audit_events.checked_add(1).ok_or(Error::StorageUnavailable)?;
        Ok(())
    }

    fn commit<T>(&mut self, mut next: Self, value: T, receipt_backed: bool) -> Result<T, Error> {
        let fault = self.fault.take();
        next.fault = None;
        let unknown = if receipt_backed {
            Error::CommitOutcomeUnknown
        } else {
            Error::UpdateCommitOutcomeUnknown
        };
        match fault {
            Some(Fault::Rollback) => Err(Error::StorageUnavailable),
            Some(Fault::UnknownRollback) => Err(unknown),
            Some(Fault::UnknownCommitted) => {
                *self = next;
                Err(unknown)
            }
            Some(Fault::LostResponse) => {
                *self = next;
                Err(Error::ResponseLost)
            }
            None => {
                *self = next;
                Ok(value)
            }
        }
    }
}

fn role_from_str(role: &str) -> Result<TeamRole, Error> {
    match role {
        "owner" => Ok(TeamRole::Owner),
        "administrator" => Ok(TeamRole::Administrator),
        "member" => Ok(TeamRole::Member),
        "approver" => Ok(TeamRole::Approver),
        "security_auditor" => Ok(TeamRole::SecurityAuditor),
        _ => Err(Error::InvalidRequest),
    }
}

fn capacity<K: Ord, V>(entries: &BTreeMap<K, V>, key: &K) -> Result<(), Error> {
    if entries.len() >= FIXTURE_CAPACITY && !entries.contains_key(key) {
        Err(Error::StorageUnavailable)
    } else {
        Ok(())
    }
}

fn precondition(actual: Option<&str>, expected: &str) -> Result<(), Error> {
    let actual = parse_organization_if_match(actual).map_err(precondition_error)?;
    if actual != expected {
        return Err(Error::PreconditionFailed);
    }
    Ok(())
}

fn precondition_error(error: OrganizationPreconditionError) -> Error {
    match error {
        OrganizationPreconditionError::Required => Error::PreconditionRequired,
        OrganizationPreconditionError::Invalid => Error::InvalidRequest,
    }
}

fn deadline(now: u64) -> Result<u64, Error> {
    now.checked_add(TEAM_RECEIPT_LIFETIME_SECONDS).ok_or(Error::InvalidRequest)
}

fn tag() -> String {
    format!("\"{}\"", Uuid::now_v7())
}
fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn later_timestamp<'a>(left: &'a str, right: &'a str) -> &'a str {
    let key = |text: &'a str| {
        let fraction = text[19..].strip_prefix('.').unwrap_or("").trim_end_matches('Z');
        (&text[..19], fraction.trim_end_matches('0'))
    };
    if key(left) >= key(right) { left } else { right }
}
