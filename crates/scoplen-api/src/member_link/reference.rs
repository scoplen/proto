// SPDX-License-Identifier: Apache-2.0
//! Serialized D-170 reference peer with trusted current-state and callback fixtures.
//!
//! The caller supplies authenticated browser bindings and verified callback results. This
//! models the state and receipt contract after transport proofs, not the provider exchange.

use std::collections::{BTreeMap, BTreeSet};

use cedar_policy::PolicySet;
use scoplen_crypto::SecretVec;
use uuid::Uuid;

use super::{
    LinkAttempt, LinkAttemptStarted, LinkConnection, LinkMembership, MemberLink, MemberLinkStatus,
    SelfLinkStatus,
};
use crate::{
    account_browser::{AccountBrowserAccessScope as Scope, AccountBrowserWriter},
    auth_connection_draft::test_login::DraftLoginStatus,
    control_plane::OrganizationAuthorizer,
    grant::format_grant_timestamp,
    organization::{ORGANIZATION_CREATION_RECEIPT_SECONDS, OrganizationResource, valid_uuid},
    organization_reference::{
        OrganizationReferenceError as Error, OrganizationReferenceFault as Fault,
        authorize_organization_action,
    },
};

const FRESH_SECONDS: u64 = 300;

/// Authenticated native writer and router/clock facts for one operation.
#[derive(Clone, Copy, Debug)]
pub struct LinkContext {
    /// Original authenticated browser family.
    pub writer: AccountBrowserWriter,
    /// Selected Organization.
    pub organization: Uuid,
    /// Current trusted Unix seconds.
    pub now: u64,
}

/// Successful audit transition without any provider data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LinkEvent {
    /// Start created a pending attempt.
    Started,
    /// The callback finished with the public proof state.
    Finished(DraftLoginStatus),
    /// The original writer abandoned the attempt.
    Abandoned,
    /// The original writer confirmed the association.
    Confirmed,
    /// A member or authorized Owner withdrew a reviewed link.
    Withdrawn,
}

/// Attributable audit projection committed alongside state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinkAudit {
    /// Authenticated Account and family.
    pub writer: AccountBrowserWriter,
    /// Target Organization and Membership.
    pub membership: LinkMembership,
    /// Link operation.
    pub event: LinkEvent,
    /// Applicable original attempt identifier.
    pub attempt: Option<Uuid>,
    /// Applicable link identifier.
    pub link: Option<Uuid>,
    /// Applicable connection revision.
    pub revision: Option<Uuid>,
}

/// Trusted bounded callback outcome supplied after the transport proof and exchange.
#[derive(Clone, Copy)]
pub enum LinkProof {
    /// The exact context's keyed comparison value for the verified human subject.
    Verified([u8; 32]),
    /// A terminal provider denial or unsuccessful verification.
    Failed,
}

struct Family {
    writer: AccountBrowserWriter,
    scope: String,
    password_at: u64,
    expires_at: u64,
}

struct Membership {
    resource: OrganizationResource,
    active: bool,
    generation: u64,
    link: Option<StoredLink>,
}

struct StoredLink {
    public: MemberLink,
    comparison: [u8; 32],
}

struct Connection {
    configuration: LinkConnection,
    active: bool,
    trusted: bool,
}

struct Organization {
    connection: Option<Connection>,
    used_revisions: BTreeSet<Uuid>,
    memberships: BTreeMap<Uuid, Membership>,
    policies: PolicySet,
}

impl Default for Organization {
    fn default() -> Self {
        Self {
            connection: None,
            used_revisions: BTreeSet::new(),
            memberships: BTreeMap::new(),
            policies: PolicySet::new(),
        }
    }
}

enum State {
    Pending,
    Exchanging,
    Verified([u8; 32]),
    Failed,
}

struct Attempt {
    writer: AccountBrowserWriter,
    generation: u64,
    expires_at: u64,
    public: LinkAttempt,
    state: State,
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct Confirmation {
    writer: AccountBrowserWriter,
    membership: LinkMembership,
    attempt: Uuid,
    revision: Uuid,
}

struct Receipt {
    binding: Confirmation,
    created_at: u64,
    result: MemberLink,
}

/// Independent in-memory image for one deployment. Mutations serialize through an exclusive
/// borrow and can inject the shared transaction outcomes before or after publication.
#[derive(Default)]
pub struct MemberLinkReferencePeer {
    organizations: BTreeMap<Uuid, Organization>,
    families: BTreeMap<Uuid, Family>,
    attempts: BTreeMap<Uuid, Attempt>,
    used_attempts: BTreeSet<Uuid>,
    used_links: BTreeSet<Uuid>,
    receipts: BTreeMap<(Uuid, Uuid), Receipt>,
    audit: Vec<LinkAudit>,
    fault: Option<Fault>,
}

impl MemberLinkReferencePeer {
    /// Install a verified live family. Refresh can preserve its original scope and password time.
    pub fn set_browser(
        &mut self,
        writer: AccountBrowserWriter,
        scope: &str,
        password_at: u64,
        expires_at: u64,
    ) {
        self.families.insert(
            writer.family_id(),
            Family { writer, scope: scope.into(), password_at, expires_at },
        );
    }

    /// Revoke the current browser family.
    pub fn revoke_browser(&mut self, family: Uuid) {
        self.families.remove(&family);
    }

    /// Install the Organization's trusted current Membership and roles.
    ///
    /// # Errors
    /// Rejects invalid fixtures and conflicting Account/Membership bindings.
    pub fn set_membership(
        &mut self,
        resource: OrganizationResource,
        active: bool,
    ) -> Result<(), Error> {
        resource.validate().map_err(|_| Error::InvalidRequest)?;
        let member = resource.membership.id;
        let account = resource.membership.account_id;
        let org = self.organizations.entry(resource.id).or_default();
        if org.memberships.iter().any(|(id, current)| {
            (*id == member) != (current.resource.membership.account_id == account)
        }) {
            return Err(Error::InvalidRequest);
        }
        if let Some(current) = org.memberships.get_mut(&member) {
            if current.active && !active {
                current.generation = next_generation(current)?;
                current.link = None;
            }
            current.resource = resource;
            current.active = active;
        } else {
            org.memberships
                .insert(member, Membership { resource, active, generation: 0, link: None });
        }
        Ok(())
    }

    /// Install current custom policies alongside mandatory tenant checks.
    ///
    /// # Errors
    /// Rejects invalid Organization policies.
    pub fn set_policies(&mut self, organization: Uuid, policies: PolicySet) -> Result<(), Error> {
        OrganizationAuthorizer::new(organization, &policies).map_err(|_| Error::InvalidRequest)?;
        self.organizations.entry(organization).or_default().policies = policies;
        Ok(())
    }

    /// Install an active revision. Different identity context retires current links.
    ///
    /// # Errors
    /// Rejects malformed revisions, reuse of an immutable revision or exhausted generations.
    pub fn activate(
        &mut self,
        organization: Uuid,
        connection: LinkConnection,
    ) -> Result<(), Error> {
        valid_uuid(organization, "organization_id").map_err(|_| Error::InvalidRequest)?;
        connection.wire().map_err(|_| Error::InvalidRequest)?;
        let org = self.organizations.entry(organization).or_default();
        if org.used_revisions.contains(&connection.id) {
            return Err(Error::Conflict);
        }
        if let Some(previous) = &org.connection
            && previous.configuration.target != connection.target
        {
            for member in org.memberships.values().filter(|member| member.link.is_some()) {
                next_generation(member)?;
            }
            for member in org.memberships.values_mut().filter(|member| member.link.is_some()) {
                member.generation += 1;
                member.link = None;
            }
        }
        org.used_revisions.insert(connection.id);
        org.connection =
            Some(Connection { configuration: connection, active: true, trusted: true });
        Ok(())
    }

    /// Suspend the current connection while retaining dormant associations.
    pub fn suspend(&mut self, organization: Uuid) {
        if let Some(connection) =
            self.organizations.get_mut(&organization).and_then(|org| org.connection.as_mut())
        {
            connection.active = false;
        }
    }

    /// Withdraw configured deployment trust for the current revision.
    pub fn withdraw_trust(&mut self, organization: Uuid) {
        if let Some(connection) =
            self.organizations.get_mut(&organization).and_then(|org| org.connection.as_mut())
        {
            connection.trusted = false;
        }
    }

    /// Script the next audited mutation's transaction or transport outcome.
    pub fn set_fault(&mut self, fault: Fault) {
        self.fault = Some(fault);
    }

    /// The committed, content-free audit projection.
    #[must_use]
    pub fn audit(&self) -> &[LinkAudit] {
        &self.audit
    }

    fn authorize(
        &self,
        ctx: LinkContext,
        scope: Scope,
    ) -> Result<(&Organization, &Membership, &Family), Error> {
        let family = self
            .families
            .get(&ctx.writer.family_id())
            .filter(|family| family.writer == ctx.writer && ctx.now < family.expires_at)
            .ok_or(Error::AuthenticationRequired)?;
        if !scope.is_present_in(&family.scope) {
            return Err(Error::Denied);
        }
        let org = self.organizations.get(&ctx.organization).ok_or(Error::NotFound)?;
        let member = org
            .memberships
            .values()
            .find(|member| {
                member.active && member.resource.membership.account_id == ctx.writer.account_id()
            })
            .ok_or(Error::NotFound)?;
        Ok((org, member, family))
    }

    fn authorize_named(
        &self,
        ctx: LinkContext,
        id: Uuid,
    ) -> Result<(&Organization, &Membership), Error> {
        let (org, actor, _) = self.authorize(ctx, Scope::AuthLinksWithdraw)?;
        if !actor.resource.membership.roles.iter().any(|role| role == "owner") {
            return Err(Error::Denied);
        }
        authorize_organization_action(&actor.resource, "manage_members", &org.policies, ctx.now)?;
        let target =
            org.memberships.get(&id).filter(|member| member.active).ok_or(Error::NotFound)?;
        Ok((org, target))
    }

    /// Read the authenticated member's current link and any active configuration.
    ///
    /// # Errors
    /// Rejects unauthenticated, unscoped or inactive callers.
    pub fn read_self(&self, ctx: LinkContext) -> Result<SelfLinkStatus, Error> {
        let (org, member, _) = self.authorize(ctx, Scope::AuthLinksSelf)?;
        let connection = org
            .connection
            .as_ref()
            .filter(|connection| connection.active)
            .map(|connection| connection.configuration.clone());
        Ok(SelfLinkStatus { status: status(member), connection })
    }

    /// Read only the authorized target Membership's public link.
    ///
    /// # Errors
    /// Rejects missing Owner and Cedar authority or an inaccessible target.
    pub fn read_named(&self, ctx: LinkContext, member: Uuid) -> Result<MemberLinkStatus, Error> {
        let (_, target) = self.authorize_named(ctx, member)?;
        Ok(status(target))
    }

    /// Start one bounded attempt using only current native authority.
    ///
    /// # Errors
    /// Rejects stale authority or revision, invalid navigation, a linked member,
    /// a used identifier, an occupied original family or a failed commit.
    pub fn start(
        &mut self,
        ctx: LinkContext,
        revision: Uuid,
        id: Uuid,
        navigation: SecretVec,
    ) -> Result<LinkAttemptStarted, Error> {
        let (org, member, family) = self.authorize(ctx, Scope::AuthLinksSelf)?;
        let deadline = fresh_password(family, ctx.now)?;
        let connection = current_connection(org, revision)?;
        if member.link.is_some()
            || self.used_attempts.contains(&id)
            || self
                .attempts
                .values()
                .any(|entry| entry.writer == ctx.writer && ctx.now < entry.expires_at)
        {
            return Err(Error::Conflict);
        }
        let expires_at = deadline.min(family.expires_at);
        let attempt = LinkAttempt {
            id,
            membership: membership_context(member),
            connection_revision: revision,
            status: DraftLoginStatus::Pending,
            expires_at: format_grant_timestamp(expires_at).map_err(|_| Error::InvalidRequest)?,
        };
        let output = LinkAttemptStarted { attempt: attempt.clone(), authorization_url: navigation };
        output.to_json(&connection.target.issuer).map_err(|_| Error::InvalidRequest)?;
        let entry = Attempt {
            writer: ctx.writer,
            generation: member.generation,
            expires_at,
            public: attempt,
            state: State::Pending,
        };
        self.commit(attempt_event(&entry, LinkEvent::Started, None), false, |peer| {
            peer.used_attempts.insert(id);
            peer.attempts.insert(id, entry);
            output
        })
    }

    fn original_attempt(&self, ctx: LinkContext, id: Uuid) -> Result<&Attempt, Error> {
        let (org, member, _) = self.authorize(ctx, Scope::AuthLinksSelf)?;
        let attempt = self
            .attempts
            .get(&id)
            .filter(|entry| {
                entry.writer == ctx.writer
                    && entry.public.membership == membership_context(member)
                    && entry.generation == member.generation
                    && ctx.now < entry.expires_at
            })
            .ok_or(Error::NotFound)?;
        current_connection(org, attempt.public.connection_revision).map_err(|_| Error::NotFound)?;
        Ok(attempt)
    }

    /// Read a still-eligible attempt in its original family.
    ///
    /// # Errors
    /// Rejects an invalid caller, foreign attempt, expiry or invalidated context.
    pub fn read_attempt(&self, ctx: LinkContext, id: Uuid) -> Result<LinkAttempt, Error> {
        Ok(self.original_attempt(ctx, id)?.public.clone())
    }

    /// Claim a callback after external purpose, cookie, state, issuer and path validation.
    ///
    /// # Errors
    /// Rejects wrong immutable context, duplicate claims, expiry or invalidation.
    pub fn claim(&mut self, ctx: LinkContext, id: Uuid, revision: Uuid) -> Result<(), Error> {
        let attempt = self.original_attempt(ctx, id)?;
        if attempt.public.connection_revision != revision
            || !matches!(attempt.state, State::Pending)
        {
            return Err(Error::NotFound);
        }
        self.attempts.get_mut(&id).ok_or(Error::NotFound)?.state = State::Exchanging;
        Ok(())
    }

    /// Record a claimed callback's terminal exchange result with its audit record.
    ///
    /// # Errors
    /// Rejects stale Membership, family, trust, revision or expiry, and failed commits.
    pub fn finish(
        &mut self,
        ctx: LinkContext,
        id: Uuid,
        revision: Uuid,
        proof: LinkProof,
    ) -> Result<(), Error> {
        let attempt = self.original_attempt(ctx, id)?;
        if attempt.public.connection_revision != revision
            || !matches!(attempt.state, State::Exchanging)
        {
            return Err(Error::NotFound);
        }
        let (state, status) = match proof {
            LinkProof::Verified(comparison) => {
                (State::Verified(comparison), DraftLoginStatus::Verified)
            }
            LinkProof::Failed => (State::Failed, DraftLoginStatus::Failed),
        };
        let event = attempt_event(attempt, LinkEvent::Finished(status), None);
        let updated = Attempt {
            writer: attempt.writer,
            generation: attempt.generation,
            expires_at: attempt.expires_at,
            public: LinkAttempt { status, ..attempt.public.clone() },
            state,
        };
        self.commit(event, false, |peer| {
            peer.attempts.insert(id, updated);
        })
    }

    /// Abandon only a still-eligible original attempt, including a claimed exchange.
    ///
    /// # Errors
    /// Rejects foreign or stale attempts and failed commits.
    pub fn abandon(&mut self, ctx: LinkContext, id: Uuid) -> Result<(), Error> {
        let attempt = self.original_attempt(ctx, id)?;
        self.commit(attempt_event(attempt, LinkEvent::Abandoned, None), false, |peer| {
            peer.attempts.remove(&id);
        })
    }

    /// Confirm a verified attempt or recover the exact original result.
    /// The supplied link ID allocates a new association only on the original commit.
    ///
    /// # Errors
    /// Rejects stale authority or context, changed receipt binding, conflicting links
    /// or failed commits.
    pub fn confirm(
        &mut self,
        ctx: LinkContext,
        id: Uuid,
        revision: Uuid,
        key: Uuid,
        link: Uuid,
    ) -> Result<MemberLink, Error> {
        valid_uuid(key, "Idempotency-Key").map_err(|_| Error::InvalidRequest)?;
        let (org, member, family) = self.authorize(ctx, Scope::AuthLinksSelf)?;
        fresh_password(family, ctx.now)?;
        current_connection(org, revision)?;
        let membership = membership_context(member);
        let binding = Confirmation { writer: ctx.writer, membership, attempt: id, revision };
        let receipt_key = (ctx.writer.account_id(), key);
        if let Some(receipt) = self.receipts.get(&receipt_key) {
            if receipt.binding != binding
                || ctx
                    .now
                    .checked_sub(receipt.created_at)
                    .is_none_or(|age| age >= ORGANIZATION_CREATION_RECEIPT_SECONDS)
            {
                return Err(Error::Conflict);
            }
            return Ok(receipt.result.clone());
        }
        let attempt = self.original_attempt(ctx, id)?;
        if attempt.public.connection_revision != revision {
            return Err(Error::PreconditionFailed);
        }
        let State::Verified(comparison) = attempt.state else { return Err(Error::Conflict) };
        if member.link.is_some()
            || self.used_links.contains(&link)
            || org.memberships.values().any(|other| {
                other.link.as_ref().is_some_and(|other| other.comparison == comparison)
            })
        {
            return Err(Error::Conflict);
        }
        let generation = next_generation(member)?;
        let link = MemberLink {
            id: link,
            created_at: format_grant_timestamp(ctx.now).map_err(|_| Error::InvalidRequest)?,
            membership,
        };
        link.to_json().map_err(|_| Error::InvalidRequest)?;
        let audit = attempt_event(attempt, LinkEvent::Confirmed, Some(link.id));
        self.commit(audit, true, |peer| {
            peer.attempts.remove(&id);
            peer.used_links.insert(link.id);
            let member = peer.member_mut(membership);
            member.generation = generation;
            member.link = Some(StoredLink { public: link.clone(), comparison });
            peer.receipts.insert(
                receipt_key,
                Receipt { binding, created_at: ctx.now, result: link.clone() },
            );
            link
        })
    }

    /// Unlink the authenticated member's current reviewed association.
    ///
    /// # Errors
    /// Rejects absent links, stale tags, insufficient authority and failed commits.
    pub fn unlink_self(&mut self, ctx: LinkContext, link: Uuid) -> Result<(), Error> {
        let (org, member, _) = self.authorize(ctx, Scope::AuthLinksSelf)?;
        let (audit, generation) = withdrawal(ctx, org, member, link)?;
        self.withdraw(audit, generation)
    }

    /// Withdraw the reviewed association for an exact target as an authorized Owner.
    ///
    /// # Errors
    /// Rejects inaccessible targets, stale tags, insufficient authority and failed commits.
    pub fn withdraw_named(
        &mut self,
        ctx: LinkContext,
        member: Uuid,
        link: Uuid,
    ) -> Result<(), Error> {
        let (org, target) = self.authorize_named(ctx, member)?;
        let (audit, generation) = withdrawal(ctx, org, target, link)?;
        self.withdraw(audit, generation)
    }

    fn withdraw(&mut self, audit: LinkAudit, generation: u64) -> Result<(), Error> {
        self.commit(audit, false, |peer| {
            let member = peer.member_mut(audit.membership);
            member.link = None;
            member.generation = generation;
        })
    }

    fn member_mut(&mut self, member: LinkMembership) -> &mut Membership {
        self.organizations
            .get_mut(&member.organization_id)
            .expect("authorized Organization")
            .memberships
            .get_mut(&member.membership_id)
            .expect("authorized Membership")
    }

    fn commit<T>(
        &mut self,
        audit: LinkAudit,
        receipt: bool,
        apply: impl FnOnce(&mut Self) -> T,
    ) -> Result<T, Error> {
        let unknown =
            if receipt { Error::CommitOutcomeUnknown } else { Error::UpdateCommitOutcomeUnknown };
        let fault = self.fault.take();
        match fault {
            Some(Fault::Rollback) => return Err(Error::StorageUnavailable),
            Some(Fault::UnknownRollback) => return Err(unknown),
            _ => {}
        }
        let result = apply(self);
        self.audit.push(audit);
        match fault {
            Some(Fault::UnknownCommitted) => Err(unknown),
            Some(Fault::LostResponse) => Err(Error::ResponseLost),
            _ => Ok(result),
        }
    }
}

fn membership_context(member: &Membership) -> LinkMembership {
    LinkMembership {
        organization_id: member.resource.id,
        membership_id: member.resource.membership.id,
    }
}

fn status(member: &Membership) -> MemberLinkStatus {
    MemberLinkStatus {
        membership: membership_context(member),
        link: member.link.as_ref().map(|link| link.public.clone()),
    }
}

fn next_generation(member: &Membership) -> Result<u64, Error> {
    member.generation.checked_add(1).ok_or(Error::StorageUnavailable)
}

fn fresh_password(family: &Family, now: u64) -> Result<u64, Error> {
    family
        .password_at
        .checked_add(FRESH_SECONDS)
        .filter(|deadline| now >= family.password_at && now < *deadline)
        .ok_or(Error::Denied)
}

fn current_connection(org: &Organization, revision: Uuid) -> Result<&LinkConnection, Error> {
    let connection = org
        .connection
        .as_ref()
        .filter(|connection| connection.active && connection.trusted)
        .ok_or(Error::Conflict)?;
    if connection.configuration.id != revision {
        return Err(Error::PreconditionFailed);
    }
    Ok(&connection.configuration)
}

fn attempt_event(attempt: &Attempt, event: LinkEvent, link: Option<Uuid>) -> LinkAudit {
    LinkAudit {
        writer: attempt.writer,
        membership: attempt.public.membership,
        event,
        attempt: Some(attempt.public.id),
        link,
        revision: Some(attempt.public.connection_revision),
    }
}

fn withdrawal(
    ctx: LinkContext,
    org: &Organization,
    member: &Membership,
    id: Uuid,
) -> Result<(LinkAudit, u64), Error> {
    let link = member.link.as_ref().ok_or(Error::NotFound)?;
    if link.public.id != id {
        return Err(Error::PreconditionFailed);
    }
    Ok((
        LinkAudit {
            writer: ctx.writer,
            membership: membership_context(member),
            event: LinkEvent::Withdrawn,
            attempt: None,
            link: Some(id),
            revision: org.connection.as_ref().map(|connection| connection.configuration.id),
        },
        next_generation(member)?,
    ))
}
