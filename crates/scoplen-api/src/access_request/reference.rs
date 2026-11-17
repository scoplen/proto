// SPDX-License-Identifier: Apache-2.0
//! Independent D-150 transaction image with trusted current-state fixture setters.
//! This is no HTTP authentication, durable database, audit hash-chain or notification peer.

use std::collections::BTreeMap;

use cedar_policy::{Context as CedarContext, Decision, Entities, PolicySet, Request};
use scoplen_crypto::DeviceAccessTokenClaims;
use serde_json::{Value, json};
use uuid::Uuid;

use super::{
    ACCESS_REQUEST_PENDING_SECONDS, AccessRequestCheckRequest, AccessRequestCheckResponse,
    AccessRequestCreateRequest, AccessRequestDecision, AccessRequestDecisionRequest,
    AccessRequestFields, AccessRequestGrant, AccessRequestListQuery, AccessRequestOutcome,
    AccessRequestPage, AccessRequestResource, AccessRequestStatus, AccessRequestView,
};
use crate::{
    account_browser::{AccountBrowserAccessScope, AccountBrowserWriter},
    auth::DeviceAccessScope,
    control_plane::{
        OrganizationAuthorizationContext, OrganizationAuthorizer, OrganizationHostGrant,
    },
    grant::{GrantFields, format_grant_timestamp, parse_grant_timestamp},
    organization::{
        OrganizationCodecError, OrganizationPreconditionError, OrganizationResource,
        parse_organization_if_match, valid_uuid,
    },
    organization_reference::OrganizationReferenceError as Error,
};

/// Independently authenticated original writer; no Operator or synthetic Device exists.
#[derive(Clone, Copy)]
pub enum AccessRequestReferenceCaller<'a> {
    /// Verified enrolled-Device claims; proof/replay verification is external.
    Device(&'a DeviceAccessTokenClaims),
    /// Verified opaque Account-browser family.
    AccountBrowser(AccountBrowserWriter),
}

/// Router-owned context with trusted current whole-second time.
#[derive(Clone, Copy)]
pub struct AccessRequestReferenceContext<'a> {
    /// Current authentication profile.
    pub caller: AccessRequestReferenceCaller<'a>,
    /// Owning Organization selected by the trusted route.
    pub organization: Uuid,
    /// Trusted Unix time, independent of caller input.
    pub now: u64,
}

/// Scripted transaction/response fault, consumed only by a real mutation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccessRequestReferenceFault {
    /// Confirmed rollback of all state.
    Rollback,
    /// Required audit append failed; all state rolls back.
    AuditFailure,
    /// Unconfirmed COMMIT actually rolled back.
    UnknownRollback,
    /// Unconfirmed COMMIT actually published the complete image.
    UnknownCommitted,
    /// Complete commit with a lost response.
    LostResponse,
}

/// Exact writer kind retained in original receipts and attributable audit records.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccessRequestReferenceActor {
    /// Actual Device id.
    Device(Uuid),
    /// Actual Account-browser family id.
    AccountBrowser(Uuid),
}

/// Content-free committed audit append; no integrity-chain evidence is supplied.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccessRequestReferenceAudit {
    /// Fixed request/Grant event kind.
    pub kind: &'static str,
    /// Owning Organization.
    pub organization: Uuid,
    /// Recorded request or Grant id.
    pub object_id: Uuid,
    /// Current actor Account; absent for worker expiry.
    pub actor_account: Option<Uuid>,
    /// Real writer; absent for worker expiry.
    pub actor: Option<AccessRequestReferenceActor>,
}

#[derive(Clone)]
struct Device {
    account: Uuid,
    key: String,
    active: bool,
}
#[derive(Clone)]
struct Browser {
    account: Uuid,
    scope: String,
    active: bool,
}
#[derive(Clone)]
struct Receipt {
    origin: String,
    organization: Uuid,
    writer: AccessRequestReferenceActor,
    operation: &'static str,
    id: Uuid,
    precondition: Option<String>,
    payload: Vec<u8>,
    response: Vec<u8>,
    expires_at: u64,
}

/// Independent current state and one atomic image for request/Grant/receipt/audit publication.
#[derive(Clone)]
pub struct AccessRequestReferencePeer {
    origin: String,
    accounts: BTreeMap<Uuid, bool>,
    devices: BTreeMap<Uuid, Device>,
    browsers: BTreeMap<Uuid, Browser>,
    organizations: BTreeMap<Uuid, bool>,
    memberships: BTreeMap<(Uuid, Uuid), (OrganizationResource, bool)>,
    hosts: BTreeMap<(Uuid, Uuid), bool>,
    groups: BTreeMap<(Uuid, Uuid), Vec<Uuid>>,
    policies: BTreeMap<Uuid, PolicySet>,
    rows: BTreeMap<(Uuid, Uuid), AccessRequestResource>,
    grants: BTreeMap<(Uuid, Uuid), (OrganizationHostGrant, bool)>,
    receipts: BTreeMap<(Uuid, Uuid), Receipt>,
    revisions: BTreeMap<Uuid, u64>,
    audit: Vec<AccessRequestReferenceAudit>,
    fault: Option<AccessRequestReferenceFault>,
}

impl std::fmt::Debug for AccessRequestReferencePeer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccessRequestReferencePeer").finish_non_exhaustive()
    }
}

impl AccessRequestReferencePeer {
    /// Bind a fresh peer to its trusted canonical origin.
    /// # Errors
    /// Rejects invalid origin syntax.
    pub fn new(origin: &str) -> Result<Self, Error> {
        scoplen_crypto::validate_server_origin(origin).map_err(|_| Error::InvalidRequest)?;
        Ok(Self {
            origin: origin.into(),
            accounts: BTreeMap::new(),
            devices: BTreeMap::new(),
            browsers: BTreeMap::new(),
            organizations: BTreeMap::new(),
            memberships: BTreeMap::new(),
            hosts: BTreeMap::new(),
            groups: BTreeMap::new(),
            policies: BTreeMap::new(),
            rows: BTreeMap::new(),
            grants: BTreeMap::new(),
            receipts: BTreeMap::new(),
            revisions: BTreeMap::new(),
            audit: Vec::new(),
            fault: None,
        })
    }
    /// Install current Account eligibility independently of JWT claims.
    pub fn set_account_active(&mut self, account: Uuid, active: bool) {
        self.accounts.insert(account, active);
    }
    /// Install a verified current Device/key binding.
    pub fn set_device(&mut self, claims: &DeviceAccessTokenClaims, active: bool) {
        self.devices.insert(
            claims.did,
            Device { account: claims.sub, key: claims.cnf_jkt.clone(), active },
        );
    }
    /// Install a verified browser family and its original scope ceiling.
    pub fn set_browser(&mut self, writer: AccountBrowserWriter, scope: &str, active: bool) {
        self.browsers.insert(
            writer.family_id(),
            Browser { account: writer.account_id(), scope: scope.into(), active },
        );
    }
    /// Install trusted Organization lifecycle; restoration never revives withdrawn Grants.
    pub fn set_organization_active(&mut self, organization: Uuid, active: bool) {
        self.organizations.insert(organization, active);
        if !active {
            for ((org, _), (_, withdrawn)) in &mut self.grants {
                if *org == organization {
                    *withdrawn = true;
                }
            }
        }
    }
    /// Install current Membership/roles and withdraw old effective Grants on lifecycle loss.
    /// # Errors
    /// Rejects malformed trusted fixture metadata before changing state.
    pub fn set_membership(
        &mut self,
        resource: OrganizationResource,
        active: bool,
    ) -> Result<(), Error> {
        resource.validate().map_err(|_| Error::InvalidRequest)?;
        let previous = self
            .memberships
            .get(&(resource.id, resource.membership.account_id))
            .map(|(value, _)| value.membership.id);
        if !active || previous.is_some_and(|id| id != resource.membership.id) {
            for ((org, _), members) in &mut self.groups {
                if *org == resource.id {
                    members.retain(|id| *id != resource.membership.id && Some(*id) != previous);
                }
            }
        }
        for ((org, _), (grant, withdrawn)) in &mut self.grants {
            if *org == resource.id
                && ((!active && grant.fields.membership == resource.membership.id)
                    || previous.is_some_and(|id| {
                        id != resource.membership.id && grant.fields.membership == id
                    }))
            {
                *withdrawn = true;
            }
        }
        self.memberships.insert((resource.id, resource.membership.account_id), (resource, active));
        Ok(())
    }
    /// Install one trusted local Group and its current Membership associations.
    /// # Errors
    /// Rejects invalid ids or absent/inactive/foreign Membership references.
    pub fn set_group(
        &mut self,
        organization: Uuid,
        group: Uuid,
        members: Vec<Uuid>,
    ) -> Result<(), Error> {
        valid_uuid(group, "group").map_err(|_| Error::InvalidRequest)?;
        valid_uuid(organization, "organization").map_err(|_| Error::InvalidRequest)?;
        if members.iter().any(|id| {
            !self.memberships.iter().any(|((org, account), (member, active))| {
                *org == organization
                    && *active
                    && self.accounts.get(account) == Some(&true)
                    && member.membership.id == *id
            })
        }) {
            return Err(Error::InvalidRequest);
        }
        self.groups.insert((organization, group), members);
        Ok(())
    }
    /// Install a current live Host, applying pending-request and current-Grant deletion guards.
    /// # Errors
    /// Rejects invalid ids or guarded deletion.
    pub fn set_host(&mut self, organization: Uuid, host: Uuid, live: bool) -> Result<(), Error> {
        valid_uuid(organization, "organization").map_err(|_| Error::InvalidRequest)?;
        valid_uuid(host, "host").map_err(|_| Error::InvalidRequest)?;
        if !live && !self.host_deletion_allowed(organization, host) {
            return Err(Error::Conflict);
        }
        self.hosts.insert((organization, host), live);
        Ok(())
    }
    /// Inspect committed reference guards; expired-but-unprocessed Pending still guards deletion.
    #[must_use]
    pub fn host_deletion_allowed(&self, organization: Uuid, host: Uuid) -> bool {
        !self.rows.iter().any(|((org, _), row)| {
            *org == organization
                && row.fields.host == host
                && row.status == AccessRequestStatus::Pending
        }) && !self.grants.iter().any(|((org, _), (grant, withdrawn))| {
            *org == organization && !withdrawn && grant.fields.host == host
        })
    }
    /// Install current custom policy while retaining mandatory schema, roles and tenant guards.
    /// # Errors
    /// Rejects invalid Organization policy.
    pub fn set_policies(&mut self, organization: Uuid, policies: PolicySet) -> Result<(), Error> {
        OrganizationAuthorizer::new(organization, &policies).map_err(|_| Error::InvalidRequest)?;
        self.policies.insert(organization, policies);
        Ok(())
    }
    /// Script one real transaction; read/check/confirmation do not consume it.
    pub fn set_fault(&mut self, fault: AccessRequestReferenceFault) {
        self.fault = Some(fault);
    }
    /// Observe attributable appends committed in the same image.
    #[must_use]
    pub fn audit(&self) -> &[AccessRequestReferenceAudit] {
        &self.audit
    }
    /// Observe only the revision changed by approval's bound Grant publication.
    #[must_use]
    pub fn revision(&self, organization: Uuid) -> u64 {
        self.revisions.get(&organization).copied().unwrap_or(0)
    }
    /// Inspect current active-reference Grants for the existing D-147 connect/expiry helper.
    #[must_use]
    pub fn current_grants(&self, organization: Uuid) -> Vec<OrganizationHostGrant> {
        if self.organizations.get(&organization) != Some(&true) {
            return Vec::new();
        }
        self.grants
            .iter()
            .filter(|((org, _), (grant, withdrawn))| {
                *org == organization
                    && !withdrawn
                    && self.hosts.get(&(organization, grant.fields.host)) == Some(&true)
                    && self.memberships.iter().any(|((org, account), (member, active))| {
                        *org == organization
                            && *active
                            && member.membership.id == grant.fields.membership
                            && self.accounts.get(account) == Some(&true)
                    })
            })
            .map(|(_, (grant, _))| grant.clone())
            .collect()
    }
    /// Install a trusted external authorized withdrawal without changing request approval history.
    /// # Errors
    /// Rejects absent/foreign Grant ids. This setter is not a public management endpoint.
    pub fn withdraw_grant(&mut self, organization: Uuid, id: Uuid) -> Result<(), Error> {
        self.grants.get_mut(&(organization, id)).ok_or(Error::NotFound)?.1 = true;
        Ok(())
    }
    /// Evaluate concrete input without creating a request, receipt, revision or audit.
    /// # Errors
    /// Rejects authentication/scope/tenant/visibility failures and evaluation faults.
    pub fn check(
        &self,
        context: AccessRequestReferenceContext<'_>,
        body: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let input =
            AccessRequestCheckRequest::from_json(body).map_err(|error| request_error(&error))?;
        let (account, _) = self.authorize(context, "write")?;
        let allowed =
            self.eligibility(context.organization, account, &input.fields, context.now)?;
        AccessRequestCheckResponse { allowed }.to_json().map_err(|_| Error::StorageUnavailable)
    }
    /// Create the immutable application, or confirm its exact original successful bytes.
    /// # Errors
    /// Rejects current authority, invalid input, receipt/id conflicts and transaction faults.
    pub fn create(
        &mut self,
        context: AccessRequestReferenceContext<'_>,
        key: Uuid,
        body: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let input =
            AccessRequestCreateRequest::from_json(body).map_err(|error| request_error(&error))?;
        let (account, writer) = self.authorize(context, "write")?;
        let payload = input.to_json().map_err(|error| request_error(&error))?;
        valid_uuid(key, "key").map_err(|_| Error::InvalidRequest)?;
        if let Some(response) =
            self.confirm(context, account, writer, key, "create", input.id, None, &payload)?
        {
            let row = self.rows.get(&(context.organization, input.id)).ok_or(Error::NotFound)?;
            if row.requester_account_id != account {
                return Err(Error::NotFound);
            }
            return Ok(response);
        }
        if self.rows.keys().any(|(_, id)| *id == input.id) {
            return Err(Error::Conflict);
        }
        if !self.eligibility(context.organization, account, &input.fields, context.now)? {
            return Err(Error::Denied);
        }
        let timestamp = format_grant_timestamp(context.now).map_err(|_| Error::InvalidRequest)?;
        let expires_at = format_grant_timestamp(
            context.now.checked_add(ACCESS_REQUEST_PENDING_SECONDS).ok_or(Error::InvalidRequest)?,
        )
        .map_err(|_| Error::InvalidRequest)?;
        let member = self.member(context.organization, account)?;
        let row = AccessRequestResource {
            id: input.id,
            etag: tag(),
            created_at: timestamp.clone(),
            updated_at: timestamp,
            requester_account_id: account,
            requester_membership_id: member.membership.id,
            fields: input.fields,
            expires_at,
            status: AccessRequestStatus::Pending,
            decision: None,
            grant: None,
        };
        let response = row.to_json().map_err(|_| Error::InvalidRequest)?;
        let fault = self.begin_mutation()?;
        self.rows.insert((context.organization, row.id), row);
        self.remember(
            context,
            account,
            writer,
            key,
            "create",
            input.id,
            None,
            payload,
            response.clone(),
        );
        self.append(
            context.organization,
            input.id,
            Some(account),
            Some(writer),
            "organization.access_request_created",
        );
        finish(fault)?;
        Ok(response)
    }
    /// Read own history or a currently routed request, without policy-directory permission.
    /// # Errors
    /// Rejects absent/foreign/inaccessible requests and invalid current authentication.
    pub fn read(
        &self,
        context: AccessRequestReferenceContext<'_>,
        id: Uuid,
    ) -> Result<Vec<u8>, Error> {
        let (account, _) = self.authorize(context, "read")?;
        let row = self.rows.get(&(context.organization, id)).ok_or(Error::NotFound)?;
        self.readable(context.organization, account, row, context.now)?;
        row.to_json().map_err(|_| Error::StorageUnavailable)
    }
    /// List only own history or currently routed unexpired Pending requests, page by page.
    /// # Errors
    /// Rejects invalid query/authentication or evaluation failures; no partial Page is returned.
    pub fn list<'a>(
        &self,
        context: AccessRequestReferenceContext<'_>,
        parameters: impl IntoIterator<Item = (&'a str, &'a str)>,
    ) -> Result<Vec<u8>, Error> {
        let query = AccessRequestListQuery::from_parameters(parameters)
            .map_err(|error| request_error(&error))?;
        let (account, _) = self.authorize(context, "read")?;
        let mut eligible = Vec::new();
        for ((org, id), row) in &self.rows {
            if *org != context.organization || query.page.cursor.is_some_and(|cursor| *id <= cursor)
            {
                continue;
            }
            let include = match query.view {
                AccessRequestView::Mine => row.requester_account_id == account,
                AccessRequestView::Approvals => {
                    row.status == AccessRequestStatus::Pending
                        && context.now
                            < parse_grant_timestamp(&row.expires_at)
                                .map_err(|_| Error::StorageUnavailable)?
                        && self.routed(context.organization, account, row, context.now)?
                }
            };
            if include {
                eligible.push(row.clone());
            }
            if eligible.len() > usize::from(query.page.limit) {
                break;
            }
        }
        let more = eligible.len() > usize::from(query.page.limit);
        eligible.truncate(usize::from(query.page.limit));
        let next_cursor = if more { eligible.last().map(|row| row.id) } else { None };
        AccessRequestPage { items: eligible, next_cursor }
            .to_json()
            .map_err(|_| Error::StorageUnavailable)
    }
    /// Decide once, atomically publishing approval's exact finite Grant and audit pair.
    /// # Errors
    /// Rejects current routing/eligibility, preconditions, receipt conflicts or storage faults.
    pub fn decide(
        &mut self,
        context: AccessRequestReferenceContext<'_>,
        id: Uuid,
        key: Uuid,
        if_match: Option<&str>,
        body: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let input =
            AccessRequestDecisionRequest::from_json(body).map_err(|error| request_error(&error))?;
        self.transition(context, id, key, if_match, Some(input))
    }
    /// Withdraw only the caller's own unexpired Pending intent, without current Host visibility.
    /// # Errors
    /// Rejects invalid current requester, preconditions, receipt conflicts or storage faults.
    pub fn cancel(
        &mut self,
        context: AccessRequestReferenceContext<'_>,
        id: Uuid,
        key: Uuid,
        if_match: Option<&str>,
    ) -> Result<Vec<u8>, Error> {
        self.transition(context, id, key, if_match, None)
    }
    /// Commit bounded overdue Pending transitions; their deadlines already prohibit decisions.
    /// # Errors
    /// Rejects invalid trusted time/batch or scripted transaction failure.
    pub fn expire(&mut self, now: u64, limit: usize) -> Result<usize, Error> {
        let timestamp = format_grant_timestamp(now).map_err(|_| Error::InvalidRequest)?;
        if !(1..=500).contains(&limit) {
            return Err(Error::InvalidRequest);
        }
        let ids = self
            .rows
            .iter()
            .filter(|(_, row)| {
                row.status == AccessRequestStatus::Pending
                    && parse_grant_timestamp(&row.expires_at).is_ok_and(|expires| now >= expires)
            })
            .map(|(id, _)| *id)
            .take(limit)
            .collect::<Vec<_>>();
        if ids.is_empty() {
            return Ok(0);
        }
        let fault = self.begin_mutation()?;
        for (org, id) in &ids {
            let row = self.rows.get_mut(&(*org, *id)).ok_or(Error::StorageUnavailable)?;
            row.status = AccessRequestStatus::Expired;
            row.etag = tag();
            row.updated_at.clone_from(&timestamp);
            self.append(*org, *id, None, None, "organization.access_request_expired");
        }
        finish(fault)?;
        Ok(ids.len())
    }

    #[expect(
        clippy::too_many_lines,
        reason = "Keep authorization, original-operation confirmation and atomic publication in review order."
    )]
    fn transition(
        &mut self,
        context: AccessRequestReferenceContext<'_>,
        id: Uuid,
        key: Uuid,
        if_match: Option<&str>,
        decision: Option<AccessRequestDecisionRequest>,
    ) -> Result<Vec<u8>, Error> {
        let operation = if decision.is_some() { "decide" } else { "cancel" };
        let (account, writer) =
            self.authorize(context, if decision.is_some() { "decide" } else { "write" })?;
        let mut row = self.rows.get(&(context.organization, id)).cloned().ok_or(Error::NotFound)?;
        if decision.is_some() {
            if !self.routed(context.organization, account, &row, context.now)? {
                return Err(Error::NotFound);
            }
        } else if row.requester_account_id != account {
            return Err(Error::NotFound);
        }
        valid_uuid(key, "key").map_err(|_| Error::InvalidRequest)?;
        let precondition = parse_organization_if_match(if_match).map_err(|error| match error {
            OrganizationPreconditionError::Required => Error::PreconditionRequired,
            OrganizationPreconditionError::Invalid => Error::InvalidRequest,
        })?;
        let payload = decision
            .map(AccessRequestDecisionRequest::to_json)
            .transpose()
            .map_err(|error| request_error(&error))?
            .unwrap_or_default();
        if let Some(response) = self.confirm(
            context,
            account,
            writer,
            key,
            operation,
            id,
            Some(precondition),
            &payload,
        )? {
            return Ok(response);
        }
        if precondition != row.etag {
            return Err(Error::PreconditionFailed);
        }
        if row.status != AccessRequestStatus::Pending
            || context.now
                >= parse_grant_timestamp(&row.expires_at).map_err(|_| Error::StorageUnavailable)?
        {
            return Err(Error::Conflict);
        }
        if decision.is_some() {
            let requester = self
                .member(context.organization, row.requester_account_id)
                .map_err(|_| Error::Conflict)?;
            if requester.membership.id != row.requester_membership_id
                || self.accounts.get(&row.requester_account_id) != Some(&true)
            {
                return Err(Error::Conflict);
            }
            match self.eligibility(
                context.organization,
                row.requester_account_id,
                &row.fields,
                context.now,
            ) {
                Ok(true) => {}
                Ok(false) | Err(Error::NotFound) => return Err(Error::Conflict),
                Err(error) => return Err(error),
            }
        }
        let timestamp = format_grant_timestamp(context.now).map_err(|_| Error::InvalidRequest)?;
        row.etag = tag();
        row.updated_at.clone_from(&timestamp);
        let mut grant = None;
        let kind = if let Some(outcome) = decision.map(|value| value.decision) {
            row.decision = Some(AccessRequestDecision {
                outcome,
                actor_account_id: account,
                decided_at: timestamp,
            });
            if outcome == AccessRequestOutcome::Approve {
                let end = context
                    .now
                    .checked_add(u64::from(row.fields.duration_seconds))
                    .ok_or(Error::InvalidRequest)?;
                format_grant_timestamp(end).map_err(|_| Error::InvalidRequest)?;
                let grant_id = Uuid::now_v7();
                let fields = GrantFields {
                    membership: row.requester_membership_id,
                    host: row.fields.host,
                    remote_user: row.fields.remote_user.clone(),
                    valid_from: context.now,
                    valid_until: Some(end),
                };
                fields.validate().map_err(|_| Error::InvalidRequest)?;
                row.grant = Some(AccessRequestGrant {
                    id: grant_id,
                    valid_from: context.now,
                    valid_until: end,
                });
                row.status = AccessRequestStatus::Approved;
                grant = Some(OrganizationHostGrant {
                    id: grant_id,
                    organization: context.organization,
                    fields,
                });
                "organization.access_request_approved"
            } else {
                row.status = AccessRequestStatus::Denied;
                "organization.access_request_denied"
            }
        } else {
            row.status = AccessRequestStatus::Cancelled;
            "organization.access_request_cancelled"
        };
        let response = row.to_json().map_err(|_| Error::InvalidRequest)?;
        let fault = self.begin_mutation()?;
        self.rows.insert((context.organization, id), row);
        self.remember(
            context,
            account,
            writer,
            key,
            operation,
            id,
            Some(precondition),
            payload,
            response.clone(),
        );
        self.append(context.organization, id, Some(account), Some(writer), kind);
        if let Some(grant) = grant {
            let grant_id = grant.id;
            self.grants.insert((context.organization, grant_id), (grant, false));
            *self.revisions.entry(context.organization).or_default() += 1;
            self.append(
                context.organization,
                grant_id,
                Some(account),
                Some(writer),
                "organization.grants_created",
            );
        }
        finish(fault)?;
        Ok(response)
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "Compare each original immutable receipt binding explicitly."
    )]
    fn confirm(
        &self,
        context: AccessRequestReferenceContext<'_>,
        account: Uuid,
        writer: AccessRequestReferenceActor,
        key: Uuid,
        operation: &'static str,
        id: Uuid,
        precondition: Option<&str>,
        payload: &[u8],
    ) -> Result<Option<Vec<u8>>, Error> {
        let Some(receipt) = self.receipts.get(&(account, key)) else {
            return Ok(None);
        };
        if receipt.origin != self.origin
            || receipt.organization != context.organization
            || receipt.writer != writer
            || receipt.operation != operation
            || receipt.id != id
            || receipt.precondition.as_deref() != precondition
            || receipt.payload != payload
            || context.now >= receipt.expires_at
        {
            return Err(Error::Conflict);
        }
        Ok(Some(receipt.response.clone()))
    }
    #[expect(
        clippy::too_many_arguments,
        reason = "Persist each original immutable receipt binding explicitly."
    )]
    fn remember(
        &mut self,
        context: AccessRequestReferenceContext<'_>,
        account: Uuid,
        writer: AccessRequestReferenceActor,
        key: Uuid,
        operation: &'static str,
        id: Uuid,
        precondition: Option<&str>,
        payload: Vec<u8>,
        response: Vec<u8>,
    ) {
        self.receipts.insert(
            (account, key),
            Receipt {
                origin: self.origin.clone(),
                organization: context.organization,
                writer,
                operation,
                id,
                precondition: precondition.map(str::to_owned),
                payload,
                response,
                expires_at: context.now + ACCESS_REQUEST_PENDING_SECONDS,
            },
        );
    }
    fn append(
        &mut self,
        organization: Uuid,
        object_id: Uuid,
        actor_account: Option<Uuid>,
        actor: Option<AccessRequestReferenceActor>,
        kind: &'static str,
    ) {
        self.audit.push(AccessRequestReferenceAudit {
            kind,
            organization,
            object_id,
            actor_account,
            actor,
        });
    }
    fn begin_mutation(&mut self) -> Result<Option<AccessRequestReferenceFault>, Error> {
        match self.fault.take() {
            Some(
                AccessRequestReferenceFault::Rollback | AccessRequestReferenceFault::AuditFailure,
            ) => Err(Error::StorageUnavailable),
            Some(AccessRequestReferenceFault::UnknownRollback) => Err(Error::CommitOutcomeUnknown),
            fault => Ok(fault),
        }
    }
    fn member(&self, organization: Uuid, account: Uuid) -> Result<&OrganizationResource, Error> {
        self.memberships
            .get(&(organization, account))
            .filter(|(_, active)| *active)
            .map(|(resource, _)| resource)
            .ok_or(Error::NotFound)
    }
    fn authorize(
        &self,
        context: AccessRequestReferenceContext<'_>,
        operation: &str,
    ) -> Result<(Uuid, AccessRequestReferenceActor), Error> {
        let (account, writer, permitted) = match context.caller {
            AccessRequestReferenceCaller::Device(claims) => {
                if claims.iss != self.origin
                    || context.now < claims.iat
                    || context.now >= claims.exp
                    || !self.devices.get(&claims.did).is_some_and(|device| {
                        device.active
                            && device.account == claims.sub
                            && device.key == claims.cnf_jkt
                    })
                {
                    return Err(Error::AuthenticationRequired);
                }
                let scope = match operation {
                    "read" => DeviceAccessScope::AccessRequestsRead,
                    "decide" => DeviceAccessScope::AccessRequestsDecide,
                    _ => DeviceAccessScope::AccessRequestsWrite,
                };
                (
                    claims.sub,
                    AccessRequestReferenceActor::Device(claims.did),
                    scope.is_present_in(&claims.scope),
                )
            }
            AccessRequestReferenceCaller::AccountBrowser(writer) => {
                let browser = self
                    .browsers
                    .get(&writer.family_id())
                    .filter(|value| value.active && value.account == writer.account_id())
                    .ok_or(Error::AuthenticationRequired)?;
                let scope = match operation {
                    "read" => AccountBrowserAccessScope::AccessRequestsRead,
                    "decide" => AccountBrowserAccessScope::AccessRequestsDecide,
                    _ => AccountBrowserAccessScope::AccessRequestsWrite,
                };
                (
                    browser.account,
                    AccessRequestReferenceActor::AccountBrowser(writer.family_id()),
                    scope.is_present_in(&browser.scope),
                )
            }
        };
        if self.accounts.get(&account) != Some(&true) {
            return Err(Error::AuthenticationRequired);
        }
        if !permitted {
            return Err(Error::Denied);
        }
        valid_uuid(context.organization, "organization").map_err(|_| Error::InvalidRequest)?;
        if self.organizations.get(&context.organization) != Some(&true) {
            return Err(Error::NotFound);
        }
        self.member(context.organization, account)?;
        Ok((account, writer))
    }
    fn eligibility(
        &self,
        organization: Uuid,
        account: Uuid,
        fields: &AccessRequestFields,
        now: u64,
    ) -> Result<bool, Error> {
        if self.hosts.get(&(organization, fields.host)) != Some(&true)
            || !self.evaluate(
                organization,
                account,
                fields.host,
                now,
                "view_inventory",
                Some(fields),
                None,
            )?
        {
            return Err(Error::NotFound);
        }
        self.evaluate(organization, account, fields.host, now, "request_access", Some(fields), None)
    }
    fn routed(
        &self,
        organization: Uuid,
        account: Uuid,
        row: &AccessRequestResource,
        now: u64,
    ) -> Result<bool, Error> {
        if account == row.requester_account_id
            || self.hosts.get(&(organization, row.fields.host)) != Some(&true)
        {
            return Ok(false);
        }
        Ok(self.evaluate(
            organization,
            account,
            row.fields.host,
            now,
            "view_inventory",
            None,
            None,
        )? && self.evaluate(
            organization,
            account,
            row.fields.host,
            now,
            "approve_access",
            None,
            Some(row),
        )?)
    }
    fn readable(
        &self,
        organization: Uuid,
        account: Uuid,
        row: &AccessRequestResource,
        now: u64,
    ) -> Result<(), Error> {
        if row.requester_account_id == account || self.routed(organization, account, row, now)? {
            Ok(())
        } else {
            Err(Error::NotFound)
        }
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "Keep the trusted principal, target, context and optional request projection explicit."
    )]
    fn evaluate(
        &self,
        organization: Uuid,
        account: Uuid,
        host: Uuid,
        now: u64,
        action: &str,
        fields: Option<&AccessRequestFields>,
        row: Option<&AccessRequestResource>,
    ) -> Result<bool, Error> {
        let member = self.member(organization, account)?;
        let empty = PolicySet::new();
        let authorizer = OrganizationAuthorizer::new(
            organization,
            self.policies.get(&organization).unwrap_or(&empty),
        )
        .map_err(|_| Error::StorageUnavailable)?;
        let trusted = OrganizationAuthorizationContext::new(
            account,
            organization,
            member.membership.id,
            i64::try_from(now).map_err(|_| Error::InvalidRequest)?,
        )
        .map_err(|_| Error::InvalidRequest)?;
        let mut entities = vec![entity("Organization", organization, json!({"name":member.name}))];
        let mut account_ids = vec![account];
        if let Some(row) = row
            && row.requester_account_id != account
        {
            account_ids.push(row.requester_account_id);
        }
        for account_id in account_ids {
            entities.push(entity("Account", account_id, json!({"status": if self.accounts.get(&account_id) == Some(&true) { "active" } else { "inactive" }})));
        }
        let groups = self
            .groups
            .iter()
            .filter(|((org, _), members)| {
                *org == organization && members.contains(&member.membership.id)
            })
            .map(|((_, id), _)| reference("Group", *id))
            .collect::<Vec<_>>();
        for (org, id) in self.groups.keys() {
            if *org == organization {
                entities.push(entity("Group", *id, json!({"organization":reference("Organization", organization),"name":"Fixture group","source":"local"})));
            }
        }
        entities.push(entity("Membership", member.membership.id, json!({"account":reference("Account",account),"organization":reference("Organization",organization),"status":"active","roles":member.membership.roles,"groups":groups})));
        entities.push(entity("Host", host, json!({"organization":reference("Organization",organization),"labels":[],"host_groups":[]})));
        let mut context = json!({"organization":reference("Organization",organization),"membership":reference("Membership",member.membership.id),"now":now});
        let (kind, resource) = if let Some(row) = row {
            entities.push(entity("AccessRequest", row.id, json!({"organization":reference("Organization",organization),"requester":reference("Account",row.requester_account_id),"resource":reference("Host",host)})));
            context["requester"] = reference("Account", row.requester_account_id);
            context["resource"] = reference("Host", host);
            ("AccessRequest", row.id)
        } else {
            ("Host", host)
        };
        if action == "request_access" {
            let fields = fields.ok_or(Error::InvalidRequest)?;
            context["duration_seconds"] = json!(fields.duration_seconds);
            context["reason"] = json!(fields.reason);
        }
        let entities = Entities::from_json_value(json!(entities), None)
            .map_err(|_| Error::StorageUnavailable)?;
        let context =
            CedarContext::from_json_value(context, None).map_err(|_| Error::StorageUnavailable)?;
        let request = Request::new(
            uid("Account", account)?,
            uid("Action", action)?,
            uid(kind, resource)?,
            context,
            None,
        )
        .map_err(|_| Error::StorageUnavailable)?;
        let response = authorizer
            .authorize(&trusted, &request, &entities)
            .map_err(|_| Error::StorageUnavailable)?;
        Ok(response == Decision::Allow)
    }
}

fn uid(kind: &str, id: impl std::fmt::Display) -> Result<cedar_policy::EntityUid, Error> {
    format!("{kind}::\"{id}\"").parse().map_err(|_| Error::InvalidRequest)
}
fn reference(kind: &str, id: Uuid) -> Value {
    json!({"__entity":{"type":kind,"id":id.to_string()}})
}
fn entity(kind: &str, id: Uuid, attrs: Value) -> Value {
    let mut value = json!({"uid":{"type":kind,"id":id.to_string()},"parents":[]});
    value["attrs"] = attrs;
    value
}
fn tag() -> String {
    format!("\"{}\"", Uuid::now_v7())
}
fn request_error(error: &OrganizationCodecError) -> Error {
    if *error == OrganizationCodecError::TooLarge { Error::TooLarge } else { Error::InvalidRequest }
}
fn finish(fault: Option<AccessRequestReferenceFault>) -> Result<(), Error> {
    match fault {
        Some(AccessRequestReferenceFault::UnknownCommitted) => Err(Error::CommitOutcomeUnknown),
        Some(AccessRequestReferenceFault::LostResponse) => Err(Error::ResponseLost),
        _ => Ok(()),
    }
}
