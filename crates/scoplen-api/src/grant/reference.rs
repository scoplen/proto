// SPDX-License-Identifier: Apache-2.0
//! D-147 fixture peer for current authority, immutable receipts and atomic Grant outcomes.
//!
//! Setters install trusted current snapshots, including lifecycle withdrawal in the same image.
//! Authentication/proof verification, durable transactions, notifications, team-transition audit
//! and KRL publication remain consumer duties. This peer implements no HTTP or audit hash chain.

use std::collections::BTreeMap;

use cedar_policy::PolicySet;
use scoplen_crypto::DeviceAccessTokenClaims;
use uuid::Uuid;

use super::{
    GrantCreateRequest, GrantFields, GrantPage, GrantReplaceRequest, GrantResource,
    format_grant_timestamp,
};
use crate::{
    account_browser::{AccountBrowserAccessScope, AccountBrowserWriter},
    auth::DeviceAccessScope,
    control_plane::{OrganizationAuthorizer, OrganizationHostGrant},
    organization::{
        ORGANIZATION_CREATION_RECEIPT_SECONDS, OrganizationCodecError, OrganizationListQuery,
        OrganizationPreconditionError, OrganizationResource, parse_organization_if_match,
        valid_uuid,
    },
    organization_reference::{OrganizationReferenceError as Error, authorize_organization_action},
};

/// Externally authenticated caller facts; no Operator or synthetic Device profile exists.
#[derive(Clone, Copy)]
pub enum GrantReferenceCaller<'a> {
    /// Verified current Device claims with an independently verified proof binding.
    Device(&'a DeviceAccessTokenClaims),
    /// Verified current opaque-access Account-browser family.
    AccountBrowser(AccountBrowserWriter),
}

/// Captured trusted request context; route and method are fixed by each peer method.
#[derive(Clone, Copy)]
pub struct GrantReferenceContext<'a> {
    /// Authentication profile and original writer.
    pub caller: GrantReferenceCaller<'a>,
    /// Router-owned Organization id.
    pub organization: Uuid,
    /// Trusted whole Unix seconds.
    pub now: u64,
}

/// One attempted transaction's storage or delivery result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GrantReferenceFault {
    /// Confirmed rollback of row, revision, audit and receipt.
    Rollback,
    /// Audit append failure rolls back the entire mutation.
    AuditFailure,
    /// Commit was sent but rolled back without a confirmed acknowledgement.
    UnknownRollback,
    /// Mutation committed without a confirmed acknowledgement.
    UnknownCommitted,
    /// Mutation committed but its response was lost.
    LostResponse,
}

/// Real audit writer, also bound into original create receipts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GrantReferenceActor {
    /// Enrolled Device id from the verified session.
    Device(Uuid),
    /// Real browser family; it has no Device id.
    AccountBrowser(Uuid),
}

/// Attributable append record; this is no integrity-chain verification evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GrantReferenceAudit {
    /// One of the three fixed Grant producer event kinds.
    pub kind: &'static str,
    /// Router-owned Organization.
    pub organization: Uuid,
    /// Grant object id, never an inferred current policy.
    pub object_id: Uuid,
    /// Current authenticated Account.
    pub actor_account: Uuid,
    /// Original current Device or browser-family writer.
    pub actor: GrantReferenceActor,
}

#[derive(Clone)]
struct Device {
    account: Uuid,
    proof_key: String,
    active: bool,
}

#[derive(Clone)]
struct Browser {
    account: Uuid,
    scope: String,
    active: bool,
}

#[derive(Clone)]
struct Row {
    resource: GrantResource,
    withdrawn: bool,
}

#[derive(Clone)]
struct Receipt {
    origin: String,
    organization: Uuid,
    writer: GrantReferenceActor,
    payload: Vec<u8>,
    response: Vec<u8>,
    expires_at: u64,
}

/// Independent in-memory current state and immutable create confirmations.
#[derive(Clone)]
pub struct GrantReferencePeer {
    origin: String,
    accounts: BTreeMap<Uuid, bool>,
    devices: BTreeMap<Uuid, Device>,
    browsers: BTreeMap<Uuid, Browser>,
    organizations: BTreeMap<Uuid, bool>,
    memberships: BTreeMap<(Uuid, Uuid), (OrganizationResource, bool)>,
    hosts: BTreeMap<(Uuid, Uuid), bool>,
    policies: BTreeMap<Uuid, PolicySet>,
    rows: BTreeMap<(Uuid, Uuid), Row>,
    receipts: BTreeMap<(Uuid, Uuid), Receipt>,
    revisions: BTreeMap<Uuid, u64>,
    audit: Vec<GrantReferenceAudit>,
    fault: Option<GrantReferenceFault>,
}

impl std::fmt::Debug for GrantReferencePeer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GrantReferencePeer").finish_non_exhaustive()
    }
}

impl GrantReferencePeer {
    /// Create a fixture bound to one canonical trusted deployment origin.
    /// # Errors
    /// Rejects an invalid origin.
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
            policies: BTreeMap::new(),
            rows: BTreeMap::new(),
            receipts: BTreeMap::new(),
            revisions: BTreeMap::new(),
            audit: Vec::new(),
            fault: None,
        })
    }

    /// Install current Account eligibility independently of any token snapshot.
    pub fn set_account_active(&mut self, account: Uuid, active: bool) {
        self.accounts.insert(account, active);
    }

    /// Install a current Device/key binding from independently verified fixture claims.
    pub fn set_device(&mut self, claims: &DeviceAccessTokenClaims, active: bool) {
        self.devices.insert(
            claims.did,
            Device { account: claims.sub, proof_key: claims.cnf_jkt.clone(), active },
        );
    }

    /// Install a current browser family and its server-owned exact scope ceiling.
    pub fn set_browser(&mut self, writer: AccountBrowserWriter, scope: &str, active: bool) {
        self.browsers.insert(
            writer.family_id(),
            Browser { account: writer.account_id(), scope: scope.into(), active },
        );
    }

    /// Install a trusted lifecycle snapshot; dissolution withdraws all current Grants.
    /// Restoring a fixture Organization never clears a retained withdrawal marker.
    pub fn set_organization_active(&mut self, organization: Uuid, active: bool) {
        self.organizations.insert(organization, active);
        if !active {
            for ((org, _), row) in &mut self.rows {
                if *org == organization {
                    row.withdrawn = true;
                }
            }
        }
    }

    /// Install a trusted atomic membership/lifecycle snapshot.
    /// Suspension, removal or leave withdraws current Grants; restore/rejoin never revives them.
    /// Team-transition audit and revision belong to the transaction supplying this snapshot.
    /// # Errors
    /// Rejects malformed metadata, ids or roles before changing the snapshot.
    pub fn set_membership(
        &mut self,
        resource: OrganizationResource,
        active: bool,
    ) -> Result<(), Error> {
        resource.validate().map_err(|_| Error::InvalidRequest)?;
        let old = self.memberships.get(&(resource.id, resource.membership.account_id));
        let prior_membership = old.map(|(value, _)| value.membership.id);
        for ((org, _), row) in &mut self.rows {
            if *org == resource.id
                && ((!active && row.resource.fields.membership == resource.membership.id)
                    || prior_membership.is_some_and(|id| {
                        id != resource.membership.id && row.resource.fields.membership == id
                    }))
            {
                row.withdrawn = true;
            }
        }
        self.memberships.insert((resource.id, resource.membership.account_id), (resource, active));
        Ok(())
    }

    /// Install a live same-team Host fixture, respecting the Grant deletion guard.
    /// # Errors
    /// Rejects invalid ids or deletion while an unwithdrawn Grant still refers to the Host.
    pub fn set_host(&mut self, organization: Uuid, host: Uuid, live: bool) -> Result<(), Error> {
        valid_uuid(organization, "organization").map_err(|_| Error::InvalidRequest)?;
        valid_uuid(host, "host").map_err(|_| Error::InvalidRequest)?;
        if !live && !self.host_deletion_allowed(organization, host) {
            return Err(Error::Conflict);
        }
        self.hosts.insert((organization, host), live);
        Ok(())
    }

    /// Inspect the trusted deletion guard, including future and expired unwithdrawn rows.
    #[must_use]
    pub fn host_deletion_allowed(&self, organization: Uuid, host: Uuid) -> bool {
        !self.rows.iter().any(|((org, _), row)| {
            *org == organization && !row.withdrawn && row.resource.fields.host == host
        })
    }

    /// Install current custom policies while retaining built-in tenant and role guards.
    /// # Errors
    /// Rejects policies outside the shared Organization schema/profile.
    pub fn set_policies(&mut self, organization: Uuid, policies: PolicySet) -> Result<(), Error> {
        OrganizationAuthorizer::new(organization, &policies).map_err(|_| Error::InvalidRequest)?;
        self.policies.insert(organization, policies);
        Ok(())
    }

    /// Script the next actual mutation; reads, confirmations and equal PUTs do not consume it.
    pub fn set_fault(&mut self, fault: GrantReferenceFault) {
        self.fault = Some(fault);
    }

    /// Observe committed Grant audit appends; lifecycle snapshots add no per-Grant fan-out.
    #[must_use]
    pub fn audit(&self) -> &[GrantReferenceAudit] {
        &self.audit
    }

    /// Observe the revision changed in the same Grant mutation image as its row and audit.
    #[must_use]
    pub fn revision(&self, organization: Uuid) -> u64 {
        self.revisions.get(&organization).copied().unwrap_or(0)
    }

    /// Supply current, unwithdrawn same-team fields to the shared authorization helper.
    /// Time filtering remains the helper's responsibility; no receipt is an authority source.
    #[must_use]
    pub fn current_grants(&self, organization: Uuid) -> Vec<OrganizationHostGrant> {
        if self.organizations.get(&organization) != Some(&true) {
            return Vec::new();
        }
        self.rows
            .iter()
            .filter(|((org, _), row)| *org == organization && !row.withdrawn)
            .filter(|(_, row)| self.validate_references(organization, &row.resource.fields).is_ok())
            .map(|(_, row)| OrganizationHostGrant {
                id: row.resource.id,
                organization,
                fields: row.resource.fields.clone(),
            })
            .collect()
    }

    /// Execute the exact POST or return its immutable original create confirmation.
    /// # Errors
    /// Rejects syntax/current authority, conflicting receipt/id, references or transaction faults.
    pub fn create(
        &mut self,
        context: GrantReferenceContext<'_>,
        key: Uuid,
        body: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let request = GrantCreateRequest::from_json(body).map_err(|error| request_error(&error))?;
        valid_uuid(key, "idempotency key").map_err(|_| Error::InvalidRequest)?;
        let (account, writer) = self.authorize(context, true)?;
        let payload = request.to_json().map_err(|_| Error::InvalidRequest)?;
        if let Some(receipt) = self.receipts.get(&(account, key)) {
            if receipt.origin != self.origin
                || receipt.organization != context.organization
                || receipt.writer != writer
                || receipt.payload != payload
                || context.now >= receipt.expires_at
            {
                return Err(Error::Conflict);
            }
            return Ok(receipt.response.clone());
        }
        if self.rows.keys().any(|(_, id)| *id == request.id) {
            return Err(Error::Conflict);
        }
        self.validate_references(context.organization, &request.fields)?;
        let timestamp = format_grant_timestamp(context.now).map_err(|_| Error::InvalidRequest)?;
        let resource = GrantResource {
            id: request.id,
            etag: tag(),
            created_at: timestamp.clone(),
            updated_at: timestamp,
            fields: request.fields,
        };
        let response = resource.to_json().map_err(|_| Error::InvalidRequest)?;
        let expires_at = context
            .now
            .checked_add(ORGANIZATION_CREATION_RECEIPT_SECONDS)
            .ok_or(Error::InvalidRequest)?;
        let fault = self.begin_mutation(false)?;
        self.rows.insert(
            (context.organization, resource.id),
            Row { resource: resource.clone(), withdrawn: false },
        );
        self.receipts.insert(
            (account, key),
            Receipt {
                origin: self.origin.clone(),
                organization: context.organization,
                writer,
                payload,
                response: response.clone(),
                expires_at,
            },
        );
        self.append(
            context.organization,
            resource.id,
            account,
            writer,
            "organization.grants_created",
        );
        finish_mutation(fault, false)?;
        Ok(response)
    }

    /// Read only one current, unwithdrawn projection, including expired intervals.
    /// # Errors
    /// Rejects syntax/current authority or missing/withdrawn rows.
    pub fn read(&self, context: GrantReferenceContext<'_>, id: Uuid) -> Result<Vec<u8>, Error> {
        self.authorize(context, false)?;
        self.current_row(context.organization, id)?
            .resource
            .to_json()
            .map_err(|_| Error::StorageUnavailable)
    }

    /// Read an ascending current Page under the existing strict limit/cursor profile.
    /// # Errors
    /// Rejects invalid query/current authority or an unusable stored projection.
    pub fn list<'a>(
        &self,
        context: GrantReferenceContext<'_>,
        parameters: impl IntoIterator<Item = (&'a str, &'a str)>,
    ) -> Result<Vec<u8>, Error> {
        let query = OrganizationListQuery::from_parameters(parameters)
            .map_err(|_| Error::InvalidRequest)?;
        self.authorize(context, false)?;
        let mut remaining = self
            .rows
            .iter()
            .filter(|((org, id), row)| {
                *org == context.organization
                    && !row.withdrawn
                    && query.cursor.is_none_or(|cursor| *id > cursor)
            })
            .map(|(_, row)| row.resource.clone());
        let items: Vec<_> = remaining.by_ref().take(usize::from(query.limit)).collect();
        let next_cursor = remaining.next().and_then(|_| items.last().map(|item| item.id));
        GrantPage { items, next_cursor }.to_json().map_err(|_| Error::StorageUnavailable)
    }

    /// Replace all five desired fields using only the caller's original strong validator.
    /// Equal replacement does not mutate, append audit or advance revision.
    /// # Errors
    /// Rejects syntax/current authority, unavailable rows/references, stale tags or commit faults.
    pub fn replace(
        &mut self,
        context: GrantReferenceContext<'_>,
        id: Uuid,
        if_match: Option<&str>,
        body: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let request =
            GrantReplaceRequest::from_json(body).map_err(|error| request_error(&error))?;
        let (account, writer) = self.authorize(context, true)?;
        let original = self.current_row(context.organization, id)?.resource.clone();
        check_precondition(if_match, &original.etag)?;
        self.validate_references(context.organization, &request.fields)?;
        if request.fields == original.fields {
            return original.to_json().map_err(|_| Error::StorageUnavailable);
        }
        let resource = GrantResource {
            fields: request.fields,
            etag: tag(),
            updated_at: format_grant_timestamp(context.now).map_err(|_| Error::InvalidRequest)?,
            ..original
        };
        let response = resource.to_json().map_err(|_| Error::InvalidRequest)?;
        let fault = self.begin_mutation(true)?;
        self.rows.insert((context.organization, id), Row { resource, withdrawn: false });
        self.append(context.organization, id, account, writer, "organization.grants_updated");
        finish_mutation(fault, true)?;
        Ok(response)
    }

    /// Withdraw a row using only its original validator, retaining its used id and receipt.
    /// # Errors
    /// Rejects current authority, absent/withdrawn rows, invalid/stale tags or transaction faults.
    pub fn delete(
        &mut self,
        context: GrantReferenceContext<'_>,
        id: Uuid,
        if_match: Option<&str>,
    ) -> Result<(), Error> {
        let (account, writer) = self.authorize(context, true)?;
        let original = self.current_row(context.organization, id)?.resource.clone();
        check_precondition(if_match, &original.etag)?;
        let fault = self.begin_mutation(true)?;
        self.rows.get_mut(&(context.organization, id)).ok_or(Error::NotFound)?.withdrawn = true;
        self.append(context.organization, id, account, writer, "organization.grants_deleted");
        finish_mutation(fault, true)
    }

    fn current_row(&self, organization: Uuid, id: Uuid) -> Result<&Row, Error> {
        valid_uuid(id, "id").map_err(|_| Error::InvalidRequest)?;
        self.rows.get(&(organization, id)).filter(|row| !row.withdrawn).ok_or(Error::NotFound)
    }

    fn validate_references(&self, organization: Uuid, fields: &GrantFields) -> Result<(), Error> {
        let member = self.memberships.iter().any(|((org, account), (resource, active))| {
            *org == organization
                && *active
                && resource.membership.id == fields.membership
                && self.accounts.get(account) == Some(&true)
        });
        if !member || self.hosts.get(&(organization, fields.host)) != Some(&true) {
            return Err(Error::InvalidRequest);
        }
        Ok(())
    }

    fn authorize(
        &self,
        context: GrantReferenceContext<'_>,
        write: bool,
    ) -> Result<(Uuid, GrantReferenceActor), Error> {
        let (account, writer, scope) = match context.caller {
            GrantReferenceCaller::Device(claims) => {
                if claims.iss != self.origin
                    || context.now < claims.iat
                    || context.now >= claims.exp
                    || !self.devices.get(&claims.did).is_some_and(|device| {
                        device.active
                            && device.account == claims.sub
                            && device.proof_key == claims.cnf_jkt
                    })
                {
                    return Err(Error::AuthenticationRequired);
                }
                let required = if write {
                    DeviceAccessScope::PoliciesWrite
                } else {
                    DeviceAccessScope::PoliciesRead
                };
                (
                    claims.sub,
                    GrantReferenceActor::Device(claims.did),
                    required.is_present_in(&claims.scope),
                )
            }
            GrantReferenceCaller::AccountBrowser(writer) => {
                let family = self
                    .browsers
                    .get(&writer.family_id())
                    .filter(|family| family.active && family.account == writer.account_id())
                    .ok_or(Error::AuthenticationRequired)?;
                let required = if write {
                    AccountBrowserAccessScope::PoliciesWrite
                } else {
                    AccountBrowserAccessScope::PoliciesRead
                };
                (
                    family.account,
                    GrantReferenceActor::AccountBrowser(writer.family_id()),
                    required.is_present_in(&family.scope),
                )
            }
        };
        if self.accounts.get(&account) != Some(&true) {
            return Err(Error::AuthenticationRequired);
        }
        if !scope {
            return Err(Error::Denied);
        }
        let (resource, active) =
            self.memberships.get(&(context.organization, account)).ok_or(Error::NotFound)?;
        if !active || self.organizations.get(&context.organization) != Some(&true) {
            return Err(Error::NotFound);
        }
        let empty = PolicySet::new();
        authorize_organization_action(
            resource,
            if write { "manage_policy" } else { "view_policy" },
            self.policies.get(&context.organization).unwrap_or(&empty),
            context.now,
        )?;
        Ok((account, writer))
    }

    fn begin_mutation(&mut self, update: bool) -> Result<Option<GrantReferenceFault>, Error> {
        let fault = self.fault.take();
        match fault {
            Some(GrantReferenceFault::Rollback | GrantReferenceFault::AuditFailure) => {
                Err(Error::StorageUnavailable)
            }
            Some(GrantReferenceFault::UnknownRollback) => Err(unknown_commit(update)),
            _ => Ok(fault),
        }
    }

    fn append(
        &mut self,
        organization: Uuid,
        object_id: Uuid,
        account: Uuid,
        actor: GrantReferenceActor,
        kind: &'static str,
    ) {
        *self.revisions.entry(organization).or_default() += 1;
        self.audit.push(GrantReferenceAudit {
            kind,
            organization,
            object_id,
            actor_account: account,
            actor,
        });
    }
}

fn check_precondition(supplied: Option<&str>, current: &str) -> Result<(), Error> {
    let original = parse_organization_if_match(supplied).map_err(|error| match error {
        OrganizationPreconditionError::Required => Error::PreconditionRequired,
        OrganizationPreconditionError::Invalid => Error::InvalidRequest,
    })?;
    if original != current {
        return Err(Error::PreconditionFailed);
    }
    Ok(())
}

fn unknown_commit(update: bool) -> Error {
    if update { Error::UpdateCommitOutcomeUnknown } else { Error::CommitOutcomeUnknown }
}

fn finish_mutation(fault: Option<GrantReferenceFault>, update: bool) -> Result<(), Error> {
    match fault {
        Some(GrantReferenceFault::UnknownCommitted) => Err(unknown_commit(update)),
        Some(GrantReferenceFault::LostResponse) => Err(Error::ResponseLost),
        _ => Ok(()),
    }
}

fn tag() -> String {
    format!("\"{}\"", Uuid::now_v7())
}

fn request_error(error: &OrganizationCodecError) -> Error {
    if *error == OrganizationCodecError::TooLarge { Error::TooLarge } else { Error::InvalidRequest }
}
