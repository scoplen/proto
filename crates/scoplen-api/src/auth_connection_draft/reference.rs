// SPDX-License-Identifier: Apache-2.0
//! Reference peer for serialized D-166 mutations. Fixture setters install trusted state.
//! Consumers verify credentials, `DPoP`, replay, Origin and admission before invoking storage.

use std::collections::{BTreeMap, BTreeSet};

use cedar_policy::PolicySet;
use scoplen_crypto::DeviceAccessTokenClaims;
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use super::{DraftCreate, DraftResource, require_empty_slot};
use crate::{
    account_browser::{AccountBrowserAccessScope, AccountBrowserWriter},
    auth::DeviceAccessScope,
    control_plane::OrganizationAuthorizer,
    grant::format_grant_timestamp,
    organization::{
        ORGANIZATION_CREATION_RECEIPT_SECONDS, OrganizationCodecError,
        OrganizationPreconditionError, OrganizationResource, parse_organization_if_match,
        valid_uuid,
    },
    organization_reference::{
        OrganizationReferenceError as Error, OrganizationReferenceFault as Fault,
        authorize_organization_action,
    },
};

/// Trusted authentication result supplied by the consumer's proof verifier.
#[derive(Clone, Copy)]
pub enum DraftCaller<'a> {
    /// Enrolled Device access token and verified proof binding.
    Device(&'a DeviceAccessTokenClaims),
    /// Access and proof bound to this Account-browser family.
    Browser(AccountBrowserWriter),
}

/// Router- and clock-owned input for one request.
#[derive(Clone, Copy)]
pub struct DraftContext<'a> {
    /// Authenticated caller.
    pub caller: DraftCaller<'a>,
    /// Organization selected in the canonical URL.
    pub organization: Uuid,
    /// Current Unix seconds.
    pub now: u64,
}

/// Original authenticated writer in receipts and audit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DraftWriter {
    /// Enrolled Device ID.
    Device(Uuid),
    /// Original Account-browser family ID.
    Browser(Uuid),
}

/// Attributable mutation recorded atomically with the slot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DraftAudit {
    /// Successful operation: POST or DELETE.
    pub method: &'static str,
    /// Selected Organization.
    pub organization: Uuid,
    /// Created or cancelled generation.
    pub generation: Uuid,
    /// Authenticated Account.
    pub account: Uuid,
    /// Verified Device or family.
    pub writer: DraftWriter,
}

struct Receipt {
    operation: DraftAudit,
    request_digest: [u8; 32],
    created_at: u64,
}

struct Mutation<'a> {
    method: &'static str,
    condition: &'a str,
    payload: &'a [u8],
}

impl Mutation<'_> {
    fn digest(
        &self,
        origin: &str,
        org: Uuid,
        account: Uuid,
        writer: DraftWriter,
        key: Uuid,
    ) -> [u8; 32] {
        let (kind, id) = match writer {
            DraftWriter::Device(id) => ("device", id),
            DraftWriter::Browser(id) => ("account-browser", id),
        };
        let path = format!("/api/v1/orgs/{org}/auth-connection-draft");
        let mut hash = Sha256::new();
        for bytes in [
            origin.as_bytes(),
            account.as_bytes(),
            kind.as_bytes(),
            id.as_bytes(),
            key.as_bytes(),
            self.method.as_bytes(),
            path.as_bytes(),
            self.condition.as_bytes(),
            self.payload,
        ] {
            hash.update((bytes.len() as u64).to_be_bytes());
            hash.update(bytes);
        }
        hash.finalize().into()
    }
}

/// An in-memory reference image for exactly one trusted deployment origin.
/// Exclusive mutation serializes the empty slot, current policies, receipts and audit.
pub struct DraftReferencePeer {
    origin: String,
    accounts: BTreeSet<Uuid>,
    devices: BTreeMap<Uuid, (Uuid, String)>,
    families: BTreeMap<Uuid, (Uuid, String)>,
    organizations: BTreeSet<Uuid>,
    memberships: BTreeMap<(Uuid, Uuid), OrganizationResource>,
    policies: BTreeMap<Uuid, PolicySet>,
    drafts: BTreeMap<Uuid, DraftResource>,
    receipts: BTreeMap<(Uuid, Uuid), Receipt>,
    audit: Vec<DraftAudit>,
    fault: Option<Fault>,
}

impl DraftReferencePeer {
    /// Initialize independent state and receipt namespace for a trusted deployment.
    /// # Errors
    /// Rejects an invalid deployment origin.
    pub fn new(origin: &str) -> Result<Self, Error> {
        scoplen_crypto::validate_server_origin(origin).map_err(|_| Error::InvalidRequest)?;
        Ok(Self {
            origin: origin.into(),
            accounts: BTreeSet::new(),
            devices: BTreeMap::new(),
            families: BTreeMap::new(),
            organizations: BTreeSet::new(),
            memberships: BTreeMap::new(),
            policies: BTreeMap::new(),
            drafts: BTreeMap::new(),
            receipts: BTreeMap::new(),
            audit: Vec::new(),
            fault: None,
        })
    }

    /// Install the current Account eligibility snapshot.
    pub fn set_account(&mut self, account: Uuid, active: bool) {
        if active {
            self.accounts.insert(account);
        } else {
            self.accounts.remove(&account);
        }
    }

    /// Install or revoke a Device's current Account/key binding.
    pub fn set_device(&mut self, claims: &DeviceAccessTokenClaims, active: bool) {
        if active {
            self.devices.insert(claims.did, (claims.sub, claims.cnf_jkt.clone()));
        } else {
            self.devices.remove(&claims.did);
        }
    }

    /// Install or revoke the current verified family with its actual scope ceiling.
    pub fn set_browser(&mut self, writer: AccountBrowserWriter, scope: &str, active: bool) {
        if active {
            self.families.insert(writer.family_id(), (writer.account_id(), scope.into()));
        } else {
            self.families.remove(&writer.family_id());
        }
    }

    /// Install the selected Organization's lifecycle state.
    pub fn set_organization(&mut self, organization: Uuid, active: bool) {
        if active {
            self.organizations.insert(organization);
        } else {
            self.organizations.remove(&organization);
        }
    }

    /// Install the current membership and role projection.
    /// # Errors
    /// Rejects malformed membership fixture metadata.
    pub fn set_membership(
        &mut self,
        resource: OrganizationResource,
        active: bool,
    ) -> Result<(), Error> {
        resource.validate().map_err(|_| Error::InvalidRequest)?;
        let index = (resource.id, resource.membership.account_id);
        if active {
            self.memberships.insert(index, resource);
        } else {
            self.memberships.remove(&index);
        }
        Ok(())
    }

    /// Install current Cedar policies alongside the mandatory tenant guards.
    /// # Errors
    /// Rejects unsupported Organization policies.
    pub fn set_policies(&mut self, organization: Uuid, policies: PolicySet) -> Result<(), Error> {
        OrganizationAuthorizer::new(organization, &policies).map_err(|_| Error::InvalidRequest)?;
        self.policies.insert(organization, policies);
        Ok(())
    }

    /// Script a confirmed rollback (including audit failure), unknown commit or lost response.
    pub fn set_fault(&mut self, fault: Fault) {
        self.fault = Some(fault);
    }

    /// Committed audit appends without issuer values.
    #[must_use]
    pub fn audit(&self) -> &[DraftAudit] {
        &self.audit
    }

    fn authorize(&self, ctx: DraftContext<'_>) -> Result<(Uuid, DraftWriter), Error> {
        let (account, writer, scoped) = match ctx.caller {
            DraftCaller::Device(claims) => {
                if claims.iss != self.origin
                    || ctx.now < claims.iat
                    || ctx.now >= claims.exp
                    || !self.devices.get(&claims.did).is_some_and(|(account, jkt)| {
                        account == &claims.sub && jkt == &claims.cnf_jkt
                    })
                {
                    return Err(Error::AuthenticationRequired);
                }
                (
                    claims.sub,
                    DraftWriter::Device(claims.did),
                    DeviceAccessScope::AuthDraftsManage.is_present_in(&claims.scope),
                )
            }
            DraftCaller::Browser(browser) => {
                let (account, scope) = self
                    .families
                    .get(&browser.family_id())
                    .filter(|(account, _)| *account == browser.account_id())
                    .ok_or(Error::AuthenticationRequired)?;
                (
                    *account,
                    DraftWriter::Browser(browser.family_id()),
                    AccountBrowserAccessScope::AuthDraftsManage.is_present_in(scope),
                )
            }
        };
        if !self.accounts.contains(&account) {
            return Err(Error::AuthenticationRequired);
        }
        if !scoped {
            return Err(Error::Denied);
        }
        let membership = self
            .memberships
            .get(&(ctx.organization, account))
            .filter(|_| self.organizations.contains(&ctx.organization))
            .ok_or(Error::NotFound)?;
        if !membership
            .membership
            .roles
            .iter()
            .any(|r| matches!(r.as_str(), "owner" | "administrator"))
        {
            return Err(Error::Denied);
        }
        let empty = PolicySet::new();
        authorize_organization_action(
            membership,
            "manage_organization",
            self.policies.get(&ctx.organization).unwrap_or(&empty),
            ctx.now,
        )?;
        Ok((account, writer))
    }

    /// Read the current generation after authorization.
    /// # Errors
    /// Returns the standard static not-found for an authorized empty slot.
    pub fn read(&self, ctx: DraftContext<'_>) -> Result<DraftResource, Error> {
        self.authorize(ctx)?;
        self.drafts.get(&ctx.organization).cloned().ok_or(Error::NotFound)
    }

    /// Create only in an empty slot, or confirm the original writer's creation.
    /// # Errors
    /// Returns bounded syntax, authority, receipt, conditional or transaction errors.
    pub fn create(
        &mut self,
        ctx: DraftContext<'_>,
        key: Uuid,
        condition: Option<&str>,
        body: &[u8],
    ) -> Result<DraftResource, Error> {
        require_empty_slot(condition).map_err(precondition_error)?;
        let request = DraftCreate::from_json(body).map_err(|e| {
            if e == OrganizationCodecError::TooLarge {
                Error::TooLarge
            } else {
                Error::InvalidRequest
            }
        })?;
        let canonical = request.to_json().map_err(|_| Error::InvalidRequest)?;
        let (account, writer) = self.authorize(ctx)?;
        let digest = Mutation { method: "POST", condition: "*", payload: &canonical }.digest(
            &self.origin,
            ctx.organization,
            account,
            writer,
            key,
        );
        let receipt = self.receipt(ctx.now, account, key, digest)?;
        let (generation, now) = match receipt {
            Some(r) => (r.operation.generation, r.created_at),
            None if self.drafts.contains_key(&ctx.organization) => {
                return Err(Error::PreconditionFailed);
            }
            None => (Uuid::now_v7(), ctx.now),
        };
        let resource = DraftResource {
            id: generation,
            organization_id: ctx.organization,
            created_at: format_grant_timestamp(now).map_err(|_| Error::InvalidRequest)?,
            issuer: request.issuer,
        };
        if receipt.is_some() {
            return Ok(resource);
        }
        let operation = DraftAudit {
            method: "POST",
            organization: ctx.organization,
            generation,
            account,
            writer,
        };
        self.commit(
            key,
            Receipt { operation, request_digest: digest, created_at: now },
            Some(resource.clone()),
        )?;
        Ok(resource)
    }

    /// Cancel the reviewed generation, or confirm its original cancellation.
    /// # Errors
    /// Returns bounded syntax, authority, receipt, conditional or transaction errors.
    pub fn cancel(
        &mut self,
        ctx: DraftContext<'_>,
        key: Uuid,
        condition: Option<&str>,
    ) -> Result<(), Error> {
        let condition = parse_organization_if_match(condition).map_err(precondition_error)?;
        let (account, writer) = self.authorize(ctx)?;
        let digest = Mutation { method: "DELETE", condition, payload: &[] }.digest(
            &self.origin,
            ctx.organization,
            account,
            writer,
            key,
        );
        if self.receipt(ctx.now, account, key, digest)?.is_some() {
            return Ok(());
        }
        let current = self
            .drafts
            .get(&ctx.organization)
            .filter(|r| r.etag() == condition)
            .ok_or(Error::PreconditionFailed)?;
        let operation = DraftAudit {
            method: "DELETE",
            organization: ctx.organization,
            generation: current.id,
            account,
            writer,
        };
        self.commit(key, Receipt { operation, request_digest: digest, created_at: ctx.now }, None)
    }

    fn receipt(
        &self,
        now: u64,
        account: Uuid,
        key: Uuid,
        digest: [u8; 32],
    ) -> Result<Option<&Receipt>, Error> {
        valid_uuid(key, "Idempotency-Key").map_err(|_| Error::InvalidRequest)?;
        let Some(r) = self.receipts.get(&(account, key)) else { return Ok(None) };
        if r.request_digest != digest
            || now
                .checked_sub(r.created_at)
                .is_none_or(|age| age >= ORGANIZATION_CREATION_RECEIPT_SECONDS)
        {
            return Err(Error::Conflict);
        }
        Ok(Some(r))
    }

    fn commit(
        &mut self,
        key: Uuid,
        receipt: Receipt,
        draft: Option<DraftResource>,
    ) -> Result<(), Error> {
        let fault = self.fault.take();
        match fault {
            Some(Fault::Rollback) => return Err(Error::StorageUnavailable),
            Some(Fault::UnknownRollback) => return Err(Error::CommitOutcomeUnknown),
            _ => {}
        }
        let op = receipt.operation;
        if let Some(draft) = draft {
            self.drafts.insert(op.organization, draft);
        } else {
            self.drafts.remove(&op.organization);
        }
        self.receipts.insert((op.account, key), receipt);
        self.audit.push(op);
        match fault {
            Some(Fault::UnknownCommitted) => Err(Error::CommitOutcomeUnknown),
            Some(Fault::LostResponse) => Err(Error::ResponseLost),
            _ => Ok(()),
        }
    }
}

fn precondition_error(error: OrganizationPreconditionError) -> Error {
    match error {
        OrganizationPreconditionError::Invalid => Error::InvalidRequest,
        OrganizationPreconditionError::Required => Error::PreconditionRequired,
    }
}
