// SPDX-License-Identifier: Apache-2.0
//! Independent D-151 transaction fixture. Setters supply trusted current state.
//! This is not HTTP authentication, durable storage, an audit chain or notification transport.

use std::collections::{BTreeMap, BTreeSet};

use cedar_policy::{Context, Decision, Entities, PolicySet, Request};
use scoplen_crypto::DeviceAccessTokenClaims;
use scoplen_model::{Hlc, Object};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::{
    INVENTORY_IMPORT_RECEIPT_SECONDS, InventoryImportPair, InventoryImportRequest,
    InventoryImportResult,
};
use crate::{
    account_browser::{AccountBrowserAccessScope, AccountBrowserWriter},
    auth::DeviceAccessScope,
    control_plane::{OrganizationAuthorizationContext, OrganizationAuthorizer},
    organization::{OrganizationCodecError, OrganizationResource, valid_uuid},
    organization_reference::OrganizationReferenceError as Error,
};

/// Already verified principal; proof verification/admission remain outside the fixture.
#[derive(Clone, Copy)]
pub enum InventoryImportReferenceCaller<'a> {
    /// Current enrolled Device token claims.
    Device(&'a DeviceAccessTokenClaims),
    /// Current Account-browser family.
    AccountBrowser(AccountBrowserWriter),
}

/// Trusted routed Organization and current Unix seconds.
#[derive(Clone, Copy)]
pub struct InventoryImportReferenceContext<'a> {
    /// Authenticated principal.
    pub caller: InventoryImportReferenceCaller<'a>,
    /// Exact Organization selected by the router.
    pub organization: Uuid,
    /// Current trusted time.
    pub now: u64,
}

/// Real writer attribution shared by origins, original receipts and audit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InventoryImportReferenceWriter {
    /// Enrolled Device id.
    Device(Uuid),
    /// Actual browser family id; never a synthetic Device.
    AccountBrowser(Uuid),
}
impl InventoryImportReferenceWriter {
    fn id(self) -> Uuid {
        match self {
            Self::Device(id) | Self::AccountBrowser(id) => id,
        }
    }
    fn kind(self) -> &'static str {
        match self {
            Self::Device(_) => "device",
            Self::AccountBrowser(_) => "account-browser",
        }
    }
}

/// One operation's scripted transaction fault.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InventoryImportReferenceFault {
    /// All writes roll back.
    Rollback,
    /// Encoding fails after preparation, without publication.
    EncodingFailure,
    /// Mandatory audit fails after the first prepared object.
    AuditFailure,
    /// COMMIT is uncertain and actually rolled back.
    UnknownRollback,
    /// COMMIT is uncertain and actually published the whole batch.
    UnknownCommitted,
    /// A complete commit's response is lost.
    LostResponse,
}

/// Content-free attributable existing inventory event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InventoryImportReferenceAudit {
    /// Always `organization.inventory_created`.
    pub kind: &'static str,
    /// Owning Organization.
    pub organization: Uuid,
    /// Original object id, in Host-then-Login order.
    pub object_id: Uuid,
    /// Committing Account.
    pub account: Uuid,
    /// Actual committing writer.
    pub writer: InventoryImportReferenceWriter,
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
    digest: [u8; 32],
    result: InventoryImportResult,
    expires_at: u64,
}

/// One atomic image for ordinary objects, sequences, view revision, receipt and audit.
#[derive(Clone)]
pub struct InventoryImportReferencePeer {
    origin: String,
    accounts: BTreeMap<Uuid, bool>,
    devices: BTreeMap<Uuid, Device>,
    browsers: BTreeMap<Uuid, Browser>,
    organizations: BTreeSet<Uuid>,
    memberships: BTreeMap<(Uuid, Uuid), (OrganizationResource, bool)>,
    policies: BTreeMap<Uuid, PolicySet>,
    used: BTreeSet<(Uuid, Uuid)>,
    objects: BTreeMap<(Uuid, Uuid), (Object, u64)>,
    counts: BTreeMap<Uuid, usize>,
    sequences: BTreeMap<Uuid, u64>,
    revisions: BTreeMap<Uuid, u64>,
    receipts: BTreeMap<(Uuid, Uuid), Receipt>,
    audit: Vec<InventoryImportReferenceAudit>,
    hints: Vec<Uuid>,
    fault: Option<InventoryImportReferenceFault>,
}
impl std::fmt::Debug for InventoryImportReferencePeer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InventoryImportReferencePeer").finish_non_exhaustive()
    }
}

impl InventoryImportReferencePeer {
    /// Start an independent image for one canonical trusted deployment origin.
    /// # Errors
    /// Rejects invalid origin syntax.
    pub fn new(origin: &str) -> Result<Self, Error> {
        scoplen_crypto::validate_server_origin(origin).map_err(|_| Error::InvalidRequest)?;
        Ok(Self {
            origin: origin.into(),
            accounts: BTreeMap::new(),
            devices: BTreeMap::new(),
            browsers: BTreeMap::new(),
            organizations: BTreeSet::new(),
            memberships: BTreeMap::new(),
            policies: BTreeMap::new(),
            used: BTreeSet::new(),
            objects: BTreeMap::new(),
            counts: BTreeMap::new(),
            sequences: BTreeMap::new(),
            revisions: BTreeMap::new(),
            receipts: BTreeMap::new(),
            audit: Vec::new(),
            hints: Vec::new(),
            fault: None,
        })
    }
    /// Install trusted current Account state.
    pub fn set_account_active(&mut self, account: Uuid, active: bool) {
        self.accounts.insert(account, active);
    }
    /// Install trusted current enrolled Device/key binding.
    pub fn set_device(&mut self, claims: &DeviceAccessTokenClaims, active: bool) {
        self.devices.insert(
            claims.did,
            Device { account: claims.sub, key: claims.cnf_jkt.clone(), active },
        );
    }
    /// Install trusted current browser family and scope ceiling.
    pub fn set_browser(&mut self, writer: AccountBrowserWriter, scope: &str, active: bool) {
        self.browsers.insert(
            writer.family_id(),
            Browser { account: writer.account_id(), scope: scope.into(), active },
        );
    }
    /// Install current Organization presence independently of membership.
    pub fn set_organization_active(&mut self, organization: Uuid, active: bool) {
        if active {
            self.organizations.insert(organization);
        } else {
            self.organizations.remove(&organization);
        }
    }
    /// Install a trusted caller-specific current Membership projection.
    /// # Errors
    /// Rejects invalid projection syntax.
    pub fn set_membership(
        &mut self,
        resource: OrganizationResource,
        active: bool,
    ) -> Result<(), Error> {
        resource.validate().map_err(|_| Error::InvalidRequest)?;
        self.memberships.insert((resource.id, resource.membership.account_id), (resource, active));
        Ok(())
    }
    /// Install this Organization's enabled custom policies; built-in guards still apply.
    pub fn set_policies(&mut self, organization: Uuid, policies: PolicySet) {
        self.policies.insert(organization, policies);
    }
    /// Reserve a previously used id, including one whose object has been tombstoned.
    pub fn reserve_used_id(&mut self, organization: Uuid, id: Uuid) {
        self.used.insert((organization, id));
    }
    /// Supply the trusted existing live-object count for the fixed 100,000-object quota.
    pub fn set_object_count(&mut self, organization: Uuid, count: usize) {
        self.counts.insert(organization, count);
    }
    /// Script the next actual mutation, leaving exact confirmation independent.
    pub fn set_fault(&mut self, fault: InventoryImportReferenceFault) {
        self.fault = Some(fault);
    }
    /// Current ordinary K-1 object and its allocated vault sequence.
    #[must_use]
    pub fn object(&self, organization: Uuid, id: Uuid) -> Option<&(Object, u64)> {
        self.objects.get(&(organization, id))
    }
    /// Current positive view revision, or zero before its first mutation.
    #[must_use]
    pub fn revision(&self, organization: Uuid) -> u64 {
        self.revisions.get(&organization).copied().unwrap_or(0)
    }
    /// Complete content-free committed audit.
    #[must_use]
    pub fn audit(&self) -> &[InventoryImportReferenceAudit] {
        &self.audit
    }
    /// One changed-only hint for each actual complete commit.
    #[must_use]
    pub fn hints(&self) -> &[Uuid] {
        &self.hints
    }

    /// Execute one atomic typed batch or confirm only its original receipt.
    /// # Errors
    /// Rejects syntax/current authority/conflicts/quota, and models rollback/unknown outcomes.
    #[expect(
        clippy::too_many_lines,
        reason = "Keep receipt confirmation and the complete atomic publication boundary together."
    )]
    pub fn create(
        &mut self,
        context: InventoryImportReferenceContext<'_>,
        key: Uuid,
        input: &[u8],
    ) -> Result<InventoryImportResult, Error> {
        let request = InventoryImportRequest::from_json(input).map_err(codec_error)?;
        valid_uuid(key, "idempotency key").map_err(codec_error)?;
        let (account, writer) = self.authorize(context)?;
        self.evaluate(
            context,
            account,
            "manage_inventory",
            "Organization",
            context.organization,
            &request,
        )?;
        let payload = request.to_json().map_err(codec_error)?;
        let digest = self.digest(context.organization, account, writer, &payload);
        if let Some(receipt) =
            self.receipts.get(&(account, key)).filter(|receipt| context.now < receipt.expires_at)
        {
            if receipt.digest != digest {
                return Err(Error::Conflict);
            }
            return Ok(receipt.result.clone());
        }
        let count = self.counts.get(&context.organization).copied().unwrap_or(0);
        if count.checked_add(request.rows.len() * 2).is_none_or(|count| count > 100_000) {
            return Err(Error::Conflict);
        }
        for row in &request.rows {
            if [row.host_id, row.access_profile_id]
                .iter()
                .any(|id| self.used.contains(&(context.organization, *id)))
            {
                return Err(Error::Conflict);
            }
            self.evaluate(context, account, "view_inventory", "Host", row.host_id, &request)?;
            self.evaluate(
                context,
                account,
                "view_inventory",
                "AccessProfile",
                row.access_profile_id,
                &request,
            )?;
        }
        let fault = self.fault.take();
        let mut next = self.clone();
        let mut sequence = next.sequences.get(&context.organization).copied().unwrap_or(0);
        let clock = Hlc::from_wire(context.now).map_err(|_| Error::InvalidRequest)?;
        for row in &request.rows {
            let (host, login) = row.inventory_creates().map_err(codec_error)?;
            for create in [host, login] {
                let object =
                    create.fields.to_object(create.id, clock, writer.id()).map_err(codec_error)?;
                object.encode().map_err(|_| Error::InvalidRequest)?;
                sequence = sequence.checked_add(1).ok_or(Error::StorageUnavailable)?;
                next.used.insert((context.organization, create.id));
                next.objects.insert((context.organization, create.id), (object, sequence));
                next.audit.push(InventoryImportReferenceAudit {
                    kind: "organization.inventory_created",
                    organization: context.organization,
                    object_id: create.id,
                    account,
                    writer,
                });
                if fault == Some(InventoryImportReferenceFault::AuditFailure) {
                    return Err(Error::StorageUnavailable);
                }
            }
        }
        let result = InventoryImportResult {
            items: request
                .rows
                .iter()
                .map(|row| InventoryImportPair {
                    host_id: row.host_id,
                    access_profile_id: row.access_profile_id,
                })
                .collect(),
        };
        result.to_json().map_err(codec_error)?;
        if matches!(
            fault,
            Some(
                InventoryImportReferenceFault::Rollback
                    | InventoryImportReferenceFault::EncodingFailure
            )
        ) {
            return Err(Error::StorageUnavailable);
        }
        if fault == Some(InventoryImportReferenceFault::UnknownRollback) {
            return Err(Error::CommitOutcomeUnknown);
        }
        next.counts.insert(context.organization, count + request.rows.len() * 2);
        next.sequences.insert(context.organization, sequence);
        next.revisions.insert(
            context.organization,
            self.revision(context.organization).checked_add(1).ok_or(Error::StorageUnavailable)?,
        );
        next.receipts.insert(
            (account, key),
            Receipt {
                digest,
                result: result.clone(),
                expires_at: context
                    .now
                    .checked_add(INVENTORY_IMPORT_RECEIPT_SECONDS)
                    .ok_or(Error::StorageUnavailable)?,
            },
        );
        if fault != Some(InventoryImportReferenceFault::UnknownCommitted) {
            next.hints.push(context.organization);
        }
        *self = next;
        if matches!(
            fault,
            Some(
                InventoryImportReferenceFault::UnknownCommitted
                    | InventoryImportReferenceFault::LostResponse
            )
        ) {
            return Err(Error::CommitOutcomeUnknown);
        }
        Ok(result)
    }

    fn digest(
        &self,
        organization: Uuid,
        account: Uuid,
        writer: InventoryImportReferenceWriter,
        payload: &[u8],
    ) -> [u8; 32] {
        let mut digest = Sha256::new();
        for part in [
            b"spl-organization-inventory-import-v1".as_slice(),
            self.origin.as_bytes(),
            account.as_bytes(),
            writer.kind().as_bytes(),
            writer.id().as_bytes(),
            b"POST",
            format!("/api/v1/orgs/{organization}/inventory/imports").as_bytes(),
            payload,
        ] {
            digest.update(u64::try_from(part.len()).unwrap_or(u64::MAX).to_be_bytes());
            digest.update(part);
        }
        digest.finalize().into()
    }
    fn authorize(
        &self,
        context: InventoryImportReferenceContext<'_>,
    ) -> Result<(Uuid, InventoryImportReferenceWriter), Error> {
        let (account, writer, permitted) = match context.caller {
            InventoryImportReferenceCaller::Device(claims) => {
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
                (
                    claims.sub,
                    InventoryImportReferenceWriter::Device(claims.did),
                    DeviceAccessScope::InventoryWrite.is_present_in(&claims.scope),
                )
            }
            InventoryImportReferenceCaller::AccountBrowser(writer) => {
                let browser = self
                    .browsers
                    .get(&writer.family_id())
                    .filter(|browser| browser.active && browser.account == writer.account_id())
                    .ok_or(Error::AuthenticationRequired)?;
                (
                    browser.account,
                    InventoryImportReferenceWriter::AccountBrowser(writer.family_id()),
                    AccountBrowserAccessScope::InventoryWrite.is_present_in(&browser.scope),
                )
            }
        };
        if self.accounts.get(&account) != Some(&true) {
            return Err(Error::AuthenticationRequired);
        }
        if !permitted {
            return Err(Error::Denied);
        }
        if !self.organizations.contains(&context.organization)
            || !self
                .memberships
                .get(&(context.organization, account))
                .is_some_and(|(_, active)| *active)
        {
            return Err(Error::NotFound);
        }
        Ok((account, writer))
    }
    fn evaluate(
        &self,
        context: InventoryImportReferenceContext<'_>,
        account: Uuid,
        action: &str,
        kind: &str,
        id: Uuid,
        batch: &InventoryImportRequest,
    ) -> Result<(), Error> {
        let member =
            &self.memberships.get(&(context.organization, account)).ok_or(Error::NotFound)?.0;
        let empty = PolicySet::new();
        let authorizer = OrganizationAuthorizer::new(
            context.organization,
            self.policies.get(&context.organization).unwrap_or(&empty),
        )
        .map_err(|_| Error::StorageUnavailable)?;
        let trusted = OrganizationAuthorizationContext::new(
            account,
            context.organization,
            member.membership.id,
            i64::try_from(context.now).map_err(|_| Error::InvalidRequest)?,
        )
        .map_err(|_| Error::InvalidRequest)?;
        let mut entities = vec![
            entity("Organization", context.organization, json!({"name":member.name})),
            entity("Account", account, json!({"status":"active"})),
            entity(
                "Membership",
                member.membership.id,
                json!({"account":reference("Account",account),"organization":reference("Organization",context.organization),"status":"active","roles":member.membership.roles,"groups":[]}),
            ),
        ];
        for row in batch.rows.iter().filter(|_| action != "manage_inventory") {
            entities.push(entity("Host",row.host_id,json!({"organization":reference("Organization",context.organization),"labels":[],"host_groups":[]})));
            entities.push(entity("AccessProfile",row.access_profile_id,json!({"organization":reference("Organization",context.organization),"host":reference("Host",row.host_id)})));
        }
        let entities = Entities::from_json_value(json!(entities), None)
            .map_err(|_| Error::StorageUnavailable)?;
        let cedar_context=Context::from_json_value(json!({"organization":reference("Organization",context.organization),"membership":reference("Membership",member.membership.id),"now":context.now}),None).map_err(|_|Error::StorageUnavailable)?;
        let request = Request::new(
            uid("Account", account)?,
            uid("Action", action)?,
            uid(kind, id)?,
            cedar_context,
            None,
        )
        .map_err(|_| Error::StorageUnavailable)?;
        match authorizer
            .authorize(&trusted, &request, &entities)
            .map_err(|_| Error::StorageUnavailable)?
        {
            Decision::Allow => Ok(()),
            Decision::Deny => {
                Err(if action == "view_inventory" { Error::NotFound } else { Error::Denied })
            }
        }
    }
}

#[expect(
    clippy::needless_pass_by_value,
    reason = "Map the owned codec error directly through Result::map_err."
)]
fn codec_error(error: OrganizationCodecError) -> Error {
    match error {
        OrganizationCodecError::TooLarge => Error::TooLarge,
        _ => Error::InvalidRequest,
    }
}
fn uid(kind: &str, id: impl std::fmt::Display) -> Result<cedar_policy::EntityUid, Error> {
    format!("{kind}::\"{id}\"").parse().map_err(|_| Error::StorageUnavailable)
}
fn reference(kind: &str, id: Uuid) -> Value {
    json!({"__entity":{"type":kind,"id":id.to_string()}})
}
fn entity(kind: &str, id: Uuid, attrs: Value) -> Value {
    let mut result = json!({"uid":{"type":kind,"id":id.to_string()},"parents":[]});
    result["attrs"] = attrs;
    result
}
