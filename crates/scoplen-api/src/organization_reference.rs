// SPDX-License-Identifier: Apache-2.0
//! Narrow D-130 test peer: current membership, creation receipt and scripted commit outcomes.
//!
//! Signature/DPoP verification, replay admission, durable storage and audit chains remain
//! production consumer duties. Fixture setters supply trusted current state, never HTTP input.

use std::collections::BTreeMap;

use scoplen_crypto::DeviceAccessTokenClaims;
use uuid::Uuid;

use crate::{
    auth::DeviceAccessScope,
    organization::{
        ORGANIZATION_CREATION_RECEIPT_SECONDS, OrganizationCreateRequest, OrganizationListQuery,
        OrganizationMembership, OrganizationPage, OrganizationResource,
    },
};

/// A one-operation transaction or network fault.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OrganizationReferenceFault {
    /// State and audit both roll back before commit.
    Rollback,
    /// Commit was sent but rolled back, without a confirmed acknowledgement.
    UnknownRollback,
    /// State and audit committed, without a confirmed acknowledgement.
    UnknownCommitted,
    /// State and audit committed, but no response was delivered.
    LostResponse,
}

/// Content-free fixture outcomes.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum OrganizationReferenceError {
    /// The request or supplied fixture metadata is invalid.
    #[error("invalid organization request")]
    InvalidRequest,
    /// Caller is not the current eligible Account/Device/key binding.
    #[error("organization authentication required")]
    AuthenticationRequired,
    /// Missing exact scope or creation policy disabled.
    #[error("organization operation denied")]
    Denied,
    /// Missing Organization or current caller membership, deliberately indistinguishable.
    #[error("organization not found")]
    NotFound,
    /// The same Account/key was used with another canonical creation payload.
    #[error("organization creation conflict")]
    Conflict,
    /// Confirmed rollback.
    #[error("organization storage unavailable")]
    StorageUnavailable,
    /// No confirmed commit outcome.
    #[error("organization commit outcome unknown")]
    CommitOutcomeUnknown,
    /// No response arrived.
    #[error("organization response lost")]
    ResponseLost,
}

impl OrganizationReferenceError {
    /// Render the exact D-130 problem classification, or no problem for a lost response.
    /// # Errors
    /// Rejects an invalid request instance through the shared problem validator.
    pub fn problem(
        self,
        instance: &str,
    ) -> Result<Option<crate::ProblemDetails>, crate::ApiContractError> {
        let (status, code, changed, retryable, detail) = match self {
            Self::InvalidRequest => (
                400,
                "organization.invalid_request",
                false,
                false,
                "The team request is invalid. No team data changed. Correct the request before trying again.",
            ),
            Self::AuthenticationRequired => (
                401,
                "auth.authentication_required",
                false,
                false,
                "The current Device could not be authenticated. No team data changed. Authenticate again.",
            ),
            Self::Denied => (
                403,
                "policy.denied",
                false,
                false,
                "The team operation is not permitted. No team data changed. Obtain a fresh permitted Device session or contact the deployment administrator.",
            ),
            Self::NotFound => (
                404,
                "organization.not_found",
                false,
                false,
                "The team is unavailable. No team data changed. Refresh your team list.",
            ),
            Self::Conflict => (
                409,
                "organization.conflict",
                false,
                false,
                "The creation key belongs to another payload. No team data changed. Preserve the original operation.",
            ),
            Self::StorageUnavailable => (
                503,
                "organization.storage_unavailable",
                false,
                true,
                "The team operation rolled back. No team data changed. Retry with a fresh proof and the original creation key and payload when applicable.",
            ),
            Self::CommitOutcomeUnknown => (
                503,
                "organization.commit_outcome_unknown",
                true,
                true,
                "Team creation could not be confirmed and may have changed data. Preserve and retry only the original key and payload with a fresh proof within the original 24-hour window.",
            ),
            Self::ResponseLost => return Ok(None),
        };
        crate::ProblemDetails::new(
            crate::ErrorCode::new(code)?,
            status,
            "Team operation was not confirmed",
            detail,
            instance,
            changed,
            retryable,
        )
        .map(Some)
    }
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
}
#[derive(Clone)]
struct Receipt {
    payload: Vec<u8>,
    organization: Uuid,
    expires_at: u64,
}

/// In-memory reference state for independent codec and outcome tests.
#[derive(Clone, Default)]
pub struct OrganizationReferencePeer {
    allow_creation: bool,
    principals: BTreeMap<Uuid, Principal>,
    teams: BTreeMap<Uuid, Team>,
    receipts: BTreeMap<(Uuid, Uuid), Receipt>,
    audit_events: u64,
    fault: Option<OrganizationReferenceFault>,
}

impl std::fmt::Debug for OrganizationReferencePeer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OrganizationReferencePeer")
            .field("teams", &self.teams.len())
            .finish_non_exhaustive()
    }
}

impl OrganizationReferencePeer {
    /// Set the deployment creation policy without changing existing teams.
    pub fn set_allow_creation(&mut self, allow: bool) {
        self.allow_creation = allow;
    }

    /// Install a synthetic already-verified current Device/Account/proof-key binding.
    pub fn set_principal(&mut self, claims: &DeviceAccessTokenClaims, active: bool) {
        self.principals.insert(
            claims.did,
            Principal { account: claims.sub, key: claims.cnf_jkt.clone(), active },
        );
    }

    /// Script one eligible creation's transaction/response failure.
    pub fn set_fault(&mut self, fault: OrganizationReferenceFault) {
        self.fault = Some(fault);
    }

    /// Set an existing team's caller membership current state.
    pub fn set_membership_active(&mut self, organization: Uuid, active: bool) {
        if let Some(team) = self.teams.get_mut(&organization) {
            team.active = active;
        }
    }

    /// Count synthetic successful creation audit records.
    #[must_use]
    pub const fn audit_events(&self) -> u64 {
        self.audit_events
    }

    /// Create or confirm the Account's original exact team creation.
    ///
    /// `timestamp` is a trusted synthetic UTC projection; `now` is trusted elapsed fixture time.
    /// Signature, issuer, token-profile, proof and replay verification are external.
    /// # Errors
    /// Rejects malformed requests, stale principal, absent scope, policy or receipt conflicts,
    /// or returns the scripted atomic fault.
    pub fn create(
        &mut self,
        claims: &DeviceAccessTokenClaims,
        key: Uuid,
        body: &[u8],
        now: u64,
        timestamp: &str,
    ) -> Result<OrganizationResource, OrganizationReferenceError> {
        use OrganizationReferenceError as Error;
        let request =
            OrganizationCreateRequest::from_json(body).map_err(|_| Error::InvalidRequest)?;
        crate::organization::parse_organization_idempotency_key(&key.to_string())
            .map_err(|_| Error::InvalidRequest)?;
        self.authorize(claims, DeviceAccessScope::OrganizationCreate, now)?;
        let payload = request.to_json().map_err(|_| Error::InvalidRequest)?;
        if let Some(receipt) =
            self.receipts.get(&(claims.sub, key)).filter(|receipt| now < receipt.expires_at)
        {
            if receipt.payload != payload {
                return Err(Error::Conflict);
            }
            return self.read_authorized(claims.sub, receipt.organization);
        }
        if !self.allow_creation {
            return Err(Error::Denied);
        }
        let organization = Uuid::now_v7();
        let resource = OrganizationResource {
            id: organization,
            etag: format!("\"{organization}\""),
            created_at: timestamp.into(),
            updated_at: timestamp.into(),
            name: request.name,
            membership: OrganizationMembership {
                id: Uuid::now_v7(),
                account_id: claims.sub,
                roles: vec!["owner".into()],
            },
        };
        resource.to_json().map_err(|_| Error::InvalidRequest)?;
        let expires_at =
            now.checked_add(ORGANIZATION_CREATION_RECEIPT_SECONDS).ok_or(Error::InvalidRequest)?;
        let fault = self.fault.take();
        if fault == Some(OrganizationReferenceFault::Rollback) {
            return Err(Error::StorageUnavailable);
        }
        if fault == Some(OrganizationReferenceFault::UnknownRollback) {
            return Err(Error::CommitOutcomeUnknown);
        }
        self.teams.insert(organization, Team { resource: resource.clone(), active: true });
        self.receipts.insert((claims.sub, key), Receipt { payload, organization, expires_at });
        self.audit_events += 1;
        match fault {
            Some(OrganizationReferenceFault::UnknownCommitted) => Err(Error::CommitOutcomeUnknown),
            Some(OrganizationReferenceFault::LostResponse) => Err(Error::ResponseLost),
            _ => Ok(resource),
        }
    }

    /// Read only the caller's current membership projection.
    /// # Errors
    /// Rejects stale principal, absent scope and missing/foreign/inactive membership.
    pub fn read(
        &self,
        claims: &DeviceAccessTokenClaims,
        organization: Uuid,
        now: u64,
    ) -> Result<OrganizationResource, OrganizationReferenceError> {
        self.authorize(claims, DeviceAccessScope::OrganizationRead, now)?;
        self.read_authorized(claims.sub, organization)
    }

    /// Discover only the current caller's active teams, independent of its JWT `org` snapshot.
    /// # Errors
    /// Rejects stale principal, absent scope or invalid query.
    pub fn list(
        &self,
        claims: &DeviceAccessTokenClaims,
        query: OrganizationListQuery,
        now: u64,
    ) -> Result<OrganizationPage, OrganizationReferenceError> {
        query.validate().map_err(|_| OrganizationReferenceError::InvalidRequest)?;
        self.authorize(claims, DeviceAccessScope::OrganizationRead, now)?;
        let mut items: Vec<_> = self
            .teams
            .values()
            .filter(|team| {
                team.active
                    && team.resource.membership.account_id == claims.sub
                    && query.cursor.is_none_or(|cursor| team.resource.id > cursor)
            })
            .take(usize::from(query.limit) + 1)
            .map(|team| team.resource.clone())
            .collect();
        let next_cursor = if items.len() > usize::from(query.limit) {
            items.pop();
            items.last().map(|team| team.id)
        } else {
            None
        };
        Ok(OrganizationPage { items, next_cursor })
    }

    fn read_authorized(
        &self,
        account: Uuid,
        organization: Uuid,
    ) -> Result<OrganizationResource, OrganizationReferenceError> {
        self.teams
            .get(&organization)
            .filter(|team| team.active && team.resource.membership.account_id == account)
            .map(|team| team.resource.clone())
            .ok_or(OrganizationReferenceError::NotFound)
    }
    fn authorize(
        &self,
        claims: &DeviceAccessTokenClaims,
        scope: DeviceAccessScope,
        now: u64,
    ) -> Result<(), OrganizationReferenceError> {
        if now < claims.iat
            || now >= claims.exp
            || !self
                .principals
                .get(&claims.did)
                .is_some_and(|p| p.active && p.account == claims.sub && p.key == claims.cnf_jkt)
        {
            return Err(OrganizationReferenceError::AuthenticationRequired);
        }
        if !scope.is_present_in(&claims.scope) {
            return Err(OrganizationReferenceError::Denied);
        }
        Ok(())
    }
}
