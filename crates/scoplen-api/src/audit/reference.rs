// SPDX-License-Identifier: Apache-2.0
//! D-144 current-authority and scripted-response peer, without production storage or chains.
//!
//! Setters install trusted fixture facts. Callers supply externally verified authentication
//! and proof bindings; this peer never authenticates a credential or verifies a hash chain.

use std::collections::BTreeMap;

use cedar_policy::PolicySet;
use scoplen_crypto::DeviceAccessTokenClaims;
use uuid::Uuid;

use super::{
    AuditCodecError, AuditListQuery, AuditPage, AuditRange, AuditVerification,
    MAX_AUDIT_VERIFY_EVENT_BYTES,
};
use crate::{
    account_browser::{AccountBrowserAccessScope, AccountBrowserWriter},
    auth::DeviceAccessScope,
    control_plane::OrganizationAuthorizer,
    organization::OrganizationResource,
    organization_reference::{OrganizationReferenceError, authorize_organization_action},
};

/// Already authenticated profile facts; no HTTP token parser or Operator profile is provided.
#[derive(Clone, Copy)]
pub enum AuditReferenceCaller<'a> {
    /// Independently verified Device claims and proof-key binding.
    Device(&'a DeviceAccessTokenClaims),
    /// Independently verified opaque Account-browser access record and proof.
    AccountBrowser(AccountBrowserWriter),
}

/// Content-free read failures; an integrity failure is a successful verification response.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum AuditReferenceError {
    /// Invalid decoded request syntax or a range beyond the known chain extent.
    #[error("invalid audit request")]
    InvalidRequest,
    /// Missing current Account, Device or browser-family binding.
    #[error("audit authentication required")]
    AuthenticationRequired,
    /// Missing exact scope or current Cedar permit.
    #[error("audit operation denied")]
    Denied,
    /// Missing active Organization or current active membership.
    #[error("audit organization not found")]
    NotFound,
    /// Complete query, response, interval or examined original-byte overflow.
    #[error("audit request too large")]
    TooLarge,
    /// Unavailable scripted storage or unusable stored response metadata.
    #[error("audit storage unavailable")]
    StorageUnavailable,
}

impl AuditReferenceError {
    /// Render the existing bounded read-only problem classification.
    /// # Errors
    /// Rejects an invalid request instance through the shared problem codec.
    pub fn problem(self, instance: &str) -> Result<crate::ProblemDetails, crate::ApiContractError> {
        let (status, code, retryable, detail) = match self {
            Self::InvalidRequest => (
                400,
                "organization.invalid_request",
                false,
                "The audit request is invalid. Correct the selection before trying again.",
            ),
            Self::AuthenticationRequired => (
                401,
                "auth.authentication_required",
                false,
                "The current session could not be authenticated. Authenticate again.",
            ),
            Self::Denied => (
                403,
                "policy.denied",
                false,
                "Audit access is not permitted. Obtain a permitted session or contact the team owner.",
            ),
            Self::NotFound => (
                404,
                "organization.not_found",
                false,
                "The team is unavailable. Refresh your team list.",
            ),
            Self::TooLarge => (
                413,
                "organization.invalid_request",
                false,
                "The audit selection exceeds its bound. Select a smaller page or interval.",
            ),
            Self::StorageUnavailable => (
                503,
                "organization.storage_unavailable",
                true,
                "The audit read could not be completed. Retry the read with a fresh proof.",
            ),
        };
        crate::ProblemDetails::new(
            crate::ErrorCode::new(code)?,
            status,
            "Audit read was not completed",
            detail,
            instance,
            false,
            retryable,
        )
    }
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
struct VerificationResponse {
    body: Vec<u8>,
    known_extent: u64,
    examined_original_bytes: usize,
}

/// Reusable immutable response scripts guarded by the current trusted fixture snapshot.
#[derive(Clone, Default)]
pub struct AuditReferencePeer {
    accounts: BTreeMap<Uuid, bool>,
    devices: BTreeMap<Uuid, Device>,
    browsers: BTreeMap<Uuid, Browser>,
    organizations: BTreeMap<Uuid, bool>,
    memberships: BTreeMap<(Uuid, Uuid), (OrganizationResource, bool)>,
    policies: BTreeMap<Uuid, PolicySet>,
    page: Option<Vec<u8>>,
    verification: Option<VerificationResponse>,
    storage_available: bool,
}

impl std::fmt::Debug for AuditReferencePeer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditReferencePeer").finish_non_exhaustive()
    }
}

impl AuditReferencePeer {
    /// Install current Account eligibility independently of token or membership snapshots.
    pub fn set_account_active(&mut self, account: Uuid, active: bool) {
        self.accounts.insert(account, active);
    }

    /// Install a current Device binding; never copy membership or roles from token claims.
    pub fn set_device(&mut self, claims: &DeviceAccessTokenClaims, active: bool) {
        self.devices.insert(
            claims.did,
            Device { account: claims.sub, proof_key: claims.cnf_jkt.clone(), active },
        );
    }

    /// Install a current opaque-access family and its server-owned exact scope ceiling.
    /// Credential expiry/generation/proof checks belong to the browser authentication peer.
    pub fn set_browser(&mut self, writer: AccountBrowserWriter, scope: &str, active: bool) {
        self.browsers.insert(
            writer.family_id(),
            Browser { account: writer.account_id(), scope: scope.into(), active },
        );
    }

    /// Install current Organization eligibility independently of membership and token claims.
    pub fn set_organization_active(&mut self, organization: Uuid, active: bool) {
        self.organizations.insert(organization, active);
    }

    /// Install one current caller membership; historical event actors need no current record.
    /// # Errors
    /// Rejects malformed fixture identity, roles or Organization metadata.
    pub fn set_membership(
        &mut self,
        resource: OrganizationResource,
        active: bool,
    ) -> Result<(), AuditReferenceError> {
        resource.validate().map_err(|_| AuditReferenceError::InvalidRequest)?;
        self.memberships.insert((resource.id, resource.membership.account_id), (resource, active));
        Ok(())
    }

    /// Replace this Organization's current custom policy set, retaining built-in guards/roles.
    /// # Errors
    /// Rejects invalid policy/schema ownership before installing any replacement.
    pub fn set_policies(
        &mut self,
        organization: Uuid,
        policies: PolicySet,
    ) -> Result<(), AuditReferenceError> {
        OrganizationAuthorizer::new(organization, &policies)
            .map_err(|_| AuditReferenceError::InvalidRequest)?;
        self.policies.insert(organization, policies);
        Ok(())
    }

    /// Script an original Page response, including intentionally malformed/oversized test bodies.
    pub fn set_page_response(&mut self, body: &[u8]) {
        self.page = Some(body.to_vec());
    }

    /// Script a precomputed integrity outcome and its independently supplied read-budget facts.
    /// No projected JSON is hashed, no checkpoints are signed, and no chain is collected here.
    pub fn set_verification_response(
        &mut self,
        body: &[u8],
        known_extent: u64,
        examined_original_bytes: usize,
    ) {
        self.verification = Some(VerificationResponse {
            body: body.to_vec(),
            known_extent,
            examined_original_bytes,
        });
    }

    /// Script read availability without changing any response bytes or current authority.
    pub fn set_storage_available(&mut self, available: bool) {
        self.storage_available = available;
    }

    /// Read the original scripted Page after fresh current authority and request binding checks.
    /// # Errors
    /// Rejects request, current-authority, storage, encoded-body or response-context failures.
    pub fn list<'a>(
        &self,
        caller: AuditReferenceCaller<'_>,
        organization: Uuid,
        parameters: impl IntoIterator<Item = (&'a str, &'a str)>,
        now: u64,
    ) -> Result<Vec<u8>, AuditReferenceError> {
        super::valid_uuid(organization, "organization_id").map_err(request_error)?;
        let query = AuditListQuery::from_parameters(parameters).map_err(request_error)?;
        self.authorize(caller, organization, now)?;
        let body = self.page.as_ref().ok_or(AuditReferenceError::StorageUnavailable)?;
        AuditPage::from_json_for(body, organization, &query).map_err(response_error)?;
        Ok(body.clone())
    }

    /// Return a scripted success or first-failure result for exactly the captured interval.
    /// # Errors
    /// Rejects invalid/out-of-extent requests, stale authority, storage, budgets or response binding.
    pub fn verify<'a>(
        &self,
        caller: AuditReferenceCaller<'_>,
        organization: Uuid,
        parameters: impl IntoIterator<Item = (&'a str, &'a str)>,
        now: u64,
    ) -> Result<Vec<u8>, AuditReferenceError> {
        super::valid_uuid(organization, "organization_id").map_err(request_error)?;
        let range = AuditRange::from_parameters(parameters).map_err(request_error)?;
        self.authorize(caller, organization, now)?;
        let response = self.verification.as_ref().ok_or(AuditReferenceError::StorageUnavailable)?;
        if range.to_sequence > response.known_extent {
            return Err(AuditReferenceError::InvalidRequest);
        }
        if response.examined_original_bytes > MAX_AUDIT_VERIFY_EVENT_BYTES {
            return Err(AuditReferenceError::TooLarge);
        }
        AuditVerification::from_json_for(&response.body, organization, range)
            .map_err(response_error)?;
        Ok(response.body.clone())
    }

    fn authorize(
        &self,
        caller: AuditReferenceCaller<'_>,
        organization: Uuid,
        now: u64,
    ) -> Result<(), AuditReferenceError> {
        use AuditReferenceError as Error;
        let (account, scope) = match caller {
            AuditReferenceCaller::Device(claims) => {
                if now < claims.iat
                    || now >= claims.exp
                    || !self.devices.get(&claims.did).is_some_and(|device| {
                        device.active
                            && device.account == claims.sub
                            && device.proof_key == claims.cnf_jkt
                    })
                {
                    return Err(Error::AuthenticationRequired);
                }
                (claims.sub, DeviceAccessScope::AuditRead.is_present_in(&claims.scope))
            }
            AuditReferenceCaller::AccountBrowser(writer) => {
                let family = self
                    .browsers
                    .get(&writer.family_id())
                    .filter(|family| family.active && family.account == writer.account_id())
                    .ok_or(Error::AuthenticationRequired)?;
                (family.account, AccountBrowserAccessScope::AuditRead.is_present_in(&family.scope))
            }
        };
        if self.accounts.get(&account) != Some(&true) {
            return Err(Error::AuthenticationRequired);
        }
        if !scope {
            return Err(Error::Denied);
        }
        let (resource, active) =
            self.memberships.get(&(organization, account)).ok_or(Error::NotFound)?;
        if !active || self.organizations.get(&organization) != Some(&true) {
            return Err(Error::NotFound);
        }
        let empty = PolicySet::new();
        authorize_organization_action(
            resource,
            "view_audit",
            self.policies.get(&organization).unwrap_or(&empty),
            now,
        )
        .map_err(|error| {
            if error == OrganizationReferenceError::Denied {
                Error::Denied
            } else {
                Error::StorageUnavailable
            }
        })?;
        if !self.storage_available {
            return Err(Error::StorageUnavailable);
        }
        Ok(())
    }
}

fn request_error(error: AuditCodecError) -> AuditReferenceError {
    if error == AuditCodecError::TooLarge {
        AuditReferenceError::TooLarge
    } else {
        AuditReferenceError::InvalidRequest
    }
}

fn response_error(error: AuditCodecError) -> AuditReferenceError {
    if error == AuditCodecError::TooLarge {
        AuditReferenceError::TooLarge
    } else {
        AuditReferenceError::StorageUnavailable
    }
}
