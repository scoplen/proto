// SPDX-License-Identifier: Apache-2.0
//! D-124 single-family test peer with scripted identity and transaction failures.
//!
//! This peer is not authentication, signature verification, admission, audit or durable storage.
//! Callers supply independently verified token/proof inputs. Its only success type is the
//! route-specific confirmation, so an already-revoked family cannot yield authorization evidence.

use std::{collections::BTreeSet, fmt};

use scoplen_crypto::OperatorAccessTokenClaims;

use crate::{
    ApiContractError, ErrorCode, ProblemDetails,
    operator_auth::{OperatorLogoutRequest, OperatorLogoutResponse},
};

/// One scripted failure at the next eligible termination.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReferenceOperatorLogoutFault {
    /// Storage/audit failed with a confirmed rollback.
    BeforeCommit,
    /// Commit was attempted but rolled back; the caller cannot know that outcome.
    UnknownRollback,
    /// Commit succeeded but its acknowledgement could not be confirmed.
    UnknownCommitted,
    /// Commit succeeded but no HTTP response reached the caller.
    LostResponse,
}

/// Content-free fixture outcomes; a missing response carries no HTTP problem.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ReferenceOperatorLogoutError {
    /// Invalid bounded request syntax.
    #[error("invalid Operator logout request")]
    InvalidRequest,
    /// Encoded request exceeds the endpoint's complete-body bound.
    #[error("Operator logout request too large")]
    TooLarge,
    /// Token/family time, identity or binding is no longer eligible.
    #[error("Operator logout authentication required")]
    AuthenticationRequired,
    /// The externally verified proof id was already claimed by this fixture.
    #[error("invalid Operator logout proof")]
    InvalidProof,
    /// Confirmed precommit failure.
    #[error("Operator logout storage unavailable")]
    StorageUnavailable,
    /// Commit was attempted; no successful confirmation is available.
    #[error("Operator logout commit outcome unknown")]
    CommitOutcomeUnknown,
    /// The network delivered no response.
    #[error("Operator logout response lost")]
    ResponseLost,
}

impl ReferenceOperatorLogoutError {
    /// Render D-124's existing registered problems, or no problem for a lost response.
    ///
    /// # Errors
    /// Rejects an invalid request instance through the common problem validator.
    pub fn problem(self, instance: &str) -> Result<Option<ProblemDetails>, ApiContractError> {
        let (status, code, changed, retryable) = match self {
            Self::InvalidRequest => (400, "auth.invalid_request", false, false),
            Self::TooLarge => (413, "auth.invalid_request", false, false),
            Self::AuthenticationRequired => (401, "auth.authentication_required", false, false),
            Self::InvalidProof => (400, "auth.invalid_dpop_proof", false, false),
            Self::StorageUnavailable => (503, "auth.storage_unavailable", false, true),
            Self::CommitOutcomeUnknown => (503, "auth.commit_outcome_unknown", true, true),
            Self::ResponseLost => return Ok(None),
        };
        ProblemDetails::new(
            ErrorCode::new(code)?, status, "Operator sign out was not confirmed",
            "Keep the current credentials. Retry explicitly with a fresh proof while the access token is valid; do not refresh automatically.",
            instance, changed, retryable,
        ).map(Some)
    }
}

/// Synthetic state for one already-authenticated family, independent of every other peer.
pub struct ReferenceOperatorLogoutPeer {
    original: OperatorAccessTokenClaims,
    family_expires_at: u64,
    operator_active: bool,
    credential_active: bool,
    revoked_at: Option<u64>,
    revocation_events: u64,
    proofs: BTreeSet<String>,
    fault: Option<ReferenceOperatorLogoutFault>,
}

impl fmt::Debug for ReferenceOperatorLogoutPeer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("ReferenceOperatorLogoutPeer").finish_non_exhaustive()
    }
}

impl ReferenceOperatorLogoutPeer {
    /// Retain synthetic original family bindings; production validation is external.
    #[must_use]
    pub fn new(original: OperatorAccessTokenClaims, family_expires_at: u64) -> Self {
        Self {
            original,
            family_expires_at,
            operator_active: true,
            credential_active: true,
            revoked_at: None,
            revocation_events: 0,
            proofs: BTreeSet::new(),
            fault: None,
        }
    }

    /// Script current identity checks without claiming to verify a stored passkey.
    pub fn set_identity_active(&mut self, operator: bool, credential: bool) {
        self.operator_active = operator;
        self.credential_active = credential;
    }

    /// Script one transaction or response fault without weakening eligibility checks.
    pub fn set_fault(&mut self, fault: ReferenceOperatorLogoutFault) {
        self.fault = Some(fault);
    }

    /// Observe the synthetic transition time; this is not an authorization capability.
    #[must_use]
    pub const fn revoked_at(&self) -> Option<u64> {
        self.revoked_at
    }

    /// Count atomic synthetic revocation events, excluding terminal confirmations.
    #[must_use]
    pub const fn revocation_events(&self) -> u64 {
        self.revocation_events
    }

    /// Exercise termination after external token/proof verification, using a fresh proof id.
    ///
    /// # Errors
    /// Rejects invalid body, stale/mismatched identity, proof replay or scripted storage faults.
    /// The token signature, token profile, `DPoP` signature/ath/Origin and admission are external.
    pub fn terminate(
        &mut self,
        body: &[u8],
        verified: &OperatorAccessTokenClaims,
        verified_proof_id: &str,
        now: u64,
    ) -> Result<OperatorLogoutResponse, ReferenceOperatorLogoutError> {
        use ReferenceOperatorLogoutError as Error;
        OperatorLogoutRequest::from_json(body).map_err(|error| match error {
            crate::operator_auth::OperatorAuthCodecError::TooLarge(_) => Error::TooLarge,
            _ => Error::InvalidRequest,
        })?;
        if !self.operator_active
            || !self.credential_active
            || now >= self.family_expires_at
            || now < verified.iat
            || now >= verified.exp
            || verified.iat < self.original.iat
            || verified.iss != self.original.iss
            || verified.sub != self.original.sub
            || verified.sid != self.original.sid
            || verified.cnf_jkt != self.original.cnf_jkt
            || verified.scope != self.original.scope
        {
            return Err(Error::AuthenticationRequired);
        }
        if verified_proof_id.is_empty() || !self.proofs.insert(verified_proof_id.to_owned()) {
            return Err(Error::InvalidProof);
        }
        let fault = self.fault.take();
        if self.revoked_at.is_some() {
            return match fault {
                None => Ok(OperatorLogoutResponse),
                Some(ReferenceOperatorLogoutFault::LostResponse) => Err(Error::ResponseLost),
                _ => Err(Error::StorageUnavailable),
            };
        }
        if matches!(fault, Some(ReferenceOperatorLogoutFault::BeforeCommit)) {
            return Err(Error::StorageUnavailable);
        }
        if matches!(fault, Some(ReferenceOperatorLogoutFault::UnknownRollback)) {
            return Err(Error::CommitOutcomeUnknown);
        }
        if self.revoked_at.is_none() {
            self.revoked_at = Some(now);
            self.revocation_events += 1;
        }
        match fault {
            Some(ReferenceOperatorLogoutFault::UnknownCommitted) => {
                Err(Error::CommitOutcomeUnknown)
            }
            Some(ReferenceOperatorLogoutFault::LostResponse) => Err(Error::ResponseLost),
            _ => Ok(OperatorLogoutResponse),
        }
    }
}
