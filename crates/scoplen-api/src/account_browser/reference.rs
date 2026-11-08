// SPDX-License-Identifier: Apache-2.0
//! Bounded single-family D-140 fixture using real opaque-token and endpoint codecs.
//!
//! The caller supplies already verified password/proof/current Account facts and fresh random
//! credentials. This peer supplies no HTTP, password verification, durable storage or audit chain.

use std::collections::{BTreeMap, BTreeSet};

use super::{
    ACCOUNT_BROWSER_ACCESS_SECONDS, ACCOUNT_BROWSER_FAMILY_SECONDS, AccountBrowserAccessOperation,
    AccountBrowserAccessRequirement, AccountBrowserAccessToken, AccountBrowserCodecError,
    AccountBrowserLogoutRequest, AccountBrowserLogoutResponse, AccountBrowserOperation,
    AccountBrowserRefreshRequest, AccountBrowserRefreshResponse, AccountBrowserRefreshToken,
    AccountBrowserWriter, INITIAL_ACCOUNT_BROWSER_ACCESS_SCOPE,
};
use crate::auth::BrowserAuthTokenResponse;
use crate::{ApiContractError, ErrorCode, ProblemDetails};

/// One scripted transaction failure on the next eligible refresh/logout.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReferenceAccountBrowserFault {
    /// Confirmed storage/audit rollback before COMMIT.
    BeforeCommit,
    /// COMMIT rolled back but its result is unavailable to the caller.
    UnknownRollback,
    /// COMMIT succeeded but its acknowledgement is unavailable.
    UnknownCommitted,
    /// COMMIT succeeded and the network lost the successful response.
    LostResponse,
}

/// Content-free fixture errors; uncertain refresh never returns credentials.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ReferenceAccountBrowserError {
    /// Invalid bounded wire input.
    #[error("invalid Account browser request")]
    InvalidRequest,
    /// Complete request body exceeds the endpoint's byte bound.
    #[error("Account browser request too large")]
    TooLarge,
    /// Current identity, lifetime, token or trusted binding is unavailable.
    #[error("Account browser authentication required")]
    AuthenticationRequired,
    /// A verified proof id is empty, reused or exceeds the fixture bound.
    #[error("invalid Account browser proof")]
    InvalidProof,
    /// Confirmed precommit failure.
    #[error("Account browser storage unavailable")]
    StorageUnavailable,
    /// No confirmed result; refresh is non-retryable, logout permits explicit fresh-proof retry.
    #[error("Account browser commit outcome unknown")]
    CommitOutcomeUnknown,
    /// The successful response was not delivered.
    #[error("Account browser response lost")]
    ResponseLost,
}

impl ReferenceAccountBrowserError {
    /// Render existing registered failures; only logout permits explicit uncertain-COMMIT retry.
    /// # Errors
    /// Rejects an invalid problem instance. A lost response has no HTTP problem.
    pub fn problem(
        self,
        operation: AccountBrowserOperation,
        instance: &str,
    ) -> Result<Option<ProblemDetails>, ApiContractError> {
        let (status, code, changed, retryable) = match self {
            Self::InvalidRequest => (400, "auth.invalid_request", false, false),
            Self::TooLarge => (413, "auth.invalid_request", false, false),
            Self::AuthenticationRequired => (401, "auth.authentication_required", false, false),
            Self::InvalidProof => (400, "auth.invalid_dpop_proof", false, false),
            Self::StorageUnavailable => (503, "auth.storage_unavailable", false, true),
            Self::CommitOutcomeUnknown => (
                503,
                "auth.commit_outcome_unknown",
                true,
                operation == AccountBrowserOperation::Logout,
            ),
            Self::ResponseLost => return Ok(None),
        };
        ProblemDetails::new(
            ErrorCode::new(code)?,
            status,
            "Account browser operation was not confirmed",
            "Retain only the original pending operation and follow its explicit recovery rules.",
            instance,
            changed,
            retryable,
        )
        .map(Some)
    }
}

/// Independent fixture for one already password-authenticated family. Only digests are retained.
pub struct ReferenceAccountBrowserPeer {
    writer: AccountBrowserWriter,
    origin: String,
    jkt: String,
    generation: u64,
    current_generation: u64,
    account_active: bool,
    created_at: u64,
    expires_at: u64,
    revoked: bool,
    access: BTreeMap<[u8; 32], (u64, u64)>,
    refresh: [u8; 32],
    spent: BTreeSet<[u8; 32]>,
    proofs: BTreeSet<String>,
    events: u64,
    fault: Option<ReferenceAccountBrowserFault>,
}

impl std::fmt::Debug for ReferenceAccountBrowserPeer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("ReferenceAccountBrowserPeer").finish_non_exhaustive()
    }
}

impl ReferenceAccountBrowserPeer {
    /// Seed a confirmed login using externally verified facts and independently random tokens.
    /// The fixed ceiling cannot be supplied or widened by a caller.
    /// # Errors
    /// Rejects invalid origin/generation/JKT/time or expiry arithmetic overflow.
    pub fn new(
        writer: AccountBrowserWriter,
        origin: &str,
        jkt: &str,
        generation: u64,
        access: &AccountBrowserAccessToken,
        refresh: &AccountBrowserRefreshToken,
        now: u64,
    ) -> Result<Self, AccountBrowserCodecError> {
        scoplen_crypto::validate_server_origin(origin)
            .map_err(|_| AccountBrowserCodecError::Invalid)?;
        if generation == 0 || jkt.is_empty() || jkt.len() > 256 || now == 0 {
            return Err(AccountBrowserCodecError::Invalid);
        }
        let expires_at = now
            .checked_add(ACCOUNT_BROWSER_FAMILY_SECONDS)
            .ok_or(AccountBrowserCodecError::Invalid)?;
        Ok(Self {
            writer,
            origin: origin.into(),
            jkt: jkt.into(),
            generation,
            current_generation: generation,
            account_active: true,
            created_at: now,
            expires_at,
            revoked: false,
            access: BTreeMap::from([(
                access.digest(),
                (now, now + ACCOUNT_BROWSER_ACCESS_SECONDS),
            )]),
            refresh: refresh.digest(),
            spent: BTreeSet::new(),
            proofs: BTreeSet::new(),
            events: 1,
            fault: None,
        })
    }

    /// Script current Account/password facts; never a Device or Operator identity.
    pub fn set_current_account(&mut self, active: bool, generation: u64) {
        self.account_active = active;
        self.current_generation = generation;
    }

    /// Script one eligible atomic transaction or response failure.
    pub fn set_fault(&mut self, fault: ReferenceAccountBrowserFault) {
        self.fault = Some(fault);
    }

    /// Count atomic synthetic login/refresh/reuse-revocation/logout audit events.
    #[must_use]
    pub const fn events(&self) -> u64 {
        self.events
    }

    /// Check current authentication and this profile's operation ceiling after external proof verification.
    /// Current Organization membership/Cedar authorization remains entirely outside this peer.
    /// # Errors
    /// Rejects revoked/expired/current-state mismatch, proof replay or incorrect supplied Origin.
    pub fn authorize(
        &mut self,
        token: &AccountBrowserAccessToken,
        jkt: &str,
        origin: Option<&str>,
        operation: AccountBrowserAccessOperation,
        proof_id: &str,
        now: u64,
    ) -> Result<AccountBrowserWriter, ReferenceAccountBrowserError> {
        use ReferenceAccountBrowserError as Error;
        if self.revoked
            || !self.eligible(token, jkt, now)
            || origin.is_some_and(|origin| origin != self.origin)
            || (operation.http_method() != "GET" && origin != Some(self.origin.as_str()))
            || !matches!(operation.requirement(), AccountBrowserAccessRequirement::AnyScope(scopes) if scopes.iter().any(|scope| scope.is_present_in(INITIAL_ACCOUNT_BROWSER_ACCESS_SCOPE)))
        {
            return Err(Error::AuthenticationRequired);
        }
        self.claim_proof(proof_id)?;
        Ok(self.writer)
    }

    /// Exercise cookie-only fresh-proof rotation. New credentials are returned only after confirmation.
    /// The caller verifies the proof has no ath and generates both replacement tokens independently.
    /// # Errors
    /// Rejects malformed body, wrong current binding, spent-token reuse, proof replay or scripted faults.
    #[allow(clippy::too_many_arguments)] // Captured credential/proof bindings are deliberately explicit.
    pub fn rotate(
        &mut self,
        body: &[u8],
        refresh: &AccountBrowserRefreshToken,
        next_access: &AccountBrowserAccessToken,
        next_refresh: &AccountBrowserRefreshToken,
        jkt: &str,
        origin: &str,
        proof_id: &str,
        now: u64,
    ) -> Result<AccountBrowserRefreshResponse, ReferenceAccountBrowserError> {
        use ReferenceAccountBrowserError as Error;
        AccountBrowserRefreshRequest::from_json(body).map_err(Self::request_error)?;
        if self.revoked || !self.current(now) || jkt != self.jkt || origin != self.origin {
            return Err(Error::AuthenticationRequired);
        }
        self.claim_proof(proof_id)?;
        let digest = refresh.digest();
        if self.spent.contains(&digest) {
            let fault = self.fault.take();
            Self::before_commit(fault)?;
            self.revoked = true;
            self.events += 1;
            return Err(match fault {
                Some(ReferenceAccountBrowserFault::UnknownCommitted) => Error::CommitOutcomeUnknown,
                Some(ReferenceAccountBrowserFault::LostResponse) => Error::ResponseLost,
                _ => Error::AuthenticationRequired,
            });
        }
        if digest != self.refresh
            || self.spent.len() >= 4096
            || next_refresh.digest() == digest
            || self.spent.contains(&next_refresh.digest())
            || self.access.contains_key(&next_access.digest())
        {
            return Err(Error::AuthenticationRequired);
        }
        let expiry =
            now.checked_add(ACCOUNT_BROWSER_ACCESS_SECONDS).ok_or(Error::AuthenticationRequired)?;
        let fault = self.fault.take();
        Self::before_commit(fault)?;
        self.spent.insert(digest);
        self.refresh = next_refresh.digest();
        self.access.retain(|_, (_, expiry)| *expiry > now);
        self.access.insert(next_access.digest(), (now, expiry));
        self.events += 1;
        match fault {
            Some(ReferenceAccountBrowserFault::UnknownCommitted) => {
                Err(Error::CommitOutcomeUnknown)
            }
            Some(ReferenceAccountBrowserFault::LostResponse) => Err(Error::ResponseLost),
            _ => Ok(AccountBrowserRefreshResponse(BrowserAuthTokenResponse {
                access_token: next_access.as_str().into(),
                token_type: "DPoP".into(),
                expires_in: ACCOUNT_BROWSER_ACCESS_SECONDS,
                refresh_expires_in: self.expires_at - now,
            })),
        }
    }

    /// Terminate/confirm only this original access-bound family, ignoring every cookie.
    /// Already-revoked confirmation never returns a general authentication result.
    /// # Errors
    /// Rejects invalid body/current binding, expired access/family, replay or scripted faults.
    pub fn terminate(
        &mut self,
        body: &[u8],
        access: &AccountBrowserAccessToken,
        jkt: &str,
        origin: &str,
        proof_id: &str,
        now: u64,
    ) -> Result<AccountBrowserLogoutResponse, ReferenceAccountBrowserError> {
        use ReferenceAccountBrowserError as Error;
        AccountBrowserLogoutRequest::from_json(body).map_err(Self::request_error)?;
        if !self.eligible(access, jkt, now) || origin != self.origin {
            return Err(Error::AuthenticationRequired);
        }
        self.claim_proof(proof_id)?;
        let fault = self.fault.take();
        if self.revoked {
            return match fault {
                None => Ok(AccountBrowserLogoutResponse),
                Some(ReferenceAccountBrowserFault::LostResponse) => Err(Error::ResponseLost),
                _ => Err(Error::StorageUnavailable),
            };
        }
        if matches!(fault, Some(ReferenceAccountBrowserFault::BeforeCommit)) {
            return Err(Error::StorageUnavailable);
        }
        if matches!(fault, Some(ReferenceAccountBrowserFault::UnknownRollback)) {
            return Err(Error::CommitOutcomeUnknown);
        }
        self.revoked = true;
        self.events += 1;
        match fault {
            Some(ReferenceAccountBrowserFault::UnknownCommitted) => {
                Err(Error::CommitOutcomeUnknown)
            }
            Some(ReferenceAccountBrowserFault::LostResponse) => Err(Error::ResponseLost),
            _ => Ok(AccountBrowserLogoutResponse),
        }
    }

    fn current(&self, now: u64) -> bool {
        self.account_active
            && self.current_generation == self.generation
            && self.created_at <= now
            && now < self.expires_at
    }
    fn eligible(&self, token: &AccountBrowserAccessToken, jkt: &str, now: u64) -> bool {
        self.current(now)
            && jkt == self.jkt
            && self
                .access
                .get(&token.digest())
                .is_some_and(|(issued, expiry)| *issued <= now && now < *expiry)
    }
    fn claim_proof(&mut self, proof: &str) -> Result<(), ReferenceAccountBrowserError> {
        if proof.is_empty()
            || proof.len() > 256
            || self.proofs.len() >= 8192
            || !self.proofs.insert(proof.into())
        {
            return Err(ReferenceAccountBrowserError::InvalidProof);
        }
        Ok(())
    }
    fn before_commit(
        fault: Option<ReferenceAccountBrowserFault>,
    ) -> Result<(), ReferenceAccountBrowserError> {
        match fault {
            Some(ReferenceAccountBrowserFault::BeforeCommit) => {
                Err(ReferenceAccountBrowserError::StorageUnavailable)
            }
            Some(ReferenceAccountBrowserFault::UnknownRollback) => {
                Err(ReferenceAccountBrowserError::CommitOutcomeUnknown)
            }
            _ => Ok(()),
        }
    }
    fn request_error(error: AccountBrowserCodecError) -> ReferenceAccountBrowserError {
        if error == AccountBrowserCodecError::TooLarge {
            ReferenceAccountBrowserError::TooLarge
        } else {
            ReferenceAccountBrowserError::InvalidRequest
        }
    }
}
