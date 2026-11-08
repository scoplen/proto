// SPDX-License-Identifier: Apache-2.0
//! Narrow D-141 fixture peer for issuance receipts and atomic membership/serial revocation.
//!
//! Every actor, permission and seed is a trusted fixture fact, not untrusted request input.
//! This peer does not authenticate, sign certificates, encode KRLs, evaluate policy, implement
//! team lifecycle endpoints, or supply HTTP, durable storage, `DPoP` admission or an audit chain.

use std::collections::{BTreeMap, BTreeSet};

use uuid::Uuid;

use crate::{ApiContractError, ErrorCode, ProblemDetails, certificate::CertificateIssuanceRequest};

/// Frozen per-CA outstanding-issuance ceiling, including revoked unexpired certificates.
pub const CERTIFICATE_REFERENCE_ISSUANCE_LIMIT: usize = 100_000;
const RECEIPT_SECONDS: u64 = 86_400;

/// Externally verified fixture facts; these fields perform no authentication or policy checks.
/// Independent admission facts stay separate so fixtures can verify rejection priority.
#[derive(Clone)]
#[allow(clippy::struct_excessive_bools)]
pub struct CertificateReferenceActor {
    /// Captured trusted origin; must equal the peer's configured fixture origin.
    pub origin: String,
    /// Authenticated Account selected by the fixture adapter.
    pub account: Uuid,
    /// Current enrolled Device selected by the fixture adapter.
    pub device: Uuid,
    /// Fixture confirmation of current Account/Device/key authority.
    pub current_identity: bool,
    /// Fixture confirmation of the exact `certificates:issue` permission.
    pub issue_scope: bool,
    /// Fixture confirmation of the exact `ca:read` permission.
    pub ca_read_scope: bool,
    /// Fixture confirmation of all current target/read/connect and TTL policy requirements.
    pub targets_authorized: bool,
}

/// The membership state supplied by an existing, independently authorized lifecycle fixture.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CertificateReferenceMemberStatus {
    /// Current membership grants access, subject to the fixture's per-target authorization.
    Active,
    /// Suspended membership grants no access.
    Suspended,
    /// Removed membership grants no access; rejoin needs separate trusted authorization.
    Removed,
}

/// Issuance metadata only; this is not a signed or usable SSH certificate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CertificateReferenceIssued {
    /// Owning Organization.
    pub organization: Uuid,
    /// Exact issuing CA.
    pub authority: Uuid,
    /// Account receiving the issuance.
    pub account: Uuid,
    /// Device receiving the issuance.
    pub device: Uuid,
    /// Positive serial allocated once under the modeled authority transaction.
    pub serial: u64,
    /// Authorized fixture expiry; the fixture has already checked the request TTL policy.
    pub valid_before: u64,
}

/// Current CA-bound KRL state; encoding and OpenSSH interoperability are separate codec tests.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CertificateReferenceSnapshot {
    /// Owning Organization.
    pub organization: Uuid,
    /// Exact CA, including for an empty snapshot.
    pub authority: Uuid,
    /// Persisted positive version, changed only when the effective serial set changes.
    pub version: u64,
    /// Generation time retained unchanged by reads and no-ops.
    pub generated_at: u64,
    /// Sorted unique serials that were unexpired when this snapshot was generated.
    pub revoked_serials: Vec<u64>,
}

/// One scripted transaction/response fault, consumed by the next actual mutation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CertificateReferenceFault {
    /// Confirmed precommit rollback, including a mandatory-audit failure.
    Rollback,
    /// No commit occurred, but its acknowledgement is uncertain.
    UnknownRollback,
    /// State committed, but its acknowledgement is uncertain.
    UnknownCommitted,
    /// State committed, but no response reached the caller.
    LostResponse,
}

/// Content-free outcomes of the narrow fixture peer.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum CertificateReferenceError {
    /// Invalid typed request or fixture seed.
    #[error("invalid certificate request")]
    InvalidRequest,
    /// The trusted fixture does not confirm a current Account/Device identity.
    #[error("certificate authentication required")]
    AuthenticationRequired,
    /// Current scope, origin, target authority or lifecycle authorization is absent.
    #[error("certificate operation denied")]
    Denied,
    /// Unknown/foreign CA, unavailable Organization or inactive/missing membership.
    #[error("organization not found")]
    NotFound,
    /// An operation key is already bound to different original request context.
    #[error("certificate receipt conflicts")]
    Conflict,
    /// The strictly matched original receipt's serial has been revoked.
    #[error("certificate revoked")]
    Revoked,
    /// This CA already has the maximum number of unexpired issued certificates.
    #[error("certificate issuance quota exceeded")]
    QuotaExceeded,
    /// Confirmed rollback or inability to validate a complete result.
    #[error("certificate storage unavailable")]
    StorageUnavailable,
    /// Issuance may have committed; only original-key/body confirmation is eligible.
    #[error("certificate issuance commit outcome unknown")]
    CommitOutcomeUnknown,
    /// Lifecycle update may have committed; refresh/review rather than automatically replay.
    #[error("membership update commit outcome unknown")]
    UpdateCommitOutcomeUnknown,
    /// No HTTP problem was delivered.
    #[error("certificate response lost")]
    ResponseLost,
}

impl CertificateReferenceError {
    /// Produce the frozen classification, or no problem when the response was lost.
    /// # Errors
    /// Rejects an invalid problem instance through the public problem validator.
    pub fn problem(self, instance: &str) -> Result<Option<ProblemDetails>, ApiContractError> {
        let (status, code, changed, retryable, detail) = match self {
            Self::InvalidRequest => (
                400,
                "certificate.invalid_request",
                false,
                false,
                "The request is invalid. No certificate was issued. Correct the request before trying again.",
            ),
            Self::AuthenticationRequired => (
                401,
                "auth.authentication_required",
                false,
                false,
                "Current Account and Device authority could not be verified. Authenticate again.",
            ),
            Self::Denied => (
                403,
                "policy.denied",
                false,
                false,
                "Current authority does not permit this operation. Review access before trying again.",
            ),
            Self::NotFound => (
                404,
                "organization.not_found",
                false,
                false,
                "The team or certificate authority is unavailable. Refresh current membership.",
            ),
            Self::Conflict => (
                409,
                "organization.conflict",
                false,
                false,
                "The operation key conflicts with its original request. Preserve the original operation and review it.",
            ),
            Self::Revoked => (
                409,
                "certificate.revoked",
                false,
                false,
                "The original certificate was revoked. This confirmation issued no new certificate. Review access and explicitly start a new connection.",
            ),
            Self::QuotaExceeded => (
                413,
                "certificate.quota_exceeded",
                false,
                false,
                "The authority has reached its unexpired issuance limit. No new certificate was issued. Wait for certificates to expire before explicitly starting a new connection.",
            ),
            Self::StorageUnavailable => (
                503,
                "organization.storage_unavailable",
                false,
                true,
                "The operation could not be confirmed. Preserve its original request and retry with fresh authority.",
            ),
            Self::CommitOutcomeUnknown => (
                503,
                "organization.commit_outcome_unknown",
                true,
                true,
                "Issuance may have committed. Explicitly confirm only the original key and payload within the original receipt window.",
            ),
            Self::UpdateCommitOutcomeUnknown => (
                503,
                "organization.commit_outcome_unknown",
                true,
                false,
                "The membership update may have committed. Refresh current state and review another explicit action.",
            ),
            Self::ResponseLost => return Ok(None),
        };
        ProblemDetails::new(
            ErrorCode::new(code)?,
            status,
            "Certificate reference outcome",
            detail,
            instance,
            changed,
            retryable,
        )
        .map(Some)
    }
}

/// Internal-fixture dissolution hook outcome, without HTTP or receipt semantics.
///
/// The separate team reference owns the actual receipt-backed dissolution response contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum CertificateReferenceDissolutionError {
    /// Trusted fixture authority or candidate validation rejected the transaction.
    #[error("certificate dissolution fixture rejected")]
    Rejected(#[from] CertificateReferenceError),
    /// Confirmed rollback published none of the candidate state.
    #[error("certificate dissolution fixture rolled back")]
    RolledBack,
    /// The fixture cannot establish whether the transaction committed.
    #[error("certificate dissolution fixture commit outcome unknown")]
    CommitOutcomeUnknown,
    /// The state committed but the fixture lost its response.
    #[error("certificate dissolution fixture response lost")]
    ResponseLost,
}

enum TransactionError {
    RolledBack,
    Unknown,
    ResponseLost,
}

impl TransactionError {
    fn operation_error(self, issuance: bool) -> CertificateReferenceError {
        match self {
            Self::RolledBack => CertificateReferenceError::StorageUnavailable,
            Self::Unknown if issuance => CertificateReferenceError::CommitOutcomeUnknown,
            Self::Unknown => CertificateReferenceError::UpdateCommitOutcomeUnknown,
            Self::ResponseLost => CertificateReferenceError::ResponseLost,
        }
    }
}

impl From<TransactionError> for CertificateReferenceDissolutionError {
    fn from(error: TransactionError) -> Self {
        match error {
            TransactionError::RolledBack => Self::RolledBack,
            TransactionError::Unknown => Self::CommitOutcomeUnknown,
            TransactionError::ResponseLost => Self::ResponseLost,
        }
    }
}

#[derive(Clone)]
struct Receipt {
    organization: Uuid,
    authority: Uuid,
    device: Uuid,
    canonical_body: Vec<u8>,
    expires_at: u64,
    issued: CertificateReferenceIssued,
}

#[derive(Clone)]
struct Team {
    authority: Uuid,
    members: BTreeMap<Uuid, CertificateReferenceMemberStatus>,
    dissolved: bool,
    revision: u64,
    last_serial: u64,
    issued: BTreeMap<u64, CertificateReferenceIssued>,
    // Retained independently of the effective, expiry-filtered public snapshot.
    revoked: BTreeSet<u64>,
    snapshot: CertificateReferenceSnapshot,
}

/// In-memory fixture restart image, not serialized or durable production storage.
#[derive(Clone)]
pub struct CertificateReferenceImage {
    origin: String,
    teams: BTreeMap<Uuid, Team>,
    receipts: BTreeMap<(Uuid, Uuid), Receipt>,
    audit_events: u64,
}

/// Small trusted-fixture peer for D-141; there is one initial CA per Organization.
pub struct CertificateReferencePeer {
    image: CertificateReferenceImage,
    fault: Option<CertificateReferenceFault>,
}

impl CertificateReferencePeer {
    /// Start an empty peer with an externally validated canonical fixture origin.
    #[must_use]
    pub fn new(origin: &str) -> Self {
        Self {
            image: CertificateReferenceImage {
                origin: origin.to_owned(),
                teams: BTreeMap::new(),
                receipts: BTreeMap::new(),
                audit_events: 0,
            },
            fault: None,
        }
    }

    /// Capture complete in-memory fixture state; faults are intentionally not restart state.
    #[must_use]
    pub fn image(&self) -> CertificateReferenceImage {
        self.image.clone()
    }

    /// Restore only an image captured by this fixture; this is not an untrusted decoder.
    #[must_use]
    pub fn from_image(image: CertificateReferenceImage) -> Self {
        Self { image, fault: None }
    }

    /// Seed one trusted fixture CA and its version-one empty snapshot, without production audit.
    /// # Errors
    /// Rejects duplicate Organizations or invalid fixture identifiers/time.
    pub fn add_ca(
        &mut self,
        organization: Uuid,
        authority: Uuid,
        now: u64,
    ) -> Result<(), CertificateReferenceError> {
        valid_ids(&[organization, authority])?;
        if now == 0 || self.image.teams.contains_key(&organization) {
            return Err(CertificateReferenceError::InvalidRequest);
        }
        self.image.teams.insert(
            organization,
            Team {
                authority,
                members: BTreeMap::new(),
                dissolved: false,
                revision: 1,
                last_serial: 0,
                issued: BTreeMap::new(),
                revoked: BTreeSet::new(),
                snapshot: CertificateReferenceSnapshot {
                    organization,
                    authority,
                    version: 1,
                    generated_at: now,
                    revoked_serials: Vec::new(),
                },
            },
        );
        Ok(())
    }

    /// Seed a previously absent trusted fixture membership, not a lifecycle operation.
    /// # Errors
    /// Rejects invalid identifiers, unknown teams and replacement of existing membership.
    pub fn set_initial_member(
        &mut self,
        organization: Uuid,
        account: Uuid,
        status: CertificateReferenceMemberStatus,
    ) -> Result<(), CertificateReferenceError> {
        valid_ids(&[organization, account])?;
        let team =
            self.image.teams.get_mut(&organization).ok_or(CertificateReferenceError::NotFound)?;
        if team.members.contains_key(&account) {
            return Err(CertificateReferenceError::InvalidRequest);
        }
        team.members.insert(account, status);
        Ok(())
    }

    /// Seed verified issuance metadata for bounded pressure tests, without a receipt or audit.
    /// # Errors
    /// Rejects invalid/duplicate serials, identifiers, expiry or CA ownership.
    pub fn seed_issued(
        &mut self,
        issued: CertificateReferenceIssued,
    ) -> Result<(), CertificateReferenceError> {
        valid_ids(&[issued.organization, issued.authority, issued.account, issued.device])?;
        let team = self
            .image
            .teams
            .get_mut(&issued.organization)
            .ok_or(CertificateReferenceError::NotFound)?;
        if team.authority != issued.authority
            || issued.serial == 0
            || issued.valid_before == 0
            || team.issued.contains_key(&issued.serial)
        {
            return Err(CertificateReferenceError::InvalidRequest);
        }
        team.last_serial = team.last_serial.max(issued.serial);
        team.issued.insert(issued.serial, issued);
        Ok(())
    }

    /// Script the next actual mutation's transaction/response result.
    pub fn set_fault(&mut self, fault: CertificateReferenceFault) {
        self.fault = Some(fault);
    }

    /// Count modeled atomic business audit events; this is not a production audit chain.
    #[must_use]
    pub fn audit_events(&self) -> u64 {
        self.image.audit_events
    }

    /// Inspect trusted fixture counters without implying public access authority.
    #[must_use]
    pub fn counters(&self, organization: Uuid) -> Option<(u64, u64, usize)> {
        self.image
            .teams
            .get(&organization)
            .map(|team| (team.last_serial, team.revision, team.issued.len()))
    }

    /// Inspect persisted state for trusted fixture assertions, including after dissolution.
    /// This bypasses request authority and must never be exposed as a public reader.
    #[must_use]
    pub fn inspect_snapshot(&self, organization: Uuid) -> Option<CertificateReferenceSnapshot> {
        self.image.teams.get(&organization).map(|team| team.snapshot.clone())
    }

    fn identity(&self, actor: &CertificateReferenceActor) -> Result<(), CertificateReferenceError> {
        if !actor.current_identity {
            return Err(CertificateReferenceError::AuthenticationRequired);
        }
        if actor.origin != self.image.origin {
            return Err(CertificateReferenceError::Denied);
        }
        Ok(())
    }

    fn team(
        &self,
        actor: &CertificateReferenceActor,
        organization: Uuid,
        authority: Uuid,
    ) -> Result<&Team, CertificateReferenceError> {
        let team = self.image.teams.get(&organization).filter(|team| {
            team.authority == authority
                && !team.dissolved
                && team.members.get(&actor.account)
                    == Some(&CertificateReferenceMemberStatus::Active)
        });
        team.ok_or(CertificateReferenceError::NotFound)
    }

    /// Model fixed POST issuance after trusted fixture authentication and target authorization.
    /// # Errors
    /// Preserves current-authority priority, exact receipt binding, revoked termination, capacity
    /// and scripted atomic failures. No SSH certificate or signer is created.
    #[allow(clippy::too_many_arguments)]
    pub fn issue(
        &mut self,
        actor: &CertificateReferenceActor,
        organization: Uuid,
        authority: Uuid,
        key: Uuid,
        request: &CertificateIssuanceRequest,
        now: u64,
    ) -> Result<CertificateReferenceIssued, CertificateReferenceError> {
        self.identity(actor)?;
        if !actor.issue_scope {
            return Err(CertificateReferenceError::Denied);
        }
        let team = self.team(actor, organization, authority)?;
        if !actor.targets_authorized {
            return Err(CertificateReferenceError::Denied);
        }
        valid_ids(&[actor.account, actor.device, key])?;
        let body = request.to_json().map_err(|_| CertificateReferenceError::InvalidRequest)?;
        if now == 0 {
            return Err(CertificateReferenceError::InvalidRequest);
        }
        if let Some(receipt) = self
            .image
            .receipts
            .get(&(actor.account, key))
            .filter(|receipt| now < receipt.expires_at)
        {
            if receipt.organization != organization
                || receipt.authority != authority
                || receipt.device != actor.device
                || receipt.canonical_body != body
            {
                return Err(CertificateReferenceError::Conflict);
            }
            if team.revoked.contains(&receipt.issued.serial) {
                return Err(CertificateReferenceError::Revoked);
            }
            return Ok(receipt.issued.clone());
        }
        if team.issued.values().filter(|issued| issued.valid_before > now).count()
            >= CERTIFICATE_REFERENCE_ISSUANCE_LIMIT
        {
            return Err(CertificateReferenceError::QuotaExceeded);
        }
        let mut next = team.clone();
        let serial =
            next.last_serial.checked_add(1).ok_or(CertificateReferenceError::StorageUnavailable)?;
        let issued = CertificateReferenceIssued {
            organization,
            authority,
            account: actor.account,
            device: actor.device,
            serial,
            valid_before: now
                .checked_add(u64::from(request.ttl_seconds))
                .ok_or(CertificateReferenceError::InvalidRequest)?,
        };
        let receipt = Receipt {
            organization,
            authority,
            device: actor.device,
            canonical_body: body,
            expires_at: now
                .checked_add(RECEIPT_SECONDS)
                .ok_or(CertificateReferenceError::InvalidRequest)?,
            issued: issued.clone(),
        };
        next.last_serial = serial;
        next.issued.insert(serial, issued.clone());
        self.commit(organization, next, Some(((actor.account, key), receipt)))
            .map_err(|error| error.operation_error(true))?;
        Ok(issued)
    }

    /// Model an already-authorized membership update, including restore/rejoin.
    /// `permitted` includes external manager/self-leave, `ETag` and last-Owner checks.
    /// # Errors
    /// Rejects current identity/membership or fixture permission before changing any state.
    #[allow(clippy::too_many_arguments)]
    pub fn change_member(
        &mut self,
        actor: &CertificateReferenceActor,
        organization: Uuid,
        authority: Uuid,
        account: Uuid,
        status: CertificateReferenceMemberStatus,
        permitted: bool,
        now: u64,
    ) -> Result<(), CertificateReferenceError> {
        self.identity(actor)?;
        let team = self.team(actor, organization, authority)?;
        if !permitted {
            return Err(CertificateReferenceError::Denied);
        }
        let current = team.members.get(&account).ok_or(CertificateReferenceError::NotFound)?;
        if current == &status {
            return Ok(());
        }
        let mut next = team.clone();
        next.members.insert(account, status);
        if status != CertificateReferenceMemberStatus::Active {
            next.revoked.extend(
                next.issued
                    .values()
                    .filter(|issued| issued.account == account && issued.valid_before > now)
                    .map(|issued| issued.serial),
            );
        }
        refresh_snapshot(&mut next, now)?;
        next.revision =
            next.revision.checked_add(1).ok_or(CertificateReferenceError::StorageUnavailable)?;
        self.commit(organization, next, None).map_err(|error| error.operation_error(false))
    }

    /// Model the KRL portion of an already-authorized existing dissolution transaction.
    /// Historical dissolution receipt handling belongs to the separate team reference.
    /// This trusted transaction hook has no HTTP or receipt-backed outcome mapping.
    /// # Errors
    /// Rejects current identity/membership or fixture permission before the atomic transition.
    pub fn dissolve(
        &mut self,
        actor: &CertificateReferenceActor,
        organization: Uuid,
        authority: Uuid,
        permitted: bool,
        now: u64,
    ) -> Result<(), CertificateReferenceDissolutionError> {
        self.identity(actor)?;
        let team = self.team(actor, organization, authority)?;
        if !permitted {
            return Err(CertificateReferenceError::Denied.into());
        }
        let mut next = team.clone();
        next.dissolved = true;
        next.members
            .values_mut()
            .for_each(|status| *status = CertificateReferenceMemberStatus::Removed);
        next.revoked.extend(
            next.issued
                .values()
                .filter(|issued| issued.valid_before > now)
                .map(|issued| issued.serial),
        );
        refresh_snapshot(&mut next, now)?;
        next.revision =
            next.revision.checked_add(1).ok_or(CertificateReferenceError::StorageUnavailable)?;
        self.commit(organization, next, None).map_err(Into::into)
    }

    /// Read the complete persisted fixture snapshot with current native CA-read authority.
    /// # Errors
    /// Rejects identity, scope and tenant/membership failures without changing snapshot state.
    pub fn snapshot(
        &self,
        actor: &CertificateReferenceActor,
        organization: Uuid,
        authority: Uuid,
    ) -> Result<CertificateReferenceSnapshot, CertificateReferenceError> {
        self.identity(actor)?;
        if !actor.ca_read_scope {
            return Err(CertificateReferenceError::Denied);
        }
        Ok(self.team(actor, organization, authority)?.snapshot.clone())
    }

    fn commit(
        &mut self,
        organization: Uuid,
        next: Team,
        receipt: Option<((Uuid, Uuid), Receipt)>,
    ) -> Result<(), TransactionError> {
        let audit = self.image.audit_events.checked_add(1).ok_or(TransactionError::RolledBack)?;
        let fault = self.fault.take();
        match fault {
            Some(CertificateReferenceFault::Rollback) => return Err(TransactionError::RolledBack),
            Some(CertificateReferenceFault::UnknownRollback) => {
                return Err(TransactionError::Unknown);
            }
            _ => {}
        }
        self.image.teams.insert(organization, next);
        if let Some((key, receipt)) = receipt {
            self.image.receipts.insert(key, receipt);
        }
        self.image.audit_events = audit;
        match fault {
            Some(CertificateReferenceFault::UnknownCommitted) => Err(TransactionError::Unknown),
            Some(CertificateReferenceFault::LostResponse) => Err(TransactionError::ResponseLost),
            _ => Ok(()),
        }
    }
}

fn valid_ids(ids: &[Uuid]) -> Result<(), CertificateReferenceError> {
    for id in ids {
        scoplen_model::validate_uuid_v7(*id)
            .map_err(|_| CertificateReferenceError::InvalidRequest)?;
    }
    Ok(())
}

fn refresh_snapshot(team: &mut Team, now: u64) -> Result<(), CertificateReferenceError> {
    if now == 0 {
        return Err(CertificateReferenceError::InvalidRequest);
    }
    let serials: Vec<_> = team
        .revoked
        .iter()
        .copied()
        .filter(|serial| team.issued.get(serial).is_some_and(|issued| issued.valid_before > now))
        .collect();
    if serials.len() > CERTIFICATE_REFERENCE_ISSUANCE_LIMIT {
        return Err(CertificateReferenceError::StorageUnavailable);
    }
    if serials != team.snapshot.revoked_serials {
        team.snapshot.version = team
            .snapshot
            .version
            .checked_add(1)
            .ok_or(CertificateReferenceError::StorageUnavailable)?;
        team.snapshot.generated_at = now;
        team.snapshot.revoked_serials = serials;
    }
    Ok(())
}
