// SPDX-License-Identifier: Apache-2.0
//! In-memory D-114 relay fixture with explicit external authentication/admission boundaries.
//! Never use this peer as a production authorization, audit, rate-limit or transaction store.

use scoplen_crypto::{DeviceCertificate, SecretBytes};
use uuid::Uuid;

use crate::{
    ErrorCode, ProblemDetails,
    pairing::{
        PairingCodecError, PairingCompleteRequest, PairingContext, PairingMessageAck,
        PairingMessageRequest, PairingReceipt, PairingSnapshot, PairingState,
    },
    sync::SyncAccountKeyBundleUpdate,
};

/// Caller identity supplied by the fixture's independently verified authentication boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReferencePairingActor {
    /// Capability possession, compared with constant-time secret equality.
    Responder(SecretBytes<32>),
    /// Existing principal; `authorized` represents current state, DPoP/replay and scope checks.
    Initiator {
        /// Verified current account.
        account_id: Uuid,
        /// Verified current device.
        device_id: Uuid,
        /// Recomputed on every call, including reads and completed replay.
        authorized: bool,
    },
}

/// A one-shot fault around the next actual state mutation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReferencePairingFault {
    /// Known failure before business-state mutation.
    BeforeMutation,
    /// Mutation committed but its successful reply is lost.
    AfterCommit,
}

/// Public failure semantics without submitted values.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ReferencePairingError {
    /// Invalid input syntax; no mutation.
    #[error("invalid pairing request")]
    InvalidRequest,
    /// Incoming payload exceeds the fixed contract budget.
    #[error("pairing request too large")]
    TooLarge,
    /// Unavailable capability, session, role or authorization.
    #[error("pairing denied")]
    Denied,
    /// Incompatible transcript, phase or approval.
    #[error("pairing conflict")]
    Conflict,
    /// Known precommit rollback.
    #[error("pairing storage unavailable")]
    StorageUnavailable,
    /// An attempted state change may have committed.
    #[error("pairing commit outcome unknown")]
    CommitOutcomeUnknown,
}

impl From<PairingCodecError> for ReferencePairingError {
    fn from(error: PairingCodecError) -> Self {
        match error {
            PairingCodecError::TooLarge(_) => Self::TooLarge,
            _ => Self::InvalidRequest,
        }
    }
}

impl ReferencePairingError {
    /// Render the registered bounded problem semantics for a synthetic HTTP adapter.
    ///
    /// # Errors
    /// Rejects an empty request instance id through the common problem validator.
    pub fn problem(&self, instance: &str) -> Result<ProblemDetails, crate::ApiContractError> {
        let (status, code, changed, retryable) = match self {
            Self::InvalidRequest => (400, "auth.invalid_request", false, false),
            Self::TooLarge => (413, "auth.invalid_request", false, false),
            Self::Denied => (401, "auth.pairing_denied", false, false),
            Self::Conflict => (409, "auth.pairing_conflict", false, false),
            Self::StorageUnavailable => (503, "auth.storage_unavailable", false, true),
            Self::CommitOutcomeUnknown => (503, "auth.commit_outcome_unknown", true, false),
        };
        ProblemDetails::new(
            ErrorCode::new(code)?,
            status,
            "Pairing request failed",
            "Retain the pending identity and inspect the authenticated pairing state before another action.",
            instance,
            changed,
            retryable,
        )
    }
}

/// One finite relay session, used by independently built consumer tests.
#[derive(Debug)]
pub struct ReferencePairingPeer {
    snapshot: PairingSnapshot,
    token: SecretBytes<32>,
    account_id: Option<Uuid>,
    expires_at_ms: u64,
    retained_until_ms: u64,
    fingerprint: Option<[u8; 32]>,
    fault: Option<ReferencePairingFault>,
}

impl ReferencePairingPeer {
    /// Create an unclaimed fixture; callers supply a trusted synthetic wall-clock expiry.
    ///
    /// # Errors
    /// Rejects malformed or already claimed context.
    pub fn new(
        context: PairingContext,
        token: SecretBytes<32>,
        expires_at_ms: u64,
    ) -> Result<Self, ReferencePairingError> {
        let snapshot = PairingSnapshot {
            context,
            state: PairingState::Waiting,
            messages: vec![],
            receipt: None,
        };
        snapshot.validate()?;
        Ok(Self {
            snapshot,
            token,
            account_id: None,
            expires_at_ms,
            retained_until_ms: expires_at_ms.saturating_add(86_400_000),
            fingerprint: None,
            fault: None,
        })
    }

    /// Inject a one-shot known rollback or lost commit acknowledgement.
    pub const fn inject_fault(&mut self, fault: ReferencePairingFault) {
        self.fault = Some(fault);
    }

    /// Claim one account/device. Another device cannot take over, even in the same account.
    ///
    /// # Errors
    /// Rejects unauthorized callers, unavailable/expired sessions and incompatible phase.
    pub fn claim(
        &mut self,
        actor: &ReferencePairingActor,
        now_ms: u64,
    ) -> Result<PairingContext, ReferencePairingError> {
        self.expire(now_ms);
        let ReferencePairingActor::Initiator { account_id, device_id, authorized: true } = actor
        else {
            return Err(ReferencePairingError::Denied);
        };
        if scoplen_model::validate_uuid_v7(*account_id).is_err()
            || scoplen_model::validate_uuid_v7(*device_id).is_err()
        {
            return Err(ReferencePairingError::Denied);
        }
        if self.snapshot.state.is_terminal() {
            return Err(ReferencePairingError::Denied);
        }
        if let Some(bound) = self.snapshot.context.initiator_device_id {
            return if bound == *device_id && self.account_id == Some(*account_id) {
                Ok(self.snapshot.context.clone())
            } else {
                Err(ReferencePairingError::Denied)
            };
        }
        let fault = self.before_mutation()?;
        self.snapshot.context.initiator_device_id = Some(*device_id);
        self.account_id = Some(*account_id);
        self.snapshot.state = PairingState::Exchanging;
        Self::after_mutation(fault)?;
        Ok(self.snapshot.context.clone())
    }

    /// Read a consistent finite snapshot after rechecking caller authorization.
    ///
    /// # Errors
    /// Rejects unavailable/retired sessions and invalid current role credentials.
    pub fn read(
        &mut self,
        actor: &ReferencePairingActor,
        now_ms: u64,
    ) -> Result<PairingSnapshot, ReferencePairingError> {
        self.authorize(actor, now_ms)?;
        Ok(self.snapshot.clone())
    }

    /// Accept the next role-owned slot or an exact immutable retransmission.
    ///
    /// # Errors
    /// Rejects invalid payloads, wrong role/order, replacement bytes and expired sessions.
    pub fn message(
        &mut self,
        actor: &ReferencePairingActor,
        message: PairingMessageRequest,
        now_ms: u64,
    ) -> Result<PairingMessageAck, ReferencePairingError> {
        self.authorize(actor, now_ms)?;
        message.validate()?;
        let role = match actor {
            ReferencePairingActor::Responder(_) => crate::pairing::PairingRole::Responder,
            ReferencePairingActor::Initiator { .. } => crate::pairing::PairingRole::Initiator,
        };
        if message.step.role() != role {
            return Err(ReferencePairingError::Denied);
        }
        if self.snapshot.state == PairingState::Expired {
            return Err(ReferencePairingError::Denied);
        }
        if self.snapshot.state.is_terminal() {
            return Err(ReferencePairingError::Conflict);
        }
        if let Some(existing) = self.snapshot.messages.get(message.step.index()) {
            return if *existing == message {
                Ok(PairingMessageAck { step: message.step })
            } else {
                Err(ReferencePairingError::Conflict)
            };
        }
        if self.snapshot.context.initiator_device_id.is_none()
            || message.step.index() != self.snapshot.messages.len()
        {
            return Err(ReferencePairingError::Conflict);
        }
        let fault = self.before_mutation()?;
        let step = message.step;
        self.snapshot.messages.push(message);
        if self.snapshot.messages.len() == 7 {
            self.snapshot.state = PairingState::Ready;
        }
        Self::after_mutation(fault)?;
        Ok(PairingMessageAck { step })
    }

    /// Complete once through an independently supplied cryptographic/admission verifier.
    ///
    /// The callback checks account signatures, context-bound possession, full recipients,
    /// current revision and projected capacities; a denial leaves this peer unchanged.
    ///
    /// # Errors
    /// Rejects invalid role/phase/bytes, admission failure, conflicting replay or scripted faults.
    pub fn complete<F>(
        &mut self,
        actor: &ReferencePairingActor,
        request: &PairingCompleteRequest,
        now_ms: u64,
        verify: F,
    ) -> Result<PairingReceipt, ReferencePairingError>
    where
        F: FnOnce(
            &PairingContext,
            &[u8],
            &PairingCompleteRequest,
        ) -> Result<PairingReceipt, ReferencePairingError>,
    {
        self.authorize(actor, now_ms)?;
        if !matches!(actor, ReferencePairingActor::Initiator { .. }) {
            return Err(ReferencePairingError::Denied);
        }
        if self.snapshot.state == PairingState::Expired {
            return Err(ReferencePairingError::Denied);
        }
        if self.snapshot.state == PairingState::Completed {
            let fingerprint = request.approval_fingerprint()?;
            return if self.fingerprint == Some(fingerprint) {
                self.snapshot.receipt.clone().ok_or(ReferencePairingError::Conflict)
            } else {
                Err(ReferencePairingError::Conflict)
            };
        }
        if self.snapshot.state != PairingState::Ready {
            return Err(ReferencePairingError::Conflict);
        }
        let fingerprint = request.approval_fingerprint()?;
        if self.snapshot.messages[6].payload != request.new_device_signature {
            return Err(ReferencePairingError::InvalidRequest);
        }
        let certificate = DeviceCertificate::decode(&request.device_certificate)
            .map_err(|_| ReferencePairingError::InvalidRequest)?;
        let update = SyncAccountKeyBundleUpdate::from_cbor(&request.key_bundle_update)
            .map_err(|_| ReferencePairingError::InvalidRequest)?;
        if Some(certificate.account_id) != self.account_id
            || certificate.device_id != self.snapshot.context.responder_device_id
        {
            return Err(ReferencePairingError::InvalidRequest);
        }
        let receipt = verify(&self.snapshot.context, &self.snapshot.messages[5].payload, request)?;
        receipt.validate()?;
        if Some(receipt.account_id) != self.account_id
            || receipt.device_id != self.snapshot.context.responder_device_id
            || receipt.revision != update.revision
        {
            return Err(ReferencePairingError::InvalidRequest);
        }
        let fault = self.before_mutation()?;
        self.fingerprint = Some(fingerprint);
        self.snapshot.receipt = Some(receipt.clone());
        self.snapshot.state = PairingState::Completed;
        self.snapshot.messages.clear();
        self.retained_until_ms = now_ms.saturating_add(86_400_000);
        Self::after_mutation(fault)?;
        Ok(receipt)
    }

    /// Cancel once; a repeated cancellation has no new state mutation.
    ///
    /// # Errors
    /// Rejects unauthorized/expired sessions, completed admission and scripted faults.
    pub fn cancel(
        &mut self,
        actor: &ReferencePairingActor,
        now_ms: u64,
    ) -> Result<(), ReferencePairingError> {
        self.authorize(actor, now_ms)?;
        if self.snapshot.state == PairingState::Cancelled {
            return Ok(());
        }
        if self.snapshot.state == PairingState::Completed {
            return Err(ReferencePairingError::Conflict);
        }
        if self.snapshot.state == PairingState::Expired {
            return Err(ReferencePairingError::Denied);
        }
        let fault = self.before_mutation()?;
        self.snapshot.state = PairingState::Cancelled;
        self.snapshot.messages.clear();
        Self::after_mutation(fault)
    }

    fn expire(&mut self, now_ms: u64) {
        if !self.snapshot.state.is_terminal() && now_ms >= self.expires_at_ms {
            self.snapshot.state = PairingState::Expired;
            self.snapshot.messages.clear();
        }
    }

    fn authorize(
        &mut self,
        actor: &ReferencePairingActor,
        now_ms: u64,
    ) -> Result<(), ReferencePairingError> {
        self.expire(now_ms);
        if now_ms >= self.retained_until_ms {
            return Err(ReferencePairingError::Denied);
        }
        let valid = match actor {
            ReferencePairingActor::Responder(token) => token == &self.token,
            ReferencePairingActor::Initiator { account_id, device_id, authorized } => {
                *authorized
                    && Some(*account_id) == self.account_id
                    && Some(*device_id) == self.snapshot.context.initiator_device_id
            }
        };
        if valid { Ok(()) } else { Err(ReferencePairingError::Denied) }
    }

    fn before_mutation(&mut self) -> Result<Option<ReferencePairingFault>, ReferencePairingError> {
        let fault = self.fault.take();
        if fault == Some(ReferencePairingFault::BeforeMutation) {
            return Err(ReferencePairingError::StorageUnavailable);
        }
        Ok(fault)
    }

    fn after_mutation(fault: Option<ReferencePairingFault>) -> Result<(), ReferencePairingError> {
        if fault == Some(ReferencePairingFault::AfterCommit) {
            Err(ReferencePairingError::CommitOutcomeUnknown)
        } else {
            Ok(())
        }
    }
}
