// SPDX-License-Identifier: Apache-2.0
//! D-114 bounded pairing transport. Syntax is not account admission or channel authentication.

use std::fmt;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use scoplen_crypto::{DeviceCertificate, SecretBytes, SecretVec, validate_server_origin};
use scoplen_model::validate_uuid_v7;
use serde::Serialize;
use serde_json::{Map, Value};
use thiserror::Error;
use uuid::Uuid;

use crate::{certificate::valid_utc_timestamp, request_wire, sync::SyncAccountKeyBundleUpdate};

/// Complete create/claim or small message/acknowledgement budget.
pub const MAX_PAIRING_SMALL_BYTES: usize = 256;
/// Complete create/claim response or problem budget.
pub const MAX_PAIRING_CONTEXT_BYTES: usize = 4_096;
/// New-device encrypted frame bound, including nonce and tag.
pub const MAX_PAIRING_NEW_DEVICE_FRAME_BYTES: usize = 131_072;
/// Complete encoded new-device message request budget.
pub const MAX_PAIRING_NEW_DEVICE_MESSAGE_BYTES: usize = 196_608;
/// Handoff encrypted frame bound, preserving the full four-MiB Personal-key inner budget.
pub const MAX_PAIRING_HANDOFF_FRAME_BYTES: usize = 4_456_448;
/// Complete handoff or approval JSON request budget.
pub const MAX_PAIRING_LARGE_REQUEST_BYTES: usize = 6_291_456;
/// Complete snapshot response budget, including ignored extensions.
pub const MAX_PAIRING_SNAPSHOT_BYTES: usize = 8_388_608;
/// Maximum decoded certificate bytes.
pub const MAX_PAIRING_CERTIFICATE_BYTES: usize = 65_536;
/// Maximum decoded signed K-4 update bytes.
pub const MAX_PAIRING_KEY_UPDATE_BYTES: usize = 4_194_304;

/// Nominal source policy for pairing reads.
pub const PAIRING_READ_RATE_LIMIT_POLICY: &str = "\"pairing\";q=120;w=60";
/// Nominal source policy for every pairing mutation.
pub const PAIRING_MUTATION_RATE_LIMIT_POLICY: &str = "\"pairing\";q=30;w=60";

/// Public pairing admission headers without private bucket identities.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PairingRateLimitHeaders {
    retry_after_seconds: u16,
    read: bool,
}

impl PairingRateLimitHeaders {
    /// Construct the nominal profile from the greatest applicable admission delay.
    ///
    /// # Errors
    /// Rejects a delay outside 1..=300 seconds.
    pub fn new(retry_after_seconds: u16, read: bool) -> Result<Self, PairingCodecError> {
        if !(1..=300).contains(&retry_after_seconds) {
            return Err(PairingCodecError::InvalidField("retry_after_seconds"));
        }
        Ok(Self { retry_after_seconds, read })
    }

    /// Decimal `Retry-After` value and `RateLimit` reset delay, in seconds.
    #[must_use]
    pub const fn retry_after_seconds(self) -> u16 {
        self.retry_after_seconds
    }

    /// Exact structured `RateLimit` value with zero advertised remaining capacity.
    #[must_use]
    pub fn rate_limit(self) -> String {
        format!("\"pairing\";r=0;t={}", self.retry_after_seconds)
    }

    /// Exact structured `RateLimit-Policy` value.
    #[must_use]
    pub const fn rate_limit_policy(self) -> &'static str {
        if self.read { PAIRING_READ_RATE_LIMIT_POLICY } else { PAIRING_MUTATION_RATE_LIMIT_POLICY }
    }
}

/// Redacted transport failure, with no submitted values.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum PairingCodecError {
    /// The complete body or binary field exceeds its bound.
    #[error("pairing message exceeds {0} bytes")]
    TooLarge(usize),
    /// Malformed JSON, duplicate names, trailing data or a non-object root.
    #[error("invalid pairing JSON")]
    InvalidJson,
    /// Missing, mistyped, noncanonical or forbidden member.
    #[error("invalid pairing field: {0}")]
    InvalidField(&'static str),
    /// Inconsistent state, role, transcript prefix or receipt.
    #[error("inconsistent pairing state")]
    InvalidState,
    /// Forbidden request metadata or missing response cache prevention.
    #[error("invalid pairing HTTP metadata")]
    HttpMetadata,
}

/// Fixed cryptographic role; not a proof of HTTP authentication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PairingRole {
    /// Existing enrolled device, authorized separately with current `DPoP` credentials.
    Initiator,
    /// New device, authorized separately with its session capability.
    Responder,
}

/// The seven immutable ordered relay slots.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PairingStep {
    /// Initiator's compressed `CPace` share.
    InitiatorShare,
    /// Responder's compressed `CPace` share.
    ResponderShare,
    /// Responder's channel confirmation.
    ResponderConfirmation,
    /// Initiator's channel confirmation.
    InitiatorConfirmation,
    /// Responder's authenticated new-device package.
    NewDevice,
    /// Initiator's authenticated account-root/key handoff.
    Handoff,
    /// Responder's public fixed-width device possession signature.
    Acceptance,
}

impl PairingStep {
    /// All slots in exact wire order.
    pub const ALL: [Self; 7] = [
        Self::InitiatorShare,
        Self::ResponderShare,
        Self::ResponderConfirmation,
        Self::InitiatorConfirmation,
        Self::NewDevice,
        Self::Handoff,
        Self::Acceptance,
    ];

    /// Exact case-sensitive wire name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InitiatorShare => "initiator_share",
            Self::ResponderShare => "responder_share",
            Self::ResponderConfirmation => "responder_confirmation",
            Self::InitiatorConfirmation => "initiator_confirmation",
            Self::NewDevice => "new_device",
            Self::Handoff => "handoff",
            Self::Acceptance => "acceptance",
        }
    }

    /// Recognize a supported slot; unknown slots cannot extend this finite protocol.
    #[must_use]
    pub fn from_wire(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|step| step.as_str() == value)
    }

    /// Zero-based position in the complete prefix.
    #[must_use]
    pub const fn index(self) -> usize {
        match self {
            Self::InitiatorShare => 0,
            Self::ResponderShare => 1,
            Self::ResponderConfirmation => 2,
            Self::InitiatorConfirmation => 3,
            Self::NewDevice => 4,
            Self::Handoff => 5,
            Self::Acceptance => 6,
        }
    }

    /// Only this role may send the slot.
    #[must_use]
    pub const fn role(self) -> PairingRole {
        match self {
            Self::InitiatorShare | Self::InitiatorConfirmation | Self::Handoff => {
                PairingRole::Initiator
            }
            _ => PairingRole::Responder,
        }
    }

    /// Maximum complete decoded frame or fixed binary value.
    #[must_use]
    pub const fn max_payload_bytes(self) -> usize {
        match self {
            Self::NewDevice => MAX_PAIRING_NEW_DEVICE_FRAME_BYTES,
            Self::Handoff => MAX_PAIRING_HANDOFF_FRAME_BYTES,
            Self::Acceptance => 64,
            _ => 32,
        }
    }

    /// Complete encoded request budget for this slot.
    #[must_use]
    pub const fn request_body_limit(self) -> usize {
        match self {
            Self::NewDevice => MAX_PAIRING_NEW_DEVICE_MESSAGE_BYTES,
            Self::Handoff => MAX_PAIRING_LARGE_REQUEST_BYTES,
            _ => MAX_PAIRING_SMALL_BYTES,
        }
    }

    fn validate_payload(self, payload: &[u8]) -> Result<(), PairingCodecError> {
        if payload.len() > self.max_payload_bytes() {
            return Err(PairingCodecError::TooLarge(self.max_payload_bytes()));
        }
        let valid = match self {
            Self::NewDevice | Self::Handoff => payload.len() > 40,
            _ => payload.len() == self.max_payload_bytes(),
        };
        if !valid {
            return Err(PairingCodecError::InvalidField("payload"));
        }
        Ok(())
    }
}

/// Server session projection, compared with independently retained local context by consumers.
#[derive(Clone, Eq, PartialEq)]
pub struct PairingContext {
    /// Canonical trusted HTTPS deployment origin, at most 2048 ASCII bytes.
    pub origin: String,
    /// Fresh canonical `UUIDv7` session locator.
    pub pairing_id: Uuid,
    /// Null before claim; immutable enrolled initiator afterward.
    pub initiator_device_id: Option<Uuid>,
    /// Retained new-device `UUIDv7`.
    pub responder_device_id: Uuid,
    /// Fixed UTC expiry; does not extend the client's monotonic deadline.
    pub expires_at: String,
}

/// Anonymous creation names only the locally retained new-device id.
#[derive(Clone, Eq, PartialEq)]
pub struct PairingCreateRequest {
    /// Existing pending `UUIDv7`; no public keys or password are submitted.
    pub device_id: Uuid,
}

/// Creation discloses the responder capability exactly once.
#[derive(Clone, Eq, PartialEq)]
pub struct PairingCreateResponse {
    /// Newly created, unclaimed context.
    pub context: PairingContext,
    /// Zeroizing capability, never a URL, UI snapshot or log field.
    pub new_device_token: SecretBytes<32>,
}

/// Explicit claim intent with the exact empty-object request.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PairingClaimRequest;

/// Immutable claimed initiator context, with no capability disclosure.
#[derive(Clone, Eq, PartialEq)]
pub struct PairingClaimResponse {
    /// Context with a non-null initiator.
    pub context: PairingContext,
}

/// An opaque relay slot, not a verified `CPace` share, confirmation or frame.
#[derive(Clone, Eq, PartialEq)]
pub struct PairingMessageRequest {
    /// Fixed step name.
    pub step: PairingStep,
    /// Exact decoded bytes; retain encoded messages for retransmission without re-encryption.
    pub payload: Vec<u8>,
}

/// Slot acknowledgement; no payload echo.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PairingMessageAck {
    /// Accepted exact slot.
    pub step: PairingStep,
}

/// Admission receipt; still requires retained-device authentication and anchored K-4 reads.
#[derive(Clone, Eq, PartialEq)]
pub struct PairingReceipt {
    /// Existing admitted account.
    pub account_id: Uuid,
    /// Newly admitted device, equal to the context's responder.
    pub device_id: Uuid,
    /// Exact positive committed bundle revision.
    pub revision: u64,
}

/// Server phase, never sufficient to establish cryptographic trust or commit rollback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PairingState {
    /// No initiator has claimed.
    Waiting,
    /// Claimed; zero through six immutable slots.
    Exchanging,
    /// All seven slots present, awaiting completion.
    Ready,
    /// Atomic admission committed, payloads removed.
    Completed,
    /// Explicitly cancelled, payloads removed.
    Cancelled,
    /// Fixed deadline reached, payloads removed.
    Expired,
}

impl PairingState {
    /// Exact wire phase.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Waiting => "waiting",
            Self::Exchanging => "exchanging",
            Self::Ready => "ready",
            Self::Completed => "completed",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
        }
    }

    /// Whether relay payloads have been removed.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Cancelled | Self::Expired)
    }
}

/// Complete bounded prefix from one session snapshot, with no incremental merge semantics.
#[derive(Clone, Eq, PartialEq)]
pub struct PairingSnapshot {
    /// Session and fixed roles.
    pub context: PairingContext,
    /// Phase consistent with the prefix/receipt.
    pub state: PairingState,
    /// At most seven exact slots in order; empty when terminal.
    pub messages: Vec<PairingMessageRequest>,
    /// Only completed snapshots carry a receipt.
    pub receipt: Option<PairingReceipt>,
}

/// Old-device atomic admission plan. Signature authenticity is a separate server/core check.
#[derive(Clone, Eq, PartialEq)]
pub struct PairingCompleteRequest {
    /// Exact signed canonical K-2 certificate, 1..65536 bytes.
    pub device_certificate: Vec<u8>,
    /// Exact signed canonical K-4 update, 1..4194304 bytes.
    pub key_bundle_update: Vec<u8>,
    /// Exact fixed-width new-device possession signature saved with its checkpoint.
    pub new_device_signature: [u8; 64],
}

macro_rules! redacted_debug {
    ($($ty:ty),+ $(,)?) => {$(impl fmt::Debug for $ty {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct(stringify!($ty)).finish_non_exhaustive()
        }
    })+};
}
redacted_debug!(
    PairingContext,
    PairingCreateRequest,
    PairingCreateResponse,
    PairingClaimResponse,
    PairingMessageRequest,
    PairingReceipt,
    PairingSnapshot,
    PairingCompleteRequest
);

#[derive(Serialize)]
struct ContextWire<'a> {
    origin: &'a str,
    pairing_id: String,
    initiator_device_id: Option<String>,
    responder_device_id: String,
    expires_at: &'a str,
}

impl PairingContext {
    /// Validate syntax only; no response can establish a new trust origin.
    ///
    /// # Errors
    /// Rejects noncanonical origin, identifiers or UTC expiry.
    pub fn validate(&self) -> Result<(), PairingCodecError> {
        if self.origin.len() > 2048 || validate_server_origin(&self.origin).is_err() {
            return Err(PairingCodecError::InvalidField("origin"));
        }
        uuid(self.pairing_id, "pairing_id")?;
        uuid(self.responder_device_id, "responder_device_id")?;
        if let Some(id) = self.initiator_device_id {
            uuid(id, "initiator_device_id")?;
        }
        if !valid_utc_timestamp(&self.expires_at) {
            return Err(PairingCodecError::InvalidField("expires_at"));
        }
        Ok(())
    }

    fn wire(&self) -> ContextWire<'_> {
        ContextWire {
            origin: &self.origin,
            pairing_id: self.pairing_id.to_string(),
            initiator_device_id: self.initiator_device_id.map(|id| id.to_string()),
            responder_device_id: self.responder_device_id.to_string(),
            expires_at: &self.expires_at,
        }
    }

    fn from_value(value: Value) -> Result<Self, PairingCodecError> {
        let mut fields = object(value, "context")?;
        let initiator_device_id = match fields.remove("initiator_device_id") {
            Some(Value::Null) => None,
            Some(value) => Some(parse_uuid(value, "initiator_device_id")?),
            None => return Err(PairingCodecError::InvalidField("initiator_device_id")),
        };
        let context = Self {
            origin: text(&mut fields, "origin")?,
            pairing_id: take_uuid(&mut fields, "pairing_id")?,
            initiator_device_id,
            responder_device_id: take_uuid(&mut fields, "responder_device_id")?,
            expires_at: text(&mut fields, "expires_at")?,
        };
        context.validate()?;
        Ok(context)
    }
}

impl PairingCreateRequest {
    /// Decode the anonymous one-field request.
    ///
    /// # Errors
    /// Rejects duplicates, unknown fields, invalid identifiers and exceeded complete-body bounds.
    pub fn from_json(input: &[u8]) -> Result<Self, PairingCodecError> {
        let mut fields = decode(input, MAX_PAIRING_SMALL_BYTES)?;
        let request = Self { device_id: take_uuid(&mut fields, "device_id")? };
        no_extra(&fields)?;
        Ok(request)
    }

    /// Encode the exact field order after mutable-field validation.
    ///
    /// # Errors
    /// Rejects an invalid identifier or body budget.
    pub fn to_json(&self) -> Result<Vec<u8>, PairingCodecError> {
        #[derive(Serialize)]
        struct Wire {
            device_id: String,
        }
        uuid(self.device_id, "device_id")?;
        encode(&Wire { device_id: self.device_id.to_string() }, MAX_PAIRING_SMALL_BYTES)
    }
}

impl PairingClaimRequest {
    /// Decode exactly an empty object, not an empty body.
    ///
    /// # Errors
    /// Rejects any field or invalid/bounded JSON.
    pub fn from_json(input: &[u8]) -> Result<Self, PairingCodecError> {
        no_extra(&decode(input, MAX_PAIRING_SMALL_BYTES)?)?;
        Ok(Self)
    }

    /// Encode the explicit empty-object intent.
    ///
    /// # Errors
    /// This fixed body is always within its budget.
    pub fn to_json(&self) -> Result<Vec<u8>, PairingCodecError> {
        Ok(b"{}".to_vec())
    }
}

impl PairingCreateResponse {
    /// Decode a creation result without treating its context as independently trusted.
    ///
    /// # Errors
    /// Rejects invalid context, a noncanonical capability, duplicates or oversized complete JSON.
    pub fn from_json(input: &[u8]) -> Result<Self, PairingCodecError> {
        let mut fields = decode(input, MAX_PAIRING_CONTEXT_BYTES)?;
        let context = take_context(&mut fields)?;
        let token = SecretVec::new(binary(&mut fields, "new_device_token", 32)?);
        let new_device_token = SecretBytes::from_slice(token.as_bytes())
            .ok_or(PairingCodecError::InvalidField("new_device_token"))?;
        if context.initiator_device_id.is_some() {
            return Err(PairingCodecError::InvalidState);
        }
        Ok(Self { context, new_device_token })
    }

    /// Encode the unclaimed context and one-time capability in contract order.
    ///
    /// # Errors
    /// Rejects invalid mutable context or a claimed creation response.
    pub fn to_json(&self) -> Result<Vec<u8>, PairingCodecError> {
        #[derive(Serialize)]
        struct Wire<'a> {
            context: ContextWire<'a>,
            new_device_token: String,
        }
        self.context.validate()?;
        if self.context.initiator_device_id.is_some() {
            return Err(PairingCodecError::InvalidState);
        }
        encode(
            &Wire {
                context: self.context.wire(),
                new_device_token: URL_SAFE_NO_PAD.encode(self.new_device_token.as_bytes()),
            },
            MAX_PAIRING_CONTEXT_BYTES,
        )
    }
}

impl PairingClaimResponse {
    /// Decode a claimed context with additive response extensions.
    ///
    /// # Errors
    /// Rejects missing initiator, invalid context or complete JSON.
    pub fn from_json(input: &[u8]) -> Result<Self, PairingCodecError> {
        let mut fields = decode(input, MAX_PAIRING_CONTEXT_BYTES)?;
        let context = take_context(&mut fields)?;
        if context.initiator_device_id.is_none() {
            return Err(PairingCodecError::InvalidState);
        }
        Ok(Self { context })
    }

    /// Encode the claimed context after validation.
    ///
    /// # Errors
    /// Rejects missing initiator, invalid context or encoded bounds.
    pub fn to_json(&self) -> Result<Vec<u8>, PairingCodecError> {
        #[derive(Serialize)]
        struct Wire<'a> {
            context: ContextWire<'a>,
        }
        self.context.validate()?;
        if self.context.initiator_device_id.is_none() {
            return Err(PairingCodecError::InvalidState);
        }
        encode(&Wire { context: self.context.wire() }, MAX_PAIRING_CONTEXT_BYTES)
    }
}

#[derive(Serialize)]
struct MessageWire {
    step: &'static str,
    payload: String,
}

impl PairingMessageRequest {
    /// Validate decoded binary bounds; does not verify `CPace` or AEAD.
    ///
    /// # Errors
    /// Rejects wrong fixed lengths or empty/oversized frames.
    pub fn validate(&self) -> Result<(), PairingCodecError> {
        self.step.validate_payload(&self.payload)
    }

    /// Decode one strict slot request, enforcing its own smaller complete-body budget.
    ///
    /// # Errors
    /// Rejects unknown/duplicate fields, unsupported slots and noncanonical or oversized payloads.
    pub fn from_json(input: &[u8]) -> Result<Self, PairingCodecError> {
        let mut fields = decode(input, MAX_PAIRING_LARGE_REQUEST_BYTES)?;
        let message = Self::from_fields(&mut fields)?;
        no_extra(&fields)?;
        check_len(input.len(), message.step.request_body_limit())?;
        Ok(message)
    }

    fn from_fields(fields: &mut Map<String, Value>) -> Result<Self, PairingCodecError> {
        let step = take_step(fields)?;
        let payload = binary(fields, "payload", step.max_payload_bytes())?;
        let message = Self { step, payload };
        message.validate()?;
        Ok(message)
    }

    fn wire(&self) -> MessageWire {
        MessageWire { step: self.step.as_str(), payload: URL_SAFE_NO_PAD.encode(&self.payload) }
    }

    /// Encode exact step and payload after mutable-field validation.
    ///
    /// # Errors
    /// Rejects wrong payload size or exceeded body budget.
    pub fn to_json(&self) -> Result<Vec<u8>, PairingCodecError> {
        self.validate()?;
        encode(&self.wire(), self.step.request_body_limit())
    }
}

impl PairingMessageAck {
    /// Decode a bounded acknowledgement with additive extensions.
    ///
    /// # Errors
    /// Rejects unknown slots, malformed or oversized complete JSON.
    pub fn from_json(input: &[u8]) -> Result<Self, PairingCodecError> {
        Ok(Self { step: take_step(&mut decode(input, MAX_PAIRING_SMALL_BYTES)?)? })
    }

    /// Encode only the accepted step.
    ///
    /// # Errors
    /// Rejects an exceeded complete-body budget.
    pub fn to_json(&self) -> Result<Vec<u8>, PairingCodecError> {
        #[derive(Serialize)]
        struct Wire {
            step: &'static str,
        }
        encode(&Wire { step: self.step.as_str() }, MAX_PAIRING_SMALL_BYTES)
    }
}

#[derive(Serialize)]
struct ReceiptWire {
    account_id: String,
    device_id: String,
    revision: u64,
}

impl PairingReceipt {
    /// Validate ids and a positive committed revision.
    ///
    /// # Errors
    /// Rejects invalid ids or revision zero.
    pub fn validate(&self) -> Result<(), PairingCodecError> {
        uuid(self.account_id, "account_id")?;
        uuid(self.device_id, "device_id")?;
        if self.revision == 0 {
            return Err(PairingCodecError::InvalidField("revision"));
        }
        Ok(())
    }

    fn wire(&self) -> ReceiptWire {
        ReceiptWire {
            account_id: self.account_id.to_string(),
            device_id: self.device_id.to_string(),
            revision: self.revision,
        }
    }

    fn from_fields(fields: &mut Map<String, Value>) -> Result<Self, PairingCodecError> {
        let receipt = Self {
            account_id: take_uuid(fields, "account_id")?,
            device_id: take_uuid(fields, "device_id")?,
            revision: fields
                .remove("revision")
                .and_then(|v| v.as_u64())
                .ok_or(PairingCodecError::InvalidField("revision"))?,
        };
        receipt.validate()?;
        Ok(receipt)
    }

    /// Decode a bounded receipt without establishing new cryptographic trust.
    ///
    /// # Errors
    /// Rejects invalid, duplicate or oversized JSON.
    pub fn from_json(input: &[u8]) -> Result<Self, PairingCodecError> {
        Self::from_fields(&mut decode(input, MAX_PAIRING_SMALL_BYTES)?)
    }

    /// Encode the exact account/device/revision receipt.
    ///
    /// # Errors
    /// Rejects invalid mutable fields or body bounds.
    pub fn to_json(&self) -> Result<Vec<u8>, PairingCodecError> {
        self.validate()?;
        encode(&self.wire(), MAX_PAIRING_SMALL_BYTES)
    }
}

impl PairingSnapshot {
    /// Validate a complete immutable prefix with phase/receipt consistency.
    ///
    /// # Errors
    /// Rejects wrong slot order, duplicate slots, phase mismatch or invalid receipt.
    pub fn validate(&self) -> Result<(), PairingCodecError> {
        self.context.validate()?;
        if self.messages.len() > 7 {
            return Err(PairingCodecError::InvalidState);
        }
        for (index, message) in self.messages.iter().enumerate() {
            if message.step.index() != index {
                return Err(PairingCodecError::InvalidState);
            }
            message.validate()?;
        }
        let claimed = self.context.initiator_device_id.is_some();
        let valid = match self.state {
            PairingState::Waiting => !claimed && self.messages.is_empty() && self.receipt.is_none(),
            PairingState::Exchanging => {
                claimed && self.messages.len() < 7 && self.receipt.is_none()
            }
            PairingState::Ready => claimed && self.messages.len() == 7 && self.receipt.is_none(),
            PairingState::Completed => {
                claimed && self.messages.is_empty() && self.receipt.is_some()
            }
            PairingState::Cancelled | PairingState::Expired => {
                self.messages.is_empty() && self.receipt.is_none()
            }
        };
        if !valid {
            return Err(PairingCodecError::InvalidState);
        }
        if let Some(receipt) = &self.receipt {
            receipt.validate()?;
            if receipt.device_id != self.context.responder_device_id {
                return Err(PairingCodecError::InvalidState);
            }
        }
        Ok(())
    }

    /// Decode one complete snapshot; never merge separately unverified prefixes.
    ///
    /// # Errors
    /// Rejects duplicate names, invalid fields, inconsistent state or full-body excess.
    pub fn from_json(input: &[u8]) -> Result<Self, PairingCodecError> {
        let mut fields = decode(input, MAX_PAIRING_SNAPSHOT_BYTES)?;
        let context = take_context(&mut fields)?;
        let state_text = text(&mut fields, "state")?;
        let state = [
            PairingState::Waiting,
            PairingState::Exchanging,
            PairingState::Ready,
            PairingState::Completed,
            PairingState::Cancelled,
            PairingState::Expired,
        ]
        .into_iter()
        .find(|state| state.as_str() == state_text)
        .ok_or(PairingCodecError::InvalidField("state"))?;
        let Some(Value::Array(values)) = fields.remove("messages") else {
            return Err(PairingCodecError::InvalidField("messages"));
        };
        if values.len() > 7 {
            return Err(PairingCodecError::InvalidState);
        }
        let messages =
            values.into_iter().map(Self::message_from_value).collect::<Result<_, _>>()?;
        let receipt = match fields.remove("receipt") {
            Some(Value::Null) => None,
            Some(value) => Some(PairingReceipt::from_fields(&mut object(value, "receipt")?)?),
            None => return Err(PairingCodecError::InvalidField("receipt")),
        };
        let snapshot = Self { context, state, messages, receipt };
        snapshot.validate()?;
        Ok(snapshot)
    }

    fn message_from_value(value: Value) -> Result<PairingMessageRequest, PairingCodecError> {
        PairingMessageRequest::from_fields(&mut object(value, "messages")?)
    }

    /// Encode the full validated snapshot in contract field order.
    ///
    /// # Errors
    /// Rejects invalid mutable fields, phase/prefix mismatch or encoded bounds.
    pub fn to_json(&self) -> Result<Vec<u8>, PairingCodecError> {
        #[derive(Serialize)]
        struct Wire<'a> {
            context: ContextWire<'a>,
            state: &'static str,
            messages: Vec<MessageWire>,
            receipt: Option<ReceiptWire>,
        }
        self.validate()?;
        encode(
            &Wire {
                context: self.context.wire(),
                state: self.state.as_str(),
                messages: self.messages.iter().map(PairingMessageRequest::wire).collect(),
                receipt: self.receipt.as_ref().map(PairingReceipt::wire),
            },
            MAX_PAIRING_SNAPSHOT_BYTES,
        )
    }
}

impl PairingCompleteRequest {
    /// Recheck exact canonical K-2/K-4 syntax and bounds, without verifying signatures.
    ///
    /// # Errors
    /// Rejects malformed/noncanonical artifacts or excessive binary sizes.
    pub fn validate(&self) -> Result<(), PairingCodecError> {
        check_len(self.device_certificate.len(), MAX_PAIRING_CERTIFICATE_BYTES)?;
        check_len(self.key_bundle_update.len(), MAX_PAIRING_KEY_UPDATE_BYTES)?;
        let certificate = DeviceCertificate::decode(&self.device_certificate)
            .map_err(|_| PairingCodecError::InvalidField("device_certificate"))?;
        if certificate.encode().ok().as_deref() != Some(self.device_certificate.as_slice()) {
            return Err(PairingCodecError::InvalidField("device_certificate"));
        }
        let bundle = SyncAccountKeyBundleUpdate::from_cbor(&self.key_bundle_update)
            .map_err(|_| PairingCodecError::InvalidField("key_bundle_update"))?;
        if bundle.to_cbor().ok().as_deref() != Some(self.key_bundle_update.as_slice()) {
            return Err(PairingCodecError::InvalidField("key_bundle_update"));
        }
        Ok(())
    }

    /// Decode exactly the three approval fields, retaining original canonical bytes.
    ///
    /// # Errors
    /// Rejects unknown/duplicate fields, noncanonical binary/artifacts or oversized input.
    pub fn from_json(input: &[u8]) -> Result<Self, PairingCodecError> {
        let mut fields = decode(input, MAX_PAIRING_LARGE_REQUEST_BYTES)?;
        let device_certificate =
            binary(&mut fields, "device_certificate", MAX_PAIRING_CERTIFICATE_BYTES)?;
        let key_bundle_update =
            binary(&mut fields, "key_bundle_update", MAX_PAIRING_KEY_UPDATE_BYTES)?;
        let new_device_signature = binary(&mut fields, "new_device_signature", 64)?
            .try_into()
            .map_err(|_| PairingCodecError::InvalidField("new_device_signature"))?;
        no_extra(&fields)?;
        let request = Self { device_certificate, key_bundle_update, new_device_signature };
        request.validate()?;
        Ok(request)
    }

    /// Encode the exact validated approval in specified field order.
    ///
    /// # Errors
    /// Rejects invalid mutable artifacts or body bounds.
    pub fn to_json(&self) -> Result<Vec<u8>, PairingCodecError> {
        #[derive(Serialize)]
        struct Wire {
            device_certificate: String,
            key_bundle_update: String,
            new_device_signature: String,
        }
        self.validate()?;
        encode(
            &Wire {
                device_certificate: URL_SAFE_NO_PAD.encode(&self.device_certificate),
                key_bundle_update: URL_SAFE_NO_PAD.encode(&self.key_bundle_update),
                new_device_signature: URL_SAFE_NO_PAD.encode(self.new_device_signature),
            },
            MAX_PAIRING_LARGE_REQUEST_BYTES,
        )
    }

    /// Shared domain-separated fingerprint for exact completion replay; not authorization.
    ///
    /// # Errors
    /// Rejects invalid artifact syntax/bounds before asking the crypto helper to hash bytes.
    pub fn approval_fingerprint(&self) -> Result<[u8; 32], PairingCodecError> {
        self.validate()?;
        scoplen_crypto::pairing_approval_fingerprint(
            &self.device_certificate,
            &self.key_bundle_update,
            &self.new_device_signature,
        )
        .map_err(|_| PairingCodecError::InvalidField("approval_fingerprint"))
    }
}

/// Validate common forbidden request metadata before accessing session state.
///
/// # Errors
/// Rejects any query, idempotency/precondition/cache header or an unexpected nonempty body.
pub fn validate_pairing_request_metadata(
    query: Option<&str>,
    body: &[u8],
    permits_body: bool,
    has_idempotency_key: bool,
    has_precondition_or_cache_header: bool,
) -> Result<(), PairingCodecError> {
    if query.is_some()
        || (!permits_body && !body.is_empty())
        || has_idempotency_key
        || has_precondition_or_cache_header
    {
        return Err(PairingCodecError::HttpMetadata);
    }
    Ok(())
}

/// Validate required noncacheable response metadata independently of a body codec.
///
/// # Errors
/// Rejects missing/incorrect cache/referrer headers and any `ETag`.
pub fn validate_pairing_response_metadata(
    cache_control: Option<&str>,
    pragma: Option<&str>,
    referrer_policy: Option<&str>,
    has_etag: bool,
) -> Result<(), PairingCodecError> {
    if cache_control != Some("no-store")
        || pragma != Some("no-cache")
        || referrer_policy != Some("no-referrer")
        || has_etag
    {
        return Err(PairingCodecError::HttpMetadata);
    }
    Ok(())
}

/// Decode the exact responder Authorization value without logging a plain token.
///
/// # Errors
/// Rejects another scheme, whitespace aliases, padding, wrong length or noncanonical base64url.
pub fn decode_pairing_authorization(value: &str) -> Result<SecretBytes<32>, PairingCodecError> {
    let text = value.strip_prefix("Pairing ").ok_or(PairingCodecError::HttpMetadata)?;
    if text.len() != 43 {
        return Err(PairingCodecError::HttpMetadata);
    }
    let bytes =
        SecretVec::new(URL_SAFE_NO_PAD.decode(text).map_err(|_| PairingCodecError::HttpMetadata)?);
    if URL_SAFE_NO_PAD.encode(bytes.as_bytes()) != text {
        return Err(PairingCodecError::HttpMetadata);
    }
    SecretBytes::from_slice(bytes.as_bytes()).ok_or(PairingCodecError::HttpMetadata)
}

/// Construct the responder header for the core's HTTP boundary only; never expose it to UI.
#[must_use]
pub fn encode_pairing_authorization(token: &SecretBytes<32>) -> String {
    format!("Pairing {}", URL_SAFE_NO_PAD.encode(token.as_bytes()))
}

fn decode(input: &[u8], max: usize) -> Result<Map<String, Value>, PairingCodecError> {
    check_len(input.len(), max)?;
    request_wire::decode_unique_object(input).map_err(|()| PairingCodecError::InvalidJson)
}
fn encode(value: &impl Serialize, max: usize) -> Result<Vec<u8>, PairingCodecError> {
    let bytes = serde_json::to_vec(value).map_err(|_| PairingCodecError::InvalidJson)?;
    check_len(bytes.len(), max)?;
    Ok(bytes)
}
fn check_len(len: usize, max: usize) -> Result<(), PairingCodecError> {
    if len > max { Err(PairingCodecError::TooLarge(max)) } else { Ok(()) }
}
fn object(value: Value, name: &'static str) -> Result<Map<String, Value>, PairingCodecError> {
    match value {
        Value::Object(fields) => Ok(fields),
        _ => Err(PairingCodecError::InvalidField(name)),
    }
}
fn text(fields: &mut Map<String, Value>, name: &'static str) -> Result<String, PairingCodecError> {
    match fields.remove(name) {
        Some(Value::String(text)) => Ok(text),
        _ => Err(PairingCodecError::InvalidField(name)),
    }
}
fn uuid(id: Uuid, name: &'static str) -> Result<(), PairingCodecError> {
    validate_uuid_v7(id).map_err(|_| PairingCodecError::InvalidField(name))
}
fn parse_uuid(value: Value, name: &'static str) -> Result<Uuid, PairingCodecError> {
    let Value::String(text) = value else {
        return Err(PairingCodecError::InvalidField(name));
    };
    let id = Uuid::parse_str(&text).map_err(|_| PairingCodecError::InvalidField(name))?;
    uuid(id, name)?;
    if id.to_string() != text {
        return Err(PairingCodecError::InvalidField(name));
    }
    Ok(id)
}
fn take_uuid(
    fields: &mut Map<String, Value>,
    name: &'static str,
) -> Result<Uuid, PairingCodecError> {
    parse_uuid(fields.remove(name).ok_or(PairingCodecError::InvalidField(name))?, name)
}
fn binary(
    fields: &mut Map<String, Value>,
    name: &'static str,
    max: usize,
) -> Result<Vec<u8>, PairingCodecError> {
    let text = text(fields, name)?;
    check_len(text.len(), (max * 4).div_ceil(3))?;
    let bytes = URL_SAFE_NO_PAD.decode(&text).map_err(|_| PairingCodecError::InvalidField(name))?;
    if bytes.is_empty() || URL_SAFE_NO_PAD.encode(&bytes) != text {
        return Err(PairingCodecError::InvalidField(name));
    }
    check_len(bytes.len(), max)?;
    Ok(bytes)
}
fn take_context(fields: &mut Map<String, Value>) -> Result<PairingContext, PairingCodecError> {
    PairingContext::from_value(
        fields.remove("context").ok_or(PairingCodecError::InvalidField("context"))?,
    )
}
fn take_step(fields: &mut Map<String, Value>) -> Result<PairingStep, PairingCodecError> {
    PairingStep::from_wire(&text(fields, "step")?).ok_or(PairingCodecError::InvalidField("step"))
}
fn no_extra(fields: &Map<String, Value>) -> Result<(), PairingCodecError> {
    if fields.is_empty() { Ok(()) } else { Err(PairingCodecError::InvalidField("unknown")) }
}
