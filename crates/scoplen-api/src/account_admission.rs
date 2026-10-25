// SPDX-License-Identifier: Apache-2.0
//! D-128 native Account entry transport. These codecs confer no production authorization.
//!
//! Durable rate admission, original challenge/receipt lookup, current-state CAS and mandatory
//! audit remain consumer transactions. Confirmation never falls through to a new mutation.

use std::{
    fmt,
    ops::{Deref, DerefMut},
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use scoplen_crypto::{AccountRequestProof, AccountRequestSignatureInput, SecretBytes, SecretVec};
use scoplen_model::validate_uuid_v7;
use serde::{Serialize, Serializer, ser::SerializeMap};
use serde_json::{Map, Value};
use thiserror::Error;
use uuid::Uuid;

pub use scoplen_crypto::{AccountRequestIntent, AccountRequestKind};
mod protected;
pub use protected::{
    AccountBootstrapSnapshot, AccountDeviceAdmissionPayload, AccountPersonalBootstrap,
    AccountPersonalEpoch, AccountRegistrationPayload,
};

/// Maximum complete protected registration bytes.
pub const MAX_ACCOUNT_REGISTRATION_PAYLOAD_BYTES: usize = 262_144;
/// Maximum complete protected admission bytes.
pub const MAX_ACCOUNT_ADMISSION_PAYLOAD_BYTES: usize = 4_325_376;
/// Maximum complete protected bootstrap snapshot bytes.
pub const MAX_ACCOUNT_BOOTSTRAP_BYTES: usize = 9_437_184;
/// Maximum complete encoded RFC 9457 failure body.
pub const MAX_ACCOUNT_ENTRY_PROBLEM_BYTES: usize = 4_096;
/// Password options and request challenges expire after exactly this many milliseconds.
pub const ACCOUNT_ATTEMPT_LIFETIME_MS: u64 = 120_000;
/// Admission capabilities expire after exactly this many milliseconds.
pub const ACCOUNT_ADMISSION_LIFETIME_MS: u64 = 300_000;

/// Exact unauthenticated native route registration. No existing principal scope substitutes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccountEntryOperation {
    /// Fresh submit/confirm possession challenge.
    RequestChallenge,
    /// Stable Account registration or its exact terminal confirmation.
    Register,
    /// Fixed-profile password options with one-use attempt.
    PasswordOptions,
    /// Password verification and complete encrypted snapshot/capability.
    PasswordLogin,
    /// Fresh Device admission or its exact terminal confirmation.
    DeviceAdmission,
}

impl AccountEntryOperation {
    /// Resolve only the exact POST routes; this is not an authorization decision.
    #[must_use]
    pub fn from_route(method: &str, path: &str) -> Option<Self> {
        if method != "POST" {
            return None;
        }
        match path {
            "/api/v1/auth/accounts/requests/challenge" => Some(Self::RequestChallenge),
            "/api/v1/auth/accounts/register" => Some(Self::Register),
            "/api/v1/auth/accounts/password/options" => Some(Self::PasswordOptions),
            "/api/v1/auth/accounts/password/login" => Some(Self::PasswordLogin),
            "/api/v1/auth/accounts/device-admissions" => Some(Self::DeviceAdmission),
            _ => None,
        }
    }

    /// Complete encoded request/response byte limits, including whitespace and extensions.
    #[must_use]
    pub const fn body_limits(self) -> (usize, usize) {
        match self {
            Self::RequestChallenge | Self::PasswordLogin => {
                (512, if matches!(self, Self::PasswordLogin) { 12_587_008 } else { 1_024 })
            }
            Self::Register => (524_288, 1_024),
            Self::PasswordOptions => (256, 1_024),
            Self::DeviceAdmission => (6_291_456, 1_024),
        }
    }
}

/// Redacted transport and public-binding failures, without attacker-controlled diagnostics.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum AccountAdmissionCodecError {
    /// A complete encoded/decoded field or collection exceeds its fixed bound.
    #[error("Account entry payload exceeds its bound")]
    TooLarge,
    /// Invalid UTF-8/JSON, recursive duplicate names, missing/unknown or noncanonical fields.
    #[error("invalid Account entry request")]
    InvalidJson,
    /// Protected CBOR, version, artifact shape or canonical context is invalid.
    #[error("invalid protected Account payload")]
    InvalidProtected,
    /// An exact canonical identity, origin, capability, receipt or signature does not match.
    #[error("Account authentication is required")]
    Binding,
    /// A previously valid snapshot changed or unsupported rotation/material is proposed.
    #[error("Account admission state has changed")]
    AdmissionConflict,
    /// Wrong media/content encoding.
    #[error("unsupported Account entry media type")]
    MediaType,
    /// Prohibited header/query or incorrect cache metadata.
    #[error("invalid Account entry HTTP metadata")]
    HttpMetadata,
    /// A supplied HTTP Origin differs from the trusted origin.
    #[error("Account entry origin is denied")]
    OriginDenied,
}

/// Native-only request metadata, after duplicate-header detection by the HTTP adapter.
#[derive(Clone, Copy, Debug, Default)]
#[allow(clippy::struct_excessive_bools)] // Independent HTTP header presence is not a state machine.
pub struct AccountEntryHttpMetadata<'a> {
    /// Exact content type; JSON optionally admits one UTF-8 charset parameter.
    pub content_type: &'a str,
    /// Absent or exactly identity content encoding.
    pub content_encoding: Option<&'a str>,
    /// Native callers may omit Origin; supplied values must equal the trusted origin.
    pub origin: Option<&'a str>,
    /// Presence includes an empty query suffix.
    pub has_query: bool,
    /// Any Authorization header is prohibited.
    pub has_authorization: bool,
    /// Any `DPoP` header is prohibited.
    pub has_dpop: bool,
    /// Any Cookie header is prohibited.
    pub has_cookie: bool,
    /// Idempotency-Key is not this protocol's terminal-receipt mechanism.
    pub has_idempotency_key: bool,
    /// If-Match is not this protocol's current-snapshot CAS.
    pub has_if_match: bool,
}

impl AccountEntryHttpMetadata<'_> {
    /// Validate native request metadata before protected identity lookup.
    /// # Errors
    /// Distinguishes malformed trusted origin, unsupported media, forbidden input and Origin denial.
    pub fn validate(self, trusted_origin: &str) -> Result<(), AccountAdmissionCodecError> {
        scoplen_crypto::validate_server_origin(trusted_origin)
            .map_err(|_| AccountAdmissionCodecError::InvalidProtected)?;
        if !matches!(self.content_type, "application/json" | "application/json; charset=utf-8")
            || !matches!(self.content_encoding, None | Some("identity"))
        {
            return Err(AccountAdmissionCodecError::MediaType);
        }
        if self.has_query
            || self.has_authorization
            || self.has_dpop
            || self.has_cookie
            || self.has_idempotency_key
            || self.has_if_match
        {
            return Err(AccountAdmissionCodecError::HttpMetadata);
        }
        if self.origin.is_some_and(|o| o != trusted_origin) {
            return Err(AccountAdmissionCodecError::OriginDenied);
        }
        Ok(())
    }
}

/// Public challenge request, with explicit mutation versus historical-confirmation intent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccountRequestChallengeRequest {
    /// Stable Account operation domain.
    pub kind: AccountRequestKind,
    /// Fresh request intent; confirm never creates state.
    pub intent: AccountRequestIntent,
    /// Stable operation id, without an existence lookup during challenge issuance.
    pub operation_id: Uuid,
    /// Fresh or original retained Device id.
    pub device_id: Uuid,
}

impl AccountRequestChallengeRequest {
    /// Decode strict bounded JSON with no unknown or recursively duplicated members.
    /// # Errors
    /// Rejects malformed, unknown, noncanonical or oversized fields.
    pub fn from_json(input: &[u8]) -> Result<Self, AccountAdmissionCodecError> {
        let mut f = object(input, 512)?;
        let value = Self {
            kind: take_kind(&mut f)?,
            intent: take_intent(&mut f)?,
            operation_id: take_uuid(&mut f, "operation_id")?,
            device_id: take_uuid(&mut f, "device_id")?,
        };
        no_extensions(&f)?;
        Ok(value)
    }
    /// Encode deterministic fields after checking mutable identifiers.
    /// # Errors
    /// Rejects non-v7 ids or an exceeded complete-body bound.
    pub fn to_json(&self) -> Result<Vec<u8>, AccountAdmissionCodecError> {
        valid_uuid(self.operation_id)?;
        valid_uuid(self.device_id)?;
        json(
            vec![
                ("kind", string(self.kind.as_str())),
                ("intent", string(self.intent.as_str())),
                ("operation_id", string(self.operation_id.to_string())),
                ("device_id", string(self.device_id.to_string())),
            ],
            512,
        )
    }
}

/// Independent fresh challenge and nonce. They are bearer proof inputs, never public diagnostics.
#[derive(Clone, Eq, PartialEq)]
pub struct AccountRequestChallengeResponse {
    /// Random 32-byte one-use attempt id.
    pub attempt_id: SecretBytes<32>,
    /// Independent random 32-byte nonce.
    pub nonce: SecretBytes<32>,
    /// Positive trusted Unix milliseconds, encoded as a canonical decimal string.
    pub expires_at_ms: u64,
}

impl AccountRequestChallengeResponse {
    /// Decode a bounded response; extensions are ignored after duplicate-name checking.
    /// # Errors
    /// Rejects invalid required fields or the entire response bound.
    pub fn from_json(input: &[u8]) -> Result<Self, AccountAdmissionCodecError> {
        let mut f = object(input, 1_024)?;
        Ok(Self {
            attempt_id: SecretBytes::new(take_fixed(&mut f, "attempt_id")?),
            nonce: SecretBytes::new(take_fixed(&mut f, "nonce")?),
            expires_at_ms: take_decimal(&mut f, "expires_at_ms")?,
        })
    }
    /// Encode a complete challenge with no identifiers or extension data.
    /// # Errors
    /// Rejects nonpositive expiry or response-size failure.
    pub fn to_json(&self) -> Result<Vec<u8>, AccountAdmissionCodecError> {
        json(
            vec![
                ("attempt_id", b64(self.attempt_id.as_ref())),
                ("nonce", b64(self.nonce.as_ref())),
                ("expires_at_ms", decimal(self.expires_at_ms)?),
            ],
            1_024,
        )
    }
}

/// Username-only password options request. No aliases or normalization are accepted.
#[derive(Clone, Eq, PartialEq)]
pub struct AccountPasswordOptionsRequest {
    /// Exact 3..64-byte lowercase ASCII deployment-local username.
    pub username: String,
}

impl AccountPasswordOptionsRequest {
    /// Decode the single exact required username field.
    /// # Errors
    /// Rejects malformed/unknown/duplicate or noncanonical input and complete bodies over 256 bytes.
    pub fn from_json(input: &[u8]) -> Result<Self, AccountAdmissionCodecError> {
        let mut f = object(input, 256)?;
        let username = take_text(&mut f, "username")?;
        validate_username(&username)?;
        no_extensions(&f)?;
        Ok(Self { username })
    }
    /// Encode without changing the chosen username.
    /// # Errors
    /// Rejects a noncanonical username or exceeded body bound.
    pub fn to_json(&self) -> Result<Vec<u8>, AccountAdmissionCodecError> {
        validate_username(&self.username)?;
        json(vec![("username", string(&self.username))], 256)
    }
}

/// Fixed profile-one options for current and synthetic usernames, with indistinguishable shape.
#[derive(Clone, Eq, PartialEq)]
pub struct AccountPasswordOptionsResponse {
    /// Raw one-use random attempt id, whose digest alone is stored by the server.
    pub attempt_id: SecretBytes<32>,
    /// Sixteen-byte current or stable synthetic salt.
    pub salt: [u8; 16],
    /// Positive trusted Unix-millisecond expiry.
    pub expires_at_ms: u64,
}

impl AccountPasswordOptionsResponse {
    /// Decode required options while rejecting recursive duplicate response names.
    /// # Errors
    /// Rejects a non-one profile, malformed byte fields/time, or the full response bound.
    pub fn from_json(input: &[u8]) -> Result<Self, AccountAdmissionCodecError> {
        let mut f = object(input, 1_024)?;
        take_profile(&mut f)?;
        Ok(Self {
            attempt_id: SecretBytes::new(take_fixed(&mut f, "attempt_id")?),
            salt: take_fixed(&mut f, "salt")?,
            expires_at_ms: take_decimal(&mut f, "expires_at_ms")?,
        })
    }
    /// Encode the sole profile without Account, generation, roots or an existence hint.
    /// # Errors
    /// Rejects nonpositive expiry or exceeded complete response size.
    pub fn to_json(&self) -> Result<Vec<u8>, AccountAdmissionCodecError> {
        json(
            vec![
                ("attempt_id", b64(self.attempt_id.as_ref())),
                ("profile", Value::from(1)),
                ("salt", b64(&self.salt)),
                ("expires_at_ms", decimal(self.expires_at_ms)?),
            ],
            1_024,
        )
    }
}

/// Transient Rust-owned password authentication; no ordinary token is issued by this request.
#[derive(Clone, Eq, PartialEq)]
pub struct AccountPasswordLoginRequest {
    /// One-use attempt bound to origin, username, profile and salt.
    pub attempt_id: SecretBytes<32>,
    /// Password-derived `AuthSecret`, zeroized on drop and never stored in a recovery digest.
    pub auth_secret: SecretBytes<32>,
}

impl AccountPasswordLoginRequest {
    /// Decode exact transient secret bytes; the caller also zeroizes its original input buffer.
    /// # Errors
    /// Rejects unknown/duplicate members, noncanonical bytes or a body above 512 bytes.
    pub fn from_json(input: &[u8]) -> Result<Self, AccountAdmissionCodecError> {
        let mut f = object(input, 512)?;
        let value = Self {
            attempt_id: SecretBytes::new(take_fixed(&mut f, "attempt_id")?),
            auth_secret: SecretBytes::new(take_fixed(&mut f, "auth_secret")?),
        };
        no_extensions(&f)?;
        Ok(value)
    }
    /// Encode only into a redacted zeroizing secret buffer owned by the native HTTP layer.
    /// # Errors
    /// Rejects an exceeded complete request bound.
    pub fn to_json(&self) -> Result<SecretVec, AccountAdmissionCodecError> {
        let a = SecretVec::new(URL_SAFE_NO_PAD.encode(self.attempt_id.as_ref()).into_bytes());
        let b = SecretVec::new(URL_SAFE_NO_PAD.encode(self.auth_secret.as_ref()).into_bytes());
        let mut body = Vec::with_capacity(123);
        body.extend_from_slice(b"{\"attempt_id\":\"");
        body.extend_from_slice(a.as_bytes());
        body.extend_from_slice(b"\",\"auth_secret\":\"");
        body.extend_from_slice(b.as_bytes());
        body.extend_from_slice(b"\"}");
        Ok(SecretVec::new(body))
    }
}

/// Complete encrypted bootstrap plus one single-use admission capability, never session tokens.
#[derive(Clone, Eq, PartialEq)]
pub struct AccountPasswordLoginResponse {
    /// Raw random 32-byte capability, never included in the stable protected payload/receipt.
    pub admission_token: SecretBytes<32>,
    /// Positive trusted expiry, exactly five minutes after capability creation.
    pub expires_at_ms: u64,
    /// Exact original protected snapshot bytes; no reconstruction from a GET projection.
    pub snapshot: SecretVec,
}

impl AccountPasswordLoginResponse {
    /// Decode and publicly validate the complete encrypted bootstrap.
    /// # Errors
    /// Rejects body/decoded bounds, noncanonical fields or invalid protected bindings.
    pub fn from_json(input: &[u8]) -> Result<Self, AccountAdmissionCodecError> {
        let mut f = object(input, 12_587_008)?;
        let value = Self {
            admission_token: SecretBytes::new(take_fixed(&mut f, "admission_token")?),
            expires_at_ms: take_decimal(&mut f, "expires_at_ms")?,
            snapshot: SecretVec::new(take_bytes(&mut f, "snapshot", MAX_ACCOUNT_BOOTSTRAP_BYTES)?),
        };
        AccountBootstrapSnapshot::from_cbor(value.snapshot.as_bytes())?;
        Ok(value)
    }
    /// Preflight the complete JSON envelope as well as the decoded nine-MiB snapshot.
    /// # Errors
    /// Rejects invalid required fields, protected snapshot or complete response bound.
    pub fn to_json(&self) -> Result<Vec<u8>, AccountAdmissionCodecError> {
        AccountBootstrapSnapshot::from_cbor(self.snapshot.as_bytes())?;
        json(
            vec![
                ("admission_token", b64(self.admission_token.as_ref())),
                ("expires_at_ms", decimal(self.expires_at_ms)?),
                ("snapshot", b64(self.snapshot.as_bytes())),
            ],
            12_587_008,
        )
    }
}

/// Original registration bytes and Account signature with one fresh challenge and Device proof.
#[derive(Clone, Eq, PartialEq)]
pub struct AccountRegistrationRequest {
    /// Explicit submit or historical confirm, bound by the fresh Device proof.
    pub intent: AccountRequestIntent,
    /// Exact retained complete protected registration bytes.
    pub payload: SecretVec,
    /// Stable additional Account signature, unchanged across confirmation.
    pub account_signature: [u8; 64],
    /// Fresh one-use request challenge.
    pub attempt_id: SecretBytes<32>,
    /// Exact nonce from the fresh challenge.
    pub nonce: SecretBytes<32>,
    /// Raw P-256 r||s over the original unprehashed proof input.
    pub device_proof: [u8; 64],
}

impl AccountRegistrationRequest {
    /// Decode exact request members and protected business payload, without receipt lookup.
    /// # Errors
    /// Rejects syntax/bounds/unknown fields and publicly verifiable protected binding failures.
    pub fn from_json(input: &[u8]) -> Result<Self, AccountAdmissionCodecError> {
        let mut f = object(input, 524_288)?;
        let value = Self {
            intent: take_intent(&mut f)?,
            payload: SecretVec::new(take_bytes(
                &mut f,
                "payload",
                MAX_ACCOUNT_REGISTRATION_PAYLOAD_BYTES,
            )?),
            account_signature: take_fixed(&mut f, "account_signature")?,
            attempt_id: SecretBytes::new(take_fixed(&mut f, "attempt_id")?),
            nonce: SecretBytes::new(take_fixed(&mut f, "nonce")?),
            device_proof: take_fixed(&mut f, "device_proof")?,
        };
        no_extensions(&f)?;
        AccountRegistrationPayload::from_cbor(value.payload.as_bytes())?;
        Ok(value)
    }
    /// Encode deterministic native request fields while preserving original business bytes.
    /// # Errors
    /// Rejects invalid protected bytes or the entire 524,288-byte body bound.
    pub fn to_json(&self) -> Result<Vec<u8>, AccountAdmissionCodecError> {
        AccountRegistrationPayload::from_cbor(self.payload.as_bytes())?;
        json(
            request_fields(
                self.intent,
                self.payload.as_bytes(),
                &self.account_signature,
                self.attempt_id.as_bytes(),
                self.nonce.as_bytes(),
                &self.device_proof,
            ),
            524_288,
        )
    }
    /// Verify the exact Account and independent Device signatures using a trusted origin.
    ///
    /// The consumer separately binds and atomically claims the original live challenge or receipt.
    /// # Errors
    /// Rejects a changed canonical origin, business payload or either signature.
    pub fn verify_proof(
        &self,
        trusted_origin: &str,
    ) -> Result<[u8; 32], AccountAdmissionCodecError> {
        let p = AccountRegistrationPayload::from_cbor(self.payload.as_bytes())?;
        if p.origin != trusted_origin {
            return Err(AccountAdmissionCodecError::Binding);
        }
        let input = AccountRequestSignatureInput::new(
            AccountRequestKind::Register,
            self.payload.as_bytes(),
        )
        .map_err(|_| AccountAdmissionCodecError::InvalidProtected)?;
        input
            .verify(&p.account_signing_public_key, &self.account_signature)
            .map_err(|_| AccountAdmissionCodecError::Binding)?;
        let digest = input.request_digest(&self.account_signature);
        let proof = AccountRequestProof::new(
            AccountRequestKind::Register,
            self.intent,
            trusted_origin,
            self.attempt_id.as_bytes(),
            self.nonce.as_bytes(),
            p.operation_id,
            p.device_id,
            &digest,
        )
        .map_err(|_| AccountAdmissionCodecError::InvalidProtected)?;
        let cert = scoplen_crypto::DeviceCertificate::decode(&p.device_certificate)
            .map_err(|_| AccountAdmissionCodecError::InvalidProtected)?;
        proof
            .verify(&cert.signing_public_key, &self.device_proof)
            .map_err(|_| AccountAdmissionCodecError::Binding)?;
        Ok(digest)
    }
}

/// Admission envelope. Confirm's required null capability cannot enter the submit branch.
#[derive(Clone, Eq, PartialEq)]
pub struct AccountDeviceAdmissionRequest {
    /// Explicit mutation or receipt-only intent.
    pub intent: AccountRequestIntent,
    /// Original complete protected payload, unchanged during historical confirmation.
    pub payload: SecretVec,
    /// Original additional Account signature.
    pub account_signature: [u8; 64],
    /// Fresh one-use challenge id.
    pub attempt_id: SecretBytes<32>,
    /// Fresh challenge nonce.
    pub nonce: SecretBytes<32>,
    /// Original Device key's fresh P-256 proof.
    pub device_proof: [u8; 64],
    /// Submit requires one raw capability; confirm requires JSON null.
    pub admission_token: Option<SecretBytes<32>>,
}

impl AccountDeviceAdmissionRequest {
    /// Decode exact required admission members and enforce the intent/token sum type.
    /// # Errors
    /// Rejects unknown/duplicate fields, malformed protected bytes or illegal token/intent pairs.
    pub fn from_json(input: &[u8]) -> Result<Self, AccountAdmissionCodecError> {
        let mut f = object(input, 6_291_456)?;
        let intent = take_intent(&mut f)?;
        let token = match (intent, f.get("admission_token")) {
            (AccountRequestIntent::Submit, Some(Value::String(_))) => {
                Some(SecretBytes::new(take_fixed(&mut f, "admission_token")?))
            }
            (AccountRequestIntent::Confirm, Some(Value::Null)) => {
                f.remove("admission_token");
                None
            }
            _ => return Err(AccountAdmissionCodecError::InvalidJson),
        };
        let value = Self {
            intent,
            payload: SecretVec::new(take_bytes(
                &mut f,
                "payload",
                MAX_ACCOUNT_ADMISSION_PAYLOAD_BYTES,
            )?),
            account_signature: take_fixed(&mut f, "account_signature")?,
            attempt_id: SecretBytes::new(take_fixed(&mut f, "attempt_id")?),
            nonce: SecretBytes::new(take_fixed(&mut f, "nonce")?),
            device_proof: take_fixed(&mut f, "device_proof")?,
            admission_token: token,
        };
        no_extensions(&f)?;
        AccountDeviceAdmissionPayload::from_cbor(value.payload.as_bytes())?;
        Ok(value)
    }
    /// Encode exact retained business material and the correctly typed capability field.
    /// # Errors
    /// Rejects an illegal token/intent pair, invalid payload or exceeded whole-body bound.
    pub fn to_json(&self) -> Result<Vec<u8>, AccountAdmissionCodecError> {
        if matches!(
            (self.intent, &self.admission_token),
            (AccountRequestIntent::Submit, None) | (AccountRequestIntent::Confirm, Some(_))
        ) {
            return Err(AccountAdmissionCodecError::InvalidJson);
        }
        AccountDeviceAdmissionPayload::from_cbor(self.payload.as_bytes())?;
        let mut fields = request_fields(
            self.intent,
            self.payload.as_bytes(),
            &self.account_signature,
            self.attempt_id.as_bytes(),
            self.nonce.as_bytes(),
            &self.device_proof,
        );
        fields.push((
            "admission_token",
            self.admission_token.as_ref().map_or(Value::Null, |t| b64(t.as_ref())),
        ));
        json(fields, 6_291_456)
    }
    /// Verify signatures with a transaction-current or immutable historical receipt root.
    ///
    /// No current-authorization or durable receipt evidence is returned by this helper.
    /// # Errors
    /// Rejects changed origin, Account/Device signatures or malformed protected material.
    pub fn verify_proof(
        &self,
        trusted_origin: &str,
        trusted_root: &[u8; 32],
    ) -> Result<[u8; 32], AccountAdmissionCodecError> {
        let p = AccountDeviceAdmissionPayload::from_cbor(self.payload.as_bytes())?;
        if p.origin != trusted_origin {
            return Err(AccountAdmissionCodecError::Binding);
        }
        let input =
            AccountRequestSignatureInput::new(AccountRequestKind::Admit, self.payload.as_bytes())
                .map_err(|_| AccountAdmissionCodecError::InvalidProtected)?;
        input
            .verify(trusted_root, &self.account_signature)
            .map_err(|_| AccountAdmissionCodecError::Binding)?;
        let digest = input.request_digest(&self.account_signature);
        let cert = scoplen_crypto::DeviceCertificate::decode(&p.device_certificate)
            .map_err(|_| AccountAdmissionCodecError::InvalidProtected)?;
        cert.verify(trusted_root).map_err(|_| AccountAdmissionCodecError::Binding)?;
        let proof = AccountRequestProof::new(
            AccountRequestKind::Admit,
            self.intent,
            trusted_origin,
            self.attempt_id.as_bytes(),
            self.nonce.as_bytes(),
            p.operation_id,
            p.device_id,
            &digest,
        )
        .map_err(|_| AccountAdmissionCodecError::InvalidProtected)?;
        proof
            .verify(&cert.signing_public_key, &self.device_proof)
            .map_err(|_| AccountAdmissionCodecError::Binding)?;
        Ok(digest)
    }
}

/// Historical exact-commit confirmation, with no current authorization/key/capability claim.
#[derive(Clone, Eq, PartialEq)]
pub struct AccountCommittedConfirmation {
    /// Original stable operation kind.
    pub kind: AccountRequestKind,
    /// Original deployment-unique operation id.
    pub operation_id: Uuid,
    /// Original exact payload plus Account-signature digest.
    pub request_digest: [u8; 32],
    /// Originally committed Account id.
    pub account_id: Uuid,
    /// Originally committed Personal vault id.
    pub personal_vault_id: Uuid,
    /// Originally committed Device id.
    pub device_id: Uuid,
    /// Originally admitted positive K-4 revision, not a claim of current revision or authority.
    pub admitted_key_revision: u64,
}

impl AccountCommittedConfirmation {
    /// Decode bounded required fields while ignoring only unprotected response extensions.
    /// # Errors
    /// Rejects invalid outcome/kind, noncanonical ids/digest/revision or response size.
    pub fn from_json(input: &[u8]) -> Result<Self, AccountAdmissionCodecError> {
        let mut f = object(input, 1_024)?;
        if take_text(&mut f, "outcome")? != "committed" {
            return Err(AccountAdmissionCodecError::InvalidJson);
        }
        Ok(Self {
            kind: take_kind(&mut f)?,
            operation_id: take_uuid(&mut f, "operation_id")?,
            request_digest: take_fixed(&mut f, "request_digest")?,
            account_id: take_uuid(&mut f, "account_id")?,
            personal_vault_id: take_uuid(&mut f, "personal_vault_id")?,
            device_id: take_uuid(&mut f, "device_id")?,
            admitted_key_revision: take_decimal(&mut f, "admitted_key_revision")?,
        })
    }
    /// Encode only the original committed facts after mutable-field validation.
    /// # Errors
    /// Rejects invalid ids/revision or a response beyond 1,024 bytes.
    pub fn to_json(&self) -> Result<Vec<u8>, AccountAdmissionCodecError> {
        for id in [self.operation_id, self.account_id, self.personal_vault_id, self.device_id] {
            valid_uuid(id)?;
        }
        json(
            vec![
                ("outcome", string("committed")),
                ("kind", string(self.kind.as_str())),
                ("operation_id", string(self.operation_id.to_string())),
                ("request_digest", b64(&self.request_digest)),
                ("account_id", string(self.account_id.to_string())),
                ("personal_vault_id", string(self.personal_vault_id.to_string())),
                ("device_id", string(self.device_id.to_string())),
                ("admitted_key_revision", decimal(self.admitted_key_revision)?),
            ],
            1_024,
        )
    }
    /// Bind every returned fact to the original retained protected bytes and Account signature.
    /// # Errors
    /// Rejects any substituted kind, operation/id, request digest or admitted revision.
    pub fn validate_for_request(
        &self,
        kind: AccountRequestKind,
        payload: &[u8],
        signature: &[u8; 64],
    ) -> Result<(), AccountAdmissionCodecError> {
        let (operation, account, vault, device, bundle) = match kind {
            AccountRequestKind::Register => {
                let p = AccountRegistrationPayload::from_cbor(payload)?;
                (p.operation_id, p.account_id, p.personal_vault_id, p.device_id, p.key_bundle)
            }
            AccountRequestKind::Admit => {
                let p = AccountDeviceAdmissionPayload::from_cbor(payload)?;
                (p.operation_id, p.account_id, p.personal_vault_id, p.device_id, p.key_bundle)
            }
        };
        let digest = AccountRequestSignatureInput::new(kind, payload)
            .map_err(|_| AccountAdmissionCodecError::InvalidProtected)?
            .request_digest(signature);
        let revision = crate::sync::SyncAccountKeyBundleUpdate::from_cbor(&bundle)
            .map_err(|_| AccountAdmissionCodecError::InvalidProtected)?
            .revision;
        if self.kind != kind
            || self.operation_id != operation
            || self.account_id != account
            || self.personal_vault_id != vault
            || self.device_id != device
            || self.request_digest != digest
            || self.admitted_key_revision != revision
        {
            return Err(AccountAdmissionCodecError::Binding);
        }
        Ok(())
    }
}

macro_rules! http_response {
    ($($name:ty),+ $(,)?) => {$(impl $name {
        /// Decode a complete response requiring both cache-prevention headers.
        ///
        /// The native HTTP adapter separately verifies TLS, media type, redirects and cookies.
        /// # Errors
        /// Rejects missing/incorrect cache metadata and all ordinary body validation failures.
        pub fn from_http_json(
            input: &[u8],
            cache_control: Option<&str>,
            pragma: Option<&str>,
        ) -> Result<Self, AccountAdmissionCodecError> {
            if cache_control != Some("no-store") || pragma != Some("no-cache") {
                return Err(AccountAdmissionCodecError::HttpMetadata);
            }
            Self::from_json(input)
        }
    })+};
}
http_response!(
    AccountRequestChallengeResponse,
    AccountPasswordOptionsResponse,
    AccountPasswordLoginResponse,
    AccountCommittedConfirmation
);

macro_rules! redacted { ($($name:ty),+ $(,)?) => {$(impl fmt::Debug for $name { fn fmt(&self,f:&mut fmt::Formatter<'_>)->fmt::Result { f.write_str(concat!(stringify!($name),"([REDACTED])")) } })+}; }
redacted!(
    AccountRequestChallengeResponse,
    AccountPasswordOptionsRequest,
    AccountPasswordOptionsResponse,
    AccountPasswordLoginRequest,
    AccountPasswordLoginResponse,
    AccountRegistrationRequest,
    AccountDeviceAdmissionRequest,
    AccountCommittedConfirmation
);

pub(super) fn validate_origin_username(
    origin: &str,
    username: &str,
) -> Result<(), AccountAdmissionCodecError> {
    scoplen_crypto::validate_server_origin(origin)
        .map_err(|_| AccountAdmissionCodecError::InvalidProtected)?;
    validate_username(username)
}
fn validate_username(v: &str) -> Result<(), AccountAdmissionCodecError> {
    if !(3..=64).contains(&v.len())
        || !v.as_bytes()[0].is_ascii_lowercase() && !v.as_bytes()[0].is_ascii_digit()
        || !v.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-')
        })
    {
        return Err(AccountAdmissionCodecError::InvalidJson);
    }
    Ok(())
}
struct SensitiveFields(Map<String, Value>);

impl Deref for SensitiveFields {
    type Target = Map<String, Value>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for SensitiveFields {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Drop for SensitiveFields {
    fn drop(&mut self) {
        crate::request_wire::clear_json_value(Value::Object(std::mem::take(&mut self.0)));
    }
}

fn object(input: &[u8], limit: usize) -> Result<SensitiveFields, AccountAdmissionCodecError> {
    if input.len() > limit {
        return Err(AccountAdmissionCodecError::TooLarge);
    }
    if input.starts_with(&[0xef, 0xbb, 0xbf]) {
        return Err(AccountAdmissionCodecError::InvalidJson);
    }
    crate::request_wire::decode_unique_object(input)
        .map(SensitiveFields)
        .map_err(|()| AccountAdmissionCodecError::InvalidJson)
}
fn no_extensions(f: &SensitiveFields) -> Result<(), AccountAdmissionCodecError> {
    if f.is_empty() { Ok(()) } else { Err(AccountAdmissionCodecError::InvalidJson) }
}
fn take_text(f: &mut Map<String, Value>, k: &str) -> Result<String, AccountAdmissionCodecError> {
    match f.remove(k) {
        Some(Value::String(v)) => Ok(v),
        Some(value) => {
            crate::request_wire::clear_json_value(value);
            Err(AccountAdmissionCodecError::InvalidJson)
        }
        None => Err(AccountAdmissionCodecError::InvalidJson),
    }
}
fn valid_uuid(id: Uuid) -> Result<(), AccountAdmissionCodecError> {
    validate_uuid_v7(id).map_err(|_| AccountAdmissionCodecError::InvalidJson)
}
fn take_uuid(f: &mut Map<String, Value>, k: &str) -> Result<Uuid, AccountAdmissionCodecError> {
    let text = take_text(f, k)?;
    let id = Uuid::parse_str(&text).map_err(|_| AccountAdmissionCodecError::InvalidJson)?;
    if id.to_string() != text {
        return Err(AccountAdmissionCodecError::InvalidJson);
    }
    valid_uuid(id)?;
    Ok(id)
}
fn take_bytes(
    f: &mut Map<String, Value>,
    k: &str,
    limit: usize,
) -> Result<Vec<u8>, AccountAdmissionCodecError> {
    let text = SecretVec::new(take_text(f, k)?.into_bytes());
    let encoded_limit = limit
        .checked_mul(4)
        .and_then(|n| n.checked_add(2))
        .map(|n| n / 3)
        .ok_or(AccountAdmissionCodecError::TooLarge)?;
    if text.is_empty() {
        return Err(AccountAdmissionCodecError::InvalidJson);
    }
    if text.len() > encoded_limit {
        return Err(AccountAdmissionCodecError::TooLarge);
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(text.as_bytes())
        .map_err(|_| AccountAdmissionCodecError::InvalidJson)?;
    let canonical = SecretVec::new(URL_SAFE_NO_PAD.encode(&bytes).into_bytes());
    if bytes.is_empty() || bytes.len() > limit || canonical.as_bytes() != text.as_bytes() {
        return Err(AccountAdmissionCodecError::InvalidJson);
    }
    Ok(bytes)
}
fn take_fixed<const N: usize>(
    f: &mut Map<String, Value>,
    k: &str,
) -> Result<[u8; N], AccountAdmissionCodecError> {
    let bytes = SecretVec::new(take_bytes(f, k, N)?);
    bytes.as_bytes().try_into().map_err(|_| AccountAdmissionCodecError::InvalidJson)
}
fn take_decimal(f: &mut Map<String, Value>, k: &str) -> Result<u64, AccountAdmissionCodecError> {
    let v = take_text(f, k)?;
    if v.starts_with('0') || !v.bytes().all(|b| b.is_ascii_digit()) {
        return Err(AccountAdmissionCodecError::InvalidJson);
    }
    v.parse::<u64>().ok().filter(|v| *v > 0).ok_or(AccountAdmissionCodecError::InvalidJson)
}
fn take_profile(f: &mut Map<String, Value>) -> Result<(), AccountAdmissionCodecError> {
    if f.remove("profile") == Some(Value::from(1)) {
        Ok(())
    } else {
        Err(AccountAdmissionCodecError::InvalidJson)
    }
}
fn take_kind(f: &mut Map<String, Value>) -> Result<AccountRequestKind, AccountAdmissionCodecError> {
    match take_text(f, "kind")?.as_str() {
        "register" => Ok(AccountRequestKind::Register),
        "admit" => Ok(AccountRequestKind::Admit),
        _ => Err(AccountAdmissionCodecError::InvalidJson),
    }
}
fn take_intent(
    f: &mut Map<String, Value>,
) -> Result<AccountRequestIntent, AccountAdmissionCodecError> {
    match take_text(f, "intent")?.as_str() {
        "submit" => Ok(AccountRequestIntent::Submit),
        "confirm" => Ok(AccountRequestIntent::Confirm),
        _ => Err(AccountAdmissionCodecError::InvalidJson),
    }
}
fn string(v: impl Into<String>) -> Value {
    Value::String(v.into())
}
fn b64(v: &[u8]) -> Value {
    string(URL_SAFE_NO_PAD.encode(v))
}
fn decimal(v: u64) -> Result<Value, AccountAdmissionCodecError> {
    if v == 0 { Err(AccountAdmissionCodecError::InvalidJson) } else { Ok(string(v.to_string())) }
}
fn request_fields(
    intent: AccountRequestIntent,
    payload: &[u8],
    sig: &[u8; 64],
    attempt: &[u8; 32],
    nonce: &[u8; 32],
    proof: &[u8; 64],
) -> Vec<(&'static str, Value)> {
    vec![
        ("intent", string(intent.as_str())),
        ("payload", b64(payload)),
        ("account_signature", b64(sig)),
        ("attempt_id", b64(attempt)),
        ("nonce", b64(nonce)),
        ("device_proof", b64(proof)),
    ]
}
fn json(fields: Vec<(&str, Value)>, limit: usize) -> Result<Vec<u8>, AccountAdmissionCodecError> {
    struct Ordered<'a>(&'a [(&'a str, Value)]);
    impl Serialize for Ordered<'_> {
        fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            let mut map = s.serialize_map(Some(self.0.len()))?;
            for (k, v) in self.0 {
                map.serialize_entry(k, v)?;
            }
            map.end()
        }
    }
    let out = serde_json::to_vec(&Ordered(&fields));
    for (_, value) in fields {
        crate::request_wire::clear_json_value(value);
    }
    let out = out.map_err(|_| AccountAdmissionCodecError::InvalidJson)?;
    if out.len() > limit {
        return Err(AccountAdmissionCodecError::TooLarge);
    }
    Ok(out)
}
