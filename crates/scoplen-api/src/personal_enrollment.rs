// SPDX-License-Identifier: Apache-2.0
//! Bounded K-3/K-5 JSON wire for Personal invitation and first-device enrollment.

use std::fmt;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use scoplen_crypto::{DeviceCertificate, validate_server_origin};
use scoplen_model::validate_uuid_v7;
use serde::Serialize;
use serde_json::{Map, Value};
use thiserror::Error;
use uuid::Uuid;

use crate::{certificate::valid_utc_timestamp, request_wire, sync::SyncAccountKeyBundleUpdate};

/// Maximum complete invitation issuance request, including JSON whitespace.
pub const MAX_PERSONAL_INVITATION_REQUEST_BYTES: usize = 256;
/// Maximum complete invitation issuance response, including extensions.
pub const MAX_PERSONAL_INVITATION_RESPONSE_BYTES: usize = 4_096;
/// Maximum complete first-device enrollment request, including JSON whitespace.
pub const MAX_PERSONAL_ENROLLMENT_REQUEST_BYTES: usize = 1_048_576;
/// Maximum complete first-device enrollment response, including extensions.
pub const MAX_PERSONAL_ENROLLMENT_RESPONSE_BYTES: usize = 256;
/// Maximum decoded K-2 certificate and Personal vault wrap size.
pub const MAX_PERSONAL_ENROLLMENT_ARTIFACT_BYTES: usize = 65_536;

/// Nominal source quota advertised on Personal admission rejections.
pub const PERSONAL_RATE_LIMIT_POLICY: &str = "\"personal\";q=30;w=60";

/// The public Personal admission headers contain no private bucket identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PersonalRateLimitHeaders {
    retry_after_seconds: u16,
}

/// An invalid public Personal retry delay.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("Personal retry delay must be between 1 and 300 seconds")]
pub struct PersonalRateLimitHeaderError;

impl PersonalRateLimitHeaders {
    /// Construct the D-104 header profile from the latest applicable admission delay.
    ///
    /// # Errors
    ///
    /// Rejects a delay outside 1..=300 seconds.
    pub fn new(retry_after_seconds: u16) -> Result<Self, PersonalRateLimitHeaderError> {
        if !(1..=300).contains(&retry_after_seconds) {
            return Err(PersonalRateLimitHeaderError);
        }
        Ok(Self { retry_after_seconds })
    }

    /// Decimal `Retry-After` value and `RateLimit` reset delay, in seconds.
    #[must_use]
    pub fn retry_after_seconds(self) -> u16 {
        self.retry_after_seconds
    }

    /// Exact structured `RateLimit` value with zero advertised remaining capacity.
    #[must_use]
    pub fn rate_limit(self) -> String {
        format!("\"personal\";r=0;t={}", self.retry_after_seconds)
    }

    /// Exact structured `RateLimit-Policy` value.
    #[must_use]
    pub fn rate_limit_policy(self) -> &'static str {
        PERSONAL_RATE_LIMIT_POLICY
    }
}

/// A Personal invitation or enrollment message violates its wire contract.
///
/// Errors never include submitted credentials, keys, certificates, or raw bodies.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum PersonalEnrollmentCodecError {
    /// The issuance request exceeds its complete-body limit.
    #[error("Personal invitation request exceeds 256 bytes")]
    InvitationRequestTooLarge,
    /// The issuance response exceeds its complete-body limit.
    #[error("Personal invitation response exceeds 4096 bytes")]
    InvitationResponseTooLarge,
    /// The enrollment request exceeds its complete-body limit.
    #[error("Personal enrollment request exceeds 1048576 bytes")]
    EnrollmentRequestTooLarge,
    /// The enrollment response exceeds its complete-body limit.
    #[error("Personal enrollment response exceeds 256 bytes")]
    EnrollmentResponseTooLarge,
    /// JSON is malformed, has duplicate names, or has the wrong top-level shape.
    #[error("invalid Personal enrollment JSON")]
    InvalidJson,
    /// A required field is missing, mistyped, or violates its wire bound.
    #[error("invalid Personal enrollment field: {0}")]
    InvalidField(&'static str),
    /// An endpoint received a prohibited HTTP header.
    #[error("prohibited Personal enrollment header: {0}")]
    ForbiddenHeader(&'static str),
    /// A submitted Origin does not match the configured deployment origin.
    #[error("Personal enrollment origin does not match deployment")]
    OriginMismatch,
    /// Parsed artifacts are individually valid but refer to different account or device ids.
    /// This is an enrollment denial, not a malformed-body response.
    #[error("Personal enrollment artifact identity mismatch")]
    IdentityMismatch,
}

/// Exact empty body for operator-only `POST /api/v1/admin/personal-invitations`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PersonalInvitationRequest;

impl PersonalInvitationRequest {
    /// Decode the bounded empty object. Operator authentication is owned by the consumer.
    ///
    /// # Errors
    ///
    /// Rejects malformed, unknown, duplicate, or oversized input.
    pub fn from_json(input: &[u8]) -> Result<Self, PersonalEnrollmentCodecError> {
        let fields = decode_object(
            input,
            MAX_PERSONAL_INVITATION_REQUEST_BYTES,
            PersonalEnrollmentCodecError::InvitationRequestTooLarge,
        )?;
        if !fields.is_empty() {
            return Err(PersonalEnrollmentCodecError::InvalidJson);
        }
        Ok(Self)
    }

    /// Reject an idempotency key while leaving operator authentication headers to the consumer.
    ///
    /// # Errors
    ///
    /// Rejects the prohibited header or an invalid body.
    pub fn from_http_json(
        input: &[u8],
        idempotency_key_present: bool,
    ) -> Result<Self, PersonalEnrollmentCodecError> {
        if idempotency_key_present {
            return Err(PersonalEnrollmentCodecError::ForbiddenHeader("Idempotency-Key"));
        }
        Self::from_json(input)
    }

    /// Encode the exact empty request object.
    #[must_use]
    pub fn to_json(self) -> Vec<u8> {
        b"{}".to_vec()
    }
}

/// Secret-bearing, one-time response to an authorized Personal invitation issuance.
#[derive(Clone, Eq, PartialEq)]
pub struct PersonalInvitationResponse {
    /// Same-origin `/invite#token=` URL; its fragment is a bearer credential.
    pub invitation_url: String,
    /// UTC expiration timestamp.
    pub expires_at: String,
}

impl fmt::Debug for PersonalInvitationResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("PersonalInvitationResponse").finish_non_exhaustive()
    }
}

impl PersonalInvitationResponse {
    /// Validate the canonical HTTPS invitation URL and UTC expiry.
    ///
    /// # Errors
    ///
    /// Rejects invalid fields.
    pub fn validate(&self) -> Result<(), PersonalEnrollmentCodecError> {
        let (origin, token) = self
            .invitation_url
            .rsplit_once("/invite#token=")
            .ok_or(PersonalEnrollmentCodecError::InvalidField("invitation_url"))?;
        if validate_server_origin(origin).is_err()
            || decode_fixed::<32>(token, "invitation_url").is_err()
        {
            return Err(PersonalEnrollmentCodecError::InvalidField("invitation_url"));
        }
        if !valid_utc_timestamp(&self.expires_at) {
            return Err(PersonalEnrollmentCodecError::InvalidField("expires_at"));
        }
        Ok(())
    }

    /// Decode an issuance response, ignoring additive extensions.
    ///
    /// # Errors
    ///
    /// Rejects duplicate names at every depth, malformed fields, or an oversized body.
    pub fn from_json(input: &[u8]) -> Result<Self, PersonalEnrollmentCodecError> {
        let mut fields = decode_object(
            input,
            MAX_PERSONAL_INVITATION_RESPONSE_BYTES,
            PersonalEnrollmentCodecError::InvitationResponseTooLarge,
        )?;
        let response = Self {
            invitation_url: take_string(&mut fields, "invitation_url")?,
            expires_at: take_string(&mut fields, "expires_at")?,
        };
        response.validate()?;
        Ok(response)
    }

    /// Encode only the two defined response members in contract order.
    ///
    /// # Errors
    ///
    /// Rejects invalid mutable fields or an oversized encoded body.
    pub fn to_json(&self) -> Result<Vec<u8>, PersonalEnrollmentCodecError> {
        #[derive(Serialize)]
        struct Wire<'a> {
            invitation_url: &'a str,
            expires_at: &'a str,
        }
        self.validate()?;
        let encoded = serde_json::to_vec(&Wire {
            invitation_url: &self.invitation_url,
            expires_at: &self.expires_at,
        })
        .map_err(|_| PersonalEnrollmentCodecError::InvalidJson)?;
        if encoded.len() > MAX_PERSONAL_INVITATION_RESPONSE_BYTES {
            return Err(PersonalEnrollmentCodecError::InvitationResponseTooLarge);
        }
        Ok(encoded)
    }
}

/// One invitation-bound, possession-proven first-device enrollment request.
///
/// Ordinary decoding enforces syntax and artifact identity. Structural decoding is available so
/// a consumer can admit the decoded invitation digest before rejecting an identity mismatch.
/// A consumer must still verify both signatures, invitation state and origin, uniqueness, and the
/// atomic identity transaction.
#[derive(Clone, Eq, PartialEq)]
pub struct PersonalEnrollmentRequest {
    /// Decoded one-use bearer token. Never log this value.
    pub invitation_token: [u8; 32],
    /// New account identifier.
    pub account_id: Uuid,
    /// New Personal vault identifier.
    pub personal_vault_id: Uuid,
    /// Raw Ed25519 public key for the account signature.
    pub account_signing_public_key: [u8; 32],
    /// Raw X25519 public key for the account KEM.
    pub account_kem_public_key: [u8; 32],
    /// Existing K-4 signed update at revision 1 with one device wrap.
    pub key_bundle_update: SyncAccountKeyBundleUpdate,
    /// Existing K-2 signed first-device certificate.
    pub device_certificate: DeviceCertificate,
    /// Opaque epoch-1 Personal vault key wrap to the ARK.
    pub wrapped_personal_vault_key: Vec<u8>,
    /// Fixed P-256 possession signature; verification is outside this codec.
    pub device_signature: [u8; 64],
}

impl fmt::Debug for PersonalEnrollmentRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("PersonalEnrollmentRequest").finish_non_exhaustive()
    }
}

impl PersonalEnrollmentRequest {
    /// Recheck mutable public fields, canonical artifacts, revision, and sole wrap identity.
    ///
    /// # Errors
    ///
    /// Rejects malformed or mismatched artifacts. This does not verify signatures.
    pub fn validate(&self) -> Result<(), PersonalEnrollmentCodecError> {
        self.validate_structural()?;
        self.validate_identity()
    }

    fn validate_identity(&self) -> Result<(), PersonalEnrollmentCodecError> {
        if self.device_certificate.account_id != self.account_id
            || self.device_certificate.device_id != self.key_bundle_update.device_wraps[0].device_id
        {
            return Err(PersonalEnrollmentCodecError::IdentityMismatch);
        }
        Ok(())
    }

    fn validate_structural(&self) -> Result<(), PersonalEnrollmentCodecError> {
        validate_uuid_v7(self.account_id)
            .map_err(|_| PersonalEnrollmentCodecError::InvalidField("account_id"))?;
        validate_uuid_v7(self.personal_vault_id)
            .map_err(|_| PersonalEnrollmentCodecError::InvalidField("personal_vault_id"))?;
        let bundle = self
            .key_bundle_update
            .to_cbor()
            .map_err(|_| PersonalEnrollmentCodecError::InvalidField("key_bundle_update"))?;
        if bundle.len() > MAX_PERSONAL_ENROLLMENT_REQUEST_BYTES
            || self.key_bundle_update.revision != 1
            || self.key_bundle_update.device_wraps.len() != 1
        {
            return Err(PersonalEnrollmentCodecError::InvalidField("key_bundle_update"));
        }
        let certificate = self
            .device_certificate
            .encode()
            .map_err(|_| PersonalEnrollmentCodecError::InvalidField("device_certificate"))?;
        if certificate.len() > MAX_PERSONAL_ENROLLMENT_ARTIFACT_BYTES
            || DeviceCertificate::decode(&certificate).is_err()
        {
            return Err(PersonalEnrollmentCodecError::InvalidField("device_certificate"));
        }
        if self.wrapped_personal_vault_key.is_empty()
            || self.wrapped_personal_vault_key.len() > MAX_PERSONAL_ENROLLMENT_ARTIFACT_BYTES
        {
            return Err(PersonalEnrollmentCodecError::InvalidField("wrapped_personal_vault_key"));
        }
        Ok(())
    }

    /// Decode the exact, bounded JSON request with canonical binary spellings.
    ///
    /// # Errors
    ///
    /// Rejects duplicate or unknown names, invalid fields, or oversized input.
    pub fn from_json(input: &[u8]) -> Result<Self, PersonalEnrollmentCodecError> {
        let request = Self::from_json_structural(input)?;
        request.validate_identity()?;
        Ok(request)
    }

    /// Decode strict JSON, binary artifacts, and independent field bounds before digest admission.
    ///
    /// The returned request is not yet eligible for identity creation. After admission, the
    /// consumer must call [`Self::validate`] and verify signatures, invitation state, and ids.
    ///
    /// # Errors
    ///
    /// Rejects duplicate or unknown names, malformed artifacts, invalid fields, or oversized input.
    pub fn from_json_structural(input: &[u8]) -> Result<Self, PersonalEnrollmentCodecError> {
        let mut fields = decode_object(
            input,
            MAX_PERSONAL_ENROLLMENT_REQUEST_BYTES,
            PersonalEnrollmentCodecError::EnrollmentRequestTooLarge,
        )?;
        let invitation_token =
            decode_fixed(&take_string(&mut fields, "invitation_token")?, "invitation_token")?;
        let account_id = take_uuid(&mut fields, "account_id")?;
        let personal_vault_id = take_uuid(&mut fields, "personal_vault_id")?;
        let account_signing_public_key = decode_fixed(
            &take_string(&mut fields, "account_signing_public_key")?,
            "account_signing_public_key",
        )?;
        let account_kem_public_key = decode_fixed(
            &take_string(&mut fields, "account_kem_public_key")?,
            "account_kem_public_key",
        )?;
        let key_bundle_bytes = decode_binary(
            &take_string(&mut fields, "key_bundle_update")?,
            MAX_PERSONAL_ENROLLMENT_REQUEST_BYTES,
            "key_bundle_update",
        )?;
        let key_bundle_update = SyncAccountKeyBundleUpdate::from_cbor(&key_bundle_bytes)
            .map_err(|_| PersonalEnrollmentCodecError::InvalidField("key_bundle_update"))?;
        if key_bundle_update.to_cbor().ok().as_deref() != Some(key_bundle_bytes.as_slice()) {
            return Err(PersonalEnrollmentCodecError::InvalidField("key_bundle_update"));
        }
        let certificate_bytes = decode_binary(
            &take_string(&mut fields, "device_certificate")?,
            MAX_PERSONAL_ENROLLMENT_ARTIFACT_BYTES,
            "device_certificate",
        )?;
        let device_certificate = DeviceCertificate::decode(&certificate_bytes)
            .map_err(|_| PersonalEnrollmentCodecError::InvalidField("device_certificate"))?;
        if device_certificate.encode().ok().as_deref() != Some(certificate_bytes.as_slice()) {
            return Err(PersonalEnrollmentCodecError::InvalidField("device_certificate"));
        }
        let wrapped_personal_vault_key = decode_binary(
            &take_string(&mut fields, "wrapped_personal_vault_key")?,
            MAX_PERSONAL_ENROLLMENT_ARTIFACT_BYTES,
            "wrapped_personal_vault_key",
        )?;
        let device_signature =
            decode_fixed(&take_string(&mut fields, "device_signature")?, "device_signature")?;
        if !fields.is_empty() {
            return Err(PersonalEnrollmentCodecError::InvalidJson);
        }
        let request = Self {
            invitation_token,
            account_id,
            personal_vault_id,
            account_signing_public_key,
            account_kem_public_key,
            key_bundle_update,
            device_certificate,
            wrapped_personal_vault_key,
            device_signature,
        };
        request.validate_structural()?;
        Ok(request)
    }

    /// Reject credentials and idempotency on this unauthenticated endpoint; compare Origin when present.
    ///
    /// The trusted deployment origin is validated by the consumer at startup. A mismatched
    /// browser Origin is rejected before any invitation lookup or mutation.
    ///
    /// # Errors
    ///
    /// Rejects prohibited headers, a foreign Origin, or an invalid request body.
    pub fn from_http_json(
        input: &[u8],
        authorization_present: bool,
        dpop_present: bool,
        idempotency_key_present: bool,
        origin: Option<&str>,
        deployment_origin: &str,
    ) -> Result<Self, PersonalEnrollmentCodecError> {
        let request = Self::from_http_json_structural(
            input,
            authorization_present,
            dpop_present,
            idempotency_key_present,
            origin,
            deployment_origin,
        )?;
        request.validate_identity()?;
        Ok(request)
    }

    /// Decode a strict request after prohibited-header and Origin checks, before digest admission.
    ///
    /// The consumer enforces source admission before calling this method. On success it can hash
    /// the decoded invitation token for durable digest admission without testing its existence.
    /// The consumer must call [`Self::validate`] after admission; this method does not
    /// approve artifact identity or verify any signature.
    ///
    /// # Errors
    ///
    /// Rejects prohibited headers, foreign Origin, malformed input, or independent field bounds.
    pub fn from_http_json_structural(
        input: &[u8],
        authorization_present: bool,
        dpop_present: bool,
        idempotency_key_present: bool,
        origin: Option<&str>,
        deployment_origin: &str,
    ) -> Result<Self, PersonalEnrollmentCodecError> {
        if authorization_present {
            return Err(PersonalEnrollmentCodecError::ForbiddenHeader("Authorization"));
        }
        if dpop_present {
            return Err(PersonalEnrollmentCodecError::ForbiddenHeader("DPoP"));
        }
        if idempotency_key_present {
            return Err(PersonalEnrollmentCodecError::ForbiddenHeader("Idempotency-Key"));
        }
        if origin.is_some_and(|value| value != deployment_origin) {
            return Err(PersonalEnrollmentCodecError::OriginMismatch);
        }
        Self::from_json_structural(input)
    }

    /// Encode the nine request fields in the contract's fixed order.
    ///
    /// # Errors
    ///
    /// Rejects invalid mutable fields or an oversized encoded body.
    pub fn to_json(&self) -> Result<Vec<u8>, PersonalEnrollmentCodecError> {
        #[derive(Serialize)]
        struct Wire {
            invitation_token: String,
            account_id: String,
            personal_vault_id: String,
            account_signing_public_key: String,
            account_kem_public_key: String,
            key_bundle_update: String,
            device_certificate: String,
            wrapped_personal_vault_key: String,
            device_signature: String,
        }
        self.validate()?;
        let bundle = self
            .key_bundle_update
            .to_cbor()
            .map_err(|_| PersonalEnrollmentCodecError::InvalidField("key_bundle_update"))?;
        let certificate = self
            .device_certificate
            .encode()
            .map_err(|_| PersonalEnrollmentCodecError::InvalidField("device_certificate"))?;
        let encoded = serde_json::to_vec(&Wire {
            invitation_token: URL_SAFE_NO_PAD.encode(self.invitation_token),
            account_id: self.account_id.to_string(),
            personal_vault_id: self.personal_vault_id.to_string(),
            account_signing_public_key: URL_SAFE_NO_PAD.encode(self.account_signing_public_key),
            account_kem_public_key: URL_SAFE_NO_PAD.encode(self.account_kem_public_key),
            key_bundle_update: URL_SAFE_NO_PAD.encode(bundle),
            device_certificate: URL_SAFE_NO_PAD.encode(certificate),
            wrapped_personal_vault_key: URL_SAFE_NO_PAD.encode(&self.wrapped_personal_vault_key),
            device_signature: URL_SAFE_NO_PAD.encode(self.device_signature),
        })
        .map_err(|_| PersonalEnrollmentCodecError::InvalidJson)?;
        if encoded.len() > MAX_PERSONAL_ENROLLMENT_REQUEST_BYTES {
            return Err(PersonalEnrollmentCodecError::EnrollmentRequestTooLarge);
        }
        Ok(encoded)
    }
}

/// Bounded enrollment result. It is not an authentication token.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PersonalEnrollmentResponse {
    /// Created account identifier.
    pub account_id: Uuid,
    /// First enrolled device identifier from the certificate.
    pub device_id: Uuid,
    /// Created Personal vault identifier.
    pub personal_vault_id: Uuid,
}

impl PersonalEnrollmentResponse {
    /// Validate all result identifiers.
    ///
    /// # Errors
    ///
    /// Rejects a non-v7 identifier.
    pub fn validate(&self) -> Result<(), PersonalEnrollmentCodecError> {
        for (name, id) in [
            ("account_id", self.account_id),
            ("device_id", self.device_id),
            ("personal_vault_id", self.personal_vault_id),
        ] {
            validate_uuid_v7(id).map_err(|_| PersonalEnrollmentCodecError::InvalidField(name))?;
        }
        Ok(())
    }

    /// Decode a response, ignoring additive extensions but rejecting duplicates recursively.
    ///
    /// # Errors
    ///
    /// Rejects invalid fields or a complete body over 256 bytes.
    pub fn from_json(input: &[u8]) -> Result<Self, PersonalEnrollmentCodecError> {
        let mut fields = decode_object(
            input,
            MAX_PERSONAL_ENROLLMENT_RESPONSE_BYTES,
            PersonalEnrollmentCodecError::EnrollmentResponseTooLarge,
        )?;
        let response = Self {
            account_id: take_uuid(&mut fields, "account_id")?,
            device_id: take_uuid(&mut fields, "device_id")?,
            personal_vault_id: take_uuid(&mut fields, "personal_vault_id")?,
        };
        response.validate()?;
        Ok(response)
    }

    /// Encode exactly the three result identifiers in contract order.
    ///
    /// # Errors
    ///
    /// Rejects invalid fields or an oversized body.
    pub fn to_json(&self) -> Result<Vec<u8>, PersonalEnrollmentCodecError> {
        #[derive(Serialize)]
        #[allow(clippy::struct_field_names)] // D-101 fixes the JSON field names and order.
        struct Wire {
            account_id: String,
            device_id: String,
            personal_vault_id: String,
        }
        self.validate()?;
        let encoded = serde_json::to_vec(&Wire {
            account_id: self.account_id.to_string(),
            device_id: self.device_id.to_string(),
            personal_vault_id: self.personal_vault_id.to_string(),
        })
        .map_err(|_| PersonalEnrollmentCodecError::InvalidJson)?;
        if encoded.len() > MAX_PERSONAL_ENROLLMENT_RESPONSE_BYTES {
            return Err(PersonalEnrollmentCodecError::EnrollmentResponseTooLarge);
        }
        Ok(encoded)
    }
}

fn decode_object(
    input: &[u8],
    limit: usize,
    too_large: PersonalEnrollmentCodecError,
) -> Result<Map<String, Value>, PersonalEnrollmentCodecError> {
    if input.len() > limit {
        return Err(too_large);
    }
    request_wire::decode_unique_object(input)
        .map_err(|()| PersonalEnrollmentCodecError::InvalidJson)
}

fn take_string(
    fields: &mut Map<String, Value>,
    name: &'static str,
) -> Result<String, PersonalEnrollmentCodecError> {
    fields
        .remove(name)
        .and_then(|value| value.as_str().map(str::to_owned))
        .ok_or(PersonalEnrollmentCodecError::InvalidField(name))
}

fn take_uuid(
    fields: &mut Map<String, Value>,
    name: &'static str,
) -> Result<Uuid, PersonalEnrollmentCodecError> {
    let text = take_string(fields, name)?;
    let id =
        Uuid::parse_str(&text).map_err(|_| PersonalEnrollmentCodecError::InvalidField(name))?;
    if id.to_string() != text || validate_uuid_v7(id).is_err() {
        return Err(PersonalEnrollmentCodecError::InvalidField(name));
    }
    Ok(id)
}

fn decode_fixed<const N: usize>(
    text: &str,
    name: &'static str,
) -> Result<[u8; N], PersonalEnrollmentCodecError> {
    let bytes = decode_binary(text, N, name)?;
    bytes.try_into().map_err(|_| PersonalEnrollmentCodecError::InvalidField(name))
}

fn decode_binary(
    text: &str,
    max_bytes: usize,
    name: &'static str,
) -> Result<Vec<u8>, PersonalEnrollmentCodecError> {
    if text.is_empty() || !text.is_ascii() || text.len() > max_bytes.div_ceil(3) * 4 + 2 {
        return Err(PersonalEnrollmentCodecError::InvalidField(name));
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(text)
        .map_err(|_| PersonalEnrollmentCodecError::InvalidField(name))?;
    if bytes.is_empty() || bytes.len() > max_bytes || URL_SAFE_NO_PAD.encode(&bytes) != text {
        return Err(PersonalEnrollmentCodecError::InvalidField(name));
    }
    Ok(bytes)
}
