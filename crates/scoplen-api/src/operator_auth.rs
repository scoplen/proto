// SPDX-License-Identifier: Apache-2.0
//! D-111 bounded Operator ceremony transport. Embedded `WebAuthn` bytes remain opaque.
//!
//! These codecs establish no setup entitlement, passkey authentication, `DPoP` binding, or
//! authorization. Consumers consume a live bound finish ceremony before recording an embedded
//! `WebAuthn` parsing/verification denial; an outer wire error does not consume it.

use std::{fmt, net::IpAddr};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use scoplen_crypto::validate_server_origin;
use scoplen_model::validate_uuid_v7;
use serde::{Serialize, ser::SerializeMap};
use serde_json::{Map, Value, json};
use thiserror::Error;
use uuid::Uuid;

use crate::{certificate::valid_utc_timestamp, request_wire};

/// Complete options request limit, including whitespace.
pub const MAX_OPERATOR_OPTIONS_REQUEST_BYTES: usize = 256;
/// Complete setup finish request limit, including whitespace.
pub const MAX_OPERATOR_SETUP_FINISH_BYTES: usize = 32_768;
/// Complete login finish request limit, including whitespace.
pub const MAX_OPERATOR_LOGIN_FINISH_BYTES: usize = 16_384;
/// Complete options response limit, including ignored extensions.
pub const MAX_OPERATOR_OPTIONS_RESPONSE_BYTES: usize = 4_096;
/// Complete first-Operator registration result limit.
pub const MAX_OPERATOR_SETUP_RESPONSE_BYTES: usize = 256;
/// Complete browser login token response limit; its four-field codec is shared with refresh.
pub const MAX_OPERATOR_LOGIN_RESPONSE_BYTES: usize = 8_192;
/// Complete current-family logout request limit, including whitespace.
pub const MAX_OPERATOR_LOGOUT_REQUEST_BYTES: usize = 256;
/// Complete current-family logout confirmation limit, including whitespace.
pub const MAX_OPERATOR_LOGOUT_RESPONSE_BYTES: usize = 256;
/// Maximum decoded `WebAuthn` credential id.
pub const MAX_OPERATOR_CREDENTIAL_ID_BYTES: usize = 1_023;
/// Maximum decoded original client-data JSON.
pub const MAX_OPERATOR_CLIENT_DATA_BYTES: usize = 4_096;
/// Maximum decoded registration attestation object.
pub const MAX_OPERATOR_ATTESTATION_BYTES: usize = 16_384;
/// Maximum decoded assertion authenticator data.
pub const MAX_OPERATOR_AUTHENTICATOR_DATA_BYTES: usize = 4_096;

/// A structural wire failure. Error values never contain submitted secrets or field values.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum OperatorAuthCodecError {
    /// The complete encoded body exceeds its endpoint bound.
    #[error("Operator message exceeds {0} bytes")]
    TooLarge(usize),
    /// Malformed JSON, duplicate names at any depth, or a non-object root.
    #[error("invalid Operator message JSON")]
    InvalidJson,
    /// A required field is invalid or an unknown request field is present.
    #[error("invalid Operator message field: {0}")]
    InvalidField(&'static str),
}

/// One-use setup entitlement for creating registration options; not an admin credential.
#[derive(Clone, Eq, PartialEq)]
pub struct OperatorSetupOptionsRequest {
    /// Decoded 32-byte setup bearer secret. Never log it.
    pub setup_token: [u8; 32],
}

/// First-Operator registration submission. Embedded bytes are not parsed by this codec.
#[derive(Clone, Eq, PartialEq)]
pub struct OperatorSetupFinishRequest {
    /// Decoded setup entitlement, checked separately against durable digest-only state.
    pub setup_token: [u8; 32],
    /// The server-created registration ceremony.
    pub ceremony_id: Uuid,
    /// Original `WebAuthn` raw credential id.
    pub credential_id: Vec<u8>,
    /// Original client-data bytes, hashed without reserialization by the verifier.
    pub client_data_json: Vec<u8>,
    /// Original attestation CBOR, left opaque even when malformed.
    pub attestation_object: Vec<u8>,
}

/// Usernameless login options request; no operator id, email or credential list is submitted.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct OperatorLoginOptionsRequest;

/// D-124 self-family termination request. Identity is selected only from verified credentials.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct OperatorLogoutRequest;

/// Fixed route-specific confirmation, never general current-session authorization evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperatorLogoutResponse;

/// Passkey assertion submission. Lexical decoding is not signature verification.
#[derive(Clone, Eq, PartialEq)]
pub struct OperatorLoginFinishRequest {
    /// The server-created login ceremony.
    pub ceremony_id: Uuid,
    /// Original `WebAuthn` raw credential id.
    pub credential_id: Vec<u8>,
    /// Original client-data bytes.
    pub client_data_json: Vec<u8>,
    /// Original authenticator data, including flags and signature counter.
    pub authenticator_data: Vec<u8>,
    /// `WebAuthn` ES256 ASN.1 DER signature; not `DPoP`'s fixed-width signature.
    pub signature: Vec<u8>,
    /// The mandatory discoverable credential's raw Operator UUID handle.
    pub user_handle: [u8; 16],
}

/// Safe public projection of registration options and their server-selected state.
#[derive(Clone, Eq, PartialEq)]
pub struct OperatorSetupOptionsResponse {
    /// Saved registration ceremony UUID.
    pub ceremony_id: Uuid,
    /// Saved whole-second UTC expiry.
    pub expires_at: String,
    /// Prospective Operator UUID used for both `WebAuthn` user handle and name.
    pub operator_id: Uuid,
    /// Configured canonical DNS RP, without scheme or port.
    pub rp_id: String,
    /// Saved 32-byte random challenge.
    pub challenge: [u8; 32],
    /// Remaining whole ceremony seconds expressed as milliseconds, 1000..300000.
    pub timeout: u32,
}

/// Safe public projection of discoverable login options.
#[derive(Clone, Eq, PartialEq)]
pub struct OperatorLoginOptionsResponse {
    /// Saved authentication ceremony UUID.
    pub ceremony_id: Uuid,
    /// Saved whole-second UTC expiry.
    pub expires_at: String,
    /// Configured canonical DNS RP.
    pub rp_id: String,
    /// Saved 32-byte random challenge.
    pub challenge: [u8; 32],
}

/// Registration result; no token, cookie, Account, Device or Personal vault is created here.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperatorSetupFinishResponse {
    /// Newly created independent Operator.
    pub operator_id: Uuid,
}

macro_rules! redacted_debug {
    ($($message:ty),+ $(,)?) => {$ (
        impl fmt::Debug for $message {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.debug_struct(stringify!($message)).finish_non_exhaustive()
            }
        }
    )+ };
}
redacted_debug!(
    OperatorSetupOptionsRequest,
    OperatorSetupFinishRequest,
    OperatorLoginFinishRequest,
    OperatorSetupOptionsResponse,
    OperatorLoginOptionsResponse,
);

impl OperatorSetupOptionsRequest {
    /// Decode the exact bounded request.
    ///
    /// # Errors
    /// Rejects malformed, noncanonical, unknown, duplicate or oversized input.
    pub fn from_json(input: &[u8]) -> Result<Self, OperatorAuthCodecError> {
        let mut fields = object(input, MAX_OPERATOR_OPTIONS_REQUEST_BYTES)?;
        let setup_token = fixed(&mut fields, "setup_token")?;
        no_extra(&fields)?;
        Ok(Self { setup_token })
    }

    /// Encode the entitlement once in canonical base64url.
    ///
    /// # Errors
    /// Rejects an encoding failure or oversized output.
    pub fn to_json(&self) -> Result<Vec<u8>, OperatorAuthCodecError> {
        encode(&[("setup_token", binary(&self.setup_token))], MAX_OPERATOR_OPTIONS_REQUEST_BYTES)
    }
}

impl OperatorSetupFinishRequest {
    /// Decode only the outer wire. Invalid embedded `WebAuthn` JSON/CBOR stays opaque.
    ///
    /// # Errors
    /// Rejects outer JSON, unknown names, field bounds and noncanonical encodings.
    pub fn from_json(input: &[u8]) -> Result<Self, OperatorAuthCodecError> {
        let mut fields = object(input, MAX_OPERATOR_SETUP_FINISH_BYTES)?;
        let request = Self {
            setup_token: fixed(&mut fields, "setup_token")?,
            ceremony_id: take_uuid(&mut fields, "ceremony_id")?,
            credential_id: bytes(
                &mut fields,
                "credential_id",
                1,
                MAX_OPERATOR_CREDENTIAL_ID_BYTES,
            )?,
            client_data_json: bytes(
                &mut fields,
                "client_data_json",
                1,
                MAX_OPERATOR_CLIENT_DATA_BYTES,
            )?,
            attestation_object: bytes(
                &mut fields,
                "attestation_object",
                1,
                MAX_OPERATOR_ATTESTATION_BYTES,
            )?,
        };
        no_extra(&fields)?;
        Ok(request)
    }

    /// Encode fixed request fields in contract order, preserving embedded original bytes.
    ///
    /// # Errors
    /// Rejects invalid mutable fields or an oversized output.
    pub fn to_json(&self) -> Result<Vec<u8>, OperatorAuthCodecError> {
        uuid(self.ceremony_id, "ceremony_id")?;
        bound(&self.credential_id, 1, MAX_OPERATOR_CREDENTIAL_ID_BYTES, "credential_id")?;
        bound(&self.client_data_json, 1, MAX_OPERATOR_CLIENT_DATA_BYTES, "client_data_json")?;
        bound(&self.attestation_object, 1, MAX_OPERATOR_ATTESTATION_BYTES, "attestation_object")?;
        encode(
            &[
                ("setup_token", binary(&self.setup_token)),
                ("ceremony_id", json!(self.ceremony_id.to_string())),
                ("credential_id", binary(&self.credential_id)),
                ("client_data_json", binary(&self.client_data_json)),
                ("attestation_object", binary(&self.attestation_object)),
            ],
            MAX_OPERATOR_SETUP_FINISH_BYTES,
        )
    }
}

impl OperatorLoginOptionsRequest {
    /// Decode only an empty object within the complete-body bound.
    ///
    /// # Errors
    /// Rejects malformed or nonempty requests and oversized bodies.
    pub fn from_json(input: &[u8]) -> Result<Self, OperatorAuthCodecError> {
        no_extra(&object(input, MAX_OPERATOR_OPTIONS_REQUEST_BYTES)?)?;
        Ok(Self)
    }

    /// Encode the empty object.
    ///
    /// # Errors
    /// The shared encoder can report a JSON encoding error.
    pub fn to_json(self) -> Result<Vec<u8>, OperatorAuthCodecError> {
        Ok(b"{}".to_vec())
    }
}

impl OperatorLoginFinishRequest {
    /// Decode lexical bounds without interpreting or verifying embedded `WebAuthn` bytes.
    ///
    /// # Errors
    /// Rejects outer syntax, unknown fields, UUIDs, byte bounds or base64url aliases.
    pub fn from_json(input: &[u8]) -> Result<Self, OperatorAuthCodecError> {
        let mut fields = object(input, MAX_OPERATOR_LOGIN_FINISH_BYTES)?;
        let request = Self {
            ceremony_id: take_uuid(&mut fields, "ceremony_id")?,
            credential_id: bytes(
                &mut fields,
                "credential_id",
                1,
                MAX_OPERATOR_CREDENTIAL_ID_BYTES,
            )?,
            client_data_json: bytes(
                &mut fields,
                "client_data_json",
                1,
                MAX_OPERATOR_CLIENT_DATA_BYTES,
            )?,
            authenticator_data: bytes(
                &mut fields,
                "authenticator_data",
                37,
                MAX_OPERATOR_AUTHENTICATOR_DATA_BYTES,
            )?,
            signature: bytes(&mut fields, "signature", 8, 72)?,
            user_handle: fixed(&mut fields, "user_handle")?,
        };
        no_extra(&fields)?;
        Ok(request)
    }

    /// Encode the six original-byte fields in contract order.
    ///
    /// # Errors
    /// Rejects invalid mutable fields or an oversized output.
    pub fn to_json(&self) -> Result<Vec<u8>, OperatorAuthCodecError> {
        uuid(self.ceremony_id, "ceremony_id")?;
        bound(&self.credential_id, 1, MAX_OPERATOR_CREDENTIAL_ID_BYTES, "credential_id")?;
        bound(&self.client_data_json, 1, MAX_OPERATOR_CLIENT_DATA_BYTES, "client_data_json")?;
        bound(
            &self.authenticator_data,
            37,
            MAX_OPERATOR_AUTHENTICATOR_DATA_BYTES,
            "authenticator_data",
        )?;
        bound(&self.signature, 8, 72, "signature")?;
        encode(
            &[
                ("ceremony_id", json!(self.ceremony_id.to_string())),
                ("credential_id", binary(&self.credential_id)),
                ("client_data_json", binary(&self.client_data_json)),
                ("authenticator_data", binary(&self.authenticator_data)),
                ("signature", binary(&self.signature)),
                ("user_handle", binary(&self.user_handle)),
            ],
            MAX_OPERATOR_LOGIN_FINISH_BYTES,
        )
    }
}

impl OperatorSetupOptionsResponse {
    /// Parse the defined options policy while tolerating additive response extensions.
    ///
    /// # Errors
    /// Rejects invalid fixed policy, bounds, duplicate names, RP, UUIDs or expiry.
    pub fn from_json(input: &[u8]) -> Result<Self, OperatorAuthCodecError> {
        let mut fields = object(input, MAX_OPERATOR_OPTIONS_RESPONSE_BYTES)?;
        let ceremony_id = take_uuid(&mut fields, "ceremony_id")?;
        let expires_at = text(&mut fields, "expires_at")?;
        let mut options = take_object(&mut fields, "public_key")?;
        let challenge = fixed(&mut options, "challenge")?;
        let timeout = take_timeout(&mut options)?;
        let mut rp = take_object(&mut options, "rp")?;
        let rp_id = text(&mut rp, "id")?;
        require_text(&mut rp, "name", "Scoplen")?;
        let mut user = take_object(&mut options, "user")?;
        let operator_id = Uuid::from_bytes(fixed(&mut user, "id")?);
        require_text(&mut user, "name", &format!("operator:{operator_id}"))?;
        require_text(&mut user, "displayName", "Deployment operator")?;
        let Some(Value::Array(params)) = options.remove("pubKeyCredParams") else {
            return invalid("pubKeyCredParams");
        };
        if params.len() != 1 {
            return invalid("pubKeyCredParams");
        }
        let mut parameter = params[0]
            .as_object()
            .cloned()
            .ok_or(OperatorAuthCodecError::InvalidField("pubKeyCredParams"))?;
        require_text(&mut parameter, "type", "public-key")?;
        if parameter.remove("alg") != Some(json!(-7)) {
            return invalid("alg");
        }
        require_empty_array(&mut options, "excludeCredentials")?;
        require_text(&mut options, "attestation", "none")?;
        let mut selection = take_object(&mut options, "authenticatorSelection")?;
        require_text(&mut selection, "residentKey", "required")?;
        require_text(&mut selection, "userVerification", "required")?;
        if selection.remove("requireResidentKey") != Some(Value::Bool(true)) {
            return invalid("requireResidentKey");
        }
        let response = Self { ceremony_id, expires_at, operator_id, rp_id, challenge, timeout };
        response.validate()?;
        Ok(response)
    }

    /// Check projected data without claiming agreement with a consumer's private library state.
    ///
    /// # Errors
    /// Rejects non-DNS RP, invalid UUID, expiry or timeout.
    pub fn validate(&self) -> Result<(), OperatorAuthCodecError> {
        common_options(self.ceremony_id, &self.expires_at, &self.rp_id)?;
        uuid(self.operator_id, "operator_id")?;
        if !(1_000..=300_000).contains(&self.timeout) || !self.timeout.is_multiple_of(1_000) {
            return invalid("timeout");
        }
        Ok(())
    }

    /// Encode the exact public policy from server-selected registration state.
    ///
    /// # Errors
    /// Rejects invalid fields or an oversized response.
    pub fn to_json(&self) -> Result<Vec<u8>, OperatorAuthCodecError> {
        self.validate()?;
        encode(
            &[
                ("ceremony_id", json!(self.ceremony_id.to_string())),
                ("expires_at", json!(self.expires_at)),
                (
                    "public_key",
                    json!({
                        "rp": {"id": self.rp_id, "name": "Scoplen"},
                        "user": {"id": URL_SAFE_NO_PAD.encode(self.operator_id.as_bytes()), "name": format!("operator:{}",self.operator_id), "displayName": "Deployment operator"},
                        "challenge": URL_SAFE_NO_PAD.encode(self.challenge),
                        "pubKeyCredParams": [{"type":"public-key","alg":-7}],
                        "timeout": self.timeout, "excludeCredentials": [],
                        "authenticatorSelection": {"residentKey":"required","requireResidentKey":true,"userVerification":"required"},
                        "attestation":"none"
                    }),
                ),
            ],
            MAX_OPERATOR_OPTIONS_RESPONSE_BYTES,
        )
    }
}

impl OperatorLoginOptionsResponse {
    /// Parse bounded discoverable options, rejecting a credential allow-list or weaker UV.
    ///
    /// # Errors
    /// Rejects malformed data or a different required policy.
    pub fn from_json(input: &[u8]) -> Result<Self, OperatorAuthCodecError> {
        let mut fields = object(input, MAX_OPERATOR_OPTIONS_RESPONSE_BYTES)?;
        let ceremony_id = take_uuid(&mut fields, "ceremony_id")?;
        let expires_at = text(&mut fields, "expires_at")?;
        let mut options = take_object(&mut fields, "public_key")?;
        let challenge = fixed(&mut options, "challenge")?;
        if take_timeout(&mut options)? != 300_000 {
            return invalid("timeout");
        }
        let rp_id = text(&mut options, "rpId")?;
        require_empty_array(&mut options, "allowCredentials")?;
        require_text(&mut options, "userVerification", "required")?;
        let response = Self { ceremony_id, expires_at, rp_id, challenge };
        response.validate()?;
        Ok(response)
    }

    /// Validate UUID, whole-second UTC expiry and canonical DNS RP syntax.
    ///
    /// # Errors
    /// Rejects an invalid mutable field.
    pub fn validate(&self) -> Result<(), OperatorAuthCodecError> {
        common_options(self.ceremony_id, &self.expires_at, &self.rp_id)
    }

    /// Encode the required usernameless login policy.
    ///
    /// # Errors
    /// Rejects invalid fields or an oversized output.
    pub fn to_json(&self) -> Result<Vec<u8>, OperatorAuthCodecError> {
        self.validate()?;
        encode(
            &[
                ("ceremony_id", json!(self.ceremony_id.to_string())),
                ("expires_at", json!(self.expires_at)),
                (
                    "public_key",
                    json!({"challenge":URL_SAFE_NO_PAD.encode(self.challenge), "timeout":300_000,"rpId":self.rp_id,"allowCredentials":[],"userVerification":"required"}),
                ),
            ],
            MAX_OPERATOR_OPTIONS_RESPONSE_BYTES,
        )
    }
}

impl OperatorSetupFinishResponse {
    /// Decode a bounded result with unknown additive response extensions.
    ///
    /// # Errors
    /// Rejects malformed, duplicate, oversized or invalid UUID input.
    pub fn from_json(input: &[u8]) -> Result<Self, OperatorAuthCodecError> {
        let mut fields = object(input, MAX_OPERATOR_SETUP_RESPONSE_BYTES)?;
        Ok(Self { operator_id: take_uuid(&mut fields, "operator_id")? })
    }

    /// Encode only the independent Operator id; never a session.
    ///
    /// # Errors
    /// Rejects an invalid UUID or encoding failure.
    pub fn to_json(&self) -> Result<Vec<u8>, OperatorAuthCodecError> {
        uuid(self.operator_id, "operator_id")?;
        encode(
            &[("operator_id", json!(self.operator_id.to_string()))],
            MAX_OPERATOR_SETUP_RESPONSE_BYTES,
        )
    }
}

impl OperatorLogoutRequest {
    /// Decode only the empty object within the complete encoded-body bound.
    ///
    /// # Errors
    /// Rejects malformed, duplicate, nonempty, non-object or oversized input.
    pub fn from_json(input: &[u8]) -> Result<Self, OperatorAuthCodecError> {
        no_extra(&object(input, MAX_OPERATOR_LOGOUT_REQUEST_BYTES)?)?;
        Ok(Self)
    }

    /// Encode exactly `{}` without a caller-selected identity or refresh credential.
    ///
    /// # Errors
    /// This fixed representation cannot fail.
    pub fn to_json(self) -> Result<Vec<u8>, OperatorAuthCodecError> {
        Ok(b"{}".to_vec())
    }
}

impl OperatorLogoutResponse {
    /// Decode only the fixed true confirmation for the request that received it.
    ///
    /// # Errors
    /// Rejects false, missing, duplicate, unknown, mistyped or oversized fields.
    pub fn from_json(input: &[u8]) -> Result<Self, OperatorAuthCodecError> {
        let mut fields = object(input, MAX_OPERATOR_LOGOUT_RESPONSE_BYTES)?;
        if fields.remove("revoked") != Some(Value::Bool(true)) {
            return invalid("revoked");
        }
        no_extra(&fields)?;
        Ok(Self)
    }

    /// Encode only `{"revoked":true}`; it carries no token or session identity.
    ///
    /// # Errors
    /// This fixed representation cannot fail.
    pub fn to_json(self) -> Result<Vec<u8>, OperatorAuthCodecError> {
        Ok(b"{\"revoked\":true}".to_vec())
    }
}

fn invalid<T>(name: &'static str) -> Result<T, OperatorAuthCodecError> {
    Err(OperatorAuthCodecError::InvalidField(name))
}

fn object(input: &[u8], limit: usize) -> Result<Map<String, Value>, OperatorAuthCodecError> {
    if input.len() > limit {
        return Err(OperatorAuthCodecError::TooLarge(limit));
    }
    request_wire::decode_unique_object(input).map_err(|()| OperatorAuthCodecError::InvalidJson)
}

fn no_extra(fields: &Map<String, Value>) -> Result<(), OperatorAuthCodecError> {
    if fields.is_empty() { Ok(()) } else { invalid("unknown") }
}

fn text(
    fields: &mut Map<String, Value>,
    name: &'static str,
) -> Result<String, OperatorAuthCodecError> {
    fields
        .remove(name)
        .and_then(|value| value.as_str().map(str::to_owned))
        .ok_or(OperatorAuthCodecError::InvalidField(name))
}

fn take_object(
    fields: &mut Map<String, Value>,
    name: &'static str,
) -> Result<Map<String, Value>, OperatorAuthCodecError> {
    match fields.remove(name) {
        Some(Value::Object(value)) => Ok(value),
        _ => invalid(name),
    }
}

fn require_text(
    fields: &mut Map<String, Value>,
    name: &'static str,
    expected: &str,
) -> Result<(), OperatorAuthCodecError> {
    if text(fields, name)? == expected { Ok(()) } else { invalid(name) }
}

fn require_empty_array(
    fields: &mut Map<String, Value>,
    name: &'static str,
) -> Result<(), OperatorAuthCodecError> {
    if fields.remove(name) == Some(Value::Array(Vec::new())) { Ok(()) } else { invalid(name) }
}

fn take_uuid(
    fields: &mut Map<String, Value>,
    name: &'static str,
) -> Result<Uuid, OperatorAuthCodecError> {
    let text = text(fields, name)?;
    let id = Uuid::parse_str(&text).map_err(|_| OperatorAuthCodecError::InvalidField(name))?;
    uuid(id, name)?;
    if id.to_string() != text {
        return invalid(name);
    }
    Ok(id)
}

fn uuid(id: Uuid, name: &'static str) -> Result<(), OperatorAuthCodecError> {
    validate_uuid_v7(id).map_err(|_| OperatorAuthCodecError::InvalidField(name))
}

fn bytes(
    fields: &mut Map<String, Value>,
    name: &'static str,
    min: usize,
    max: usize,
) -> Result<Vec<u8>, OperatorAuthCodecError> {
    let encoded = text(fields, name)?;
    if encoded.len() > max.div_ceil(3) * 4 {
        return invalid(name);
    }
    let decoded =
        URL_SAFE_NO_PAD.decode(&encoded).map_err(|_| OperatorAuthCodecError::InvalidField(name))?;
    bound(&decoded, min, max, name)?;
    if URL_SAFE_NO_PAD.encode(&decoded) != encoded {
        return invalid(name);
    }
    Ok(decoded)
}

fn fixed<const N: usize>(
    fields: &mut Map<String, Value>,
    name: &'static str,
) -> Result<[u8; N], OperatorAuthCodecError> {
    bytes(fields, name, N, N)?.try_into().map_err(|_| OperatorAuthCodecError::InvalidField(name))
}

fn bound(
    value: &[u8],
    min: usize,
    max: usize,
    name: &'static str,
) -> Result<(), OperatorAuthCodecError> {
    if (min..=max).contains(&value.len()) { Ok(()) } else { invalid(name) }
}

fn binary(value: &[u8]) -> Value {
    Value::String(URL_SAFE_NO_PAD.encode(value))
}

fn take_timeout(fields: &mut Map<String, Value>) -> Result<u32, OperatorAuthCodecError> {
    fields
        .remove("timeout")
        .and_then(|value| value.as_u64())
        .and_then(|value| u32::try_from(value).ok())
        .ok_or(OperatorAuthCodecError::InvalidField("timeout"))
}

fn common_options(id: Uuid, expiry: &str, rp: &str) -> Result<(), OperatorAuthCodecError> {
    uuid(id, "ceremony_id")?;
    if expiry.len() != 20 || !valid_utc_timestamp(expiry) {
        return invalid("expires_at");
    }
    if rp.parse::<IpAddr>().is_ok()
        || rp.contains([':', '/', '[', ']'])
        || validate_server_origin(&format!("https://{rp}")).is_err()
    {
        return invalid("rp_id");
    }
    Ok(())
}

fn encode(fields: &[(&str, Value)], limit: usize) -> Result<Vec<u8>, OperatorAuthCodecError> {
    // A consumer can enable serde_json/preserve_order through feature unification.
    // Nested public objects retain canonical key order regardless of that feature.
    struct CanonicalValue<'a>(&'a Value);
    impl Serialize for CanonicalValue<'_> {
        fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            match self.0 {
                Value::Object(fields) => fields
                    .iter()
                    .map(|(name, value)| (name, CanonicalValue(value)))
                    .collect::<std::collections::BTreeMap<_, _>>()
                    .serialize(serializer),
                Value::Array(values) => {
                    values.iter().map(CanonicalValue).collect::<Vec<_>>().serialize(serializer)
                }
                value => value.serialize(serializer),
            }
        }
    }
    struct OrderedFields<'a>(&'a [(&'a str, Value)]);
    impl Serialize for OrderedFields<'_> {
        fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            let mut map = serializer.serialize_map(Some(self.0.len()))?;
            for (key, value) in self.0 {
                map.serialize_entry(key, &CanonicalValue(value))?;
            }
            map.end()
        }
    }
    let output = serde_json::to_vec(&OrderedFields(fields))
        .map_err(|_| OperatorAuthCodecError::InvalidJson)?;
    if output.len() > limit {
        return Err(OperatorAuthCodecError::TooLarge(limit));
    }
    Ok(output)
}
