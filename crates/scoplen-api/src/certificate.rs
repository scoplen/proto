// SPDX-License-Identifier: Apache-2.0
//! Bounded K-5 user-certificate issuance request and response.

use std::{collections::HashSet, fmt};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use scoplen_model::validate_uuid_v7;
use serde::Serialize;
use serde_json::{Map, Value};
use ssh_key::{Certificate, certificate::CertType};
use thiserror::Error;
use uuid::Uuid;

use crate::request_wire;

/// Maximum complete UTF-8 JSON request body, including whitespace and escapes.
pub const MAX_CERTIFICATE_ISSUANCE_REQUEST_BYTES: usize = 16_384;
/// Maximum number of Host or `HostGroup` selectors in one request.
pub const MAX_CERTIFICATE_ISSUANCE_TARGETS: usize = 64;
/// Maximum requested certificate lifetime in seconds.
pub const MAX_CERTIFICATE_TTL_SECONDS: u32 = 86_400;
/// Maximum complete encoded certificate Resource response.
pub const MAX_CERTIFICATE_ISSUANCE_RESPONSE_BYTES: usize = 131_072;
/// Maximum canonical certificate line in the Resource data.
pub const MAX_CERTIFICATE_LINE_BYTES: usize = 88 * 1_024;
/// Maximum decoded OpenSSH certificate blob.
pub const MAX_CERTIFICATE_BLOB_BYTES: usize = 64 * 1_024;

/// A user-certificate issuance request failed its wire contract.
///
/// Error text does not include the submitted key, username, or selectors.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum CertificateRequestCodecError {
    /// The complete encoded body exceeds 16,384 bytes.
    #[error("certificate request exceeds 16384 bytes")]
    RequestTooLarge,
    /// The JSON body has an invalid shape or duplicate or unknown fields.
    #[error("invalid certificate request JSON")]
    InvalidJson,
    /// A required field is missing, mistyped, or invalid.
    #[error("invalid certificate request field: {0}")]
    InvalidField(&'static str),
}

/// A certificate Resource response failed its bounded wire contract.
///
/// Diagnostics never include the certificate, entity tag, or request key.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum CertificateResponseCodecError {
    /// The complete JSON response exceeds 131,072 bytes.
    #[error("certificate response exceeds 131072 bytes")]
    ResponseTooLarge,
    /// The body is malformed JSON or has duplicate names at any depth.
    #[error("invalid certificate response JSON")]
    InvalidJson,
    /// A required response field is missing or invalid.
    #[error("invalid certificate response field: {0}")]
    InvalidField(&'static str),
    /// HTTP entity tag or cache-prevention metadata does not match the body contract.
    #[error("invalid certificate response HTTP metadata")]
    HttpMetadata,
    /// The original request has invalid public fields.
    #[error("invalid certificate issuance request")]
    InvalidRequest,
    /// The returned certificate's raw subject key differs from the requested key.
    #[error("certificate subject key differs from request")]
    SubjectMismatch,
}

/// Exactly one ordered, non-empty selector list.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CertificateTargets {
    /// Host identifiers in caller order.
    Hosts(Vec<Uuid>),
    /// `HostGroup` identifiers in caller order.
    HostGroups(Vec<Uuid>),
}

impl CertificateTargets {
    fn ids(&self) -> &[Uuid] {
        match self {
            Self::Hosts(ids) | Self::HostGroups(ids) => ids,
        }
    }

    fn field(&self) -> &'static str {
        match self {
            Self::Hosts(_) => "hosts",
            Self::HostGroups(_) => "host_groups",
        }
    }

    fn validate(&self) -> Result<(), CertificateRequestCodecError> {
        let ids = self.ids();
        if ids.is_empty() || ids.len() > MAX_CERTIFICATE_ISSUANCE_TARGETS {
            return Err(CertificateRequestCodecError::InvalidField(self.field()));
        }
        let mut seen = HashSet::with_capacity(ids.len());
        for id in ids {
            validate_uuid_v7(*id)
                .map_err(|_| CertificateRequestCodecError::InvalidField(self.field()))?;
            if !seen.insert(id) {
                return Err(CertificateRequestCodecError::InvalidField(self.field()));
            }
        }
        Ok(())
    }
}

/// Exact request for `POST /api/v1/orgs/{org}/certificates`.
#[derive(Clone, Eq, PartialEq)]
pub struct CertificateIssuanceRequest {
    /// Canonical single-line raw OpenSSH public key.
    pub public_key: String,
    /// Exactly one Host or `HostGroup` selector list.
    pub targets: CertificateTargets,
    /// SSH username, preserved byte for byte.
    pub remote_user: String,
    /// Requested positive lifetime, before policy and grant caps.
    pub ttl_seconds: u32,
}

impl fmt::Debug for CertificateIssuanceRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CertificateIssuanceRequest")
            .field("public_key_bytes", &self.public_key.len())
            .field("selector_kind", &self.targets.field())
            .field("selector_count", &self.targets.ids().len())
            .field("remote_user_bytes", &self.remote_user.len())
            .field("ttl_seconds", &self.ttl_seconds)
            .finish()
    }
}

impl CertificateIssuanceRequest {
    /// Construct a request and validate every public field.
    ///
    /// # Errors
    ///
    /// Rejects an invalid key, selector list, username, or lifetime.
    pub fn new(
        public_key: impl Into<String>,
        targets: CertificateTargets,
        remote_user: impl Into<String>,
        ttl_seconds: u32,
    ) -> Result<Self, CertificateRequestCodecError> {
        let request = Self {
            public_key: public_key.into(),
            targets,
            remote_user: remote_user.into(),
            ttl_seconds,
        };
        request.validate()?;
        Ok(request)
    }

    /// Validate all fields before using or encoding this request.
    ///
    /// # Errors
    ///
    /// Rejects an invalid key, selector list, username, or lifetime.
    pub fn validate(&self) -> Result<(), CertificateRequestCodecError> {
        if !request_wire::valid_raw_ssh_public_key(&self.public_key) {
            return Err(CertificateRequestCodecError::InvalidField("public_key"));
        }
        self.targets.validate()?;
        if !request_wire::valid_remote_user(&self.remote_user) {
            return Err(CertificateRequestCodecError::InvalidField("remote_user"));
        }
        if self.ttl_seconds == 0 || self.ttl_seconds > MAX_CERTIFICATE_TTL_SECONDS {
            return Err(CertificateRequestCodecError::InvalidField("ttl_seconds"));
        }
        Ok(())
    }

    /// Decode a bounded JSON body, rejecting duplicate keys and unknown fields.
    ///
    /// # Errors
    ///
    /// Rejects malformed, oversized, missing, mistyped, duplicate, or invalid input.
    pub fn from_json(input: &[u8]) -> Result<Self, CertificateRequestCodecError> {
        if input.len() > MAX_CERTIFICATE_ISSUANCE_REQUEST_BYTES {
            return Err(CertificateRequestCodecError::RequestTooLarge);
        }
        let mut fields = request_wire::decode_unique_object(input)
            .map_err(|()| CertificateRequestCodecError::InvalidJson)?;
        let public_key = take_string(&mut fields, "public_key")?;
        let targets = match (fields.remove("hosts"), fields.remove("host_groups")) {
            (Some(value), None) => CertificateTargets::Hosts(parse_ids(value, "hosts")?),
            (None, Some(value)) => CertificateTargets::HostGroups(parse_ids(value, "host_groups")?),
            _ => return Err(CertificateRequestCodecError::InvalidField("hosts or host_groups")),
        };
        let remote_user = take_string(&mut fields, "remote_user")?;
        let ttl_seconds = fields
            .remove("ttl_seconds")
            .and_then(|value| value.as_u64())
            .and_then(|value| u32::try_from(value).ok())
            .ok_or(CertificateRequestCodecError::InvalidField("ttl_seconds"))?;
        if !fields.is_empty() {
            return Err(CertificateRequestCodecError::InvalidJson);
        }
        Self::new(public_key, targets, remote_user, ttl_seconds)
    }

    /// Encode the validated request with the specified stable member order.
    ///
    /// # Errors
    ///
    /// Rejects invalid fields or an encoded body above 16,384 bytes.
    pub fn to_json(&self) -> Result<Vec<u8>, CertificateRequestCodecError> {
        #[derive(Serialize)]
        struct Wire<'a> {
            public_key: &'a str,
            #[serde(skip_serializing_if = "Option::is_none")]
            hosts: Option<Vec<String>>,
            #[serde(skip_serializing_if = "Option::is_none")]
            host_groups: Option<Vec<String>>,
            remote_user: &'a str,
            ttl_seconds: u32,
        }

        self.validate()?;
        let ids = self.targets.ids().iter().map(ToString::to_string).collect();
        let (hosts, host_groups) = match &self.targets {
            CertificateTargets::Hosts(_) => (Some(ids), None),
            CertificateTargets::HostGroups(_) => (None, Some(ids)),
        };
        let encoded = serde_json::to_vec(&Wire {
            public_key: &self.public_key,
            hosts,
            host_groups,
            remote_user: &self.remote_user,
            ttl_seconds: self.ttl_seconds,
        })
        .map_err(|_| CertificateRequestCodecError::InvalidJson)?;
        if encoded.len() > MAX_CERTIFICATE_ISSUANCE_REQUEST_BYTES {
            return Err(CertificateRequestCodecError::RequestTooLarge);
        }
        Ok(encoded)
    }
}

/// The bounded certificate Resource returned by successful user-certificate issuance.
///
/// Its certificate is parsed for canonical syntax and shape, but its signature and CA trust are
/// not verified here. Consumers must validate it at the SSH trust boundary before use.
#[derive(Clone, Eq, PartialEq)]
pub struct CertificateIssuanceResponse {
    /// Certificate resource identifier.
    pub id: Uuid,
    /// Strong HTTP entity tag, including double quotes.
    pub etag: String,
    /// UTC creation timestamp.
    pub created_at: String,
    /// UTC update timestamp.
    pub updated_at: String,
    /// Canonical single-line OpenSSH user certificate from `data.certificate`.
    pub certificate: String,
}

impl fmt::Debug for CertificateIssuanceResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CertificateIssuanceResponse")
            .field("certificate_bytes", &self.certificate.len())
            .finish_non_exhaustive()
    }
}

impl CertificateIssuanceResponse {
    /// Construct and validate a certificate Resource.
    ///
    /// # Errors
    ///
    /// Rejects invalid resource metadata or certificate syntax and shape.
    pub fn new(
        id: Uuid,
        etag: impl Into<String>,
        created_at: impl Into<String>,
        updated_at: impl Into<String>,
        certificate: impl Into<String>,
    ) -> Result<Self, CertificateResponseCodecError> {
        let response = Self {
            id,
            etag: etag.into(),
            created_at: created_at.into(),
            updated_at: updated_at.into(),
            certificate: certificate.into(),
        };
        response.validate()?;
        Ok(response)
    }

    /// Validate resource metadata and canonical certificate shape.
    ///
    /// # Errors
    ///
    /// Rejects invalid public fields, even after a caller mutates them.
    pub fn validate(&self) -> Result<(), CertificateResponseCodecError> {
        self.validated_certificate().map(|_| ())
    }

    fn validated_certificate(&self) -> Result<Certificate, CertificateResponseCodecError> {
        validate_uuid_v7(self.id).map_err(|_| CertificateResponseCodecError::InvalidField("id"))?;
        if !valid_strong_etag(&self.etag) {
            return Err(CertificateResponseCodecError::InvalidField("etag"));
        }
        if !valid_utc_timestamp(&self.created_at) {
            return Err(CertificateResponseCodecError::InvalidField("created_at"));
        }
        if !valid_utc_timestamp(&self.updated_at) {
            return Err(CertificateResponseCodecError::InvalidField("updated_at"));
        }
        parse_certificate_line(&self.certificate)
    }

    /// Decode a complete bounded JSON Resource, ignoring unknown response extensions.
    ///
    /// Duplicate field names at every depth, including ignored extensions, are rejected.
    ///
    /// # Errors
    ///
    /// Rejects malformed, missing, duplicate, invalid, or oversized input.
    pub fn from_json(input: &[u8]) -> Result<Self, CertificateResponseCodecError> {
        if input.len() > MAX_CERTIFICATE_ISSUANCE_RESPONSE_BYTES {
            return Err(CertificateResponseCodecError::ResponseTooLarge);
        }
        let mut fields = request_wire::decode_unique_object(input)
            .map_err(|()| CertificateResponseCodecError::InvalidJson)?;
        let id_text = take_response_string(&mut fields, "id")?;
        let id = Uuid::parse_str(&id_text)
            .map_err(|_| CertificateResponseCodecError::InvalidField("id"))?;
        if id.to_string() != id_text {
            return Err(CertificateResponseCodecError::InvalidField("id"));
        }
        let etag = take_response_string(&mut fields, "etag")?;
        let created_at = take_response_string(&mut fields, "created_at")?;
        let updated_at = take_response_string(&mut fields, "updated_at")?;
        let Some(Value::Object(mut data)) = fields.remove("data") else {
            return Err(CertificateResponseCodecError::InvalidField("data"));
        };
        let certificate = take_response_string(&mut data, "certificate")?;
        Self::new(id, etag, created_at, updated_at, certificate)
    }

    /// Decode a response and require the exact HTTP entity tag and cache-prevention headers.
    ///
    /// # Errors
    ///
    /// Rejects an invalid body, missing headers, or header values that differ from the contract.
    pub fn from_http_json(
        input: &[u8],
        etag_header: Option<&str>,
        cache_control: Option<&str>,
        pragma: Option<&str>,
    ) -> Result<Self, CertificateResponseCodecError> {
        let response = Self::from_json(input)?;
        if etag_header != Some(response.etag.as_str())
            || cache_control != Some("no-store")
            || pragma != Some("no-cache")
        {
            return Err(CertificateResponseCodecError::HttpMetadata);
        }
        Ok(response)
    }

    /// Encode the validated Resource with fixed envelope and data member order.
    ///
    /// # Errors
    ///
    /// Rejects invalid public fields or a complete encoded body above 131,072 bytes.
    pub fn to_json(&self) -> Result<Vec<u8>, CertificateResponseCodecError> {
        #[derive(Serialize)]
        struct Data<'a> {
            certificate: &'a str,
        }
        #[derive(Serialize)]
        struct Wire<'a> {
            id: &'a str,
            etag: &'a str,
            created_at: &'a str,
            updated_at: &'a str,
            data: Data<'a>,
        }
        self.validate()?;
        let id = self.id.to_string();
        let encoded = serde_json::to_vec(&Wire {
            id: &id,
            etag: &self.etag,
            created_at: &self.created_at,
            updated_at: &self.updated_at,
            data: Data { certificate: &self.certificate },
        })
        .map_err(|_| CertificateResponseCodecError::InvalidJson)?;
        if encoded.len() > MAX_CERTIFICATE_ISSUANCE_RESPONSE_BYTES {
            return Err(CertificateResponseCodecError::ResponseTooLarge);
        }
        Ok(encoded)
    }

    /// Compare the parsed certificate's raw subject key with the original issuance request.
    ///
    /// This only validates both messages and compares the raw subject key. It does not establish
    /// the certificate's signature, CA trust, principals, scope, current validity, or policy.
    ///
    /// # Errors
    ///
    /// Rejects an invalid request or response, or a different subject key.
    pub fn validate_request_subject(
        &self,
        request: &CertificateIssuanceRequest,
    ) -> Result<(), CertificateResponseCodecError> {
        request.validate().map_err(|_| CertificateResponseCodecError::InvalidRequest)?;
        let certificate = self.validated_certificate()?;
        let subject = ssh_key::PublicKey::from(certificate.public_key().clone())
            .to_openssh()
            .map_err(|_| CertificateResponseCodecError::InvalidField("data.certificate"))?;
        if subject != request.public_key {
            return Err(CertificateResponseCodecError::SubjectMismatch);
        }
        Ok(())
    }
}

fn take_response_string(
    fields: &mut Map<String, Value>,
    name: &'static str,
) -> Result<String, CertificateResponseCodecError> {
    fields
        .remove(name)
        .and_then(|value| value.as_str().map(str::to_owned))
        .ok_or(CertificateResponseCodecError::InvalidField(name))
}

fn valid_strong_etag(value: &str) -> bool {
    let bytes = value.as_bytes();
    (2..=256).contains(&bytes.len())
        && bytes.first() == Some(&b'"')
        && bytes.last() == Some(&b'"')
        && bytes[1..bytes.len() - 1]
            .iter()
            .all(|byte| *byte == b'!' || (b'#'..=b'~').contains(byte))
}

fn valid_utc_timestamp(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() < 20
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
        || bytes.last() != Some(&b'Z')
    {
        return false;
    }
    let Some(year) = parse_digits(&bytes[0..4]) else { return false };
    let Some(month) = parse_digits(&bytes[5..7]) else { return false };
    let Some(day) = parse_digits(&bytes[8..10]) else { return false };
    let Some(hour) = parse_digits(&bytes[11..13]) else { return false };
    let Some(minute) = parse_digits(&bytes[14..16]) else { return false };
    let Some(second) = parse_digits(&bytes[17..19]) else { return false };
    let days = match month {
        2 if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        _ => return false,
    };
    if day == 0 || day > days || hour > 23 || minute > 59 || second > 59 {
        return false;
    }
    bytes.len() == 20
        || (bytes[19] == b'.'
            && bytes.len() > 21
            && bytes[20..bytes.len() - 1].iter().all(u8::is_ascii_digit))
}

fn parse_digits(bytes: &[u8]) -> Option<u32> {
    bytes.iter().try_fold(0_u32, |value, digit| {
        if digit.is_ascii_digit() { Some(value * 10 + u32::from(*digit - b'0')) } else { None }
    })
}

fn parse_certificate_line(line: &str) -> Result<Certificate, CertificateResponseCodecError> {
    let invalid = || CertificateResponseCodecError::InvalidField("data.certificate");
    if line.is_empty() || line.len() > MAX_CERTIFICATE_LINE_BYTES || !line.is_ascii() {
        return Err(invalid());
    }
    let (algorithm, encoded) = line.split_once(' ').ok_or_else(invalid)?;
    if !matches!(
        algorithm,
        "ssh-ed25519-cert-v01@openssh.com"
            | "ecdsa-sha2-nistp256-cert-v01@openssh.com"
            | "ecdsa-sha2-nistp384-cert-v01@openssh.com"
            | "ecdsa-sha2-nistp521-cert-v01@openssh.com"
            | "ssh-rsa-cert-v01@openssh.com"
            | "sk-ssh-ed25519-cert-v01@openssh.com"
            | "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com"
    ) || encoded.is_empty()
        || encoded.bytes().any(|byte| byte.is_ascii_whitespace())
    {
        return Err(invalid());
    }
    let blob = STANDARD.decode(encoded).map_err(|_| invalid())?;
    if blob.len() > MAX_CERTIFICATE_BLOB_BYTES || STANDARD.encode(&blob) != encoded {
        return Err(invalid());
    }
    let certificate = Certificate::from_bytes(&blob).map_err(|_| invalid())?;
    if certificate.cert_type() != CertType::User
        || certificate.valid_after() >= certificate.valid_before()
        || certificate.algorithm().to_certificate_type() != algorithm
        || certificate.to_bytes().map_err(|_| invalid())? != blob
        || certificate.to_openssh().map_err(|_| invalid())? != line
    {
        return Err(invalid());
    }
    Ok(certificate)
}

fn take_string(
    fields: &mut Map<String, Value>,
    name: &'static str,
) -> Result<String, CertificateRequestCodecError> {
    fields
        .remove(name)
        .and_then(|value| value.as_str().map(str::to_owned))
        .ok_or(CertificateRequestCodecError::InvalidField(name))
}

fn parse_ids(value: Value, field: &'static str) -> Result<Vec<Uuid>, CertificateRequestCodecError> {
    let Value::Array(values) = value else {
        return Err(CertificateRequestCodecError::InvalidField(field));
    };
    if values.is_empty() || values.len() > MAX_CERTIFICATE_ISSUANCE_TARGETS {
        return Err(CertificateRequestCodecError::InvalidField(field));
    }
    values
        .into_iter()
        .map(|value| {
            let text = value.as_str().ok_or(CertificateRequestCodecError::InvalidField(field))?;
            let id = Uuid::parse_str(text)
                .map_err(|_| CertificateRequestCodecError::InvalidField(field))?;
            if id.to_string() != text {
                return Err(CertificateRequestCodecError::InvalidField(field));
            }
            Ok(id)
        })
        .collect()
}
