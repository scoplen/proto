// SPDX-License-Identifier: Apache-2.0
//! Bounded K-5 user-certificate issuance request.

use std::{collections::HashSet, fmt};

use scoplen_model::validate_uuid_v7;
use serde::Serialize;
use serde_json::{Map, Value};
use thiserror::Error;
use uuid::Uuid;

use crate::request_wire;

/// Maximum complete UTF-8 JSON request body, including whitespace and escapes.
pub const MAX_CERTIFICATE_ISSUANCE_REQUEST_BYTES: usize = 16_384;
/// Maximum number of Host or `HostGroup` selectors in one request.
pub const MAX_CERTIFICATE_ISSUANCE_TARGETS: usize = 64;
/// Maximum requested certificate lifetime in seconds.
pub const MAX_CERTIFICATE_TTL_SECONDS: u32 = 86_400;

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
