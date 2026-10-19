// SPDX-License-Identifier: Apache-2.0
//! Bounded K-5/K-6 gateway-ticket issuance JSON messages.

use std::{collections::BTreeSet, fmt, net::IpAddr};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use scoplen_model::validate_uuid_v7;
use serde::Serialize;
use serde_json::{Map, Value};
use thiserror::Error;
use uuid::Uuid;

use crate::request_wire;

/// Maximum complete UTF-8 request body, including JSON whitespace and escapes.
pub const MAX_GATEWAY_TICKET_REQUEST_BYTES: usize = 16_384;
/// Maximum complete UTF-8 response body.
pub const MAX_GATEWAY_TICKET_RESPONSE_BYTES: usize = 32_768;
/// Maximum canonical OpenSSH public-key text length.
pub const MAX_GATEWAY_SSH_PUBLIC_KEY_BYTES: usize = 8_192;
/// Maximum compact ticket length, matching the existing client hello.
pub const MAX_GATEWAY_ISSUED_TICKET_BYTES: usize = 4_096;
/// Maximum number of edge addresses in one issuance response.
pub const MAX_GATEWAY_EDGE_ADDRESSES: usize = 16;

/// An issuance message failed its bounded wire contract.
///
/// Errors deliberately omit all input and credential values.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum GatewayTicketCodecError {
    /// The complete JSON body exceeded its fixed size limit.
    #[error("gateway-ticket request exceeds its body limit")]
    RequestTooLarge,
    /// The complete JSON body exceeded its fixed size limit.
    #[error("gateway-ticket response exceeds its body limit")]
    ResponseTooLarge,
    /// The body is not valid JSON, contains duplicate keys, or has an invalid root type.
    #[error("invalid gateway-ticket JSON")]
    InvalidJson,
    /// One of the fixed contract fields is absent or invalid.
    #[error("invalid gateway-ticket field: {0}")]
    InvalidField(&'static str),
    /// The transient issuance action must not receive an idempotency key.
    #[error("gateway-ticket issuance does not accept Idempotency-Key")]
    IdempotencyKey,
}

/// The exact request body for `POST /api/v1/orgs/{org}/gateway-tickets`.
#[derive(Clone, Eq, PartialEq)]
pub struct GatewayTicketRequest {
    /// Target Host identifier.
    pub host: Uuid,
    /// SSH username, preserved byte for byte.
    pub remote_user: String,
    /// Canonical OpenSSH raw public-key line without a comment.
    pub ssh_public_key: String,
}

impl fmt::Debug for GatewayTicketRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GatewayTicketRequest")
            .field("remote_user_bytes", &self.remote_user.len())
            .field("ssh_public_key_bytes", &self.ssh_public_key.len())
            .finish_non_exhaustive()
    }
}

impl GatewayTicketRequest {
    /// Construct and validate an issuance request.
    ///
    /// # Errors
    ///
    /// Rejects an invalid Host id, SSH username, or public key.
    pub fn new(
        host: Uuid,
        remote_user: impl Into<String>,
        ssh_public_key: impl Into<String>,
    ) -> Result<Self, GatewayTicketCodecError> {
        let request =
            Self { host, remote_user: remote_user.into(), ssh_public_key: ssh_public_key.into() };
        request.validate()?;
        Ok(request)
    }

    /// Validate the fixed request fields before using or encoding them.
    ///
    /// # Errors
    ///
    /// Rejects an invalid Host id, SSH username, or public key.
    pub fn validate(&self) -> Result<(), GatewayTicketCodecError> {
        validate_uuid_v7(self.host).map_err(|_| GatewayTicketCodecError::InvalidField("host"))?;
        if !request_wire::valid_remote_user(&self.remote_user) {
            return Err(GatewayTicketCodecError::InvalidField("remote_user"));
        }
        validate_ssh_public_key(&self.ssh_public_key, "ssh_public_key")
    }

    /// Decode the bounded JSON body and reject a prohibited idempotency header.
    ///
    /// The caller supplies header presence after examining the actual HTTP request. This does not
    /// authenticate the caller or authorize issuance.
    ///
    /// # Errors
    ///
    /// Rejects the header, malformed or oversized JSON, and invalid request fields.
    pub fn from_http_json(
        input: &[u8],
        idempotency_key_present: bool,
    ) -> Result<Self, GatewayTicketCodecError> {
        if idempotency_key_present {
            return Err(GatewayTicketCodecError::IdempotencyKey);
        }
        Self::from_json(input)
    }

    /// Decode a bounded JSON request body.
    ///
    /// # Errors
    ///
    /// Rejects duplicate, unknown, missing, mistyped, invalid, or oversized input.
    pub fn from_json(input: &[u8]) -> Result<Self, GatewayTicketCodecError> {
        let mut fields = decode_object(input, MAX_GATEWAY_TICKET_REQUEST_BYTES, true)?;
        let host = take_string(&mut fields, "host")?;
        let host = parse_uuid(&host, "host")?;
        let remote_user = take_string(&mut fields, "remote_user")?;
        let ssh_public_key = take_string(&mut fields, "ssh_public_key")?;
        if !fields.is_empty() {
            return Err(GatewayTicketCodecError::InvalidJson);
        }
        Self::new(host, remote_user, ssh_public_key)
    }

    /// Encode a validated request with stable JSON field order.
    ///
    /// # Errors
    ///
    /// Rejects invalid fields or an encoded body above the limit.
    pub fn to_json(&self) -> Result<Vec<u8>, GatewayTicketCodecError> {
        #[derive(Serialize)]
        struct Wire<'a> {
            host: String,
            remote_user: &'a str,
            ssh_public_key: &'a str,
        }
        self.validate()?;
        let encoded = serde_json::to_vec(&Wire {
            host: self.host.to_string(),
            remote_user: &self.remote_user,
            ssh_public_key: &self.ssh_public_key,
        })
        .map_err(|_| GatewayTicketCodecError::InvalidJson)?;
        if encoded.len() > MAX_GATEWAY_TICKET_REQUEST_BYTES {
            return Err(GatewayTicketCodecError::RequestTooLarge);
        }
        Ok(encoded)
    }
}

/// One preferred public edge address for the raw-TLS gateway transport.
#[derive(Clone, Eq, PartialEq, Serialize)]
pub struct GatewayEdgeAddress {
    /// Canonical DNS or IP host without a scheme or port.
    pub host: String,
    /// Public TLS port.
    pub port: u16,
}

impl fmt::Debug for GatewayEdgeAddress {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GatewayEdgeAddress")
            .field("host_bytes", &self.host.len())
            .finish_non_exhaustive()
    }
}

impl GatewayEdgeAddress {
    /// Construct and validate a canonical edge address.
    ///
    /// # Errors
    ///
    /// Rejects an invalid host or port.
    pub fn new(host: impl Into<String>, port: u16) -> Result<Self, GatewayTicketCodecError> {
        let address = Self { host: host.into(), port };
        address.validate()?;
        Ok(address)
    }

    /// Validate the canonical host and port.
    ///
    /// # Errors
    ///
    /// Rejects an invalid host or port.
    pub fn validate(&self) -> Result<(), GatewayTicketCodecError> {
        if self.port == 0 || !valid_edge_host(&self.host) {
            return Err(GatewayTicketCodecError::InvalidField("edge_addresses"));
        }
        Ok(())
    }
}

/// The transient successful ticket issuance response.
///
/// The ticket remains opaque and unverified at this codec boundary.
#[derive(Clone, Eq, PartialEq)]
pub struct GatewayTicketResponse {
    /// Opaque compact JWS ticket.
    pub ticket: String,
    /// Public edge addresses in connection preference order.
    pub edge_addresses: Vec<GatewayEdgeAddress>,
    /// Canonical OpenSSH raw gateway host CA public key.
    pub gateway_host_ca_public_key: String,
}

impl fmt::Debug for GatewayTicketResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GatewayTicketResponse")
            .field("ticket_bytes", &self.ticket.len())
            .field("edge_count", &self.edge_addresses.len())
            .field("gateway_host_ca_public_key_bytes", &self.gateway_host_ca_public_key.len())
            .finish()
    }
}

impl GatewayTicketResponse {
    /// Construct and validate an unverified issuance response.
    ///
    /// # Errors
    ///
    /// Rejects malformed ticket syntax, edge addresses, or host CA key text.
    pub fn new(
        ticket: impl Into<String>,
        edge_addresses: Vec<GatewayEdgeAddress>,
        gateway_host_ca_public_key: impl Into<String>,
    ) -> Result<Self, GatewayTicketCodecError> {
        let response = Self {
            ticket: ticket.into(),
            edge_addresses,
            gateway_host_ca_public_key: gateway_host_ca_public_key.into(),
        };
        response.validate()?;
        Ok(response)
    }

    /// Validate the fixed response fields.
    ///
    /// # Errors
    ///
    /// Rejects malformed ticket syntax, edge addresses, or host CA key text.
    pub fn validate(&self) -> Result<(), GatewayTicketCodecError> {
        validate_compact_jws(&self.ticket)?;
        if self.edge_addresses.is_empty() || self.edge_addresses.len() > MAX_GATEWAY_EDGE_ADDRESSES
        {
            return Err(GatewayTicketCodecError::InvalidField("edge_addresses"));
        }
        let mut seen = BTreeSet::new();
        for address in &self.edge_addresses {
            address.validate()?;
            if !seen.insert((&address.host, address.port)) {
                return Err(GatewayTicketCodecError::InvalidField("edge_addresses"));
            }
        }
        validate_ssh_public_key(&self.gateway_host_ca_public_key, "gateway_host_ca_public_key")
    }

    /// Decode a bounded JSON response, ignoring unknown response extensions.
    ///
    /// All duplicate keys, including extension keys nested in an edge object, are rejected.
    /// This method does not validate ticket claims, signatures, or authority.
    ///
    /// # Errors
    ///
    /// Rejects malformed, duplicate, invalid, or oversized input.
    pub fn from_json(input: &[u8]) -> Result<Self, GatewayTicketCodecError> {
        let mut fields = decode_object(input, MAX_GATEWAY_TICKET_RESPONSE_BYTES, false)?;
        let ticket = take_string(&mut fields, "ticket")?;
        let addresses = fields
            .remove("edge_addresses")
            .ok_or(GatewayTicketCodecError::InvalidField("edge_addresses"))?;
        let Value::Array(addresses) = addresses else {
            return Err(GatewayTicketCodecError::InvalidField("edge_addresses"));
        };
        let mut edge_addresses =
            Vec::with_capacity(addresses.len().min(MAX_GATEWAY_EDGE_ADDRESSES));
        if addresses.is_empty() || addresses.len() > MAX_GATEWAY_EDGE_ADDRESSES {
            return Err(GatewayTicketCodecError::InvalidField("edge_addresses"));
        }
        for address in addresses {
            let Value::Object(mut address) = address else {
                return Err(GatewayTicketCodecError::InvalidField("edge_addresses"));
            };
            let host = take_string(&mut address, "host")?;
            let port = address
                .remove("port")
                .and_then(|value| value.as_u64())
                .and_then(|value| u16::try_from(value).ok())
                .ok_or(GatewayTicketCodecError::InvalidField("edge_addresses"))?;
            edge_addresses.push(GatewayEdgeAddress::new(host, port)?);
        }
        let gateway_host_ca_public_key = take_string(&mut fields, "gateway_host_ca_public_key")?;
        Self::new(ticket, edge_addresses, gateway_host_ca_public_key)
    }

    /// Encode a validated response with stable JSON field order.
    ///
    /// # Errors
    ///
    /// Rejects invalid fields or an encoded body above the limit.
    pub fn to_json(&self) -> Result<Vec<u8>, GatewayTicketCodecError> {
        #[derive(Serialize)]
        struct Wire<'a> {
            ticket: &'a str,
            edge_addresses: &'a [GatewayEdgeAddress],
            gateway_host_ca_public_key: &'a str,
        }
        self.validate()?;
        let encoded = serde_json::to_vec(&Wire {
            ticket: &self.ticket,
            edge_addresses: &self.edge_addresses,
            gateway_host_ca_public_key: &self.gateway_host_ca_public_key,
        })
        .map_err(|_| GatewayTicketCodecError::InvalidJson)?;
        if encoded.len() > MAX_GATEWAY_TICKET_RESPONSE_BYTES {
            return Err(GatewayTicketCodecError::ResponseTooLarge);
        }
        Ok(encoded)
    }
}

fn parse_uuid(value: &str, field: &'static str) -> Result<Uuid, GatewayTicketCodecError> {
    let parsed =
        Uuid::parse_str(value).map_err(|_| GatewayTicketCodecError::InvalidField(field))?;
    if parsed.to_string() != value || validate_uuid_v7(parsed).is_err() {
        return Err(GatewayTicketCodecError::InvalidField(field));
    }
    Ok(parsed)
}

fn validate_ssh_public_key(
    value: &str,
    field: &'static str,
) -> Result<(), GatewayTicketCodecError> {
    request_wire::valid_raw_ssh_public_key(value)
        .then_some(())
        .ok_or(GatewayTicketCodecError::InvalidField(field))
}

fn validate_compact_jws(value: &str) -> Result<(), GatewayTicketCodecError> {
    if value.is_empty() || value.len() > MAX_GATEWAY_ISSUED_TICKET_BYTES || !value.is_ascii() {
        return Err(GatewayTicketCodecError::InvalidField("ticket"));
    }
    let segments = value.split('.').collect::<Vec<_>>();
    if segments.len() != 3 || segments.contains(&"") {
        return Err(GatewayTicketCodecError::InvalidField("ticket"));
    }
    for segment in segments {
        let bytes = URL_SAFE_NO_PAD
            .decode(segment)
            .map_err(|_| GatewayTicketCodecError::InvalidField("ticket"))?;
        if URL_SAFE_NO_PAD.encode(bytes) != segment {
            return Err(GatewayTicketCodecError::InvalidField("ticket"));
        }
    }
    Ok(())
}

fn valid_edge_host(host: &str) -> bool {
    if host.is_empty() || !host.is_ascii() {
        return false;
    }
    if let Ok(address) = host.parse::<IpAddr>() {
        return address.to_string() == host;
    }
    if host.contains(':')
        || host.bytes().all(|byte| byte.is_ascii_digit() || byte == b'.')
        || host.len() > 253
    {
        return false;
    }
    let final_label = host.rsplit('.').next().unwrap_or(host);
    if final_label.bytes().all(|byte| byte.is_ascii_digit())
        || final_label
            .strip_prefix("0x")
            .is_some_and(|hex| hex.bytes().all(|byte| byte.is_ascii_hexdigit()))
    {
        return false;
    }
    host.split('.').all(|label| {
        let bytes = label.as_bytes();
        !bytes.is_empty()
            && bytes.len() <= 63
            && (bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit())
            && (bytes[bytes.len() - 1].is_ascii_lowercase()
                || bytes[bytes.len() - 1].is_ascii_digit())
            && bytes
                .iter()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
    })
}

fn take_string(
    fields: &mut Map<String, Value>,
    name: &'static str,
) -> Result<String, GatewayTicketCodecError> {
    fields
        .remove(name)
        .and_then(|value| value.as_str().map(str::to_owned))
        .ok_or(GatewayTicketCodecError::InvalidField(name))
}

fn decode_object(
    input: &[u8],
    limit: usize,
    request: bool,
) -> Result<Map<String, Value>, GatewayTicketCodecError> {
    if input.len() > limit {
        return Err(if request {
            GatewayTicketCodecError::RequestTooLarge
        } else {
            GatewayTicketCodecError::ResponseTooLarge
        });
    }
    request_wire::decode_unique_object(input).map_err(|()| GatewayTicketCodecError::InvalidJson)
}
