// SPDX-License-Identifier: Apache-2.0
//! D-167 Organization draft login request and response codecs.

use scoplen_crypto::SecretVec;
use serde::Serialize;
use serde_json::{Map, Value};
use url::Url;
use uuid::Uuid;

use super::{DraftRequestError, validate_issuer};
use crate::{
    certificate::valid_utc_timestamp,
    organization::{
        OrganizationCodecError as Error, OrganizationPreconditionError, encode, object,
        parse_organization_if_match, take_string, take_uuid, valid_uuid, validate_cache_headers,
    },
};

const MAX_CREDENTIAL_BYTES: usize = 512;
const MAX_START_BYTES: usize = 4_096;
const MAX_RESPONSE_BYTES: usize = 8_192;

/// Confidential client credentials owned by the start request.
#[derive(Debug, Eq, PartialEq)]
pub struct DraftLoginCredentials {
    /// Exact OAuth client identifier bytes.
    pub client_id: SecretVec,
    /// Exact OAuth client secret bytes.
    pub client_secret: SecretVec,
}

impl DraftLoginCredentials {
    /// Read the strict, bounded start body without normalizing either credential.
    /// # Errors
    /// Rejects malformed JSON, additional fields or invalid credentials.
    pub fn from_json(bytes: &[u8]) -> Result<Self, Error> {
        let mut data = object(bytes, MAX_START_BYTES)?;
        let credentials = Self::take(&mut data)?;
        if !data.is_empty() {
            return Err(Error::InvalidField("request members"));
        }
        Ok(credentials)
    }

    pub(crate) fn take(data: &mut Map<String, Value>) -> Result<Self, Error> {
        let client_id = SecretVec::new(take_string(data, "client_id")?.into_bytes());
        let client_secret = SecretVec::new(take_string(data, "client_secret")?.into_bytes());
        credential_text(&client_id, "client_id")?;
        credential_text(&client_secret, "client_secret")?;
        Ok(Self { client_id, client_secret })
    }

    /// Emit the canonical start body as redacting, zeroizing bytes.
    /// # Errors
    /// Rejects invalid mutable credential fields or body overflow.
    pub fn to_json(&self) -> Result<SecretVec, Error> {
        #[derive(Serialize)]
        struct Wire<'a> {
            client_id: &'a str,
            client_secret: &'a str,
        }
        Ok(SecretVec::new(encode(
            &Wire {
                client_id: credential_text(&self.client_id, "client_id")?,
                client_secret: credential_text(&self.client_secret, "client_secret")?,
            },
            MAX_START_BYTES,
        )?))
    }
}

pub(crate) fn credential_text<'a>(
    secret: &'a SecretVec,
    field: &'static str,
) -> Result<&'a str, Error> {
    let value = std::str::from_utf8(secret.as_bytes()).map_err(|_| Error::InvalidField(field))?;
    validate_credential_text(value, field)?;
    Ok(value)
}

pub(crate) fn validate_credential_text(value: &str, field: &'static str) -> Result<(), Error> {
    if value.is_empty() || value.len() > MAX_CREDENTIAL_BYTES || value.chars().any(char::is_control)
    {
        return Err(Error::InvalidField(field));
    }
    Ok(())
}

/// HTTP syntax for the start and status routes after exact method/path dispatch.
#[derive(Debug, Eq, PartialEq)]
pub enum DraftLoginRequest<'a> {
    /// Start with the draft's original strong precondition and client credential.
    Start {
        /// Original HTTP validator.
        if_match: &'a str,
        /// Submitted client authentication material.
        credentials: DraftLoginCredentials,
    },
    /// Read the attempt named by the route.
    Read,
}

impl<'a> DraftLoginRequest<'a> {
    /// Validate raw query, individual header values and the complete body.
    /// # Errors
    /// Rejects malformed or duplicate request metadata and invalid bodies.
    pub fn from_http(
        method: &str,
        query: Option<&str>,
        headers: impl IntoIterator<Item = (&'a str, &'a str)>,
        body: &[u8],
    ) -> Result<Self, DraftRequestError> {
        use DraftRequestError::{Invalid, MediaType, PreconditionRequired, TooLarge};
        if query.is_some() {
            return Err(Invalid);
        }
        let (mut if_match, mut content_type) = (None, None);
        for (name, value) in headers {
            let field = if name.eq_ignore_ascii_case("If-Match") {
                &mut if_match
            } else if name.eq_ignore_ascii_case("Content-Type") {
                &mut content_type
            } else if [
                "Idempotency-Key",
                "If-None-Match",
                "If-Modified-Since",
                "If-Unmodified-Since",
                "If-Range",
            ]
            .iter()
            .any(|key| name.eq_ignore_ascii_case(key))
            {
                return Err(Invalid);
            } else {
                continue;
            };
            if field.replace(value).is_some() {
                return Err(Invalid);
            }
        }
        match method {
            "GET" if if_match.is_none() && body.is_empty() => Ok(Self::Read),
            "POST" => {
                let tag = parse_organization_if_match(if_match).map_err(|error| match error {
                    OrganizationPreconditionError::Required => PreconditionRequired,
                    OrganizationPreconditionError::Invalid => Invalid,
                })?;
                if !matches!(
                    content_type,
                    Some("application/json" | "application/json; charset=utf-8")
                ) {
                    return Err(MediaType);
                }
                let credentials = DraftLoginCredentials::from_json(body)
                    .map_err(|e| if e == Error::TooLarge { TooLarge } else { Invalid })?;
                Ok(Self::Start { if_match: tag, credentials })
            }
            _ => Err(Invalid),
        }
    }
}

/// Externally visible attempt state. An outstanding exchange remains pending.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DraftLoginStatus {
    /// The test is waiting for the browser or the provider exchange.
    Pending,
    /// The test verified a human login.
    Verified,
    /// The attempt ended unsuccessfully.
    Failed,
}

/// Attempt status without provider credentials, proof or identity attributes.
#[derive(Debug, Eq, PartialEq, Serialize)]
pub struct DraftLoginAttempt {
    /// Allocated attempt `UUIDv7`.
    #[serde(serialize_with = "serialize_uuid")]
    pub id: Uuid,
    /// Selected Organization `UUIDv7`.
    #[serde(serialize_with = "serialize_uuid")]
    pub organization_id: Uuid,
    /// Original draft generation `UUIDv7`.
    #[serde(serialize_with = "serialize_uuid")]
    pub draft_generation: Uuid,
    /// Current attempt status.
    pub status: DraftLoginStatus,
    /// Server-issued expiration as UTC JSON timestamp text.
    pub expires_at: String,
}

pub(crate) fn serialize_uuid<S: serde::Serializer>(
    id: &Uuid,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.collect_str(id)
}

impl DraftLoginAttempt {
    fn take(fields: &mut Map<String, Value>) -> Result<Self, Error> {
        let attempt = Self {
            id: take_uuid(fields, "id")?,
            organization_id: take_uuid(fields, "organization_id")?,
            draft_generation: take_uuid(fields, "draft_generation")?,
            status: match take_string(fields, "status")?.as_str() {
                "pending" => DraftLoginStatus::Pending,
                "verified" => DraftLoginStatus::Verified,
                "failed" => DraftLoginStatus::Failed,
                _ => return Err(Error::InvalidField("status")),
            },
            expires_at: take_string(fields, "expires_at")?,
        };
        attempt.validate()?;
        Ok(attempt)
    }

    fn validate(&self) -> Result<(), Error> {
        valid_uuid(self.id, "id")?;
        valid_uuid(self.organization_id, "organization_id")?;
        valid_uuid(self.draft_generation, "draft_generation")?;
        if !valid_utc_timestamp(&self.expires_at) {
            return Err(Error::InvalidField("expires_at"));
        }
        Ok(())
    }

    /// Read and bind a status response to the selected draft and original attempt.
    /// # Errors
    /// Rejects invalid metadata or fields, a mismatched attempt, or a start-only URL.
    pub fn from_http_json(
        bytes: &[u8],
        expected: (Uuid, Uuid, Uuid),
        cache: Option<&str>,
        pragma: Option<&str>,
    ) -> Result<Self, Error> {
        validate_cache_headers(cache, pragma)?;
        let mut fields = object(bytes, MAX_RESPONSE_BYTES)?;
        let attempt = Self::take(&mut fields)?;
        if (attempt.organization_id, attempt.draft_generation, attempt.id) != expected {
            return Err(Error::Context);
        }
        if fields.contains_key("authorization_url") {
            return Err(Error::InvalidField("authorization_url"));
        }
        Ok(attempt)
    }

    /// Emit a validated status response.
    /// # Errors
    /// Rejects invalid mutable fields and body overflow.
    pub fn to_json(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        encode(self, MAX_RESPONSE_BYTES)
    }
}

/// Successful start response, with a redacting one-time provider navigation URL.
#[derive(Debug, Eq, PartialEq)]
pub struct DraftLoginStarted {
    /// Newly created pending attempt.
    pub attempt: DraftLoginAttempt,
    /// Original URL with OAuth state and nonce. Use only for the authorized browser navigation.
    pub authorization_url: SecretVec,
}

impl DraftLoginStarted {
    /// Read and bind a start response to the original draft and expected provider origin.
    /// # Errors
    /// Rejects invalid response metadata, context, status or authorization URL.
    pub fn from_http_json(
        bytes: &[u8],
        expected: (Uuid, Uuid),
        issuer: &str,
        cache: Option<&str>,
        pragma: Option<&str>,
    ) -> Result<Self, Error> {
        validate_cache_headers(cache, pragma)?;
        let mut fields = object(bytes, MAX_RESPONSE_BYTES)?;
        let attempt = DraftLoginAttempt::take(&mut fields)?;
        if (attempt.organization_id, attempt.draft_generation) != expected {
            return Err(Error::Context);
        }
        let authorization_url =
            SecretVec::new(take_string(&mut fields, "authorization_url")?.into_bytes());
        let response = Self { attempt, authorization_url };
        response.validate(issuer)?;
        Ok(response)
    }

    fn validate(&self, issuer: &str) -> Result<&str, Error> {
        self.attempt.validate()?;
        if self.attempt.status != DraftLoginStatus::Pending {
            return Err(Error::InvalidField("status"));
        }
        validated_navigation(&self.authorization_url, issuer)
    }

    /// Emit a bounded, redacting start response for the original provider origin.
    /// # Errors
    /// Rejects invalid mutable fields, a mismatched origin or body overflow.
    pub fn to_json(&self, issuer: &str) -> Result<SecretVec, Error> {
        #[derive(Serialize)]
        struct Wire<'a> {
            #[serde(flatten)]
            attempt: &'a DraftLoginAttempt,
            authorization_url: &'a str,
        }
        Ok(SecretVec::new(encode(
            &Wire { attempt: &self.attempt, authorization_url: self.validate(issuer)? },
            MAX_RESPONSE_BYTES,
        )?))
    }
}

pub(crate) fn validated_navigation<'a>(
    navigation: &'a SecretVec,
    issuer: &str,
) -> Result<&'a str, Error> {
    validate_issuer(issuer)?;
    let bad = Error::InvalidField("authorization_url");
    let value = std::str::from_utf8(navigation.as_bytes()).map_err(|_| bad.clone())?;
    if value.contains(['\\', '#']) || value.chars().any(|ch| ch.is_control() || ch.is_whitespace())
    {
        return Err(bad);
    }
    let (scheme, rest) = value.split_once("://").ok_or_else(|| bad.clone())?;
    let authority = rest.split(['/', '?']).next().unwrap_or_default();
    if !scheme.eq_ignore_ascii_case("https") || authority.is_empty() || authority.contains('@') {
        return Err(bad);
    }
    let url = Url::parse(value).map_err(|_| bad.clone())?;
    let issuer = Url::parse(issuer).map_err(|_| bad.clone())?;
    if url.origin() != issuer.origin() {
        return Err(bad);
    }
    Ok(value)
}
