// SPDX-License-Identifier: Apache-2.0
//! D-169 wire codecs for an Organization's login connection and activation candidate.

use std::fmt;

use scoplen_crypto::SecretVec;
use serde::Serialize;
use serde_json::{Map, Value};
use uuid::Uuid;

use crate::{
    account_browser::AccountBrowserAccessOperation,
    auth_connection_draft::{
        DraftRequestError,
        test_login::{
            DraftLoginCredentials, DraftLoginStatus, credential_text, serialize_uuid,
            validate_credential_text, validated_navigation,
        },
        validate_issuer,
    },
    certificate::valid_utc_timestamp,
    organization::{
        OrganizationCodecError as Error, encode, object, parse_organization_idempotency_key,
        take_object, take_string, take_uuid, valid_uuid, validate_cache_headers,
    },
};

const MAX_CANDIDATE_BYTES: usize = 4_096;
const MAX_RESPONSE_BYTES: usize = 8_192;

/// The revision reviewed by the original browser.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExpectedRevision {
    /// The connection has never been configured.
    Empty,
    /// The exact current version, including a suspended revision.
    Current(Uuid),
}

impl ExpectedRevision {
    fn from_headers(
        if_match: Option<&str>,
        if_none_match: Option<&str>,
    ) -> Result<Self, DraftRequestError> {
        use DraftRequestError::{Invalid, PreconditionRequired};
        match (if_match, if_none_match) {
            (None, Some("*")) => Ok(Self::Empty),
            (Some(tag), None) => {
                let raw =
                    tag.strip_prefix('"').and_then(|tag| tag.strip_suffix('"')).ok_or(Invalid)?;
                let id = Uuid::parse_str(raw).map_err(|_| Invalid)?;
                valid_uuid(id, "revision").map_err(|_| Invalid)?;
                if id.to_string() != raw {
                    return Err(Invalid);
                }
                Ok(Self::Current(id))
            }
            (None, None) => Err(PreconditionRequired),
            _ => Err(Invalid),
        }
    }
}

fn validate_space_id(space: &str) -> Result<(), Error> {
    if space.strip_prefix("spc_").is_some_and(|suffix| {
        (1..=92).contains(&suffix.len())
            && suffix.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"_-".contains(&byte))
    }) {
        Ok(())
    } else {
        Err(Error::InvalidField("space_id"))
    }
}

/// Candidate start carries the exact saved draft and the confidential client configuration.
#[derive(Eq, PartialEq)]
pub struct ActivationCandidate {
    /// Saved draft generation.
    pub draft_generation: Uuid,
    /// Selected Auth Space, preserved verbatim.
    pub space_id: String,
    /// Exact confidential credentials.
    pub credentials: DraftLoginCredentials,
}

impl fmt::Debug for ActivationCandidate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ActivationCandidate").finish_non_exhaustive()
    }
}

impl ActivationCandidate {
    /// Parse the bounded candidate body without normalizing the inputs.
    ///
    /// # Errors
    /// Rejects unknown or duplicate fields, invalid values and complete body overflow.
    pub fn from_json(bytes: &[u8]) -> Result<Self, Error> {
        let mut data = object(bytes, MAX_CANDIDATE_BYTES)?;
        let credentials = DraftLoginCredentials::take(&mut data)?;
        let draft_generation = take_uuid(&mut data, "draft_generation")?;
        let space_id = take_string(&mut data, "space_id")?;
        if !data.is_empty() {
            return Err(Error::InvalidField("candidate members"));
        }
        validate_space_id(&space_id)?;
        Ok(Self { draft_generation, space_id, credentials })
    }

    /// Emit bounded JSON in zeroizing, redacting storage.
    ///
    /// # Errors
    /// Rejects invalid values or complete body overflow.
    pub fn to_json(&self) -> Result<SecretVec, Error> {
        #[derive(Serialize)]
        struct Wire<'a> {
            #[serde(serialize_with = "serialize_uuid")]
            draft_generation: Uuid,
            client_id: &'a str,
            client_secret: &'a str,
            space_id: &'a str,
        }
        valid_uuid(self.draft_generation, "draft_generation")?;
        validate_space_id(&self.space_id)?;
        Ok(SecretVec::new(encode(
            &Wire {
                draft_generation: self.draft_generation,
                client_id: credential_text(&self.credentials.client_id, "client_id")?,
                client_secret: credential_text(&self.credentials.client_secret, "client_secret")?,
                space_id: &self.space_id,
            },
            MAX_CANDIDATE_BYTES,
        )?))
    }
}

/// Request syntax for one routed browser operation. Current authority is checked by the receiver.
#[derive(Debug, Eq, PartialEq)]
pub enum ConnectionRequest {
    /// Read the current revision.
    Read,
    /// Verify a new candidate.
    Start {
        /// Original slot condition.
        expected: ExpectedRevision,
        /// Candidate configuration.
        candidate: ActivationCandidate,
    },
    /// Read the original candidate.
    ReadActivation,
    /// Abandon the original candidate.
    Abandon,
    /// Confirm the original candidate.
    Confirm {
        /// Original slot condition.
        expected: ExpectedRevision,
        /// Original durable write key.
        key: Uuid,
    },
    /// Suspend the exact active revision.
    Suspend {
        /// Original active revision.
        revision: Uuid,
        /// Original durable write key.
        key: Uuid,
    },
}

impl ConnectionRequest {
    /// Parse complete bytes and individual headers after matching a canonical route.
    ///
    /// # Errors
    /// Rejects invalid request combinations and classifies wire failures.
    pub fn from_http<'a>(
        operation: AccountBrowserAccessOperation,
        query: Option<&str>,
        headers: impl IntoIterator<Item = (&'a str, &'a str)>,
        body: &[u8],
    ) -> Result<Self, DraftRequestError> {
        use AccountBrowserAccessOperation::{
            AuthActivationAbandon, AuthActivationConfirm, AuthActivationRead, AuthActivationStart,
            AuthConnectionRead, AuthConnectionSuspend,
        };
        use DraftRequestError::{Invalid, MediaType, TooLarge};
        if query.is_some() {
            return Err(Invalid);
        }
        let (mut matched, mut empty, mut idempotency, mut content) = (None, None, None, None);
        for (name, value) in headers {
            let field = if name.eq_ignore_ascii_case("If-Match") {
                &mut matched
            } else if name.eq_ignore_ascii_case("If-None-Match") {
                &mut empty
            } else if name.eq_ignore_ascii_case("Idempotency-Key") {
                &mut idempotency
            } else if name.eq_ignore_ascii_case("Content-Type") {
                &mut content
            } else if ["If-Modified-Since", "If-Unmodified-Since", "If-Range"]
                .iter()
                .any(|name_to_reject| name.eq_ignore_ascii_case(name_to_reject))
            {
                return Err(Invalid);
            } else {
                continue;
            };
            if field.replace(value).is_some() {
                return Err(Invalid);
            }
        }
        if operation == AuthActivationStart {
            if idempotency.is_some() {
                return Err(Invalid);
            }
            let expected = ExpectedRevision::from_headers(matched, empty)?;
            if body.len() > MAX_CANDIDATE_BYTES {
                return Err(TooLarge);
            }
            if !matches!(content, Some("application/json" | "application/json; charset=utf-8")) {
                return Err(MediaType);
            }
            let candidate = ActivationCandidate::from_json(body).map_err(|_| Invalid)?;
            return Ok(Self::Start { expected, candidate });
        }
        if !body.is_empty() || content.is_some() {
            return Err(Invalid);
        }
        if matches!(operation, AuthActivationConfirm | AuthConnectionSuspend) {
            if operation == AuthConnectionSuspend && empty.is_some() {
                return Err(Invalid);
            }
            let expected = ExpectedRevision::from_headers(matched, empty)?;
            let key = parse_organization_idempotency_key(idempotency.ok_or(Invalid)?)
                .map_err(|_| Invalid)?;
            return if operation == AuthActivationConfirm {
                Ok(Self::Confirm { expected, key })
            } else if let ExpectedRevision::Current(revision) = expected {
                Ok(Self::Suspend { revision, key })
            } else {
                Err(Invalid)
            };
        }
        if matched.is_some() || empty.is_some() || idempotency.is_some() {
            return Err(Invalid);
        }
        match operation {
            AuthConnectionRead => Ok(Self::Read),
            AuthActivationRead => Ok(Self::ReadActivation),
            AuthActivationAbandon => Ok(Self::Abandon),
            _ => Err(Invalid),
        }
    }
}

/// Safe metadata shown only to an authorized reader.
#[derive(Clone, Eq, PartialEq, Serialize)]
pub struct ConnectionTarget {
    /// Exact saved issuer.
    pub issuer: String,
    /// Client ID, distinct from the confidential client secret.
    pub client_id: String,
    /// Selected Auth Space.
    pub space_id: String,
}

impl fmt::Debug for ConnectionTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConnectionTarget").finish_non_exhaustive()
    }
}

impl ConnectionTarget {
    pub(crate) fn validate(&self) -> Result<(), Error> {
        validate_issuer(&self.issuer)?;
        validate_credential_text(&self.client_id, "client_id")?;
        validate_space_id(&self.space_id)
    }

    pub(crate) fn take(fields: &mut Map<String, Value>) -> Result<Self, Error> {
        let result = Self {
            issuer: take_string(fields, "issuer")?,
            client_id: take_string(fields, "client_id")?,
            space_id: take_string(fields, "space_id")?,
        };
        result.validate()?;
        Ok(result)
    }
}

/// Current state of a committed immutable connection revision.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ConnectionStatus {
    /// Active with a usable credential.
    Active,
    /// Suspended with no usable credential.
    Suspended,
}

/// Authorized readback of one committed revision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConnectionResource {
    /// Connection revision and strong entity tag identity.
    pub id: Uuid,
    /// Owning Organization.
    pub organization_id: Uuid,
    /// Immutable revision timestamp.
    pub created_at: String,
    /// Committed status.
    pub status: ConnectionStatus,
    /// Public connection target.
    pub target: ConnectionTarget,
}

impl ConnectionResource {
    /// Canonical strong body and response entity tag.
    #[must_use]
    pub fn etag(&self) -> String {
        format!("\"{}\"", self.id)
    }

    /// Emit an immutable Connection Resource.
    ///
    /// # Errors
    /// Rejects invalid fields or complete size overflow.
    pub fn to_json(&self) -> Result<Vec<u8>, Error> {
        #[derive(Serialize)]
        struct Data<'a> {
            #[serde(serialize_with = "serialize_uuid")]
            organization_id: Uuid,
            status: ConnectionStatus,
            #[serde(flatten)]
            target: &'a ConnectionTarget,
        }
        #[derive(Serialize)]
        struct Wire<'a> {
            #[serde(serialize_with = "serialize_uuid")]
            id: Uuid,
            etag: String,
            created_at: &'a str,
            updated_at: &'a str,
            data: Data<'a>,
        }
        valid_uuid(self.id, "id")?;
        valid_uuid(self.organization_id, "organization_id")?;
        checked_time(&self.created_at, "created_at")?;
        self.target.validate()?;
        encode(
            &Wire {
                id: self.id,
                etag: self.etag(),
                created_at: &self.created_at,
                updated_at: &self.created_at,
                data: Data {
                    organization_id: self.organization_id,
                    status: self.status,
                    target: &self.target,
                },
            },
            MAX_RESPONSE_BYTES,
        )
    }

    /// Check the Organization, strong `ETag`, cache headers and any operation-specific status.
    ///
    /// # Errors
    /// Rejects malformed or unbound results.
    pub fn from_http_json(
        bytes: &[u8],
        organization_id: Uuid,
        expected_status: Option<ConnectionStatus>,
        etag: Option<&str>,
        cache_control: Option<&str>,
        pragma: Option<&str>,
    ) -> Result<Self, Error> {
        validate_cache_headers(cache_control, pragma)?;
        let mut root = object(bytes, MAX_RESPONSE_BYTES)?;
        let mut data = take_object(&mut root, "data")?;
        validate_public_fields(&root, false)?;
        validate_public_fields(&data, false)?;
        let resource = Self {
            id: take_uuid(&mut root, "id")?,
            organization_id: take_uuid(&mut data, "organization_id")?,
            created_at: take_string(&mut root, "created_at")?,
            status: match take_string(&mut data, "status")?.as_str() {
                "active" => ConnectionStatus::Active,
                "suspended" => ConnectionStatus::Suspended,
                _ => return Err(Error::InvalidField("status")),
            },
            target: ConnectionTarget::take(&mut data)?,
        };
        checked_time(&resource.created_at, "created_at")?;
        if take_string(&mut root, "updated_at")? != resource.created_at {
            return Err(Error::InvalidField("updated_at"));
        }
        if resource.organization_id != organization_id
            || expected_status.is_some_and(|status| status != resource.status)
        {
            return Err(Error::Context);
        }
        let body_tag = take_string(&mut root, "etag")?;
        if body_tag != resource.etag() || etag != Some(body_tag.as_str()) {
            return Err(Error::HttpMetadata);
        }
        Ok(resource)
    }
}

fn checked_time(value: &str, field: &'static str) -> Result<(), Error> {
    if valid_utc_timestamp(value) { Ok(()) } else { Err(Error::InvalidField(field)) }
}

/// Immutable authorization context used to validate a candidate response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActivationContext {
    /// Selected Organization.
    pub organization_id: Uuid,
    /// Reviewed issuer draft.
    pub draft_generation: Uuid,
    /// Connection revision at start.
    pub expected_revision: ExpectedRevision,
    /// Exact original public target.
    pub target: ConnectionTarget,
}

/// Bounded candidate status. The provider's identity and tokens are excluded.
#[derive(Debug, Eq, PartialEq)]
pub struct Activation {
    /// Allocated attempt ID.
    pub id: Uuid,
    /// Immutable start context.
    pub context: ActivationContext,
    /// Current proof state.
    pub status: DraftLoginStatus,
    /// Original expiry time.
    pub expires_at: String,
}

impl Activation {
    fn take(fields: &mut Map<String, Value>) -> Result<Self, Error> {
        let expected_revision = if fields.get("expected_revision") == Some(&Value::Null) {
            fields.remove("expected_revision");
            ExpectedRevision::Empty
        } else {
            ExpectedRevision::Current(take_uuid(fields, "expected_revision")?)
        };
        let value = Self {
            id: take_uuid(fields, "id")?,
            context: ActivationContext {
                organization_id: take_uuid(fields, "organization_id")?,
                draft_generation: take_uuid(fields, "draft_generation")?,
                expected_revision,
                target: ConnectionTarget::take(fields)?,
            },
            status: match take_string(fields, "status")?.as_str() {
                "pending" => DraftLoginStatus::Pending,
                "verified" => DraftLoginStatus::Verified,
                "failed" => DraftLoginStatus::Failed,
                _ => return Err(Error::InvalidField("status")),
            },
            expires_at: take_string(fields, "expires_at")?,
        };
        checked_time(&value.expires_at, "expires_at")?;
        Ok(value)
    }

    /// Read only the original candidate and reject start-only material.
    ///
    /// # Errors
    /// Rejects malformed replies, surrounding metadata and immutable context mismatches.
    pub fn from_http_json(
        bytes: &[u8],
        original: &Self,
        etag: Option<&str>,
        cache_control: Option<&str>,
        pragma: Option<&str>,
    ) -> Result<Self, Error> {
        validate_activation_headers(etag, cache_control, pragma)?;
        let mut fields = object(bytes, MAX_RESPONSE_BYTES)?;
        let attempt = Self::take(&mut fields)?;
        validate_public_fields(&fields, false)?;
        if attempt.id != original.id
            || attempt.context != original.context
            || attempt.expires_at != original.expires_at
        {
            return Err(Error::Context);
        }
        Ok(attempt)
    }

    /// Emit a bounded candidate status.
    ///
    /// # Errors
    /// Rejects invalid fields or body overflow.
    pub fn to_json(&self) -> Result<Vec<u8>, Error> {
        self.encode(None)
    }

    fn encode(&self, authorization_url: Option<&str>) -> Result<Vec<u8>, Error> {
        #[derive(Serialize)]
        struct Wire<'a> {
            #[serde(serialize_with = "serialize_uuid")]
            id: Uuid,
            #[serde(serialize_with = "serialize_uuid")]
            organization_id: Uuid,
            #[serde(serialize_with = "serialize_uuid")]
            draft_generation: Uuid,
            expected_revision: Option<String>,
            #[serde(flatten)]
            target: &'a ConnectionTarget,
            status: DraftLoginStatus,
            expires_at: &'a str,
            #[serde(skip_serializing_if = "Option::is_none")]
            authorization_url: Option<&'a str>,
        }
        valid_uuid(self.id, "id")?;
        valid_uuid(self.context.organization_id, "organization_id")?;
        valid_uuid(self.context.draft_generation, "draft_generation")?;
        self.context.target.validate()?;
        checked_time(&self.expires_at, "expires_at")?;
        let expected_revision = match self.context.expected_revision {
            ExpectedRevision::Empty => None,
            ExpectedRevision::Current(revision) => {
                valid_uuid(revision, "expected_revision")?;
                Some(revision.to_string())
            }
        };
        encode(
            &Wire {
                id: self.id,
                organization_id: self.context.organization_id,
                draft_generation: self.context.draft_generation,
                expected_revision,
                target: &self.context.target,
                status: self.status,
                expires_at: &self.expires_at,
                authorization_url,
            },
            MAX_RESPONSE_BYTES,
        )
    }
}

fn validate_activation_headers(
    etag: Option<&str>,
    cache_control: Option<&str>,
    pragma: Option<&str>,
) -> Result<(), Error> {
    validate_cache_headers(cache_control, pragma)?;
    if etag.is_some() { Err(Error::HttpMetadata) } else { Ok(()) }
}

fn validate_public_fields(
    fields: &Map<String, Value>,
    allow_navigation: bool,
) -> Result<(), Error> {
    for field in ["client_secret", "access_token", "refresh_token", "id_token", "claims"] {
        if fields.contains_key(field) {
            return Err(Error::InvalidField(field));
        }
    }
    if !allow_navigation && fields.contains_key("authorization_url") {
        return Err(Error::InvalidField("authorization_url"));
    }
    Ok(())
}

/// A pending candidate with a redacting, one-time navigation URL.
#[derive(Debug, Eq, PartialEq)]
pub struct ActivationStarted {
    /// Newly created attempt status.
    pub attempt: Activation,
    /// One-time navigation to the approved provider origin.
    pub authorization_url: SecretVec,
}

impl ActivationStarted {
    /// Read the start response for the exact expected candidate and trusted provider origin.
    ///
    /// # Errors
    /// Rejects invalid metadata, wrong context, terminal state or an untrusted URL.
    pub fn from_http_json(
        bytes: &[u8],
        expected: &ActivationContext,
        etag: Option<&str>,
        cache_control: Option<&str>,
        pragma: Option<&str>,
    ) -> Result<Self, Error> {
        validate_activation_headers(etag, cache_control, pragma)?;
        let mut fields = object(bytes, MAX_RESPONSE_BYTES)?;
        validate_public_fields(&fields, true)?;
        let attempt = Activation::take(&mut fields)?;
        if &attempt.context != expected {
            return Err(Error::Context);
        }
        let response = Self {
            attempt,
            authorization_url: SecretVec::new(
                take_string(&mut fields, "authorization_url")?.into_bytes(),
            ),
        };
        response.validate()?;
        Ok(response)
    }

    /// Emit a bounded start response in redacting, zeroizing storage.
    ///
    /// # Errors
    /// Rejects invalid state, metadata or body overflow.
    pub fn to_json(&self) -> Result<SecretVec, Error> {
        let url = self.validate()?;
        Ok(SecretVec::new(self.attempt.encode(Some(url))?))
    }

    fn validate(&self) -> Result<&str, Error> {
        if self.attempt.status != DraftLoginStatus::Pending {
            return Err(Error::InvalidField("status"));
        }
        validated_navigation(&self.authorization_url, &self.attempt.context.target.issuer)
    }
}
