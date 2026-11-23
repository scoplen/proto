// SPDX-License-Identifier: Apache-2.0
//! D-170 wire codecs for an existing Organization Membership's identity link.

use scoplen_crypto::SecretVec;
use serde::Serialize;
use serde_json::{Map, Value};
use uuid::Uuid;

use crate::{
    account_browser::AccountBrowserAccessOperation,
    auth_connection::ConnectionTarget,
    auth_connection_draft::{
        DraftRequestError,
        test_login::{DraftLoginStatus, serialize_uuid, validated_navigation},
    },
    certificate::valid_utc_timestamp,
    organization::{
        OrganizationCodecError as Error, encode, object, parse_organization_idempotency_key,
        parse_uuid, take_string, take_uuid, valid_uuid, validate_cache_headers,
    },
};

const MAX_RESPONSE_BYTES: usize = 8_192;

/// Parsed zero-byte request and the Organization selected by the route.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MemberLinkRequest {
    /// Canonical Organization path identifier.
    pub organization_id: Uuid,
    /// Operation and its reviewed conditions.
    pub action: LinkAction,
}

/// Link request syntax. The receiver separately checks authentication and current authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LinkAction {
    /// Read the caller's own link.
    ReadSelf,
    /// Start an attempt against the reviewed active revision.
    Start {
        /// Connection revision from `If-Match`.
        revision: Uuid,
    },
    /// Read the original family's attempt.
    ReadAttempt {
        /// Attempt from the route.
        attempt: Uuid,
    },
    /// Abandon the original family's attempt.
    Abandon {
        /// Attempt from the route.
        attempt: Uuid,
    },
    /// Confirm a verified attempt or recover the exact original result.
    Confirm {
        /// Attempt from the route.
        attempt: Uuid,
        /// Original connection revision.
        revision: Uuid,
        /// Original durable write key.
        key: Uuid,
    },
    /// Unlink the caller's reviewed link.
    UnlinkSelf {
        /// Link from `If-Match`.
        link: Uuid,
    },
    /// Read a named Membership's link.
    ReadNamed {
        /// Membership from the route.
        membership: Uuid,
    },
    /// Withdraw a named Membership's reviewed link.
    WithdrawNamed {
        /// Membership from the route.
        membership: Uuid,
        /// Link from `If-Match`.
        link: Uuid,
    },
}

impl MemberLinkRequest {
    /// Decode a request after an exact router method and template match.
    /// Pass the original path captures and individual header values before joining.
    ///
    /// # Errors
    /// Rejects extra captures, noncanonical identifiers, a query, a body, and unsupported,
    /// malformed or duplicate headers. Classifies a missing required condition as 428.
    pub fn from_http<'a>(
        operation: AccountBrowserAccessOperation,
        organization: &str,
        target: Option<&str>,
        query: Option<&str>,
        headers: impl IntoIterator<Item = (&'a str, &'a str)>,
        body: &[u8],
    ) -> Result<Self, DraftRequestError> {
        use AccountBrowserAccessOperation::{
            AuthLinkAbandon, AuthLinkAttemptRead, AuthLinkConfirm, AuthLinkNamedRead,
            AuthLinkNamedWithdraw, AuthLinkSelfRead, AuthLinkSelfUnlink, AuthLinkStart,
        };
        use DraftRequestError::{Invalid, PreconditionRequired};
        let organization_id = parse_uuid(organization, "org").map_err(|_| Invalid)?;
        if query.is_some() || !body.is_empty() {
            return Err(Invalid);
        }
        let mut matched = None;
        let mut idempotency = None;
        for (name, value) in headers {
            let field = if name.eq_ignore_ascii_case("If-Match") {
                &mut matched
            } else if name.eq_ignore_ascii_case("Idempotency-Key") {
                &mut idempotency
            } else if [
                "Content-Type",
                "If-None-Match",
                "If-Modified-Since",
                "If-Unmodified-Since",
                "If-Range",
            ]
            .iter()
            .any(|blocked| name.eq_ignore_ascii_case(blocked))
            {
                return Err(Invalid);
            } else {
                continue;
            };
            if field.replace(value).is_some() {
                return Err(Invalid);
            }
        }
        if operation != AuthLinkConfirm && idempotency.is_some() {
            return Err(Invalid);
        }
        let condition = || {
            let tag = matched.ok_or(PreconditionRequired)?;
            tag.strip_prefix('"')
                .and_then(|tag| tag.strip_suffix('"'))
                .and_then(|id| parse_uuid(id, "If-Match").ok())
                .ok_or(Invalid)
        };
        let capture = || parse_uuid(target.ok_or(Invalid)?, "target").map_err(|_| Invalid);
        let action = match operation {
            AuthLinkSelfRead if target.is_none() && matched.is_none() => LinkAction::ReadSelf,
            AuthLinkStart if target.is_none() => LinkAction::Start { revision: condition()? },
            AuthLinkAttemptRead if matched.is_none() => {
                LinkAction::ReadAttempt { attempt: capture()? }
            }
            AuthLinkAbandon if matched.is_none() => LinkAction::Abandon { attempt: capture()? },
            AuthLinkConfirm => LinkAction::Confirm {
                attempt: capture()?,
                revision: condition()?,
                key: parse_organization_idempotency_key(idempotency.ok_or(Invalid)?)
                    .map_err(|_| Invalid)?,
            },
            AuthLinkSelfUnlink if target.is_none() => LinkAction::UnlinkSelf { link: condition()? },
            AuthLinkNamedRead if matched.is_none() => {
                LinkAction::ReadNamed { membership: capture()? }
            }
            AuthLinkNamedWithdraw => {
                LinkAction::WithdrawNamed { membership: capture()?, link: condition()? }
            }
            _ => return Err(Invalid),
        };
        Ok(Self { organization_id, action })
    }
}

/// Required cache and optional entity tag response metadata.
#[derive(Clone, Copy, Debug)]
pub struct LinkResponseHeaders<'a> {
    /// Original HTTP `ETag` value.
    pub etag: Option<&'a str>,
    /// Original Cache-Control value.
    pub cache_control: Option<&'a str>,
    /// Original Pragma value.
    pub pragma: Option<&'a str>,
}

impl LinkResponseHeaders<'_> {
    fn check(self, etag: Option<&str>) -> Result<(), Error> {
        validate_cache_headers(self.cache_control, self.pragma)?;
        if self.etag == etag { Ok(()) } else { Err(Error::HttpMetadata) }
    }

    /// Validate an empty abandonment or withdrawal response.
    ///
    /// # Errors
    /// Rejects missing cache metadata, an `ETag` or any response bytes.
    pub fn validate_empty(self, bytes: &[u8]) -> Result<(), Error> {
        self.check(None)?;
        if bytes.is_empty() { Ok(()) } else { Err(Error::InvalidJson) }
    }
}

/// Public context shared by links and attempts.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct LinkMembership {
    /// The selected Organization.
    #[serde(serialize_with = "serialize_uuid")]
    pub organization_id: Uuid,
    /// The current Membership in that Organization.
    #[serde(serialize_with = "serialize_uuid")]
    pub membership_id: Uuid,
}

impl LinkMembership {
    fn take(fields: &mut Map<String, Value>) -> Result<Self, Error> {
        Ok(Self {
            organization_id: take_uuid(fields, "organization_id")?,
            membership_id: take_uuid(fields, "membership_id")?,
        })
    }

    fn validate(self) -> Result<(), Error> {
        valid_uuid(self.organization_id, "organization_id")?;
        valid_uuid(self.membership_id, "membership_id")
    }
}

/// Immutable public association. The provider subject stays private.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemberLink {
    /// Identity of the link and source of its strong `ETag`.
    pub id: Uuid,
    /// Link creation time in UTC.
    pub created_at: String,
    /// Organization and Membership that own the association.
    pub membership: LinkMembership,
}

#[derive(Serialize)]
struct LinkWire<'a> {
    #[serde(serialize_with = "serialize_uuid")]
    id: Uuid,
    etag: String,
    created_at: &'a str,
    #[serde(flatten)]
    membership: LinkMembership,
}

impl MemberLink {
    /// Canonical strong entity tag returned by confirmation and reviewed for unlink.
    #[must_use]
    pub fn etag(&self) -> String {
        format!("\"{}\"", self.id)
    }

    fn wire(&self, expected: LinkMembership) -> Result<LinkWire<'_>, Error> {
        self.membership.validate()?;
        valid_uuid(self.id, "id")?;
        check_time(&self.created_at, "created_at")?;
        if self.membership != expected {
            return Err(Error::Context);
        }
        Ok(LinkWire {
            id: self.id,
            etag: self.etag(),
            created_at: &self.created_at,
            membership: self.membership,
        })
    }

    fn take(mut fields: Map<String, Value>, expected: LinkMembership) -> Result<Self, Error> {
        check_public(&fields, false)?;
        let link = Self {
            id: take_uuid(&mut fields, "id")?,
            created_at: take_string(&mut fields, "created_at")?,
            membership: LinkMembership::take(&mut fields)?,
        };
        check_time(&link.created_at, "created_at")?;
        if link.membership != expected {
            return Err(Error::Context);
        }
        check_body_etag(&mut fields, &link.etag())?;
        Ok(link)
    }

    /// Parse the confirmed link or its eligible original-writer receipt.
    ///
    /// # Errors
    /// Rejects malformed bodies, wrong Membership and mismatched HTTP/body entity tags.
    pub fn from_http_json(
        bytes: &[u8],
        expected: LinkMembership,
        headers: LinkResponseHeaders<'_>,
    ) -> Result<Self, Error> {
        let link = Self::take(object(bytes, MAX_RESPONSE_BYTES)?, expected)?;
        headers.check(Some(&link.etag()))?;
        Ok(link)
    }

    /// Emit an immutable, bounded Link Resource.
    ///
    /// # Errors
    /// Rejects invalid identifiers, timestamps or size overflow.
    pub fn to_json(&self) -> Result<Vec<u8>, Error> {
        encode(&self.wire(self.membership)?, MAX_RESPONSE_BYTES)
    }
}

/// Current public link metadata scoped to one Membership.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemberLinkStatus {
    /// Public context for the selected Membership.
    pub membership: LinkMembership,
    /// The association, if present.
    pub link: Option<MemberLink>,
}

#[derive(Serialize)]
struct StatusWire<'a> {
    #[serde(flatten)]
    membership: LinkMembership,
    link: Option<LinkWire<'a>>,
}

impl MemberLinkStatus {
    fn take(fields: &mut Map<String, Value>, expected: LinkMembership) -> Result<Self, Error> {
        check_public(fields, false)?;
        let membership = LinkMembership::take(fields)?;
        if membership != expected {
            return Err(Error::Context);
        }
        let link = take_optional_object(fields, "link")?
            .map(|link| MemberLink::take(link, membership))
            .transpose()?;
        Ok(Self { membership, link })
    }

    fn wire(&self) -> Result<StatusWire<'_>, Error> {
        self.membership.validate()?;
        Ok(StatusWire {
            membership: self.membership,
            link: self.link.as_ref().map(|link| link.wire(self.membership)).transpose()?,
        })
    }

    /// Parse a named member's status without disclosing active connection metadata.
    ///
    /// # Errors
    /// Rejects invalid headers, malformed fields or a different Membership.
    pub fn from_http_json(
        bytes: &[u8],
        expected: LinkMembership,
        headers: LinkResponseHeaders<'_>,
    ) -> Result<Self, Error> {
        headers.check(None)?;
        let mut fields = object(bytes, MAX_RESPONSE_BYTES)?;
        if fields.contains_key("connection") {
            return Err(Error::InvalidField("connection"));
        }
        Self::take(&mut fields, expected)
    }

    /// Emit the named member's status with an explicit nullable link.
    ///
    /// # Errors
    /// Rejects invalid identifiers, inconsistent context or size overflow.
    pub fn to_json(&self) -> Result<Vec<u8>, Error> {
        encode(&self.wire()?, MAX_RESPONSE_BYTES)
    }
}

/// Public metadata for the active revision visible in self status.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinkConnection {
    /// Identity of the active revision and source of its strong body tag.
    pub id: Uuid,
    /// Exact active issuer, client and Space.
    pub target: ConnectionTarget,
}

#[derive(Serialize)]
struct ActiveConnectionWire<'a> {
    #[serde(serialize_with = "serialize_uuid")]
    id: Uuid,
    etag: String,
    #[serde(flatten)]
    target: &'a ConnectionTarget,
}

impl LinkConnection {
    /// Canonical strong tag to use when starting a link attempt.
    #[must_use]
    pub fn etag(&self) -> String {
        format!("\"{}\"", self.id)
    }

    fn take(mut fields: Map<String, Value>) -> Result<Self, Error> {
        check_public(&fields, false)?;
        let connection = Self {
            id: take_uuid(&mut fields, "id")?,
            target: ConnectionTarget::take(&mut fields)?,
        };
        check_body_etag(&mut fields, &connection.etag())?;
        Ok(connection)
    }

    fn wire(&self) -> Result<ActiveConnectionWire<'_>, Error> {
        valid_uuid(self.id, "id")?;
        self.target.validate()?;
        Ok(ActiveConnectionWire { id: self.id, etag: self.etag(), target: &self.target })
    }
}

/// Self status also displays the current active revision, if any.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SelfLinkStatus {
    /// Caller-scoped public link state.
    pub status: MemberLinkStatus,
    /// Active connection, if present.
    pub connection: Option<LinkConnection>,
}

impl SelfLinkStatus {
    /// Parse the caller's current status and reviewed active revision.
    ///
    /// # Errors
    /// Rejects malformed data, a different Membership or unsupported response headers.
    pub fn from_http_json(
        bytes: &[u8],
        expected: LinkMembership,
        headers: LinkResponseHeaders<'_>,
    ) -> Result<Self, Error> {
        headers.check(None)?;
        let mut fields = object(bytes, MAX_RESPONSE_BYTES)?;
        let status = MemberLinkStatus::take(&mut fields, expected)?;
        let connection = take_optional_object(&mut fields, "connection")?
            .map(LinkConnection::take)
            .transpose()?;
        Ok(Self { status, connection })
    }

    /// Emit self status with explicit nullable link and connection members.
    ///
    /// # Errors
    /// Rejects invalid context, metadata or size overflow.
    pub fn to_json(&self) -> Result<Vec<u8>, Error> {
        #[derive(Serialize)]
        struct Wire<'a> {
            #[serde(flatten)]
            status: StatusWire<'a>,
            connection: Option<ActiveConnectionWire<'a>>,
        }
        let connection = self.connection.as_ref().map(LinkConnection::wire).transpose()?;
        encode(&Wire { status: self.status.wire()?, connection }, MAX_RESPONSE_BYTES)
    }
}

/// Public attempt status. Navigation appears only in the start response.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct LinkAttempt {
    /// Attempt identifier.
    #[serde(serialize_with = "serialize_uuid")]
    pub id: Uuid,
    /// Original Organization and Membership.
    #[serde(flatten)]
    pub membership: LinkMembership,
    /// Original active connection revision.
    #[serde(serialize_with = "serialize_uuid")]
    pub connection_revision: Uuid,
    /// State visible to the original family.
    pub status: DraftLoginStatus,
    /// Immutable UTC expiry.
    pub expires_at: String,
}

impl LinkAttempt {
    fn take(fields: &mut Map<String, Value>) -> Result<Self, Error> {
        let attempt = Self {
            id: take_uuid(fields, "id")?,
            membership: LinkMembership::take(fields)?,
            connection_revision: take_uuid(fields, "connection_revision")?,
            status: match take_string(fields, "status")?.as_str() {
                "pending" => DraftLoginStatus::Pending,
                "verified" => DraftLoginStatus::Verified,
                "failed" => DraftLoginStatus::Failed,
                _ => return Err(Error::InvalidField("status")),
            },
            expires_at: take_string(fields, "expires_at")?,
        };
        check_time(&attempt.expires_at, "expires_at")?;
        Ok(attempt)
    }

    fn validate(&self) -> Result<(), Error> {
        valid_uuid(self.id, "id")?;
        self.membership.validate()?;
        valid_uuid(self.connection_revision, "connection_revision")?;
        check_time(&self.expires_at, "expires_at")
    }

    /// Decode a status response and bind immutable fields to the original attempt.
    ///
    /// # Errors
    /// Rejects malformed or unbound responses and any start-only navigation material.
    pub fn from_http_json(
        bytes: &[u8],
        original: &Self,
        headers: LinkResponseHeaders<'_>,
    ) -> Result<Self, Error> {
        headers.check(None)?;
        let mut fields = object(bytes, MAX_RESPONSE_BYTES)?;
        check_public(&fields, false)?;
        let attempt = Self::take(&mut fields)?;
        if attempt.id != original.id
            || attempt.membership != original.membership
            || attempt.connection_revision != original.connection_revision
            || attempt.expires_at != original.expires_at
        {
            return Err(Error::Context);
        }
        Ok(attempt)
    }

    /// Emit bounded attempt status without navigation.
    ///
    /// # Errors
    /// Rejects invalid fields or size overflow.
    pub fn to_json(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        encode(self, MAX_RESPONSE_BYTES)
    }
}

/// The original pending attempt and its one-time provider navigation.
#[derive(Debug, Eq, PartialEq)]
pub struct LinkAttemptStarted {
    /// Attempt recorded by the server.
    pub attempt: LinkAttempt,
    /// Redacted URL restricted to the approved provider origin.
    pub authorization_url: SecretVec,
}

impl LinkAttemptStarted {
    /// Decode the start response for the authenticated Membership and reviewed active revision.
    ///
    /// # Errors
    /// Rejects malformed or foreign context, terminal state and untrusted navigation.
    pub fn from_http_json(
        bytes: &[u8],
        expected: LinkMembership,
        connection: &LinkConnection,
        headers: LinkResponseHeaders<'_>,
    ) -> Result<Self, Error> {
        headers.check(None)?;
        let mut fields = object(bytes, MAX_RESPONSE_BYTES)?;
        check_public(&fields, true)?;
        let attempt = LinkAttempt::take(&mut fields)?;
        if attempt.membership != expected || attempt.connection_revision != connection.id {
            return Err(Error::Context);
        }
        let response = Self {
            attempt,
            authorization_url: SecretVec::new(
                take_string(&mut fields, "authorization_url")?.into_bytes(),
            ),
        };
        response.navigation(&connection.target.issuer)?;
        Ok(response)
    }

    /// Emit the original pending attempt and URL in zeroizing, redacting storage.
    ///
    /// # Errors
    /// Rejects invalid fields, a terminal attempt, untrusted navigation or size overflow.
    pub fn to_json(&self, issuer: &str) -> Result<SecretVec, Error> {
        #[derive(Serialize)]
        struct Wire<'a> {
            #[serde(flatten)]
            attempt: &'a LinkAttempt,
            authorization_url: &'a str,
        }
        self.attempt.validate()?;
        let authorization_url = self.navigation(issuer)?;
        Ok(SecretVec::new(encode(
            &Wire { attempt: &self.attempt, authorization_url },
            MAX_RESPONSE_BYTES,
        )?))
    }

    fn navigation(&self, issuer: &str) -> Result<&str, Error> {
        if self.attempt.status != DraftLoginStatus::Pending {
            return Err(Error::InvalidField("status"));
        }
        validated_navigation(&self.authorization_url, issuer)
    }
}

fn check_time(value: &str, field: &'static str) -> Result<(), Error> {
    if valid_utc_timestamp(value) { Ok(()) } else { Err(Error::InvalidField(field)) }
}

fn check_body_etag(fields: &mut Map<String, Value>, expected: &str) -> Result<(), Error> {
    if take_string(fields, "etag")? == expected { Ok(()) } else { Err(Error::HttpMetadata) }
}

fn take_optional_object(
    fields: &mut Map<String, Value>,
    name: &'static str,
) -> Result<Option<Map<String, Value>>, Error> {
    match fields.remove(name) {
        Some(Value::Object(value)) => Ok(Some(value)),
        Some(Value::Null) => Ok(None),
        _ => Err(Error::InvalidField(name)),
    }
}

fn check_public(fields: &Map<String, Value>, allow_navigation: bool) -> Result<(), Error> {
    for field in [
        "sub",
        "subject",
        "subject_digest",
        "subject_comparison",
        "comparison_value",
        "claims",
        "client_secret",
        "access_token",
        "refresh_token",
        "id_token",
    ] {
        if fields.contains_key(field) {
            return Err(Error::InvalidField(field));
        }
    }
    if !allow_navigation && fields.contains_key("authorization_url") {
        return Err(Error::InvalidField("authorization_url"));
    }
    Ok(())
}
