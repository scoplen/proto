// SPDX-License-Identifier: Apache-2.0
//! D-136 named-Account invitation and team membership messages.
//!
//! Parsing establishes syntax and captured-response binding, never current authority.

use std::{
    collections::BTreeSet,
    fmt,
    ops::{Deref, DerefMut},
};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use scoplen_crypto::{SecretVec, TeamInvitationPassword, TeamInvitationVerifier};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, value::RawValue};
use uuid::Uuid;

use crate::{
    certificate::{valid_strong_etag, valid_utc_timestamp},
    organization::{
        MAX_ORGANIZATION_PAGE_BYTES, MAX_ORGANIZATION_RESOURCE_BYTES, OrganizationCodecError,
        OrganizationListQuery, encode, object, parse_uuid, take_object, take_string, take_uuid,
        valid_uuid, validate_cache_headers, validate_name,
    },
};

/// Complete invitation creation JSON ceiling.
pub const MAX_INVITATION_CREATE_BYTES: usize = 4_096;
/// Complete invitation acceptance JSON ceiling.
pub const MAX_INVITATION_ACCEPT_BYTES: usize = 256;
/// Complete member update JSON ceiling.
pub const MAX_MEMBER_UPDATE_BYTES: usize = 1_024;
/// Complete dissolution request JSON ceiling.
pub const MAX_DISSOLUTION_REQUEST_BYTES: usize = 256;
/// Complete historical acceptance receipt ceiling.
pub const MAX_ACCEPTANCE_RECEIPT_BYTES: usize = 1_024;
/// Complete historical dissolution receipt ceiling.
pub const MAX_DISSOLUTION_RECEIPT_BYTES: usize = 512;
/// Invitation expiry and dedicated operation receipt lifetime.
pub const TEAM_RECEIPT_LIFETIME_SECONDS: u64 = 86_400;

/// Initial built-in roles, in byte-sorted wire order; this ordering grants no authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TeamRole {
    /// Organization administration without Owner grants.
    Administrator,
    /// Approvals routed to this member.
    Approver,
    /// Explicitly permitted team use.
    Member,
    /// Organization ownership, including dissolution.
    Owner,
    /// Read-only security inspection.
    SecurityAuditor,
}

impl TeamRole {
    /// Exact case-sensitive identifier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Administrator => "administrator",
            Self::Approver => "approver",
            Self::Member => "member",
            Self::Owner => "owner",
            Self::SecurityAuditor => "security_auditor",
        }
    }

    /// Parse one exact built-in role for a request or stored membership projection.
    /// # Errors
    /// Rejects aliases and unknown role identifiers.
    pub fn parse(text: &str) -> Result<Self, OrganizationCodecError> {
        match text {
            "administrator" => Ok(Self::Administrator),
            "approver" => Ok(Self::Approver),
            "member" => Ok(Self::Member),
            "owner" => Ok(Self::Owner),
            "security_auditor" => Ok(Self::SecurityAuditor),
            _ => Err(invalid("roles")),
        }
    }
}

/// Public locator only; the separate password never appears in this type or its URL.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TeamInvitationLink {
    /// Canonical deployment HTTPS origin.
    pub origin: String,
    /// Captured Organization.
    pub organization_id: Uuid,
    /// Captured invitation.
    pub invitation_id: Uuid,
}

impl TeamInvitationLink {
    /// Parse the exact public link without normalization, aliases or secret fields.
    /// # Errors
    /// Rejects noncanonical origin, path, ids, parameter order or extra fields.
    pub fn parse(input: &str) -> Result<Self, OrganizationCodecError> {
        if input.len() > 2_200 {
            return Err(OrganizationCodecError::TooLarge);
        }
        let (origin, fragment) =
            input.split_once("/join-team#organization=").ok_or(invalid("invitation link"))?;
        let (organization, invitation) =
            fragment.split_once("&invitation=").ok_or(invalid("invitation link"))?;
        let value = Self {
            origin: origin.into(),
            organization_id: parse_uuid(organization, "organization_id")?,
            invitation_id: parse_uuid(invitation, "invitation_id")?,
        };
        value.validate()?;
        Ok(value)
    }

    /// Revalidate mutable public fields.
    /// # Errors
    /// Rejects noncanonical origin or non-UUIDv7 ids.
    pub fn validate(&self) -> Result<(), OrganizationCodecError> {
        scoplen_crypto::validate_server_origin(&self.origin).map_err(|_| invalid("origin"))?;
        valid_uuid(self.organization_id, "organization_id")?;
        valid_uuid(self.invitation_id, "invitation_id")
    }

    /// Encode the exact public locator, without a password or acceptance action.
    /// # Errors
    /// Rejects invalid public fields.
    pub fn to_url(&self) -> Result<String, OrganizationCodecError> {
        self.validate()?;
        Ok(format!(
            "{}/join-team#organization={}&invitation={}",
            self.origin, self.organization_id, self.invitation_id
        ))
    }
}

/// Exact invitation creation payload. The server resolves and binds the named Account.
#[derive(Clone, Eq, PartialEq)]
pub struct TeamInvitationCreateRequest {
    /// Client-created invitation `UUIDv7`.
    pub invitation_id: Uuid,
    /// Canonical existing deployment username.
    pub recipient_username: String,
    /// Intended built-in roles, without duplicates.
    pub roles: Vec<TeamRole>,
    /// Sensitive domain-separated password verifier.
    pub password_verifier: TeamInvitationVerifier,
}

impl fmt::Debug for TeamInvitationCreateRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TeamInvitationCreateRequest").finish_non_exhaustive()
    }
}

impl TeamInvitationCreateRequest {
    /// Revalidate ids, username and requested role set, without granting them.
    /// # Errors
    /// Rejects malformed public fields.
    pub fn validate(&self) -> Result<(), OrganizationCodecError> {
        valid_uuid(self.invitation_id, "invitation_id")?;
        validate_username(&self.recipient_username)?;
        validate_roles(&self.roles)
    }

    /// Decode the exact bounded request, retaining no plaintext invitation password.
    /// # Errors
    /// Rejects duplicate/unknown/malformed fields and noncanonical verifier encoding.
    pub fn from_json(input: &[u8]) -> Result<Self, OrganizationCodecError> {
        let mut fields = SensitiveFields(object(input, MAX_INVITATION_CREATE_BYTES)?);
        let invitation_id = take_uuid(&mut fields, "invitation_id")?;
        let recipient_username = take_string(&mut fields, "recipient_username")?;
        let roles = take_roles(&mut fields)?;
        let encoded = SecretVec::new(take_string(&mut fields, "password_verifier")?.into_bytes());
        let decoded = SecretVec::new(
            URL_SAFE_NO_PAD.decode(encoded.as_bytes()).map_err(|_| invalid("password_verifier"))?,
        );
        if decoded.len() != 32 {
            return Err(invalid("password_verifier"));
        }
        let canonical = SecretVec::new(URL_SAFE_NO_PAD.encode(decoded.as_bytes()).into_bytes());
        if canonical != encoded {
            return Err(invalid("password_verifier"));
        }
        no_extensions(&fields)?;
        let password_verifier = TeamInvitationVerifier::from_bytes(
            decoded.as_bytes().try_into().map_err(|_| invalid("password_verifier"))?,
        );
        let value = Self { invitation_id, recipient_username, roles, password_verifier };
        value.validate()?;
        Ok(value)
    }

    /// Encode canonical request order with redacting, zeroizing ownership of its bytes.
    /// # Errors
    /// Rejects invalid fields or body overflow.
    pub fn to_json(&self) -> Result<SecretVec, OrganizationCodecError> {
        #[derive(Serialize)]
        struct Wire<'a> {
            invitation_id: String,
            recipient_username: &'a str,
            roles: Vec<TeamRole>,
            password_verifier: &'a str,
        }
        self.validate()?;
        let encoded =
            SecretVec::new(URL_SAFE_NO_PAD.encode(self.password_verifier.as_bytes()).into_bytes());
        let password_verifier =
            std::str::from_utf8(encoded.as_bytes()).map_err(|_| invalid("password_verifier"))?;
        Ok(SecretVec::new(encode(
            &Wire {
                invitation_id: self.invitation_id.to_string(),
                recipient_username: &self.recipient_username,
                roles: sorted_roles(&self.roles),
                password_verifier,
            },
            MAX_INVITATION_CREATE_BYTES,
        )?))
    }
}

/// Recipient acceptance carries only the transient separate invitation password.
#[derive(Clone, Eq, PartialEq)]
pub struct TeamInvitationAcceptRequest {
    /// Exact eight-symbol password; no Account password or proposed role.
    pub password: TeamInvitationPassword,
}

impl fmt::Debug for TeamInvitationAcceptRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TeamInvitationAcceptRequest").finish_non_exhaustive()
    }
}

impl TeamInvitationAcceptRequest {
    /// Decode only the bounded, exact password field.
    /// # Errors
    /// Rejects malformed JSON, unknown fields or any password alias.
    pub fn from_json(input: &[u8]) -> Result<Self, OrganizationCodecError> {
        let mut fields = SensitiveFields(object(input, MAX_INVITATION_ACCEPT_BYTES)?);
        let text = SecretVec::new(take_string(&mut fields, "password")?.into_bytes());
        no_extensions(&fields)?;
        let password =
            TeamInvitationPassword::parse(text.as_bytes()).map_err(|_| invalid("password"))?;
        Ok(Self { password })
    }

    /// Encode the canonical acceptance request in a zeroizing body.
    /// # Errors
    /// Rejects body encoding failures.
    pub fn to_json(&self) -> Result<SecretVec, OrganizationCodecError> {
        #[derive(Serialize)]
        struct Wire<'a> {
            password: &'a str,
        }
        let password =
            std::str::from_utf8(self.password.as_bytes()).map_err(|_| invalid("password"))?;
        Ok(SecretVec::new(encode(&Wire { password }, MAX_INVITATION_ACCEPT_BYTES)?))
    }
}

/// Persisted invitation state; parsing it does not authorize acceptance or revocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TeamInvitationStatus {
    /// Awaiting the designated recipient.
    Pending,
    /// Accepted once.
    Accepted,
    /// Explicitly revoked.
    Revoked,
    /// Its fixed lifetime ended.
    Expired,
    /// Five incorrect password attempts.
    Locked,
}

impl TeamInvitationStatus {
    /// Parse the exact public invitation state without normalization.
    /// # Errors
    /// Rejects aliases and unknown states.
    pub fn parse(value: &str) -> Result<Self, OrganizationCodecError> {
        match value {
            "pending" => Ok(Self::Pending),
            "accepted" => Ok(Self::Accepted),
            "revoked" => Ok(Self::Revoked),
            "expired" => Ok(Self::Expired),
            "locked" => Ok(Self::Locked),
            _ => Err(invalid("status")),
        }
    }
}

/// Authorized administrator or fixed recipient's invitation projection, without its verifier.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TeamInvitationResource {
    /// Invitation `UUIDv7`.
    pub id: Uuid,
    /// Strong current projection validator.
    pub etag: String,
    /// UTC creation time.
    pub created_at: String,
    /// UTC update time.
    pub updated_at: String,
    /// Owning Organization.
    pub organization_id: Uuid,
    /// Current team name, authorized for this recipient preview.
    pub organization_name: String,
    /// Fixed recipient Account.
    pub recipient_account_id: Uuid,
    /// Canonical recipient username.
    pub recipient_username: String,
    /// Intended roles; syntax alone grants none.
    pub roles: Vec<TeamRole>,
    /// Original issuing Account.
    pub issuer_account_id: Uuid,
    /// Fixed UTC expiry.
    pub expires_at: String,
    /// Current invitation state.
    pub status: TeamInvitationStatus,
    /// Present exactly when accepted.
    pub membership_id: Option<Uuid>,
}

impl TeamInvitationResource {
    /// Decode an individual Resource and require its exact `ETag` and no-cache headers.
    /// The transport separately checks status, content type and request id.
    /// # Errors
    /// Rejects invalid metadata or body.
    pub fn from_http_json(
        input: &[u8],
        etag: Option<&str>,
        cache_control: Option<&str>,
        pragma: Option<&str>,
    ) -> Result<Self, OrganizationCodecError> {
        let value = Self::from_json(input)?;
        validate_resource_headers(&value.etag, etag, cache_control, pragma)?;
        Ok(value)
    }

    /// Recheck all required metadata and state-dependent membership syntax.
    /// # Errors
    /// Rejects invalid ids, roles, name, timestamps or state projection.
    pub fn validate(&self) -> Result<(), OrganizationCodecError> {
        validate_metadata(self.id, &self.etag, &self.created_at, &self.updated_at)?;
        valid_uuid(self.organization_id, "organization_id")?;
        valid_uuid(self.recipient_account_id, "recipient_account_id")?;
        valid_uuid(self.issuer_account_id, "issuer_account_id")?;
        validate_name(&self.organization_name)?;
        validate_username(&self.recipient_username)?;
        validate_roles(&self.roles)?;
        if !valid_utc_timestamp(&self.expires_at) {
            return Err(invalid("expires_at"));
        }
        if (self.status == TeamInvitationStatus::Accepted) != self.membership_id.is_some() {
            return Err(invalid("membership_id"));
        }
        if let Some(id) = self.membership_id {
            valid_uuid(id, "membership_id")?;
        }
        Ok(())
    }

    /// Bind a recipient preview to the captured Account, Organization and invitation.
    /// # Errors
    /// Rejects a valid response for another captured operation.
    pub fn validate_for_recipient(
        &self,
        account: Uuid,
        organization: Uuid,
        invitation: Uuid,
    ) -> Result<(), OrganizationCodecError> {
        self.validate()?;
        if self.recipient_account_id != account
            || self.organization_id != organization
            || self.id != invitation
        {
            return Err(OrganizationCodecError::Context);
        }
        Ok(())
    }

    /// Decode one complete Resource, including duplicate-name checks in ignored extensions.
    /// # Errors
    /// Rejects malformed or over-budget responses.
    pub fn from_json(input: &[u8]) -> Result<Self, OrganizationCodecError> {
        let mut fields = object(input, MAX_ORGANIZATION_RESOURCE_BYTES)?;
        let (id, etag, created_at, updated_at) = take_metadata(&mut fields)?;
        let mut data = take_object(&mut fields, "data")?;
        let value = Self {
            id,
            etag,
            created_at,
            updated_at,
            organization_id: take_uuid(&mut data, "organization_id")?,
            organization_name: take_string(&mut data, "organization_name")?,
            recipient_account_id: take_uuid(&mut data, "recipient_account_id")?,
            recipient_username: take_string(&mut data, "recipient_username")?,
            roles: take_roles(&mut data)?,
            issuer_account_id: take_uuid(&mut data, "issuer_account_id")?,
            expires_at: take_string(&mut data, "expires_at")?,
            status: TeamInvitationStatus::parse(&take_string(&mut data, "status")?)?,
            membership_id: take_optional_uuid(&mut data, "membership_id")?,
        };
        value.validate()?;
        Ok(value)
    }

    /// Canonical bounded Resource encoding, preserving specified field and sorted-role order.
    /// # Errors
    /// Rejects invalid public fields or complete response overflow.
    pub fn to_json(&self) -> Result<Vec<u8>, OrganizationCodecError> {
        #[derive(Serialize)]
        struct Data<'a> {
            organization_id: String,
            organization_name: &'a str,
            recipient_account_id: String,
            recipient_username: &'a str,
            roles: Vec<TeamRole>,
            issuer_account_id: String,
            expires_at: &'a str,
            status: TeamInvitationStatus,
            membership_id: Option<String>,
        }
        self.validate()?;
        encode_resource(
            self.id,
            &self.etag,
            &self.created_at,
            &self.updated_at,
            Data {
                organization_id: self.organization_id.to_string(),
                organization_name: &self.organization_name,
                recipient_account_id: self.recipient_account_id.to_string(),
                recipient_username: &self.recipient_username,
                roles: sorted_roles(&self.roles),
                issuer_account_id: self.issuer_account_id.to_string(),
                expires_at: &self.expires_at,
                status: self.status,
                membership_id: self.membership_id.map(|id| id.to_string()),
            },
        )
    }
}

/// Team-specific membership state, independent of Account or Device state.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TeamMemberStatus {
    /// Current membership.
    Active,
    /// Administrator may restore it with PATCH.
    Suspended,
    /// Only a fresh named invitation can restore it.
    Removed,
}

impl TeamMemberStatus {
    /// Parse the exact public membership state, independent of storage representations.
    /// # Errors
    /// Rejects aliases and unknown states.
    pub fn parse(text: &str) -> Result<Self, OrganizationCodecError> {
        match text {
            "active" => Ok(Self::Active),
            "suspended" => Ok(Self::Suspended),
            "removed" => Ok(Self::Removed),
            _ => Err(invalid("status")),
        }
    }
}

/// Administrative member update; removal is a separate conditional DELETE.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TeamMemberUpdateRequest {
    /// Complete intended built-in role set.
    pub roles: Vec<TeamRole>,
    /// Active or suspended, never removed.
    pub status: TeamMemberStatus,
}

impl TeamMemberUpdateRequest {
    /// Validate request syntax without deciding the caller's Owner authority.
    /// # Errors
    /// Rejects empty/duplicate roles or removed-state PATCH.
    pub fn validate(&self) -> Result<(), OrganizationCodecError> {
        validate_roles(&self.roles)?;
        if self.status == TeamMemberStatus::Removed {
            return Err(invalid("status"));
        }
        Ok(())
    }
    /// Decode only the complete roles/status update.
    /// # Errors
    /// Rejects malformed, duplicate or unknown members.
    pub fn from_json(input: &[u8]) -> Result<Self, OrganizationCodecError> {
        let mut fields = object(input, MAX_MEMBER_UPDATE_BYTES)?;
        let value = Self {
            roles: take_roles(&mut fields)?,
            status: TeamMemberStatus::parse(&take_string(&mut fields, "status")?)?,
        };
        no_extensions(&fields)?;
        value.validate()?;
        Ok(value)
    }
    /// Encode sorted roles then status, without a proposed Account or Organization.
    /// # Errors
    /// Rejects invalid mutable fields.
    pub fn to_json(&self) -> Result<Vec<u8>, OrganizationCodecError> {
        #[derive(Serialize)]
        struct Wire {
            roles: Vec<TeamRole>,
            status: TeamMemberStatus,
        }
        self.validate()?;
        encode(
            &Wire { roles: sorted_roles(&self.roles), status: self.status },
            MAX_MEMBER_UPDATE_BYTES,
        )
    }
}

/// Current authorized directory projection; contains no Personal identity data or keys.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TeamMemberResource {
    /// Membership `UUIDv7`.
    pub id: Uuid,
    /// Current strong member projection validator.
    pub etag: String,
    /// UTC creation time.
    pub created_at: String,
    /// UTC update time.
    pub updated_at: String,
    /// Owning team.
    pub organization_id: Uuid,
    /// Independent Account.
    pub account_id: Uuid,
    /// Canonical username, without email.
    pub username: String,
    /// Current built-in roles.
    pub roles: Vec<TeamRole>,
    /// Current team membership state.
    pub status: TeamMemberStatus,
}

impl TeamMemberResource {
    /// Decode a Member Resource with its exact strong validator and no-cache metadata.
    /// The transport separately checks status, content type and request id.
    /// # Errors
    /// Rejects malformed metadata or body.
    pub fn from_http_json(
        input: &[u8],
        etag: Option<&str>,
        cache_control: Option<&str>,
        pragma: Option<&str>,
    ) -> Result<Self, OrganizationCodecError> {
        let value = Self::from_json(input)?;
        validate_resource_headers(&value.etag, etag, cache_control, pragma)?;
        Ok(value)
    }

    /// Validate complete required values without establishing current authority.
    /// # Errors
    /// Rejects invalid required fields.
    pub fn validate(&self) -> Result<(), OrganizationCodecError> {
        validate_metadata(self.id, &self.etag, &self.created_at, &self.updated_at)?;
        valid_uuid(self.organization_id, "organization_id")?;
        valid_uuid(self.account_id, "account_id")?;
        validate_username(&self.username)?;
        validate_roles(&self.roles)
    }
    /// Bind a directory item to its captured team.
    /// # Errors
    /// Rejects foreign or malformed projections.
    pub fn validate_for_organization(
        &self,
        organization: Uuid,
    ) -> Result<(), OrganizationCodecError> {
        self.validate()?;
        if self.organization_id != organization {
            return Err(OrganizationCodecError::Context);
        }
        Ok(())
    }
    /// Decode a bounded Member Resource and validate ignored extensions for duplicate names.
    /// # Errors
    /// Rejects malformed required fields or complete byte overflow.
    pub fn from_json(input: &[u8]) -> Result<Self, OrganizationCodecError> {
        let mut fields = object(input, MAX_ORGANIZATION_RESOURCE_BYTES)?;
        let (id, etag, created_at, updated_at) = take_metadata(&mut fields)?;
        let mut data = take_object(&mut fields, "data")?;
        let value = Self {
            id,
            etag,
            created_at,
            updated_at,
            organization_id: take_uuid(&mut data, "organization_id")?,
            account_id: take_uuid(&mut data, "account_id")?,
            username: take_string(&mut data, "username")?,
            roles: take_roles(&mut data)?,
            status: TeamMemberStatus::parse(&take_string(&mut data, "status")?)?,
        };
        value.validate()?;
        Ok(value)
    }
    /// Encode the canonical complete Member Resource.
    /// # Errors
    /// Rejects invalid public fields or response overflow.
    pub fn to_json(&self) -> Result<Vec<u8>, OrganizationCodecError> {
        #[derive(Serialize)]
        struct Data<'a> {
            organization_id: String,
            account_id: String,
            username: &'a str,
            roles: Vec<TeamRole>,
            status: TeamMemberStatus,
        }
        self.validate()?;
        encode_resource(
            self.id,
            &self.etag,
            &self.created_at,
            &self.updated_at,
            Data {
                organization_id: self.organization_id.to_string(),
                account_id: self.account_id.to_string(),
                username: &self.username,
                roles: sorted_roles(&self.roles),
                status: self.status,
            },
        )
    }
}

/// Immutable confirmation of one historical invitation acceptance, never current membership.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TeamAcceptanceReceipt {
    /// Original invitation.
    pub invitation_id: Uuid,
    /// Original Organization.
    pub organization_id: Uuid,
    /// Original accepting Account.
    pub account_id: Uuid,
    /// Accepted membership.
    pub membership_id: Uuid,
    /// Original UTC acceptance time.
    pub accepted_at: String,
}

impl TeamAcceptanceReceipt {
    /// Validate all echoed ids and the original operation timestamp.
    /// # Errors
    /// Rejects malformed required fields.
    pub fn validate(&self) -> Result<(), OrganizationCodecError> {
        for (id, field) in [
            (self.invitation_id, "invitation_id"),
            (self.organization_id, "organization_id"),
            (self.account_id, "account_id"),
            (self.membership_id, "membership_id"),
        ] {
            valid_uuid(id, field)?;
        }
        if !valid_utc_timestamp(&self.accepted_at) {
            return Err(invalid("accepted_at"));
        }
        Ok(())
    }
    /// Bind historical success to the captured recipient, team and invitation.
    /// # Errors
    /// Rejects a valid receipt for another operation.
    pub fn validate_for_request(
        &self,
        account: Uuid,
        organization: Uuid,
        invitation: Uuid,
    ) -> Result<(), OrganizationCodecError> {
        self.validate()?;
        if self.account_id != account
            || self.organization_id != organization
            || self.invitation_id != invitation
        {
            return Err(OrganizationCodecError::Context);
        }
        Ok(())
    }
    /// Decode the complete historical receipt; extensions establish no authority.
    /// # Errors
    /// Rejects malformed or oversized input.
    pub fn from_json(input: &[u8]) -> Result<Self, OrganizationCodecError> {
        let mut fields = object(input, MAX_ACCEPTANCE_RECEIPT_BYTES)?;
        let value = Self {
            invitation_id: take_uuid(&mut fields, "invitation_id")?,
            organization_id: take_uuid(&mut fields, "organization_id")?,
            account_id: take_uuid(&mut fields, "account_id")?,
            membership_id: take_uuid(&mut fields, "membership_id")?,
            accepted_at: take_string(&mut fields, "accepted_at")?,
        };
        value.validate()?;
        Ok(value)
    }
    /// Encode the original confirmation in its specified field order.
    /// # Errors
    /// Rejects invalid fields or body overflow.
    pub fn to_json(&self) -> Result<Vec<u8>, OrganizationCodecError> {
        #[derive(Serialize)]
        struct Wire<'a> {
            invitation_id: String,
            organization_id: String,
            account_id: String,
            membership_id: String,
            accepted_at: &'a str,
        }
        self.validate()?;
        encode(
            &Wire {
                invitation_id: self.invitation_id.to_string(),
                organization_id: self.organization_id.to_string(),
                account_id: self.account_id.to_string(),
                membership_id: self.membership_id.to_string(),
                accepted_at: &self.accepted_at,
            },
            MAX_ACCEPTANCE_RECEIPT_BYTES,
        )
    }
}

/// Explicit echoed team id for Owner-only dissolution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TeamDissolveRequest {
    /// Must match the captured path Organization.
    pub organization_id: Uuid,
}

impl TeamDissolveRequest {
    /// Decode the exact bounded body, without proposed authority.
    /// # Errors
    /// Rejects malformed ids, duplicates and extensions.
    pub fn from_json(input: &[u8]) -> Result<Self, OrganizationCodecError> {
        let mut fields = object(input, MAX_DISSOLUTION_REQUEST_BYTES)?;
        let organization_id = take_uuid(&mut fields, "organization_id")?;
        no_extensions(&fields)?;
        Ok(Self { organization_id })
    }
    /// Bind the echoed id to the route before policy or mutation handling.
    /// # Errors
    /// Rejects a different Organization or invalid id.
    pub fn validate_for_organization(
        &self,
        organization: Uuid,
    ) -> Result<(), OrganizationCodecError> {
        valid_uuid(self.organization_id, "organization_id")?;
        if self.organization_id != organization {
            return Err(OrganizationCodecError::Context);
        }
        Ok(())
    }
    /// Encode the exact original dissolution payload.
    /// # Errors
    /// Rejects a non-UUIDv7 id.
    pub fn to_json(&self) -> Result<Vec<u8>, OrganizationCodecError> {
        #[derive(Serialize)]
        struct Wire {
            organization_id: String,
        }
        valid_uuid(self.organization_id, "organization_id")?;
        encode(
            &Wire { organization_id: self.organization_id.to_string() },
            MAX_DISSOLUTION_REQUEST_BYTES,
        )
    }
}

/// Historical dissolution confirmation, including after the team became inaccessible.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TeamDissolutionReceipt {
    /// Original dissolved Organization.
    pub organization_id: Uuid,
    /// Original UTC dissolution time.
    pub dissolved_at: String,
}

impl TeamDissolutionReceipt {
    /// Decode a complete bounded receipt without current-membership implications.
    /// # Errors
    /// Rejects invalid ids, timestamps, duplicate names and overflow.
    pub fn from_json(input: &[u8]) -> Result<Self, OrganizationCodecError> {
        let mut fields = object(input, MAX_DISSOLUTION_RECEIPT_BYTES)?;
        let value = Self {
            organization_id: take_uuid(&mut fields, "organization_id")?,
            dissolved_at: take_string(&mut fields, "dissolved_at")?,
        };
        value.validate_for_organization(value.organization_id)?;
        Ok(value)
    }
    /// Bind the receipt to the original captured team.
    /// # Errors
    /// Rejects malformed or foreign confirmation.
    pub fn validate_for_organization(
        &self,
        organization: Uuid,
    ) -> Result<(), OrganizationCodecError> {
        valid_uuid(self.organization_id, "organization_id")?;
        if !valid_utc_timestamp(&self.dissolved_at) {
            return Err(invalid("dissolved_at"));
        }
        if self.organization_id != organization {
            return Err(OrganizationCodecError::Context);
        }
        Ok(())
    }
    /// Encode only the historical confirmation, never retained team data.
    /// # Errors
    /// Rejects invalid fields or overflow.
    pub fn to_json(&self) -> Result<Vec<u8>, OrganizationCodecError> {
        #[derive(Serialize)]
        struct Wire<'a> {
            organization_id: String,
            dissolved_at: &'a str,
        }
        self.validate_for_organization(self.organization_id)?;
        encode(
            &Wire {
                organization_id: self.organization_id.to_string(),
                dissolved_at: &self.dissolved_at,
            },
            MAX_DISSOLUTION_RECEIPT_BYTES,
        )
    }
}

/// Ascending authorized invitation directory; not a frozen authorization snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TeamInvitationPage {
    /// Complete authorized Resources, each within its own byte ceiling.
    pub items: Vec<TeamInvitationResource>,
    /// Last returned id exactly when more eligible invitations exist.
    pub next_cursor: Option<Uuid>,
}

impl TeamInvitationPage {
    /// Revalidate each Resource, ordering and nonempty continuation.
    /// # Errors
    /// Rejects malformed items or continuation.
    pub fn validate(&self) -> Result<(), OrganizationCodecError> {
        for item in &self.items {
            item.validate()?;
        }
        validate_page_ids(
            &self.items.iter().map(|item| item.id).collect::<Vec<_>>(),
            self.next_cursor,
            None,
        )
    }
    /// Bind the page to the captured team and original continuation query.
    /// # Errors
    /// Rejects foreign Resources, excessive count or an earlier/repeated item.
    pub fn validate_for_organization(
        &self,
        organization: Uuid,
        query: OrganizationListQuery,
    ) -> Result<(), OrganizationCodecError> {
        self.validate()?;
        if self.items.iter().any(|item| item.organization_id != organization) {
            return Err(OrganizationCodecError::Context);
        }
        validate_page_ids(
            &self.items.iter().map(|item| item.id).collect::<Vec<_>>(),
            self.next_cursor,
            Some(query),
        )
    }
    /// Decode the whole bounded page and each original embedded Resource's byte size.
    /// # Errors
    /// Rejects malformed or over-budget pages and items.
    pub fn from_json(input: &[u8]) -> Result<Self, OrganizationCodecError> {
        let (items, next_cursor) = decode_page(input)?;
        let value = Self {
            items: items
                .iter()
                .map(|raw| TeamInvitationResource::from_json(raw.get().as_bytes()))
                .collect::<Result<_, _>>()?,
            next_cursor,
        };
        value.validate()?;
        Ok(value)
    }
    /// Decode a directory with mandatory cache-prevention metadata.
    /// # Errors
    /// Rejects invalid metadata, body or embedded items.
    pub fn from_http_json(
        input: &[u8],
        cache_control: Option<&str>,
        pragma: Option<&str>,
    ) -> Result<Self, OrganizationCodecError> {
        validate_cache_headers(cache_control, pragma)?;
        Self::from_json(input)
    }
    /// Canonical encoding with individual Resource validation before the page budget.
    /// # Errors
    /// Rejects invalid items or complete-body overflow.
    pub fn to_json(&self) -> Result<Vec<u8>, OrganizationCodecError> {
        self.validate()?;
        encode_page(
            self.items.iter().map(TeamInvitationResource::to_json).collect::<Result<_, _>>()?,
            self.next_cursor,
        )
    }
}

/// Ascending administrative membership directory, independently bound to its team.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TeamMemberPage {
    /// Complete authorized directory entries.
    pub items: Vec<TeamMemberResource>,
    /// Last returned membership id exactly when more items exist.
    pub next_cursor: Option<Uuid>,
}

impl TeamMemberPage {
    /// Revalidate required Resources and page ordering.
    /// # Errors
    /// Rejects malformed or duplicate items and invalid continuation.
    pub fn validate(&self) -> Result<(), OrganizationCodecError> {
        for item in &self.items {
            item.validate()?;
        }
        validate_page_ids(
            &self.items.iter().map(|item| item.id).collect::<Vec<_>>(),
            self.next_cursor,
            None,
        )
    }
    /// Bind the complete directory page to its captured Organization and query.
    /// # Errors
    /// Rejects foreign items, excess count or a repeated/earlier page range.
    pub fn validate_for_organization(
        &self,
        organization: Uuid,
        query: OrganizationListQuery,
    ) -> Result<(), OrganizationCodecError> {
        self.validate()?;
        if self.items.iter().any(|item| item.organization_id != organization) {
            return Err(OrganizationCodecError::Context);
        }
        validate_page_ids(
            &self.items.iter().map(|item| item.id).collect::<Vec<_>>(),
            self.next_cursor,
            Some(query),
        )
    }
    /// Decode original embedded Resource bytes before projecting their required fields.
    /// # Errors
    /// Rejects malformed pages or Resource/Page byte overflow.
    pub fn from_json(input: &[u8]) -> Result<Self, OrganizationCodecError> {
        let (items, next_cursor) = decode_page(input)?;
        let value = Self {
            items: items
                .iter()
                .map(|raw| TeamMemberResource::from_json(raw.get().as_bytes()))
                .collect::<Result<_, _>>()?,
            next_cursor,
        };
        value.validate()?;
        Ok(value)
    }
    /// Decode the complete Page with cache-prevention checks.
    /// # Errors
    /// Rejects malformed metadata or body.
    pub fn from_http_json(
        input: &[u8],
        cache_control: Option<&str>,
        pragma: Option<&str>,
    ) -> Result<Self, OrganizationCodecError> {
        validate_cache_headers(cache_control, pragma)?;
        Self::from_json(input)
    }
    /// Canonical Page encoding with sorted roles and original per-Resource bounds.
    /// # Errors
    /// Rejects invalid public fields or whole-body overflow.
    pub fn to_json(&self) -> Result<Vec<u8>, OrganizationCodecError> {
        self.validate()?;
        encode_page(
            self.items.iter().map(TeamMemberResource::to_json).collect::<Result<_, _>>()?,
            self.next_cursor,
        )
    }
}

fn invalid(field: &'static str) -> OrganizationCodecError {
    OrganizationCodecError::InvalidField(field)
}
fn validate_resource_headers(
    expected: &str,
    etag: Option<&str>,
    cache_control: Option<&str>,
    pragma: Option<&str>,
) -> Result<(), OrganizationCodecError> {
    validate_cache_headers(cache_control, pragma)?;
    if etag != Some(expected) {
        return Err(OrganizationCodecError::HttpMetadata);
    }
    Ok(())
}
fn validate_page_ids(
    ids: &[Uuid],
    next: Option<Uuid>,
    query: Option<OrganizationListQuery>,
) -> Result<(), OrganizationCodecError> {
    if ids.len() > 500
        || !ids.windows(2).all(|pair| pair[0] < pair[1])
        || next.is_some() && next != ids.last().copied()
    {
        return Err(invalid("page"));
    }
    if let Some(query) = query {
        query.validate()?;
        if ids.len() > usize::from(query.limit)
            || query.cursor.is_some_and(|cursor| ids.first().is_some_and(|first| *first <= cursor))
        {
            return Err(OrganizationCodecError::Context);
        }
    }
    Ok(())
}
fn decode_page(input: &[u8]) -> Result<(Vec<Box<RawValue>>, Option<Uuid>), OrganizationCodecError> {
    #[derive(Deserialize)]
    struct Wire {
        items: Vec<Box<RawValue>>,
        next_cursor: Option<String>,
    }
    let fields = object(input, MAX_ORGANIZATION_PAGE_BYTES)?;
    if !fields.contains_key("items") || !fields.contains_key("next_cursor") {
        return Err(invalid("page"));
    }
    let raw: Wire =
        serde_json::from_slice(input).map_err(|_| OrganizationCodecError::InvalidJson)?;
    if raw.items.len() > 500 {
        return Err(invalid("items"));
    }
    let next = raw.next_cursor.map(|text| parse_uuid(&text, "next_cursor")).transpose()?;
    Ok((raw.items, next))
}
fn encode_page(items: Vec<Vec<u8>>, next: Option<Uuid>) -> Result<Vec<u8>, OrganizationCodecError> {
    #[derive(Serialize)]
    struct Wire {
        items: Vec<Box<RawValue>>,
        next_cursor: Option<String>,
    }
    let items = items
        .into_iter()
        .map(|bytes| {
            RawValue::from_string(
                String::from_utf8(bytes).map_err(|_| OrganizationCodecError::InvalidJson)?,
            )
            .map_err(|_| OrganizationCodecError::InvalidJson)
        })
        .collect::<Result<_, _>>()?;
    encode(&Wire { items, next_cursor: next.map(|id| id.to_string()) }, MAX_ORGANIZATION_PAGE_BYTES)
}
fn validate_username(value: &str) -> Result<(), OrganizationCodecError> {
    crate::account_admission::validate_username(value).map_err(|_| invalid("username"))
}
fn validate_roles(roles: &[TeamRole]) -> Result<(), OrganizationCodecError> {
    if roles.is_empty()
        || roles.len() > 5
        || roles.iter().copied().collect::<BTreeSet<_>>().len() != roles.len()
    {
        return Err(invalid("roles"));
    }
    Ok(())
}
fn sorted_roles(roles: &[TeamRole]) -> Vec<TeamRole> {
    let mut values = roles.to_vec();
    values.sort_unstable();
    values
}
fn take_roles(fields: &mut Map<String, Value>) -> Result<Vec<TeamRole>, OrganizationCodecError> {
    let Some(Value::Array(values)) = fields.remove("roles") else {
        return Err(invalid("roles"));
    };
    let mut roles = values
        .into_iter()
        .map(|value| match value {
            Value::String(text) => TeamRole::parse(&text),
            _ => Err(invalid("roles")),
        })
        .collect::<Result<Vec<_>, _>>()?;
    validate_roles(&roles)?;
    roles.sort_unstable();
    Ok(roles)
}
fn take_optional_uuid(
    fields: &mut Map<String, Value>,
    name: &'static str,
) -> Result<Option<Uuid>, OrganizationCodecError> {
    match fields.remove(name) {
        Some(Value::Null) => Ok(None),
        Some(Value::String(text)) => parse_uuid(&text, name).map(Some),
        _ => Err(invalid(name)),
    }
}
fn no_extensions(fields: &Map<String, Value>) -> Result<(), OrganizationCodecError> {
    if fields.is_empty() { Ok(()) } else { Err(invalid("request members")) }
}
fn validate_metadata(
    id: Uuid,
    etag: &str,
    created: &str,
    updated: &str,
) -> Result<(), OrganizationCodecError> {
    valid_uuid(id, "id")?;
    if !valid_strong_etag(etag) {
        return Err(invalid("etag"));
    }
    if !valid_utc_timestamp(created) || !valid_utc_timestamp(updated) {
        return Err(invalid("timestamp"));
    }
    Ok(())
}
type ResourceMetadata = (Uuid, String, String, String);
fn take_metadata(
    fields: &mut Map<String, Value>,
) -> Result<ResourceMetadata, OrganizationCodecError> {
    Ok((
        take_uuid(fields, "id")?,
        take_string(fields, "etag")?,
        take_string(fields, "created_at")?,
        take_string(fields, "updated_at")?,
    ))
}
fn encode_resource(
    id: Uuid,
    etag: &str,
    created_at: &str,
    updated_at: &str,
    data: impl Serialize,
) -> Result<Vec<u8>, OrganizationCodecError> {
    #[derive(Serialize)]
    struct Wire<'a, T: Serialize> {
        id: String,
        etag: &'a str,
        created_at: &'a str,
        updated_at: &'a str,
        data: T,
    }
    encode(
        &Wire { id: id.to_string(), etag, created_at, updated_at, data },
        MAX_ORGANIZATION_RESOURCE_BYTES,
    )
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
