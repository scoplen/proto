// SPDX-License-Identifier: Apache-2.0
//! D-150 bounded single-Host access requests. Decoding establishes no current authority.

pub mod reference;

use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, value::RawValue};
use uuid::Uuid;

use crate::{
    certificate::{valid_strong_etag, valid_utc_timestamp},
    grant::{format_grant_timestamp, parse_grant_timestamp},
    organization::{
        OrganizationCodecError as Error, OrganizationListQuery, encode, object, parse_uuid,
        take_object, take_string, take_uuid, valid_uuid, validate_cache_headers,
    },
    request_wire::valid_remote_user,
};

/// Complete request/check-response bound, including original whitespace.
pub const MAX_ACCESS_REQUEST_BYTES: usize = 4_096;
/// Complete Resource bound, including original response extensions.
pub const MAX_ACCESS_REQUEST_RESOURCE_BYTES: usize = 8_192;
/// Complete Page bound.
pub const MAX_ACCESS_REQUEST_PAGE_BYTES: usize = 4_194_304;
/// Maximum Page item count.
pub const MAX_ACCESS_REQUEST_PAGE_ITEMS: usize = 500;
/// Pending deadline and original-operation receipt lifetime.
pub const ACCESS_REQUEST_PENDING_SECONDS: u64 = 86_400;

/// Exact caller-authored data. Identity and Grant fields are server-owned.
#[derive(Clone, Eq, PartialEq)]
pub struct AccessRequestFields {
    /// One explicit live Organization Host, never a `HostGroup`.
    pub host: Uuid,
    /// Exact remote username, without trimming or normalization.
    pub remote_user: String,
    /// Requested finite access interval, from 1 through 86,400 seconds.
    pub duration_seconds: u32,
    /// Review text, preserved without normalization and redacted from `Debug`.
    pub reason: String,
}

impl fmt::Debug for AccessRequestFields {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AccessRequestFields").finish_non_exhaustive()
    }
}

impl AccessRequestFields {
    /// Decode the strict four-field data object independently of its HTTP envelope.
    /// # Errors
    /// Rejects invalid fields, extensions, duplicates or complete encoded overflow.
    pub fn from_json(input: &[u8]) -> Result<Self, Error> {
        Self::from_value(&mut object(input, MAX_ACCESS_REQUEST_BYTES)?, true)
    }
    /// Encode the four validated fields in canonical order.
    /// # Errors
    /// Rejects invalid mutable fields or encoded overflow.
    pub fn to_json(&self) -> Result<Vec<u8>, Error> {
        encode(&self.wire()?, MAX_ACCESS_REQUEST_BYTES)
    }
    /// Validate syntax only, without checking current resource ownership or eligibility.
    /// # Errors
    /// Rejects invalid ids, username, duration or reason.
    pub fn validate(&self) -> Result<(), Error> {
        valid_uuid(self.host, "host")?;
        if !valid_remote_user(&self.remote_user)
            || !(1..=86_400).contains(&self.duration_seconds)
            || self.reason.is_empty()
            || self.reason.len() > 2_048
            || !self.reason.chars().any(|value| !value.is_whitespace())
            || self.reason.chars().any(|value| value.is_control() && !matches!(value, '\n' | '\t'))
        {
            return Err(Error::InvalidField("request data"));
        }
        Ok(())
    }

    fn from_value(data: &mut Map<String, Value>, strict: bool) -> Result<Self, Error> {
        let duration = data
            .remove("duration_seconds")
            .and_then(|value| value.as_u64())
            .and_then(|value| u32::try_from(value).ok())
            .ok_or(Error::InvalidField("duration_seconds"))?;
        let result = Self {
            host: take_uuid(data, "host")?,
            remote_user: take_string(data, "remote_user")?,
            duration_seconds: duration,
            reason: take_string(data, "reason")?,
        };
        if strict && !data.is_empty() {
            return Err(Error::InvalidField("request members"));
        }
        result.validate()?;
        Ok(result)
    }

    fn wire(&self) -> Result<FieldsWire<'_>, Error> {
        self.validate()?;
        Ok(FieldsWire {
            host: self.host.to_string(),
            remote_user: &self.remote_user,
            duration_seconds: self.duration_seconds,
            reason: &self.reason,
        })
    }
}

#[derive(Serialize)]
struct FieldsWire<'a> {
    host: String,
    remote_user: &'a str,
    duration_seconds: u32,
    reason: &'a str,
}

/// Side-effect-free eligibility input, bound to all four exact fields.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccessRequestCheckRequest {
    /// Concrete input to evaluate as the authenticated requester.
    pub fields: AccessRequestFields,
}

impl AccessRequestCheckRequest {
    /// Decode a strict bounded check body.
    /// # Errors
    /// Rejects malformed, duplicate, unknown, missing, null or over-bound fields.
    pub fn from_json(input: &[u8]) -> Result<Self, Error> {
        let mut fields = object(input, MAX_ACCESS_REQUEST_BYTES)?;
        let result = Self {
            fields: AccessRequestFields::from_value(&mut take_object(&mut fields, "data")?, true)?,
        };
        if !fields.is_empty() {
            return Err(Error::InvalidField("request members"));
        }
        Ok(result)
    }
    /// Encode the canonical exact-input check.
    /// # Errors
    /// Rejects invalid mutable fields or complete encoded overflow.
    pub fn to_json(&self) -> Result<Vec<u8>, Error> {
        #[derive(Serialize)]
        struct Wire<'a> {
            data: FieldsWire<'a>,
        }
        encode(&Wire { data: self.fields.wire()? }, MAX_ACCESS_REQUEST_BYTES)
    }
}

/// Complete policy evaluation result, not an access permit or reservation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AccessRequestCheckResponse {
    /// True only after a complete current `request_access` Allow.
    pub allowed: bool,
}

impl AccessRequestCheckResponse {
    /// Decode a bounded response while ignoring bounded extensions.
    /// # Errors
    /// Rejects missing/mistyped fields, recursive duplicates and overflow.
    pub fn from_json(input: &[u8]) -> Result<Self, Error> {
        let mut fields = object(input, MAX_ACCESS_REQUEST_BYTES)?;
        match fields.remove("allowed") {
            Some(Value::Bool(allowed)) => Ok(Self { allowed }),
            _ => Err(Error::InvalidField("allowed")),
        }
    }
    /// Validate standard cache-prevention metadata and decode the response.
    /// # Errors
    /// Rejects invalid headers, malformed fields or overflow.
    pub fn from_http_json(
        input: &[u8],
        cache_control: Option<&str>,
        pragma: Option<&str>,
    ) -> Result<Self, Error> {
        validate_cache_headers(cache_control, pragma)?;
        Self::from_json(input)
    }
    /// Encode the single result field.
    /// # Errors
    /// Returns an encoding failure.
    pub fn to_json(self) -> Result<Vec<u8>, Error> {
        #[derive(Serialize)]
        struct Wire {
            allowed: bool,
        }
        encode(&Wire { allowed: self.allowed }, MAX_ACCESS_REQUEST_BYTES)
    }
}

/// Exact immutable application creation body.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccessRequestCreateRequest {
    /// Original client-generated request `UUIDv7`.
    pub id: Uuid,
    /// Concrete reviewed request input.
    pub fields: AccessRequestFields,
}

impl AccessRequestCreateRequest {
    /// Decode the strict bounded creation body.
    /// # Errors
    /// Rejects malformed, duplicate, unknown, missing, null or over-bound fields.
    pub fn from_json(input: &[u8]) -> Result<Self, Error> {
        let mut fields = object(input, MAX_ACCESS_REQUEST_BYTES)?;
        let result = Self {
            id: take_uuid(&mut fields, "id")?,
            fields: AccessRequestFields::from_value(&mut take_object(&mut fields, "data")?, true)?,
        };
        if !fields.is_empty() {
            return Err(Error::InvalidField("request members"));
        }
        Ok(result)
    }
    /// Encode the canonical original-operation payload.
    /// # Errors
    /// Rejects invalid mutable fields or complete encoded overflow.
    pub fn to_json(&self) -> Result<Vec<u8>, Error> {
        #[derive(Serialize)]
        struct Wire<'a> {
            id: String,
            data: FieldsWire<'a>,
        }
        valid_uuid(self.id, "id")?;
        encode(
            &Wire { id: self.id.to_string(), data: self.fields.wire()? },
            MAX_ACCESS_REQUEST_BYTES,
        )
    }
}

/// The only two caller-authored decision values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccessRequestOutcome {
    /// Create only the original bound finite Grant.
    Approve,
    /// Deny the pending request without creating authority.
    Deny,
}

impl AccessRequestOutcome {
    /// Exact wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Approve => "approve",
            Self::Deny => "deny",
        }
    }
    fn parse(value: &str) -> Result<Self, Error> {
        match value {
            "approve" => Ok(Self::Approve),
            "deny" => Ok(Self::Deny),
            _ => Err(Error::InvalidField("decision")),
        }
    }
}

/// Exact decision body; reason and caller-authored identity are forbidden.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AccessRequestDecisionRequest {
    /// Original approve/deny selection.
    pub decision: AccessRequestOutcome,
}

impl AccessRequestDecisionRequest {
    /// Decode one strict bounded decision.
    /// # Errors
    /// Rejects missing, unknown, null, duplicate, invalid or oversized input.
    pub fn from_json(input: &[u8]) -> Result<Self, Error> {
        let mut fields = object(input, MAX_ACCESS_REQUEST_BYTES)?;
        let decision = AccessRequestOutcome::parse(&take_string(&mut fields, "decision")?)?;
        if !fields.is_empty() {
            return Err(Error::InvalidField("request members"));
        }
        Ok(Self { decision })
    }
    /// Encode the canonical original decision.
    /// # Errors
    /// Returns an encoding failure.
    pub fn to_json(self) -> Result<Vec<u8>, Error> {
        #[derive(Serialize)]
        struct Wire {
            decision: &'static str,
        }
        encode(&Wire { decision: self.decision.as_str() }, MAX_ACCESS_REQUEST_BYTES)
    }
}

/// Persisted status; unknown future values never enable a current mutation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AccessRequestStatus {
    /// Awaiting review, subject to its independent deadline.
    Pending,
    /// Approval history, not proof of current Grant authority.
    Approved,
    /// Denied by one current routed approver.
    Denied,
    /// Worker-persisted pending expiry.
    Expired,
    /// Withdrawn by its requester.
    Cancelled,
    /// Bounded future status, without authority or actions.
    Unknown(String),
}

impl AccessRequestStatus {
    /// Preserve the exact known or future wire spelling.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Pending => "pending",
            Self::Approved => "approved",
            Self::Denied => "denied",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
            Self::Unknown(value) => value,
        }
    }
    fn parse(value: String) -> Result<Self, Error> {
        let bytes = value.as_bytes();
        if !(1..=64).contains(&bytes.len())
            || !bytes[0].is_ascii_lowercase()
            || !bytes
                .iter()
                .all(|value| value.is_ascii_lowercase() || value.is_ascii_digit() || *value == b'_')
        {
            return Err(Error::InvalidField("status"));
        }
        Ok(match value.as_str() {
            "pending" => Self::Pending,
            "approved" => Self::Approved,
            "denied" => Self::Denied,
            "expired" => Self::Expired,
            "cancelled" => Self::Cancelled,
            _ => Self::Unknown(value),
        })
    }
}

/// Historical attributable decision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccessRequestDecision {
    /// Exact recorded outcome.
    pub outcome: AccessRequestOutcome,
    /// Historical Account id, never a current permission.
    pub actor_account_id: Uuid,
    /// Existing UTC metadata profile, preserving fractional seconds.
    pub decided_at: String,
}

/// Original finite Grant history, never a current Grant projection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccessRequestGrant {
    /// Server-generated Grant id.
    pub id: Uuid,
    /// Inclusive whole Unix second of approval.
    pub valid_from: u64,
    /// Exclusive finite bound exactly one requested duration later.
    pub valid_until: u64,
}

/// Server-owned request history with no embedded inventory/member projection.
#[derive(Clone, Eq, PartialEq)]
pub struct AccessRequestResource {
    /// Original request `UUIDv7`.
    pub id: Uuid,
    /// Strong current persisted projection validator.
    pub etag: String,
    /// Creation UTC metadata timestamp.
    pub created_at: String,
    /// Last persisted mutation timestamp.
    pub updated_at: String,
    /// Original authenticated requester, retained as history only.
    pub requester_account_id: Uuid,
    /// Exact original Membership, never substituted after rejoin.
    pub requester_membership_id: Uuid,
    /// Original validated input.
    pub fields: AccessRequestFields,
    /// Exactly one day after `created_at`, preserving the fractional instant.
    pub expires_at: String,
    /// Persisted state; Pending alone does not prove its deadline remains open.
    pub status: AccessRequestStatus,
    /// Approval/denial history, otherwise null for initial known states.
    pub decision: Option<AccessRequestDecision>,
    /// Original finite approval Grant, otherwise null for initial known states.
    pub grant: Option<AccessRequestGrant>,
}

impl fmt::Debug for AccessRequestResource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AccessRequestResource").finish_non_exhaustive()
    }
}

impl AccessRequestResource {
    /// Validate known values and the exact deadline/approval cross-field invariants.
    /// # Errors
    /// Rejects malformed metadata, ids, input, known states or inconsistent times.
    pub fn validate(&self) -> Result<(), Error> {
        for id in [self.id, self.requester_account_id, self.requester_membership_id] {
            valid_uuid(id, "identity")?;
        }
        self.fields.validate()?;
        if !valid_strong_etag(&self.etag) || !valid_utc_timestamp(&self.updated_at) {
            return Err(Error::InvalidField("metadata"));
        }
        let created = metadata_instant(&self.created_at)?;
        let expires = metadata_instant(&self.expires_at)?;
        if created.0.checked_add(86_400) != Some(expires.0) || created.1 != expires.1 {
            return Err(Error::InvalidField("expires_at"));
        }
        let parsed = AccessRequestStatus::parse(self.status.as_str().into())?;
        if parsed != self.status {
            return Err(Error::InvalidField("status"));
        }
        if let Some(decision) = &self.decision {
            valid_uuid(decision.actor_account_id, "actor_account_id")?;
            metadata_instant(&decision.decided_at)?;
        }
        if let Some(grant) = &self.grant {
            valid_uuid(grant.id, "grant id")?;
            format_grant_timestamp(grant.valid_from)?;
            format_grant_timestamp(grant.valid_until)?;
            if grant.valid_until <= grant.valid_from {
                return Err(Error::InvalidField("grant"));
            }
        }
        match &self.status {
            AccessRequestStatus::Pending
            | AccessRequestStatus::Expired
            | AccessRequestStatus::Cancelled => {
                if self.decision.is_some() || self.grant.is_some() {
                    return Err(Error::InvalidField("state"));
                }
            }
            AccessRequestStatus::Denied => {
                if !self
                    .decision
                    .as_ref()
                    .is_some_and(|value| value.outcome == AccessRequestOutcome::Deny)
                    || self.grant.is_some()
                {
                    return Err(Error::InvalidField("state"));
                }
            }
            AccessRequestStatus::Approved => {
                let decision = self
                    .decision
                    .as_ref()
                    .filter(|value| value.outcome == AccessRequestOutcome::Approve)
                    .ok_or(Error::InvalidField("decision"))?;
                let grant = self.grant.as_ref().ok_or(Error::InvalidField("grant"))?;
                if u64::try_from(metadata_instant(&decision.decided_at)?.0).ok()
                    != Some(grant.valid_from)
                    || grant.valid_from.checked_add(u64::from(self.fields.duration_seconds))
                        != Some(grant.valid_until)
                {
                    return Err(Error::InvalidField("grant interval"));
                }
            }
            AccessRequestStatus::Unknown(_) => {}
        }
        Ok(())
    }

    /// Bind a response to its captured request id.
    /// # Errors
    /// Rejects invalid values or another request's Resource.
    pub fn validate_for_id(&self, id: Uuid) -> Result<(), Error> {
        self.validate()?;
        valid_uuid(id, "requested id")?;
        if self.id != id {
            return Err(Error::Context);
        }
        Ok(())
    }

    /// Bind an original create confirmation to the authenticated requester and exact input.
    /// # Errors
    /// Rejects another request, input or requester.
    pub fn validate_for_create(
        &self,
        request: &AccessRequestCreateRequest,
        account: Uuid,
    ) -> Result<(), Error> {
        request.to_json()?;
        self.validate_for_id(request.id)?;
        valid_uuid(account, "account")?;
        if self.fields != request.fields || self.requester_account_id != account {
            return Err(Error::Context);
        }
        Ok(())
    }

    /// Bind a decision response to the exact reviewed immutable request and original actor.
    /// # Errors
    /// Rejects another request/input/actor or an outcome different from the captured decision.
    pub fn validate_for_decision(
        &self,
        original: &Self,
        decision: AccessRequestDecisionRequest,
        actor: Uuid,
    ) -> Result<(), Error> {
        self.validate_for_original(original)?;
        valid_uuid(actor, "actor_account_id")?;
        let status = match decision.decision {
            AccessRequestOutcome::Approve => AccessRequestStatus::Approved,
            AccessRequestOutcome::Deny => AccessRequestStatus::Denied,
        };
        if self.status != status
            || !self.decision.as_ref().is_some_and(|value| {
                value.outcome == decision.decision && value.actor_account_id == actor
            })
        {
            return Err(Error::Context);
        }
        Ok(())
    }

    /// Bind cancellation confirmation to its original immutable request and requester.
    /// # Errors
    /// Rejects changed request data, another requester or a non-cancelled response.
    pub fn validate_for_cancel(&self, original: &Self, account: Uuid) -> Result<(), Error> {
        self.validate_for_original(original)?;
        valid_uuid(account, "account")?;
        if self.status != AccessRequestStatus::Cancelled || self.requester_account_id != account {
            return Err(Error::Context);
        }
        Ok(())
    }

    fn validate_for_original(&self, original: &Self) -> Result<(), Error> {
        original.validate()?;
        self.validate_for_id(original.id)?;
        if self.requester_account_id != original.requester_account_id
            || self.requester_membership_id != original.requester_membership_id
            || self.fields != original.fields
            || self.created_at != original.created_at
            || self.expires_at != original.expires_at
        {
            return Err(Error::Context);
        }
        Ok(())
    }

    /// Decode a bounded Resource while ignoring bounded response extensions.
    /// # Errors
    /// Rejects malformed/duplicate/missing known fields, invalid cross-fields or overflow.
    pub fn from_json(input: &[u8]) -> Result<Self, Error> {
        let mut root = object(input, MAX_ACCESS_REQUEST_RESOURCE_BYTES)?;
        let mut data = take_object(&mut root, "data")?;
        let decision = match data.remove("decision") {
            Some(Value::Null) => None,
            Some(Value::Object(mut value)) => Some(AccessRequestDecision {
                outcome: AccessRequestOutcome::parse(&take_string(&mut value, "outcome")?)?,
                actor_account_id: take_uuid(&mut value, "actor_account_id")?,
                decided_at: take_string(&mut value, "decided_at")?,
            }),
            _ => return Err(Error::InvalidField("decision")),
        };
        let grant = match data.remove("grant") {
            Some(Value::Null) => None,
            Some(Value::Object(mut value)) => Some(AccessRequestGrant {
                id: take_uuid(&mut value, "id")?,
                valid_from: parse_grant_timestamp(&take_string(&mut value, "valid_from")?)?,
                valid_until: parse_grant_timestamp(&take_string(&mut value, "valid_until")?)?,
            }),
            _ => return Err(Error::InvalidField("grant")),
        };
        let result = Self {
            id: take_uuid(&mut root, "id")?,
            etag: take_string(&mut root, "etag")?,
            created_at: take_string(&mut root, "created_at")?,
            updated_at: take_string(&mut root, "updated_at")?,
            requester_account_id: take_uuid(&mut data, "requester_account_id")?,
            requester_membership_id: take_uuid(&mut data, "requester_membership_id")?,
            expires_at: take_string(&mut data, "expires_at")?,
            status: AccessRequestStatus::parse(take_string(&mut data, "status")?)?,
            fields: AccessRequestFields::from_value(&mut data, false)?,
            decision,
            grant,
        };
        result.validate()?;
        Ok(result)
    }

    /// Decode with matching strong HTTP/body `ETag` and standard cache-prevention metadata.
    /// # Errors
    /// Rejects invalid headers, body, cross-fields or overflow.
    pub fn from_http_json(
        input: &[u8],
        etag: Option<&str>,
        cache_control: Option<&str>,
        pragma: Option<&str>,
    ) -> Result<Self, Error> {
        validate_cache_headers(cache_control, pragma)?;
        let value = Self::from_json(input)?;
        if etag != Some(value.etag.as_str()) {
            return Err(Error::HttpMetadata);
        }
        Ok(value)
    }

    /// Encode complete known fields in canonical contract order.
    /// # Errors
    /// Rejects invalid fields/cross-fields or complete encoded overflow.
    pub fn to_json(&self) -> Result<Vec<u8>, Error> {
        #[derive(Serialize)]
        struct Decision<'a> {
            outcome: &'static str,
            actor_account_id: String,
            decided_at: &'a str,
        }
        #[derive(Serialize)]
        struct Grant {
            id: String,
            valid_from: String,
            valid_until: String,
        }
        #[derive(Serialize)]
        struct Data<'a> {
            requester_account_id: String,
            requester_membership_id: String,
            host: String,
            remote_user: &'a str,
            duration_seconds: u32,
            reason: &'a str,
            expires_at: &'a str,
            status: &'a str,
            decision: Option<Decision<'a>>,
            grant: Option<Grant>,
        }
        #[derive(Serialize)]
        struct Wire<'a> {
            id: String,
            etag: &'a str,
            created_at: &'a str,
            updated_at: &'a str,
            data: Data<'a>,
        }
        self.validate()?;
        let decision = self.decision.as_ref().map(|value| Decision {
            outcome: value.outcome.as_str(),
            actor_account_id: value.actor_account_id.to_string(),
            decided_at: &value.decided_at,
        });
        let grant = self
            .grant
            .as_ref()
            .map(|value| -> Result<Grant, Error> {
                Ok(Grant {
                    id: value.id.to_string(),
                    valid_from: format_grant_timestamp(value.valid_from)?,
                    valid_until: format_grant_timestamp(value.valid_until)?,
                })
            })
            .transpose()?;
        encode(
            &Wire {
                id: self.id.to_string(),
                etag: &self.etag,
                created_at: &self.created_at,
                updated_at: &self.updated_at,
                data: Data {
                    requester_account_id: self.requester_account_id.to_string(),
                    requester_membership_id: self.requester_membership_id.to_string(),
                    host: self.fields.host.to_string(),
                    remote_user: &self.fields.remote_user,
                    duration_seconds: self.fields.duration_seconds,
                    reason: &self.fields.reason,
                    expires_at: &self.expires_at,
                    status: self.status.as_str(),
                    decision,
                    grant,
                },
            },
            MAX_ACCESS_REQUEST_RESOURCE_BYTES,
        )
    }
}

/// Current list intent; no broad directory or policy lookup is granted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccessRequestView {
    /// Only this Account's original requests, including history.
    Mine,
    /// Only currently routed unexpired pending requests.
    Approvals,
}

/// Explicit list view plus the established bounded ascending locator profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AccessRequestListQuery {
    /// Required independent view selection.
    pub view: AccessRequestView,
    /// Bounded limit and optional `UUIDv7` cursor.
    pub page: OrganizationListQuery,
}

impl AccessRequestListQuery {
    /// Parse exact view/limit/cursor names without duplicates or fallback defaults for view.
    /// # Errors
    /// Rejects invalid/missing view, duplicate/unknown names or malformed paging.
    pub fn from_parameters<'a>(
        parameters: impl IntoIterator<Item = (&'a str, &'a str)>,
    ) -> Result<Self, Error> {
        let mut view = None;
        let mut page = Vec::new();
        for (key, value) in parameters {
            if key == "view" {
                if view.is_some() {
                    return Err(Error::InvalidField("view"));
                }
                view = Some(match value {
                    "mine" => AccessRequestView::Mine,
                    "approvals" => AccessRequestView::Approvals,
                    _ => return Err(Error::InvalidField("view")),
                });
            } else {
                page.push((key, value));
            }
        }
        Ok(Self {
            view: view.ok_or(Error::InvalidField("view"))?,
            page: OrganizationListQuery::from_parameters(page)?,
        })
    }
}

/// Bounded live ascending Page, never a snapshot or authority source.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccessRequestPage {
    /// Distinct ascending request Resources.
    pub items: Vec<AccessRequestResource>,
    /// Last returned id only when another currently readable item exists.
    pub next_cursor: Option<Uuid>,
}

impl AccessRequestPage {
    /// Validate item bounds, strict ordering and continuation.
    /// # Errors
    /// Rejects malformed Resources/count/order/continuation or encoded item overflow.
    pub fn validate(&self) -> Result<(), Error> {
        if self.items.len() > MAX_ACCESS_REQUEST_PAGE_ITEMS {
            return Err(Error::TooLarge);
        }
        for item in &self.items {
            item.to_json()?;
        }
        if !self.items.windows(2).all(|pair| pair[0].id < pair[1].id)
            || (self.next_cursor.is_some()
                && self.next_cursor != self.items.last().map(|item| item.id))
        {
            return Err(Error::InvalidField("page"));
        }
        Ok(())
    }
    /// Bind a Page to the original current Account/view/count/cursor.
    /// Current routing remains the server's separate duty for Approvals.
    /// # Errors
    /// Rejects mismatched count/continuation or another requester's Mine item.
    pub fn validate_for_query(
        &self,
        account: Uuid,
        query: AccessRequestListQuery,
    ) -> Result<(), Error> {
        self.validate()?;
        valid_uuid(account, "account")?;
        query.page.validate()?;
        if self.items.len() > usize::from(query.page.limit)
            || self.items.iter().any(|item| {
                query.page.cursor.is_some_and(|cursor| item.id <= cursor)
                    || (query.view == AccessRequestView::Mine
                        && item.requester_account_id != account)
                    || (query.view == AccessRequestView::Approvals
                        && item.status != AccessRequestStatus::Pending)
            })
        {
            return Err(Error::Context);
        }
        Ok(())
    }
    /// Decode a complete Page and each original embedded item before discarding extensions.
    /// # Errors
    /// Rejects malformed required fields, recursive duplicates, overflow or invalid ordering.
    pub fn from_json(input: &[u8]) -> Result<Self, Error> {
        #[derive(Deserialize)]
        struct Wire {
            items: Vec<Box<RawValue>>,
            next_cursor: Option<String>,
        }
        let fields = object(input, MAX_ACCESS_REQUEST_PAGE_BYTES)?;
        if !fields.contains_key("items") || !fields.contains_key("next_cursor") {
            return Err(Error::InvalidField("page"));
        }
        let raw: Wire = serde_json::from_slice(input).map_err(|_| Error::InvalidJson)?;
        if raw.items.len() > MAX_ACCESS_REQUEST_PAGE_ITEMS {
            return Err(Error::TooLarge);
        }
        let result = Self {
            items: raw
                .items
                .iter()
                .map(|item| AccessRequestResource::from_json(item.get().as_bytes()))
                .collect::<Result<_, _>>()?,
            next_cursor: raw
                .next_cursor
                .map(|value| parse_uuid(&value, "next_cursor"))
                .transpose()?,
        };
        result.validate()?;
        Ok(result)
    }
    /// Decode with standard no-store/no-cache metadata.
    /// # Errors
    /// Rejects invalid headers, body or bounds.
    pub fn from_http_json(
        input: &[u8],
        cache_control: Option<&str>,
        pragma: Option<&str>,
    ) -> Result<Self, Error> {
        validate_cache_headers(cache_control, pragma)?;
        Self::from_json(input)
    }
    /// Encode a complete bounded Page without losing individual item budgets.
    /// # Errors
    /// Rejects invalid values or encoded item/Page overflow.
    pub fn to_json(&self) -> Result<Vec<u8>, Error> {
        #[derive(Serialize)]
        struct Wire {
            items: Vec<Box<RawValue>>,
            next_cursor: Option<String>,
        }
        self.validate()?;
        let items = self
            .items
            .iter()
            .map(|item| {
                serde_json::from_slice::<Box<RawValue>>(&item.to_json()?)
                    .map_err(|_| Error::InvalidJson)
            })
            .collect::<Result<_, _>>()?;
        encode(
            &Wire { items, next_cursor: self.next_cursor.map(|id| id.to_string()) },
            MAX_ACCESS_REQUEST_PAGE_BYTES,
        )
    }
}

// Compare UTC instants without rounding the metadata profile's arbitrary fractional precision.
fn metadata_instant(value: &str) -> Result<(i64, &str), Error> {
    if !valid_utc_timestamp(value) {
        return Err(Error::InvalidField("timestamp"));
    }
    let number =
        |start, end| value[start..end].parse::<i64>().map_err(|_| Error::InvalidField("timestamp"));
    let year = number(0, 4)?;
    let month = number(5, 7)?;
    let day = number(8, 10)?;
    let year = year - i64::from(month <= 2);
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let shifted_month = month + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * shifted_month + 2) / 5 + day - 1;
    let days = era * 146_097 + year_of_era * 365 + year_of_era / 4 - year_of_era / 100
        + day_of_year
        - 719_468;
    let seconds = days * 86_400 + number(11, 13)? * 3_600 + number(14, 16)? * 60 + number(17, 19)?;
    let fraction =
        if value.len() == 20 { "" } else { value[20..value.len() - 1].trim_end_matches('0') };
    Ok((seconds, fraction))
}
