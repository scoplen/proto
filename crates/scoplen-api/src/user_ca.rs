// SPDX-License-Identifier: Apache-2.0
//! D-137 initial Organization-owned local Ed25519 user-CA public metadata.
//!
//! These codecs establish syntax and captured response bindings, never CA ownership or current
//! authority. Consumers retain the authenticated origin/Account/Organization/Device request
//! context; no private signing material is accepted or returned here.

use std::fmt;

use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD},
};
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    certificate::{valid_strong_etag, valid_utc_timestamp},
    organization::{
        MAX_ORGANIZATION_LIMIT, OrganizationCodecError, OrganizationListQuery, encode, object,
        parse_uuid, take_object, take_string, take_uuid, valid_uuid, validate_cache_headers,
    },
    request_wire,
};

/// Complete UTF-8 CA creation request ceiling, including whitespace and escapes.
pub const MAX_USER_CA_CREATE_BYTES: usize = 16_384;
/// Complete public Resource ceiling, including ignored extensions and whitespace in Page items.
pub const MAX_USER_CA_RESOURCE_BYTES: usize = 16_384;
/// Complete public directory Page ceiling.
pub const MAX_USER_CA_PAGE_BYTES: usize = 1_048_576;
/// Original creation/issuance receipt lifetime; historical confirmation grants no new authority.
pub const USER_CA_RECEIPT_LIFETIME_SECONDS: u64 = 86_400;

/// Exact initial local user-CA creation request; the server generates its own independent key.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct UserCaCreateRequest {
    /// Caller-created CA `UUIDv7`, immutable within its authenticated Organization.
    pub id: Uuid,
}

impl fmt::Debug for UserCaCreateRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UserCaCreateRequest").finish_non_exhaustive()
    }
}

impl UserCaCreateRequest {
    /// Construct the initial user/local payload without accepting a caller-selected key.
    /// # Errors
    /// Rejects a non-UUIDv7 id.
    pub fn new(id: Uuid) -> Result<Self, OrganizationCodecError> {
        let value = Self { id };
        value.validate()?;
        Ok(value)
    }

    /// Recheck mutable public fields before use.
    /// # Errors
    /// Rejects a non-UUIDv7 id.
    pub fn validate(&self) -> Result<(), OrganizationCodecError> {
        valid_uuid(self.id, "id")
    }

    /// Decode exactly `{id,data:{kind:"user",backend:"local"}}`.
    /// Transport consumers also reject query/If-Match and require exactly one idempotency header.
    /// # Errors
    /// Rejects oversized, malformed, duplicate, unknown, missing or invalid fields.
    pub fn from_json(input: &[u8]) -> Result<Self, OrganizationCodecError> {
        let mut fields = object(input, MAX_USER_CA_CREATE_BYTES)?;
        let id = take_uuid(&mut fields, "id")?;
        let mut data = take_object(&mut fields, "data")?;
        if take_string(&mut data, "kind")? != "user"
            || take_string(&mut data, "backend")? != "local"
            || !fields.is_empty()
            || !data.is_empty()
        {
            return Err(invalid("request members"));
        }
        Self::new(id)
    }

    /// Canonical initial request used for the original-key, original-payload receipt.
    /// # Errors
    /// Rejects invalid public fields or an encoded body overflow.
    pub fn to_json(&self) -> Result<Vec<u8>, OrganizationCodecError> {
        #[derive(Serialize)]
        struct Data {
            kind: &'static str,
            backend: &'static str,
        }
        #[derive(Serialize)]
        struct Wire {
            id: String,
            data: Data,
        }
        self.validate()?;
        encode(
            &Wire { id: self.id.to_string(), data: Data { kind: "user", backend: "local" } },
            MAX_USER_CA_CREATE_BYTES,
        )
    }
}

/// Public metadata for the initial active local user CA; contains no signing seed or key handle.
#[derive(Clone, Eq, PartialEq)]
pub struct UserCaResource {
    /// CA `UUIDv7`; its Organization provenance comes from the authenticated request.
    pub id: Uuid,
    /// Strong entity tag, including its surrounding quotes.
    pub etag: String,
    /// Valid UTC creation timestamp.
    pub created_at: String,
    /// Valid UTC update timestamp.
    pub updated_at: String,
    /// Canonical raw `ssh-ed25519` OpenSSH public-key line, without a comment.
    pub public_key: String,
    /// Exact `SHA256:` plus unpadded standard Base64 of the decoded key blob's SHA-256.
    pub fingerprint: String,
}

impl fmt::Debug for UserCaResource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UserCaResource").finish_non_exhaustive()
    }
}

impl UserCaResource {
    /// Recheck all fields, including exact canonical Ed25519 key/fingerprint equality.
    /// # Errors
    /// Rejects invalid ids, `ETag`, timestamps, keys or fingerprints.
    pub fn validate(&self) -> Result<(), OrganizationCodecError> {
        valid_uuid(self.id, "id")?;
        if !valid_strong_etag(&self.etag) {
            return Err(invalid("etag"));
        }
        if !valid_utc_timestamp(&self.created_at) || !valid_utc_timestamp(&self.updated_at) {
            return Err(invalid("timestamp"));
        }
        if self.fingerprint != user_ca_fingerprint(&self.public_key)? {
            return Err(invalid("fingerprint"));
        }
        Ok(())
    }

    /// Bind a read/create response to its captured CA id before use.
    /// This does not prove its authenticated Organization, CA trust or current membership.
    /// # Errors
    /// Rejects invalid fields, a non-UUIDv7 expectation or an id mismatch.
    pub fn validate_for_id(&self, expected_id: Uuid) -> Result<(), OrganizationCodecError> {
        self.validate()?;
        valid_uuid(expected_id, "expected_id")?;
        if self.id != expected_id {
            return Err(OrganizationCodecError::Context);
        }
        Ok(())
    }

    /// Decode bounded public metadata, ignoring extensions but rejecting duplicate names at depth.
    /// # Errors
    /// Rejects malformed, oversized, missing, mistyped or invalid fields.
    pub fn from_json(input: &[u8]) -> Result<Self, OrganizationCodecError> {
        let mut fields = object(input, MAX_USER_CA_RESOURCE_BYTES)?;
        let id = take_uuid(&mut fields, "id")?;
        let etag = take_string(&mut fields, "etag")?;
        let created_at = take_string(&mut fields, "created_at")?;
        let updated_at = take_string(&mut fields, "updated_at")?;
        let mut data = take_object(&mut fields, "data")?;
        if take_string(&mut data, "kind")? != "user"
            || take_string(&mut data, "backend")? != "local"
            || take_string(&mut data, "state")? != "active"
        {
            return Err(invalid("data"));
        }
        let public_key = take_string(&mut data, "public_key")?;
        let fingerprint = take_string(&mut data, "fingerprint")?;
        let value = Self { id, etag, created_at, updated_at, public_key, fingerprint };
        value.validate()?;
        Ok(value)
    }

    /// Decode an individual response with exact `ETag` and both cache-prevention headers.
    /// HTTP status/content type/request id and authenticated source binding are transport duties.
    /// # Errors
    /// Rejects invalid metadata or body.
    pub fn from_http_json(
        input: &[u8],
        etag: Option<&str>,
        cache_control: Option<&str>,
        pragma: Option<&str>,
    ) -> Result<Self, OrganizationCodecError> {
        let value = Self::from_json(input)?;
        if etag != Some(value.etag.as_str()) {
            return Err(OrganizationCodecError::HttpMetadata);
        }
        validate_cache_headers(cache_control, pragma)?;
        Ok(value)
    }

    /// Canonical public Resource encoding with frozen user/local/active values and no extensions.
    /// # Errors
    /// Rejects invalid public fields or complete body overflow.
    pub fn to_json(&self) -> Result<Vec<u8>, OrganizationCodecError> {
        #[derive(Serialize)]
        struct Data<'a> {
            kind: &'static str,
            backend: &'static str,
            state: &'static str,
            public_key: &'a str,
            fingerprint: &'a str,
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
        encode(
            &Wire {
                id: self.id.to_string(),
                etag: &self.etag,
                created_at: &self.created_at,
                updated_at: &self.updated_at,
                data: Data {
                    kind: "user",
                    backend: "local",
                    state: "active",
                    public_key: &self.public_key,
                    fingerprint: &self.fingerprint,
                },
            },
            MAX_USER_CA_RESOURCE_BYTES,
        )
    }
}

/// Ascending live public CA directory; listing never authorizes inventory access or issuance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UserCaPage {
    /// Public initial local-user-CA Resources.
    pub items: Vec<UserCaResource>,
    /// Last returned id only when more eligible items exist.
    pub next_cursor: Option<Uuid>,
}

impl UserCaPage {
    /// Recheck resources, cardinality, ascending distinct ids and exact continuation.
    /// # Errors
    /// Rejects invalid resources, more than 500 items or malformed continuation.
    pub fn validate(&self) -> Result<(), OrganizationCodecError> {
        if self.items.len() > usize::from(MAX_ORGANIZATION_LIMIT) {
            return Err(invalid("items"));
        }
        for item in &self.items {
            item.validate()?;
        }
        if !self.items.windows(2).all(|pair| pair[0].id < pair[1].id) {
            return Err(invalid("items"));
        }
        if self.next_cursor.is_some() && self.next_cursor != self.items.last().map(|item| item.id) {
            return Err(invalid("next_cursor"));
        }
        Ok(())
    }

    /// Bind the page to its captured query; authenticated Organization provenance is separate.
    /// # Errors
    /// Rejects invalid query/page, exceeded requested count or ids at/before the cursor.
    pub fn validate_for_query(
        &self,
        query: OrganizationListQuery,
    ) -> Result<(), OrganizationCodecError> {
        self.validate()?;
        query.validate()?;
        if self.items.len() > usize::from(query.limit)
            || self.items.iter().any(|item| query.cursor.is_some_and(|cursor| item.id <= cursor))
        {
            return Err(OrganizationCodecError::Context);
        }
        Ok(())
    }

    /// Decode each original raw Page item under its own 16,384-byte budget before normalization.
    /// # Errors
    /// Rejects malformed/oversized input, duplicate names, invalid resources or continuation.
    pub fn from_json(input: &[u8]) -> Result<Self, OrganizationCodecError> {
        #[derive(Deserialize)]
        struct Wire {
            items: Vec<Box<RawValue>>,
            next_cursor: Option<String>,
        }
        let fields = object(input, MAX_USER_CA_PAGE_BYTES)?;
        if !fields.contains_key("items") || !fields.contains_key("next_cursor") {
            return Err(invalid("page"));
        }
        let raw: Wire =
            serde_json::from_slice(input).map_err(|_| OrganizationCodecError::InvalidJson)?;
        if raw.items.len() > usize::from(MAX_ORGANIZATION_LIMIT) {
            return Err(invalid("items"));
        }
        let items = raw
            .items
            .iter()
            .map(|item| UserCaResource::from_json(item.get().as_bytes()))
            .collect::<Result<Vec<_>, _>>()?;
        let next_cursor =
            raw.next_cursor.map(|text| parse_uuid(&text, "next_cursor")).transpose()?;
        let value = Self { items, next_cursor };
        value.validate()?;
        Ok(value)
    }

    /// Decode a complete no-store/no-cache public directory Page.
    /// HTTP status/content type/request id and authenticated source binding are transport duties.
    /// # Errors
    /// Rejects invalid body or response cache metadata.
    pub fn from_http_json(
        input: &[u8],
        cache_control: Option<&str>,
        pragma: Option<&str>,
    ) -> Result<Self, OrganizationCodecError> {
        validate_cache_headers(cache_control, pragma)?;
        Self::from_json(input)
    }

    /// Canonical Page encoding, enforcing each individual Resource and the complete Page budget.
    /// # Errors
    /// Rejects invalid fields, per-item overflow or complete Page overflow.
    pub fn to_json(&self) -> Result<Vec<u8>, OrganizationCodecError> {
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
                let text = String::from_utf8(item.to_json()?)
                    .map_err(|_| OrganizationCodecError::InvalidJson)?;
                RawValue::from_string(text).map_err(|_| OrganizationCodecError::InvalidJson)
            })
            .collect::<Result<Vec<_>, _>>()?;
        encode(
            &Wire { items, next_cursor: self.next_cursor.map(|id| id.to_string()) },
            MAX_USER_CA_PAGE_BYTES,
        )
    }
}

/// Compute the exact public fingerprint after validating the canonical raw Ed25519 key profile.
/// This hashes the decoded OpenSSH key blob, never the line or bare Ed25519 bytes.
/// # Errors
/// Rejects any other algorithm, comments, noncanonical Base64, private keys or malformed blobs.
pub fn user_ca_fingerprint(public_key: &str) -> Result<String, OrganizationCodecError> {
    if !public_key.starts_with("ssh-ed25519 ")
        || !request_wire::valid_raw_ssh_public_key(public_key)
    {
        return Err(invalid("public_key"));
    }
    let (_, encoded) = public_key.split_once(' ').ok_or(invalid("public_key"))?;
    let blob = STANDARD.decode(encoded).map_err(|_| invalid("public_key"))?;
    Ok(format!("SHA256:{}", STANDARD_NO_PAD.encode(Sha256::digest(&blob))))
}

fn invalid(field: &'static str) -> OrganizationCodecError {
    OrganizationCodecError::InvalidField(field)
}
