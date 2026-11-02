// SPDX-License-Identifier: Apache-2.0
//! Revision-bound complete Organization views; these codecs do not authorize a caller.

use super::{
    MAX_SYNC_ORGANIZATION_ACK_REQUEST_BYTES, MAX_SYNC_ORGANIZATION_VIEW_QUERY_BYTES,
    OrganizationVaultContext, SyncChange, SyncChangesQuery, SyncCodecError, SyncReadLimits, Value,
    argument_bytes, canonical_decimal, decode_map, encode_map, invalid, length_argument_bytes,
    positive, read_entries_body_bytes, take_bool, take_uint, take_uuid, valid_uuid, validate_page,
};
use uuid::Uuid;

/// Query for `GET /sync/v1/vaults/{vault}/view`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SyncOrganizationViewQuery {
    pub view_revision: u64,
    pub after: u64,
    pub limit: u16,
}

impl SyncOrganizationViewQuery {
    /// Validate the positive revision and bounded page size.
    /// # Errors
    /// Rejects revision zero or a limit outside 1 through 1,000.
    pub fn validate(&self) -> Result<(), SyncCodecError> {
        positive(self.view_revision, "revision")?;
        SyncChangesQuery { after: self.after, limit: self.limit }.validate()
    }

    /// Format the three required parameters in canonical order without a leading `?`.
    /// # Errors
    /// Rejects invalid query values.
    pub fn to_query(&self) -> Result<String, SyncCodecError> {
        self.validate()?;
        Ok(format!("revision={}&after={}&limit={}", self.view_revision, self.after, self.limit))
    }

    /// Read each required canonical decimal parameter exactly once, in any order.
    /// # Errors
    /// Rejects oversized, missing, duplicate, unknown or noncanonical parameters.
    pub fn from_query(input: &str) -> Result<Self, SyncCodecError> {
        if input.len() > MAX_SYNC_ORGANIZATION_VIEW_QUERY_BYTES {
            return Err(invalid("Organization view query exceeds 67 bytes"));
        }
        let (mut revision, mut after, mut limit) = (None, None, None);
        for parameter in input.split('&') {
            let (name, value) =
                parameter.split_once('=').ok_or_else(|| invalid("invalid query parameter"))?;
            let slot = match name {
                "revision" => &mut revision,
                "after" => &mut after,
                "limit" => &mut limit,
                _ => return Err(invalid("unknown Organization view query parameter")),
            };
            if slot.is_some() {
                return Err(invalid("duplicate Organization view query parameter"));
            }
            *slot = Some(canonical_decimal(value, name)?);
        }
        let query = Self {
            view_revision: revision.ok_or_else(|| invalid("missing revision"))?,
            after: after.ok_or_else(|| invalid("missing after"))?,
            limit: u16::try_from(limit.ok_or_else(|| invalid("missing limit"))?)
                .map_err(|_| invalid("limit is out of range"))?,
        };
        query.validate()?;
        Ok(query)
    }
}

/// One page from the current authorized Organization view, independent of Personal sync.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SyncOrganizationViewResponse {
    pub organization: Uuid,
    pub vault: Uuid,
    pub view_revision: u64,
    pub objects: Vec<SyncChange>,
    pub next_cursor: u64,
    pub more: bool,
}

impl SyncOrganizationViewResponse {
    /// Validate identifiers, live K-1 objects, ordering and the default read budgets.
    /// # Errors
    /// Rejects invalid page structure, payloads or exceeded budgets.
    pub fn validate(&self) -> Result<(), SyncCodecError> {
        self.validate_with_limits(SyncReadLimits::default())
    }

    /// Preflight the complete encoded size before payload copies or K-1 parsing.
    /// # Errors
    /// Rejects invalid limits, page structure, K-1 bindings or exceeded budgets.
    pub fn validate_with_limits(&self, limits: SyncReadLimits) -> Result<(), SyncCodecError> {
        limits.validate()?;
        valid_uuid(self.organization, "organization")?;
        valid_uuid(self.vault, "vault")?;
        positive(self.view_revision, "view_revision")?;
        validate_page(&self.objects, self.next_cursor, self.more, "Organization view objects")?;
        // Six-entry map, text keys, two UUID byte strings and more's boolean.
        let objects_header = length_argument_bytes(self.objects.len())?;
        let wrapper = 94usize
            .checked_add(argument_bytes(self.view_revision))
            .and_then(|bytes| bytes.checked_add(argument_bytes(self.next_cursor)))
            .and_then(|bytes| bytes.checked_add(objects_header))
            .ok_or_else(|| invalid("Organization view encoded size overflows this platform"))?;
        read_entries_body_bytes(&self.objects, wrapper, limits)?;
        for change in &self.objects {
            if change.tombstone || change.signer_device_id.is_some() {
                return Err(invalid(
                    "Organization view requires live objects without a Device signer",
                ));
            }
            let object = scoplen_model::Object::decode(&change.payload)
                .map_err(|_| invalid("invalid Organization K-1 object"))?;
            if object.id != change.object_id || object.is_tombstoned() {
                return Err(invalid("Organization K-1 object does not match its live change"));
            }
        }
        Ok(())
    }

    /// Bind a response to the captured descriptor, vault and requested revision/page.
    /// # Errors
    /// Rejects foreign source ids, changed revisions, old entries or an exceeded page limit.
    pub fn validate_for_query(
        &self,
        source: OrganizationVaultContext,
        vault: Uuid,
        query: &SyncOrganizationViewQuery,
    ) -> Result<(), SyncCodecError> {
        self.validate_for_query_with_limits(source, vault, query, SyncReadLimits::default())
    }

    /// Bind a response to its source and query under explicit read budgets.
    /// # Errors
    /// Rejects invalid source/query/page values, correlation or exceeded budgets.
    pub fn validate_for_query_with_limits(
        &self,
        source: OrganizationVaultContext,
        vault: Uuid,
        query: &SyncOrganizationViewQuery,
        limits: SyncReadLimits,
    ) -> Result<(), SyncCodecError> {
        source.validate()?;
        valid_uuid(vault, "source vault")?;
        query.validate()?;
        self.validate_with_limits(limits)?;
        if self.organization != source.organization
            || self.vault != vault
            || self.view_revision != source.view_revision
            || self.view_revision != query.view_revision
        {
            return Err(invalid("Organization view does not match its source or revision"));
        }
        if self.objects.len() > usize::from(query.limit)
            || self.next_cursor < query.after
            || self.objects.first().is_some_and(|object| object.seq <= query.after)
        {
            return Err(invalid("Organization view does not match its requested page"));
        }
        Ok(())
    }

    /// Encode a validated page with the default read budgets.
    /// # Errors
    /// Rejects invalid pages or exceeded budgets.
    pub fn to_cbor(&self) -> Result<Vec<u8>, SyncCodecError> {
        self.to_cbor_with_limits(SyncReadLimits::default())
    }

    /// Preflight before copying payloads into deterministic CBOR values.
    /// # Errors
    /// Rejects invalid pages, limits or exceeded budgets.
    pub fn to_cbor_with_limits(&self, limits: SyncReadLimits) -> Result<Vec<u8>, SyncCodecError> {
        self.validate_with_limits(limits)?;
        encode_map(vec![
            ("organization", Value::Bytes(self.organization.as_bytes().to_vec())),
            ("vault", Value::Bytes(self.vault.as_bytes().to_vec())),
            ("view_revision", Value::UInt(self.view_revision)),
            (
                "objects",
                Value::Array(self.objects.iter().cloned().map(SyncChange::into_value).collect()),
            ),
            ("next_cursor", Value::UInt(self.next_cursor)),
            ("more", Value::Bool(self.more)),
        ])
    }

    /// Decode a page with the default read budgets, ignoring response extensions.
    /// # Errors
    /// Rejects malformed or over-budget complete bodies and invalid page values.
    pub fn from_cbor(input: &[u8]) -> Result<Self, SyncCodecError> {
        Self::from_cbor_with_limits(input, SyncReadLimits::default())
    }

    /// Bound the complete input before deterministic CBOR decoding.
    /// # Errors
    /// Rejects invalid budgets, malformed bodies, invalid page values or budget excess.
    pub fn from_cbor_with_limits(
        input: &[u8],
        limits: SyncReadLimits,
    ) -> Result<Self, SyncCodecError> {
        limits.validate()?;
        if input.len() > limits.max_body_bytes {
            return Err(invalid("Organization view exceeds the encoded-body limit"));
        }
        let mut fields = decode_map(input)?;
        let Some(Value::Array(values)) = fields.remove("objects") else {
            return Err(invalid("Organization view objects must be an array"));
        };
        if values.len() > 1_000 {
            return Err(invalid("Organization view exceeds 1000 objects"));
        }
        let response = Self {
            organization: take_uuid(&mut fields, "organization")?,
            vault: take_uuid(&mut fields, "vault")?,
            view_revision: take_uint(&mut fields, "view_revision")?,
            objects: values.into_iter().map(SyncChange::from_value).collect::<Result<_, _>>()?,
            next_cursor: take_uint(&mut fields, "next_cursor")?,
            more: take_bool(&mut fields, "more")?,
        };
        response.validate_with_limits(limits)?;
        Ok(response)
    }
}

/// Organization-only acknowledgement, sent after complete local view publication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SyncOrganizationAckRequest {
    pub cursor: u64,
    pub view_revision: u64,
}

impl SyncOrganizationAckRequest {
    /// Encode exactly the cursor and positive revision.
    /// # Errors
    /// Rejects revision zero or CBOR encoding failure.
    pub fn to_cbor(self) -> Result<Vec<u8>, SyncCodecError> {
        positive(self.view_revision, "view_revision")?;
        encode_map(vec![
            ("cursor", Value::UInt(self.cursor)),
            ("view_revision", Value::UInt(self.view_revision)),
        ])
    }

    /// Decode a strict request within its exact maximum encoded size.
    /// # Errors
    /// Rejects oversized, noncanonical or unknown fields and invalid revisions.
    pub fn from_cbor(input: &[u8]) -> Result<Self, SyncCodecError> {
        if input.len() > MAX_SYNC_ORGANIZATION_ACK_REQUEST_BYTES {
            return Err(invalid("Organization acknowledgement exceeds 40 bytes"));
        }
        let mut fields = decode_map(input)?;
        let request = Self {
            cursor: take_uint(&mut fields, "cursor")?,
            view_revision: take_uint(&mut fields, "view_revision")?,
        };
        positive(request.view_revision, "view_revision")?;
        if !fields.is_empty() {
            return Err(invalid("unknown Organization acknowledgement field"));
        }
        Ok(request)
    }
}

/// Stored progress for the same currently authorized Organization revision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SyncOrganizationAckResponse {
    pub cursor: u64,
    pub view_revision: u64,
}

impl SyncOrganizationAckResponse {
    /// Require the captured revision and a stored cursor at least as high as requested.
    /// # Errors
    /// Rejects invalid revisions, revision mismatch or cursor regression.
    pub fn validate_for_request(
        self,
        request: &SyncOrganizationAckRequest,
    ) -> Result<(), SyncCodecError> {
        positive(request.view_revision, "view_revision")?;
        if self.view_revision != request.view_revision || self.cursor < request.cursor {
            return Err(invalid("Organization acknowledgement does not match request"));
        }
        Ok(())
    }

    /// Encode a positive revision and stored cursor.
    /// # Errors
    /// Rejects revision zero or CBOR encoding failure.
    pub fn to_cbor(self) -> Result<Vec<u8>, SyncCodecError> {
        SyncOrganizationAckRequest { cursor: self.cursor, view_revision: self.view_revision }
            .to_cbor()
    }

    /// Decode a deterministic response while ignoring unknown extension fields.
    /// # Errors
    /// Rejects malformed CBOR, missing fields or revision zero.
    pub fn from_cbor(input: &[u8]) -> Result<Self, SyncCodecError> {
        let mut fields = decode_map(input)?;
        let response = Self {
            cursor: take_uint(&mut fields, "cursor")?,
            view_revision: take_uint(&mut fields, "view_revision")?,
        };
        positive(response.view_revision, "view_revision")?;
        Ok(response)
    }
}
