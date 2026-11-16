// SPDX-License-Identifier: Apache-2.0
//! Verification response syntax and interval-only checkpoint coverage.

use super::*;

/// Existing Organization checkpoint evidence; the response never supplies its trust key.
#[derive(Clone, Eq, PartialEq)]
pub struct AuditCheckpoint {
    /// Positive sequence inside the selected interval.
    pub sequence: u64,
    /// Original signed chain head.
    pub head_hash: [u8; 32],
    /// Original positive signed Unix milliseconds in reversible UTC text.
    pub signed_at: String,
    /// Original 64-byte Ed25519 signature, encoded as canonical unpadded base64url.
    pub signature: [u8; 64],
}
impl fmt::Debug for AuditCheckpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuditCheckpoint").field("sequence", &self.sequence).finish_non_exhaustive()
    }
}
impl AuditCheckpoint {
    /// Validate evidence syntax without verifying its signature or deployment trust.
    /// # Errors
    /// Rejects zero sequence or an invalid/nonpositive signed time.
    pub fn validate(&self) -> Result<(), AuditCodecError> {
        if self.sequence == 0 || parse_audit_timestamp(&self.signed_at)? <= 0 {
            return Err(AuditCodecError::InvalidField("checkpoint"));
        }
        Ok(())
    }

    /// Reconstruct the unchanged existing Organization checkpoint message.
    /// The caller supplies its independently configured audit verification key.
    /// # Errors
    /// Rejects invalid Organization or checkpoint metadata; this does not verify a signature.
    pub fn signed_payload(&self, organization: Uuid) -> Result<Vec<u8>, AuditCodecError> {
        self.validate()?;
        valid_uuid(organization, "organization_id")?;
        let milliseconds = u64::try_from(parse_audit_timestamp(&self.signed_at)?)
            .map_err(|_| AuditCodecError::InvalidField("signed_at"))?;
        let mut payload = b"spl-audit-checkpoint-v1".to_vec();
        payload.extend_from_slice(organization.as_bytes());
        payload.extend_from_slice(&self.sequence.to_be_bytes());
        payload.extend_from_slice(&self.head_hash);
        payload.extend_from_slice(&milliseconds.to_be_bytes());
        Ok(payload)
    }
}

/// Bounded integrity report, separate from signature coverage of this checked interval.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditVerification {
    /// Selected Organization `UUIDv7`.
    pub organization_id: Uuid,
    /// First selected sequence, inclusive.
    pub from_sequence: u64,
    /// Final selected sequence, inclusive.
    pub to_sequence: u64,
    /// Selected events preceding a failure, or the full interval length on success.
    pub checked_events: u64,
    /// Integrity result; storage unavailability is an HTTP problem instead.
    pub valid: bool,
    /// First failed selected sequence; predecessor failure is reported at the interval start.
    pub failure_sequence: Option<u64>,
    /// First selected event's predecessor hash on success, otherwise null.
    pub previous_hash: Option<[u8; 32]>,
    /// Final selected event hash on success, otherwise null.
    pub head_hash: Option<[u8; 32]>,
    /// Highest checked checkpoint inside the interval, or null.
    pub checkpoint: Option<AuditCheckpoint>,
    /// First sequence without an included checkpoint covering it, or null when fully covered.
    pub uncheckpointed_from_sequence: Option<u64>,
}

#[derive(Serialize, Deserialize)]
struct CheckpointWire {
    sequence: String,
    head_hash: String,
    signed_at: String,
    signature: String,
}
#[derive(Serialize, Deserialize)]
struct VerificationWire {
    organization_id: String,
    from_sequence: String,
    to_sequence: String,
    checked_events: String,
    valid: bool,
    failure_sequence: Option<String>,
    previous_hash: Option<String>,
    head_hash: Option<String>,
    checkpoint: Option<CheckpointWire>,
    uncheckpointed_from_sequence: Option<String>,
}
const VERIFICATION_FIELDS: &[&str] = &[
    "organization_id",
    "from_sequence",
    "to_sequence",
    "checked_events",
    "valid",
    "failure_sequence",
    "previous_hash",
    "head_hash",
    "checkpoint",
    "uncheckpointed_from_sequence",
];

impl AuditVerification {
    /// Selected contiguous range.
    #[must_use]
    pub const fn range(&self) -> AuditRange {
        AuditRange { from_sequence: self.from_sequence, to_sequence: self.to_sequence }
    }

    /// Validate count, failure, hash and interval-only coverage relationships.
    /// # Errors
    /// Rejects malformed or self-contradictory evidence; no signature is authenticated here.
    pub fn validate(&self) -> Result<(), AuditCodecError> {
        valid_uuid(self.organization_id, "organization_id")?;
        let count = self.range().event_count()?;
        if !self.valid {
            let failure =
                self.failure_sequence.ok_or(AuditCodecError::InvalidField("failure_sequence"))?;
            if failure < self.from_sequence
                || failure > self.to_sequence
                || self.checked_events != failure - self.from_sequence
                || self.previous_hash.is_some()
                || self.head_hash.is_some()
                || self.checkpoint.is_some()
                || self.uncheckpointed_from_sequence.is_some()
            {
                return Err(AuditCodecError::InvalidField("failed result"));
            }
            return Ok(());
        }
        if self.checked_events != count
            || self.failure_sequence.is_some()
            || self.previous_hash.is_none()
            || self.head_hash.is_none()
            || (self.from_sequence == 1 && self.previous_hash != Some([0; 32]))
        {
            return Err(AuditCodecError::InvalidField("valid result"));
        }
        let uncovered = if let Some(checkpoint) = &self.checkpoint {
            checkpoint.validate()?;
            if checkpoint.sequence < self.from_sequence || checkpoint.sequence > self.to_sequence {
                return Err(AuditCodecError::InvalidField("checkpoint range"));
            }
            if checkpoint.sequence == self.to_sequence {
                if self.head_hash != Some(checkpoint.head_hash) {
                    return Err(AuditCodecError::InvalidField("checkpoint head"));
                }
                None
            } else {
                Some(checkpoint.sequence + 1)
            }
        } else {
            Some(self.from_sequence)
        };
        if self.uncheckpointed_from_sequence != uncovered {
            return Err(AuditCodecError::InvalidField("checkpoint coverage"));
        }
        Ok(())
    }

    /// Bind the report to the captured Organization and requested interval.
    /// # Errors
    /// Rejects invalid data, wrong Organization or changed range.
    pub fn validate_for(
        &self,
        organization: Uuid,
        range: AuditRange,
    ) -> Result<(), AuditCodecError> {
        self.validate()?;
        range.validate()?;
        valid_uuid(organization, "organization_id")?;
        if self.organization_id != organization || self.range() != range {
            return Err(AuditCodecError::Context);
        }
        Ok(())
    }

    /// Decode one complete bounded result, preserving exact decimal sequence values.
    /// # Errors
    /// Rejects malformed/duplicate/missing fields, noncanonical encodings and inconsistent claims.
    pub fn from_json(input: &[u8]) -> Result<Self, AuditCodecError> {
        require_fields(&object(input, MAX_AUDIT_VERIFICATION_BYTES)?, VERIFICATION_FIELDS)?;
        let wire: VerificationWire =
            serde_json::from_slice(input).map_err(|_| AuditCodecError::InvalidJson)?;
        let result = Self {
            organization_id: parse_uuid(&wire.organization_id, "organization_id")?,
            from_sequence: parse_decimal(&wire.from_sequence, false, "from_sequence")?,
            to_sequence: parse_decimal(&wire.to_sequence, false, "to_sequence")?,
            checked_events: parse_decimal(&wire.checked_events, true, "checked_events")?,
            valid: wire.valid,
            failure_sequence: optional_sequence(wire.failure_sequence)?,
            previous_hash: wire.previous_hash.map(|s| parse_hex(&s)).transpose()?,
            head_hash: wire.head_hash.map(|s| parse_hex(&s)).transpose()?,
            checkpoint: wire
                .checkpoint
                .map(|c| {
                    let signature = URL_SAFE_NO_PAD
                        .decode(&c.signature)
                        .map_err(|_| AuditCodecError::InvalidField("signature"))?;
                    if URL_SAFE_NO_PAD.encode(&signature) != c.signature {
                        return Err(AuditCodecError::InvalidField("signature"));
                    }
                    Ok(AuditCheckpoint {
                        sequence: parse_decimal(&c.sequence, false, "checkpoint.sequence")?,
                        head_hash: parse_hex(&c.head_hash)?,
                        signed_at: c.signed_at,
                        signature: signature
                            .try_into()
                            .map_err(|_| AuditCodecError::InvalidField("signature"))?,
                    })
                })
                .transpose()?,
            uncheckpointed_from_sequence: optional_sequence(wire.uncheckpointed_from_sequence)?,
        };
        result.validate()?;
        Ok(result)
    }

    /// Decode and validate the captured request binding.
    /// # Errors
    /// Rejects invalid syntax, evidence relationships or response context.
    pub fn from_json_for(
        input: &[u8],
        organization: Uuid,
        range: AuditRange,
    ) -> Result<Self, AuditCodecError> {
        let value = Self::from_json(input)?;
        value.validate_for(organization, range)?;
        Ok(value)
    }

    /// Emit fixed-order canonical JSON after revalidation.
    /// # Errors
    /// Rejects invalid mutable fields or a complete response overflow.
    pub fn to_json(&self) -> Result<Vec<u8>, AuditCodecError> {
        self.validate()?;
        encode(
            &VerificationWire {
                organization_id: self.organization_id.to_string(),
                from_sequence: self.from_sequence.to_string(),
                to_sequence: self.to_sequence.to_string(),
                checked_events: self.checked_events.to_string(),
                valid: self.valid,
                failure_sequence: self.failure_sequence.map(|n| n.to_string()),
                previous_hash: self.previous_hash.map(|h| hex(&h)),
                head_hash: self.head_hash.map(|h| hex(&h)),
                checkpoint: self.checkpoint.as_ref().map(|c| CheckpointWire {
                    sequence: c.sequence.to_string(),
                    head_hash: hex(&c.head_hash),
                    signed_at: c.signed_at.clone(),
                    signature: URL_SAFE_NO_PAD.encode(c.signature),
                }),
                uncheckpointed_from_sequence: self
                    .uncheckpointed_from_sequence
                    .map(|n| n.to_string()),
            },
            MAX_AUDIT_VERIFICATION_BYTES,
        )
    }

    /// Whether two validated successful adjacent chunks have matching boundary hashes.
    /// This does not extend either interval's checkpoint evidence or establish an external archive.
    #[must_use]
    pub fn can_join(&self, next: &Self) -> bool {
        self.valid
            && next.valid
            && self.validate().is_ok()
            && next.validate().is_ok()
            && self.organization_id == next.organization_id
            && self.to_sequence.checked_add(1) == Some(next.from_sequence)
            && self.head_hash == next.previous_hash
    }
}

fn optional_sequence(text: Option<String>) -> Result<Option<u64>, AuditCodecError> {
    text.map(|s| parse_decimal(&s, false, "sequence")).transpose()
}
