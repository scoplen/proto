// SPDX-License-Identifier: Apache-2.0
//! Authorized Shared-vault recipient lookup and roster response codecs.

use std::collections::{BTreeMap, BTreeSet};

use scoplen_model::cbor::Value;
use uuid::Uuid;

use super::{
    MAX_SYNC_KEY_BODY_BYTES, MAX_SYNC_VAULT_EPOCH_WRAPS, MAX_SYNC_VAULT_KEY_EPOCHS, SyncCodecError,
    decode_map, encode_map, expect_map, invalid, map, positive, take_bool, take_bytes, take_uint,
    take_uuid, valid_uuid, validate_recipient_binding,
};

/// Maximum current recipients in one Shared-vault roster.
pub const MAX_SYNC_VAULT_RECIPIENTS: usize = MAX_SYNC_VAULT_EPOCH_WRAPS;
/// Maximum deterministic CBOR response for an administrator roster or lookup.
pub const MAX_SYNC_VAULT_RECIPIENTS_BODY_BYTES: usize = MAX_SYNC_KEY_BODY_BYTES;

/// Current public key publication for one Organization Membership.
///
/// The caller applies its authenticated recipient-pin and changed-root policy before wrapping.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SyncVaultRecipient {
    /// Current native Organization Membership.
    pub membership_id: Uuid,
    /// Account bound to that Membership.
    pub account_id: Uuid,
    /// Reviewed Account key publication revision.
    pub recipient_key_revision: u64,
    /// Ed25519 signing public key.
    pub signing_public_key: [u8; 32],
    /// X25519 KEM public key.
    pub kem_public_key: [u8; 32],
}

impl SyncVaultRecipient {
    /// Validate the identifiers and positive publication revision.
    ///
    /// # Errors
    ///
    /// Rejects invalid Account or Membership identifiers and a zero key revision.
    pub fn validate(&self) -> Result<(), SyncCodecError> {
        validate_recipient_binding(self.account_id, self.membership_id, self.recipient_key_revision)
    }

    /// Bind a lookup result to the Membership selected by the request path.
    ///
    /// # Errors
    ///
    /// Rejects an invalid response, an invalid path identifier or a different Membership.
    pub fn validate_for_membership(&self, membership_id: Uuid) -> Result<(), SyncCodecError> {
        valid_uuid(membership_id, "path membership_id")?;
        self.validate()?;
        if self.membership_id != membership_id {
            return Err(invalid("recipient membership_id does not match request"));
        }
        Ok(())
    }

    /// Encode a recipient lookup response as deterministic CBOR.
    ///
    /// # Errors
    ///
    /// Rejects invalid fields or a response outside the encoded body budget.
    pub fn to_cbor(&self) -> Result<Vec<u8>, SyncCodecError> {
        self.validate()?;
        let encoded = encode_map(self.fields())?;
        enforce_body_limit(&encoded)?;
        Ok(encoded)
    }

    /// Decode a recipient lookup response, accepting additive response fields.
    ///
    /// # Errors
    ///
    /// Rejects oversized bodies, malformed CBOR, invalid identifiers, zero revisions or wrong
    /// public key lengths.
    pub fn from_cbor(input: &[u8]) -> Result<Self, SyncCodecError> {
        enforce_body_limit(input)?;
        Self::from_fields(decode_map(input)?)
    }

    fn fields(&self) -> Vec<(&'static str, Value)> {
        vec![
            ("membership_id", Value::Bytes(self.membership_id.as_bytes().to_vec())),
            ("account_id", Value::Bytes(self.account_id.as_bytes().to_vec())),
            ("recipient_key_revision", Value::UInt(self.recipient_key_revision)),
            ("signing_public_key", Value::Bytes(self.signing_public_key.to_vec())),
            ("kem_public_key", Value::Bytes(self.kem_public_key.to_vec())),
        ]
    }

    fn from_fields(mut fields: BTreeMap<String, Value>) -> Result<Self, SyncCodecError> {
        let signing_public_key = take_bytes(&mut fields, "signing_public_key")?
            .try_into()
            .map_err(|_| invalid("signing_public_key must be exactly 32 bytes"))?;
        let kem_public_key = take_bytes(&mut fields, "kem_public_key")?
            .try_into()
            .map_err(|_| invalid("kem_public_key must be exactly 32 bytes"))?;
        let recipient = Self {
            membership_id: take_uuid(&mut fields, "membership_id")?,
            account_id: take_uuid(&mut fields, "account_id")?,
            recipient_key_revision: take_uint(&mut fields, "recipient_key_revision")?,
            signing_public_key,
            kem_public_key,
        };
        recipient.validate()?;
        Ok(recipient)
    }
}

/// One authorized snapshot of the Shared vault's served epochs and admitted recipients.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SyncVaultRecipientsResponse {
    /// Current Shared vault key epoch.
    pub key_epoch: u64,
    /// Pending rotation, which fences writes and admission.
    pub rotation_pending: bool,
    /// Strictly ascending positive non-retired epochs, ending at the current key epoch.
    pub served_epochs: Vec<u64>,
    /// Current admitted recipients in ascending Account UUID byte order.
    pub recipients: Vec<SyncVaultRecipient>,
}

impl SyncVaultRecipientsResponse {
    /// Validate epoch consistency, recipient bindings and uniqueness.
    ///
    /// # Errors
    ///
    /// Rejects invalid fields, invalid list lengths or ordering, duplicate Memberships or a
    /// served epoch set that ends at a different epoch.
    pub fn validate(&self) -> Result<(), SyncCodecError> {
        positive(self.key_epoch, "key_epoch")?;
        if self.served_epochs.is_empty()
            || self.served_epochs.len() > MAX_SYNC_VAULT_KEY_EPOCHS
            || self.served_epochs.first() == Some(&0)
            || self.served_epochs.last() != Some(&self.key_epoch)
            || self.served_epochs.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(invalid("served_epochs must be positive, ascending and end at key_epoch"));
        }
        if self.recipients.is_empty() || self.recipients.len() > MAX_SYNC_VAULT_RECIPIENTS {
            return Err(invalid(format!(
                "recipients must contain 1..{MAX_SYNC_VAULT_RECIPIENTS} entries"
            )));
        }
        let mut memberships = BTreeSet::new();
        let mut previous = None;
        for recipient in &self.recipients {
            recipient.validate()?;
            if previous.is_some_and(|account| account >= recipient.account_id.as_bytes()) {
                return Err(invalid("recipients must be strictly ordered by account_id"));
            }
            if !memberships.insert(recipient.membership_id) {
                return Err(invalid("recipients contain duplicate membership_id"));
            }
            previous = Some(recipient.account_id.as_bytes());
        }
        Ok(())
    }

    /// Encode the complete roster as deterministic CBOR.
    ///
    /// # Errors
    ///
    /// Rejects invalid fields or a response outside the encoded body budget.
    pub fn to_cbor(&self) -> Result<Vec<u8>, SyncCodecError> {
        self.validate()?;
        let encoded = encode_map(vec![
            ("key_epoch", Value::UInt(self.key_epoch)),
            ("rotation_pending", Value::Bool(self.rotation_pending)),
            (
                "served_epochs",
                Value::Array(self.served_epochs.iter().copied().map(Value::UInt).collect()),
            ),
            (
                "recipients",
                Value::Array(
                    self.recipients.iter().map(|recipient| map(recipient.fields())).collect(),
                ),
            ),
        ])?;
        enforce_body_limit(&encoded)?;
        Ok(encoded)
    }

    /// Decode the complete roster, accepting additive response fields.
    ///
    /// # Errors
    ///
    /// Rejects oversized bodies, malformed CBOR, invalid fields or incomplete epoch/recipient lists.
    pub fn from_cbor(input: &[u8]) -> Result<Self, SyncCodecError> {
        enforce_body_limit(input)?;
        let mut fields = decode_map(input)?;
        let Some(Value::Array(epochs)) = fields.remove("served_epochs") else {
            return Err(invalid("served_epochs must be an array"));
        };
        if epochs.len() > MAX_SYNC_VAULT_KEY_EPOCHS {
            return Err(invalid("served_epochs exceeds the maximum epoch count"));
        }
        let served_epochs = epochs
            .into_iter()
            .map(|value| match value {
                Value::UInt(epoch) => Ok(epoch),
                _ => Err(invalid("served_epochs must contain unsigned integers")),
            })
            .collect::<Result<_, _>>()?;
        let Some(Value::Array(values)) = fields.remove("recipients") else {
            return Err(invalid("recipients must be an array"));
        };
        if values.len() > MAX_SYNC_VAULT_RECIPIENTS {
            return Err(invalid("recipients exceeds the maximum recipient count"));
        }
        let recipients = values
            .into_iter()
            .map(|value| SyncVaultRecipient::from_fields(expect_map(value)?))
            .collect::<Result<_, _>>()?;
        let response = Self {
            key_epoch: take_uint(&mut fields, "key_epoch")?,
            rotation_pending: take_bool(&mut fields, "rotation_pending")?,
            served_epochs,
            recipients,
        };
        response.validate()?;
        Ok(response)
    }
}

fn enforce_body_limit(input: &[u8]) -> Result<(), SyncCodecError> {
    if input.len() > MAX_SYNC_VAULT_RECIPIENTS_BODY_BYTES {
        return Err(invalid("Shared recipient response exceeds 4 MiB"));
    }
    Ok(())
}
