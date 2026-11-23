// SPDX-License-Identifier: Apache-2.0
//! D-171 key evidence served to one current native Shared vault admission.

use std::fmt;

use scoplen_crypto::{SharedVaultAuthorityReceipt, SharedVaultKeyWrap, SharedVaultWrapOperation};
use scoplen_model::cbor::Value;
use uuid::Uuid;

use super::{
    MAX_SYNC_VAULT_KEY_EPOCHS, SyncCodecError, decode_map, encode_map,
    enforce_vault_keys_body_limit, expect_map, invalid, map, take_bytes, take_uint, take_uuid,
    valid_uuid, validate_recipient_binding,
};

/// Immutable public key material from the mutation that originally served a wrap.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SyncSharedVaultKeyPublication {
    /// Account owning the publication.
    pub account_id: Uuid,
    /// Organization Membership at publication of the wrap.
    pub membership_id: Uuid,
    /// Positive Account key publication revision.
    pub revision: u64,
    /// Ed25519 verification key.
    pub signing_public_key: [u8; 32],
    /// X25519 public key.
    pub kem_public_key: [u8; 32],
}

impl SyncSharedVaultKeyPublication {
    fn validate(self) -> Result<(), SyncCodecError> {
        validate_recipient_binding(self.account_id, self.membership_id, self.revision)
    }

    fn to_value(self) -> Value {
        map(vec![
            ("account_id", uuid_value(self.account_id)),
            ("membership_id", uuid_value(self.membership_id)),
            ("revision", Value::UInt(self.revision)),
            ("signing_public_key", Value::Bytes(self.signing_public_key.to_vec())),
            ("kem_public_key", Value::Bytes(self.kem_public_key.to_vec())),
        ])
    }

    fn from_value(value: Value) -> Result<Self, SyncCodecError> {
        let mut fields = expect_map(value)?;
        Ok(Self {
            account_id: take_uuid(&mut fields, "account_id")?,
            membership_id: take_uuid(&mut fields, "membership_id")?,
            revision: take_uint(&mut fields, "revision")?,
            signing_public_key: take_bytes(&mut fields, "signing_public_key")?
                .try_into()
                .map_err(|_| invalid("signing_public_key must be exactly 32 bytes"))?,
            kem_public_key: take_bytes(&mut fields, "kem_public_key")?
                .try_into()
                .map_err(|_| invalid("kem_public_key must be exactly 32 bytes"))?,
        })
    }
}

/// Unverified historical evidence for one Shared vault epoch.
#[derive(Clone, Eq, PartialEq)]
pub struct SyncSharedVaultKey {
    /// Positive epoch of the wrapped key.
    pub epoch: u32,
    /// Operation that published the wrap for this recipient.
    pub operation: SharedVaultWrapOperation,
    /// Historical author's public key publication.
    pub author: SyncSharedVaultKeyPublication,
    /// Recipient's historical publication for this wrap.
    pub recipient: SyncSharedVaultKeyPublication,
    /// HPKE wire artifact with the author signature.
    pub wrapped_vault_key: SharedVaultKeyWrap,
    /// Deployment audit proof for this exact wrap and admission.
    pub authority_receipt: SharedVaultAuthorityReceipt,
}

impl fmt::Debug for SyncSharedVaultKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SyncSharedVaultKey")
            .field("epoch", &self.epoch)
            .field("operation", &self.operation)
            .finish_non_exhaustive()
    }
}

impl SyncSharedVaultKey {
    fn validate(&self) -> Result<(), SyncCodecError> {
        self.author.validate()?;
        self.recipient.validate()?;
        let valid_operation = match self.operation {
            SharedVaultWrapOperation::Create => self.epoch == 1 && self.author == self.recipient,
            SharedVaultWrapOperation::Admit => {
                self.author.account_id != self.recipient.account_id
                    && self.author.membership_id != self.recipient.membership_id
            }
            SharedVaultWrapOperation::PublishEpoch => self.epoch > 1,
        };
        if self.epoch == 0 || !valid_operation {
            return Err(invalid("invalid operation or epoch in Shared vault key evidence"));
        }
        Ok(())
    }

    fn to_value(&self) -> Value {
        map(vec![
            ("epoch", Value::UInt(self.epoch.into())),
            ("operation", Value::UInt(u64::from(self.operation as u8))),
            ("author", self.author.to_value()),
            ("recipient", self.recipient.to_value()),
            ("wrapped_vault_key", Value::Bytes(self.wrapped_vault_key.encode().to_vec())),
            ("authority_receipt", Value::Bytes(self.authority_receipt.encode().to_vec())),
        ])
    }

    fn from_value(value: Value) -> Result<Self, SyncCodecError> {
        let mut fields = expect_map(value)?;
        let operation = match take_uint(&mut fields, "operation")? {
            1 => SharedVaultWrapOperation::Create,
            2 => SharedVaultWrapOperation::Admit,
            3 => SharedVaultWrapOperation::PublishEpoch,
            _ => return Err(invalid("unknown Shared vault key operation")),
        };
        Ok(Self {
            epoch: take_uint(&mut fields, "epoch")?
                .try_into()
                .map_err(|_| invalid("Shared vault epoch exceeds u32"))?,
            operation,
            author: SyncSharedVaultKeyPublication::from_value(
                fields.remove("author").ok_or_else(|| invalid("missing author"))?,
            )?,
            recipient: SyncSharedVaultKeyPublication::from_value(
                fields.remove("recipient").ok_or_else(|| invalid("missing recipient"))?,
            )?,
            wrapped_vault_key: SharedVaultKeyWrap::decode(&take_bytes(
                &mut fields,
                "wrapped_vault_key",
            )?)
            .map_err(|_| invalid("invalid Shared vault wrap envelope"))?,
            authority_receipt: SharedVaultAuthorityReceipt::decode(&take_bytes(
                &mut fields,
                "authority_receipt",
            )?)
            .map_err(|_| invalid("invalid Shared vault authority receipt envelope"))?,
        })
    }
}

/// D-171 response from the key endpoint for an Organization-owned Shared vault.
/// Author trust, audit signatures and decryption are verified separately with K-2.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SyncSharedVaultKeyDelivery {
    /// Immutable owning Organization.
    pub organization: Uuid,
    /// Vault selected by the request.
    pub vault_id: Uuid,
    /// Account authenticated on the Device.
    pub account_id: Uuid,
    /// Current native Organization Membership.
    pub membership_id: Uuid,
    /// Current recipient admission to the Shared vault.
    pub admission_id: Uuid,
    /// Complete non-retired key evidence, ordered by increasing epoch.
    pub keys: Vec<SyncSharedVaultKey>,
}

impl SyncSharedVaultKeyDelivery {
    /// Validate the wire identifiers, ordering, bounds and per-wrap recipient binding.
    ///
    /// # Errors
    /// Rejects malformed evidence, out-of-order keys and mismatched recipients.
    pub fn validate(&self) -> Result<(), SyncCodecError> {
        valid_uuid(self.organization, "organization")?;
        valid_uuid(self.vault_id, "vault_id")?;
        valid_uuid(self.account_id, "account_id")?;
        valid_uuid(self.membership_id, "membership_id")?;
        valid_uuid(self.admission_id, "admission_id")?;
        if self.keys.is_empty() || self.keys.len() > MAX_SYNC_VAULT_KEY_EPOCHS {
            return Err(invalid("invalid Shared vault key set size"));
        }
        let mut previous = 0;
        for key in &self.keys {
            key.validate()?;
            if key.epoch <= previous {
                return Err(invalid("Shared vault key epochs must be strictly ascending"));
            }
            if key.recipient.account_id != self.account_id
                || key.recipient.membership_id != self.membership_id
            {
                return Err(invalid(
                    "epoch recipient differs from the current Shared vault recipient",
                ));
            }
            previous = key.epoch;
        }
        Ok(())
    }

    /// Bind the delivery to the intended Organization, vault and current Account Membership.
    ///
    /// # Errors
    /// Rejects an invalid delivery or a mismatch with the expected recipient scope.
    pub fn validate_for_recipient(
        &self,
        organization: Uuid,
        vault_id: Uuid,
        account_id: Uuid,
        membership_id: Uuid,
    ) -> Result<(), SyncCodecError> {
        self.validate()?;
        if (self.organization, self.vault_id, self.account_id, self.membership_id)
            != (organization, vault_id, account_id, membership_id)
        {
            return Err(invalid(
                "Shared vault key delivery differs from the expected recipient scope",
            ));
        }
        Ok(())
    }

    /// Encode the complete version-one key delivery as deterministic CBOR.
    ///
    /// # Errors
    /// Rejects invalid fields or an encoded body outside the key endpoint's limit.
    pub fn to_cbor(&self) -> Result<Vec<u8>, SyncCodecError> {
        self.validate()?;
        let encoded = encode_map(vec![
            ("organization", uuid_value(self.organization)),
            ("vault_id", uuid_value(self.vault_id)),
            ("account_id", uuid_value(self.account_id)),
            ("membership_id", uuid_value(self.membership_id)),
            ("admission_id", uuid_value(self.admission_id)),
            ("keys", Value::Array(self.keys.iter().map(SyncSharedVaultKey::to_value).collect())),
        ])?;
        enforce_vault_keys_body_limit(&encoded)?;
        Ok(encoded)
    }

    /// Decode bounded deterministic CBOR, accepting additive response fields.
    ///
    /// # Errors
    /// Rejects malformed CBOR, missing evidence and invalid recipient or epoch bindings.
    pub fn from_cbor(input: &[u8]) -> Result<Self, SyncCodecError> {
        enforce_vault_keys_body_limit(input)?;
        let mut fields = decode_map(input)?;
        let Some(Value::Array(keys)) = fields.remove("keys") else {
            return Err(invalid("missing Shared vault key array"));
        };
        if keys.is_empty() || keys.len() > MAX_SYNC_VAULT_KEY_EPOCHS {
            return Err(invalid("invalid Shared vault key set size"));
        }
        let delivery = Self {
            organization: take_uuid(&mut fields, "organization")?,
            vault_id: take_uuid(&mut fields, "vault_id")?,
            account_id: take_uuid(&mut fields, "account_id")?,
            membership_id: take_uuid(&mut fields, "membership_id")?,
            admission_id: take_uuid(&mut fields, "admission_id")?,
            keys: keys.into_iter().map(SyncSharedVaultKey::from_value).collect::<Result<_, _>>()?,
        };
        delivery.validate()?;
        Ok(delivery)
    }
}

fn uuid_value(id: Uuid) -> Value {
    Value::Bytes(id.as_bytes().to_vec())
}
