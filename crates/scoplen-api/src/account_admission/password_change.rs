// SPDX-License-Identifier: Apache-2.0
//! D-152 native password replacement and historical confirmation codecs.

use super::{
    AccountAdmissionCodecError as Error, AccountPasswordChangePayload, AccountRequestIntent,
    AccountRequestKind, AccountRequestProof, AccountRequestSignatureInput,
    MAX_ACCOUNT_PASSWORD_CHANGE_PAYLOAD_BYTES, SecretBytes, SecretVec, Value, b64, decimal, json,
    no_extensions, object, request_fields, string, take_bytes, take_decimal, take_fixed,
    take_intent, take_kind, take_text, take_uuid, valid_uuid,
};
use uuid::Uuid;

/// Signed password-change ceremony; confirm carries no new mutation capability.
#[derive(Clone, Eq, PartialEq)]
pub struct AccountPasswordChangeRequest {
    /// Explicit new mutation or exact historical receipt intent.
    pub intent: AccountRequestIntent,
    /// Original complete protected bytes, retained unchanged for confirmation.
    pub payload: SecretVec,
    /// Original Account root signature over the password-change domain and payload.
    pub account_signature: [u8; 64],
    /// Fresh one-use challenge identifier.
    pub attempt_id: SecretBytes<32>,
    /// Fresh challenge nonce.
    pub nonce: SecretBytes<32>,
    /// Fresh P-256 proof using the original enrolled Device signing key.
    pub device_proof: [u8; 64],
    /// Submit requires the shared password capability; confirm requires JSON null.
    pub admission_token: Option<SecretBytes<32>>,
}

impl AccountPasswordChangeRequest {
    /// Decode exact required members, complete protected structure and successor generation.
    /// # Errors
    /// Rejects noncanonical/duplicate/unknown fields, bounds or illegal intent/token pairs.
    pub fn from_json(input: &[u8]) -> Result<Self, Error> {
        let (request, payload) = Self::decode_for_authentication(input)?;
        payload.validate()?;
        Ok(request)
    }

    /// Decode complete structure before authenticating a challenge, capability or receipt.
    ///
    /// A positive but non-successor generation is left to authenticated conflict handling.
    /// The consumer must verify current authority or an exact retained historical receipt.
    /// # Errors
    /// Rejects malformed syntax/wrapper, bounds or illegal intent/token combinations.
    pub fn decode_for_authentication(
        input: &[u8],
    ) -> Result<(Self, AccountPasswordChangePayload), Error> {
        let mut f = object(input, 16_384)?;
        let intent = take_intent(&mut f)?;
        let admission_token = match (intent, f.get("admission_token")) {
            (AccountRequestIntent::Submit, Some(Value::String(_))) => {
                Some(SecretBytes::new(take_fixed(&mut f, "admission_token")?))
            }
            (AccountRequestIntent::Confirm, Some(Value::Null)) => {
                f.remove("admission_token");
                None
            }
            _ => return Err(Error::InvalidJson),
        };
        let request = Self {
            intent,
            payload: SecretVec::new(take_bytes(
                &mut f,
                "payload",
                MAX_ACCOUNT_PASSWORD_CHANGE_PAYLOAD_BYTES,
            )?),
            account_signature: take_fixed(&mut f, "account_signature")?,
            attempt_id: SecretBytes::new(take_fixed(&mut f, "attempt_id")?),
            nonce: SecretBytes::new(take_fixed(&mut f, "nonce")?),
            device_proof: take_fixed(&mut f, "device_proof")?,
            admission_token,
        };
        no_extensions(&f)?;
        let payload =
            AccountPasswordChangePayload::from_cbor_structural(request.payload.as_bytes())?;
        Ok((request, payload))
    }

    /// Encode exact retained business material with the correctly typed capability field.
    /// # Errors
    /// Rejects invalid intent/token pairs, protected fields or the complete body bound.
    pub fn to_json(&self) -> Result<Vec<u8>, Error> {
        if matches!(
            (self.intent, &self.admission_token),
            (AccountRequestIntent::Submit, None) | (AccountRequestIntent::Confirm, Some(_))
        ) {
            return Err(Error::InvalidJson);
        }
        AccountPasswordChangePayload::from_cbor(self.payload.as_bytes())?;
        let mut fields = request_fields(
            self.intent,
            self.payload.as_bytes(),
            &self.account_signature,
            self.attempt_id.as_bytes(),
            self.nonce.as_bytes(),
            &self.device_proof,
        );
        fields.push((
            "admission_token",
            self.admission_token.as_ref().map_or(Value::Null, |token| b64(token.as_ref())),
        ));
        json(fields, 16_384)
    }

    /// Verify both signatures against transaction-current or retained original public keys.
    ///
    /// The consumer selects the Device key from current certified state or the exact receipt.
    /// This verifies possession only, leaving successor/CAS and current authority checks intact.
    /// # Errors
    /// Rejects malformed structure, substituted origin or incorrect Account/Device signatures.
    pub fn verify_proof(
        &self,
        trusted_origin: &str,
        trusted_root: &[u8; 32],
        trusted_device_signing_key: &[u8],
    ) -> Result<[u8; 32], Error> {
        let p = AccountPasswordChangePayload::from_cbor_structural(self.payload.as_bytes())?;
        if p.origin != trusted_origin {
            return Err(Error::Binding);
        }
        let input = AccountRequestSignatureInput::new(
            AccountRequestKind::PasswordChange,
            self.payload.as_bytes(),
        )
        .map_err(|_| Error::InvalidProtected)?;
        input.verify(trusted_root, &self.account_signature).map_err(|_| Error::Binding)?;
        let digest = input.request_digest(&self.account_signature);
        AccountRequestProof::new(
            AccountRequestKind::PasswordChange,
            self.intent,
            trusted_origin,
            self.attempt_id.as_bytes(),
            self.nonce.as_bytes(),
            p.operation_id,
            p.device_id,
            &digest,
        )
        .map_err(|_| Error::InvalidProtected)?
        .verify(trusted_device_signing_key, &self.device_proof)
        .map_err(|_| Error::Binding)?;
        Ok(digest)
    }
}

/// Exact historical password-change result, never a current-generation assertion.
#[derive(Clone, Eq, PartialEq)]
pub struct AccountPasswordChangeConfirmation {
    /// Original deployment-unique operation identifier.
    pub operation_id: Uuid,
    /// Original domain-separated payload and Account-signature digest.
    pub request_digest: [u8; 32],
    /// Originally committed Account identifier.
    pub account_id: Uuid,
    /// Originally committed Personal vault identifier.
    pub personal_vault_id: Uuid,
    /// Original existing Device identifier.
    pub device_id: Uuid,
    /// Positive new generation committed by this operation, which may now be historical.
    pub credential_generation: u64,
}

impl AccountPasswordChangeConfirmation {
    /// Decode bounded committed facts, ignoring only unprotected response extensions.
    /// # Errors
    /// Rejects wrong outcome/kind, noncanonical identifiers/digest/generation or size.
    pub fn from_json(input: &[u8]) -> Result<Self, Error> {
        let mut f = object(input, 1_024)?;
        if take_text(&mut f, "outcome")? != "committed"
            || take_kind(&mut f)? != AccountRequestKind::PasswordChange
        {
            return Err(Error::InvalidJson);
        }
        Ok(Self {
            operation_id: take_uuid(&mut f, "operation_id")?,
            request_digest: take_fixed(&mut f, "request_digest")?,
            account_id: take_uuid(&mut f, "account_id")?,
            personal_vault_id: take_uuid(&mut f, "personal_vault_id")?,
            device_id: take_uuid(&mut f, "device_id")?,
            credential_generation: take_decimal(&mut f, "credential_generation")?,
        })
    }

    /// Encode only the original committed facts with the fixed password-change kind.
    /// # Errors
    /// Rejects invalid identifiers, zero generation or the complete response bound.
    pub fn to_json(&self) -> Result<Vec<u8>, Error> {
        for id in [self.operation_id, self.account_id, self.personal_vault_id, self.device_id] {
            valid_uuid(id)?;
        }
        json(
            vec![
                ("outcome", string("committed")),
                ("kind", string(AccountRequestKind::PasswordChange.as_str())),
                ("operation_id", string(self.operation_id.to_string())),
                ("request_digest", b64(&self.request_digest)),
                ("account_id", string(self.account_id.to_string())),
                ("personal_vault_id", string(self.personal_vault_id.to_string())),
                ("device_id", string(self.device_id.to_string())),
                ("credential_generation", decimal(self.credential_generation)?),
            ],
            1_024,
        )
    }

    /// Bind every returned fact to the original protected bytes and Account signature.
    /// # Errors
    /// Rejects changed operation/Account/vault/Device identifiers, digest or new generation.
    pub fn validate_for_request(&self, payload: &[u8], signature: &[u8; 64]) -> Result<(), Error> {
        let p = AccountPasswordChangePayload::from_cbor(payload)?;
        let digest = AccountRequestSignatureInput::new(AccountRequestKind::PasswordChange, payload)
            .map_err(|_| Error::InvalidProtected)?
            .request_digest(signature);
        if self.operation_id != p.operation_id
            || self.account_id != p.account_id
            || self.personal_vault_id != p.personal_vault_id
            || self.device_id != p.device_id
            || self.request_digest != digest
            || self.credential_generation != p.new_credential_generation
        {
            return Err(Error::Binding);
        }
        Ok(())
    }
}
