// SPDX-License-Identifier: Apache-2.0
//! Exact version-one protected D-128 maps. No extensions are accepted here.

use std::collections::BTreeMap;

use scoplen_crypto::{
    AccountKemKeyWrap, AccountSigningKeyWrap, DeviceArkWrap, DeviceCertificate, PasswordArkWrap,
    PersonalVaultKeyWrap, RecoveryBlob, RevocationStatement, canonical_device_public_key,
    ed25519_verify, verify_device_list,
};
use scoplen_model::{
    cbor::{self, Value},
    validate_uuid_v7,
};
use uuid::Uuid;

use super::{AccountAdmissionCodecError as Error, validate_origin_username};
use crate::sync::SyncAccountKeyBundleUpdate;

/// Complete decoded registration payload bound by its additional Account signature.
#[derive(Clone, Eq, PartialEq)]
pub struct AccountRegistrationPayload {
    /// Deployment-unique stable operation identifier.
    pub operation_id: Uuid,
    /// Exact trusted canonical origin.
    pub origin: String,
    /// Exact canonical username.
    pub username: String,
    /// New Account identifier.
    pub account_id: Uuid,
    /// New Personal vault identifier.
    pub personal_vault_id: Uuid,
    /// New independently generated Device identifier.
    pub device_id: Uuid,
    /// Raw Account Ed25519 public root.
    pub account_signing_public_key: [u8; 32],
    /// Raw Account X25519 public root.
    pub account_kem_public_key: [u8; 32],
    /// Fresh client-generated credential salt.
    pub password_salt: [u8; 16],
    /// SHA-256 of the password `AuthSecret`, never the raw `AuthSecret`.
    pub verifier: [u8; 32],
    /// Exact D-127 version-one encrypted ARK.
    pub password_ark: [u8; 73],
    /// Original signed K-2 certificate bytes.
    pub device_certificate: Vec<u8>,
    /// Complete original signed revision-one K-4 PUT bytes.
    pub key_bundle: Vec<u8>,
    /// Exact D-108 Personal epoch-one wrapped key.
    pub personal_wrapped_key: [u8; 73],
}

/// One retained Personal epoch with an exact version-one wrap.
#[derive(Clone, Eq, PartialEq)]
pub struct AccountPersonalEpoch {
    /// Positive epoch number, strictly increasing in the enclosing array.
    pub epoch: u32,
    /// Exact D-108 Account/Personal-vault-bound encrypted epoch key.
    pub wrapped_key: [u8; 73],
}

/// Complete Personal key state, without Shared/Organization material.
#[derive(Clone, Eq, PartialEq)]
pub struct AccountPersonalBootstrap {
    /// Greatest included epoch, which must be present.
    pub current_epoch: u32,
    /// Pending rotation is represented faithfully and denied before admission.
    pub rotation_pending: bool,
    /// Every non-retired Personal epoch, at most 1,024.
    pub epochs: Vec<AccountPersonalEpoch>,
}

/// Complete encrypted bootstrap. Valid individual signatures do not establish freshness.
#[derive(Clone, Eq, PartialEq)]
pub struct AccountBootstrapSnapshot {
    /// Trusted canonical origin.
    pub origin: String,
    /// Requested canonical username.
    pub username: String,
    /// Account identifier anchored by the client after verified local opening.
    pub account_id: Uuid,
    /// Personal vault identifier.
    pub personal_vault_id: Uuid,
    /// Raw Account Ed25519 public root.
    pub account_signing_public_key: [u8; 32],
    /// Raw Account X25519 public root.
    pub account_kem_public_key: [u8; 32],
    /// Positive current credential generation.
    pub credential_generation: u64,
    /// D-127 salt bound to the requested options.
    pub password_salt: [u8; 16],
    /// Exact version-one D-127 password-wrapped ARK.
    pub password_ark: [u8; 73],
    /// Complete original signed K-4 update, including its signature and all wraps.
    pub key_bundle: Vec<u8>,
    /// Complete signed certificates, strictly ordered by their opaque bytes.
    pub certificates: Vec<Vec<u8>>,
    /// Complete signed revocations, strictly ordered by their opaque bytes.
    pub revocations: Vec<Vec<u8>>,
    /// Complete retained Personal epoch state.
    pub personal: AccountPersonalBootstrap,
}

/// Stable next-Device payload, separate from the raw single-use capability and fresh proof.
#[derive(Clone, Eq, PartialEq)]
pub struct AccountDeviceAdmissionPayload {
    /// Deployment-unique operation identifier.
    pub operation_id: Uuid,
    /// Exact trusted origin.
    pub origin: String,
    /// Account's canonical username.
    pub username: String,
    /// Capability-bound Account identifier.
    pub account_id: Uuid,
    /// Capability-bound Personal vault identifier.
    pub personal_vault_id: Uuid,
    /// Fresh Device identifier, never reused for an unresolved operation.
    pub device_id: Uuid,
    /// Positive snapshot-bound credential generation.
    pub credential_generation: u64,
    /// Domain-separated hash of the exact complete verified login snapshot.
    pub snapshot_digest: [u8; 32],
    /// SHA-256 of the raw admission token.
    pub capability_digest: [u8; 32],
    /// New root-signed certificate, unchanged from the original request.
    pub device_certificate: Vec<u8>,
    /// Complete signed K-4 update preserving every existing artifact/wrap byte.
    pub key_bundle: Vec<u8>,
}

macro_rules! redacted {
    ($($name:ty),+ $(,)?) => {$(impl std::fmt::Debug for $name {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(concat!(stringify!($name), "([REDACTED])"))
        }
    })+};
}
redacted!(
    AccountRegistrationPayload,
    AccountPersonalEpoch,
    AccountPersonalBootstrap,
    AccountBootstrapSnapshot,
    AccountDeviceAdmissionPayload
);

impl AccountRegistrationPayload {
    /// Validate syntax and all publicly verifiable creation bindings, without decrypting wraps.
    /// # Errors
    /// Rejects malformed artifacts, signatures, ids, profiles or initial bundle state.
    pub fn validate(&self) -> Result<(), Error> {
        validate_origin_username(&self.origin, &self.username)?;
        ids(&[self.operation_id, self.account_id, self.personal_vault_id, self.device_id])?;
        password_wrap(&self.password_ark)?;
        PersonalVaultKeyWrap::decode(&self.personal_wrapped_key)
            .map_err(|_| Error::InvalidProtected)?;
        let cert = certificate(
            &self.device_certificate,
            self.account_id,
            &self.account_signing_public_key,
        )?;
        if cert.device_id != self.device_id {
            return Err(Error::Binding);
        }
        distinct_device_keys(&cert)?;
        let bundle = signed_bundle(&self.key_bundle, &self.account_signing_public_key)?;
        if bundle.revision != 1
            || bundle.device_wraps.len() != 1
            || bundle.device_wraps[0].device_id != self.device_id
        {
            return Err(Error::Binding);
        }
        Ok(())
    }

    /// Encode the exact protected version-one map, including fixed generation/profile/epoch.
    /// # Errors
    /// Rejects invalid mutable fields or the complete 262,144-byte limit.
    pub fn to_cbor(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        encode(
            &map(vec![
                ("version", Value::UInt(1)),
                ("operation_id", id(self.operation_id)),
                ("origin", text(&self.origin)),
                ("username", text(&self.username)),
                ("account_id", id(self.account_id)),
                ("personal_vault_id", id(self.personal_vault_id)),
                ("device_id", id(self.device_id)),
                ("account_signing_public_key", bytes(&self.account_signing_public_key)),
                ("account_kem_public_key", bytes(&self.account_kem_public_key)),
                ("credential_generation", Value::UInt(1)),
                ("password_profile", Value::UInt(1)),
                ("password_salt", bytes(&self.password_salt)),
                ("verifier", bytes(&self.verifier)),
                ("password_ark", bytes(&self.password_ark)),
                ("device_certificate", bytes(&self.device_certificate)),
                ("key_bundle", bytes(&self.key_bundle)),
                ("personal_epoch", Value::UInt(1)),
                ("personal_wrapped_key", bytes(&self.personal_wrapped_key)),
            ]),
            super::MAX_ACCOUNT_REGISTRATION_PAYLOAD_BYTES,
        )
    }

    /// Decode exact deterministic CBOR, rejecting unknown fields, aliases and trailing bytes.
    /// # Errors
    /// Rejects syntax, bounds and publicly verifiable binding failures.
    pub fn from_cbor(input: &[u8]) -> Result<Self, Error> {
        let mut f = decode(input, super::MAX_ACCOUNT_REGISTRATION_PAYLOAD_BYTES)?;
        one(&mut f, "version")?;
        one(&mut f, "credential_generation")?;
        one(&mut f, "password_profile")?;
        one(&mut f, "personal_epoch")?;
        let value = Self {
            operation_id: uuid(&mut f, "operation_id")?,
            origin: string(&mut f, "origin")?,
            username: string(&mut f, "username")?,
            account_id: uuid(&mut f, "account_id")?,
            personal_vault_id: uuid(&mut f, "personal_vault_id")?,
            device_id: uuid(&mut f, "device_id")?,
            account_signing_public_key: fixed(&mut f, "account_signing_public_key")?,
            account_kem_public_key: fixed(&mut f, "account_kem_public_key")?,
            password_salt: fixed(&mut f, "password_salt")?,
            verifier: fixed(&mut f, "verifier")?,
            password_ark: fixed(&mut f, "password_ark")?,
            device_certificate: blob(&mut f, "device_certificate", 65_536)?,
            key_bundle: blob(&mut f, "key_bundle", 4_194_304)?,
            personal_wrapped_key: fixed(&mut f, "personal_wrapped_key")?,
        };
        empty(&f)?;
        value.validate()?;
        Ok(value)
    }
}

impl AccountBootstrapSnapshot {
    /// Check complete public signatures, recipient equality and all artifact/epoch bounds.
    ///
    /// Consumers additionally open all wraps, reconstruct roots, bind options and enforce anchors.
    /// # Errors
    /// Rejects malformed, incomplete, incorrectly signed or unsupported snapshot state.
    pub fn validate(&self) -> Result<(), Error> {
        validate_origin_username(&self.origin, &self.username)?;
        ids(&[self.account_id, self.personal_vault_id])?;
        if self.credential_generation == 0 {
            return Err(Error::InvalidProtected);
        }
        password_wrap(&self.password_ark)?;
        let bundle = signed_bundle(&self.key_bundle, &self.account_signing_public_key)?;
        let mut aggregate = 0_usize;
        for values in [&self.certificates, &self.revocations] {
            if values.len() > 65_536 {
                return Err(Error::TooLarge);
            }
            if values.windows(2).any(|p| p[0] >= p[1]) {
                return Err(Error::InvalidProtected);
            }
            for value in values {
                if value.is_empty() {
                    return Err(Error::InvalidProtected);
                }
                if value.len() > 65_536 {
                    return Err(Error::TooLarge);
                }
                aggregate = aggregate.checked_add(value.len()).ok_or(Error::TooLarge)?;
                if aggregate > 4_194_304 {
                    return Err(Error::TooLarge);
                }
            }
        }
        let certs = self
            .certificates
            .iter()
            .map(|b| certificate(b, self.account_id, &self.account_signing_public_key))
            .collect::<Result<Vec<_>, _>>()?;
        let revoked = self
            .revocations
            .iter()
            .map(|b| {
                preflight(b)?;
                RevocationStatement::decode(b).map_err(|_| Error::InvalidProtected)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let active = verify_device_list(&certs, &revoked, &self.account_signing_public_key)
            .map_err(|_| Error::Binding)?;
        if active.len() != bundle.device_wraps.len()
            || active.iter().zip(&bundle.device_wraps).any(|(c, w)| c.device_id != w.device_id)
        {
            return Err(Error::Binding);
        }
        if self.personal.epochs.is_empty()
            || self.personal.epochs.len() > 1_024
            || self.personal.current_epoch == 0
            || self.personal.epochs.last().map(|v| v.epoch) != Some(self.personal.current_epoch)
        {
            return Err(Error::InvalidProtected);
        }
        let mut previous = 0;
        for epoch in &self.personal.epochs {
            if epoch.epoch <= previous {
                return Err(Error::InvalidProtected);
            }
            PersonalVaultKeyWrap::decode(&epoch.wrapped_key)
                .map_err(|_| Error::InvalidProtected)?;
            previous = epoch.epoch;
        }
        Ok(())
    }

    /// Encode the complete snapshot with its original signed K-4 bytes.
    /// # Errors
    /// Rejects public validation failure or the complete nine-MiB decoded bound.
    pub fn to_cbor(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        encode(
            &map(vec![
                ("version", Value::UInt(1)),
                ("origin", text(&self.origin)),
                ("username", text(&self.username)),
                ("account_id", id(self.account_id)),
                ("personal_vault_id", id(self.personal_vault_id)),
                ("account_signing_public_key", bytes(&self.account_signing_public_key)),
                ("account_kem_public_key", bytes(&self.account_kem_public_key)),
                ("credential_generation", Value::UInt(self.credential_generation)),
                ("password_profile", Value::UInt(1)),
                ("password_salt", bytes(&self.password_salt)),
                ("password_ark", bytes(&self.password_ark)),
                ("key_bundle", bytes(&self.key_bundle)),
                (
                    "certificates",
                    Value::Array(self.certificates.iter().map(|v| bytes(v)).collect()),
                ),
                ("revocations", Value::Array(self.revocations.iter().map(|v| bytes(v)).collect())),
                (
                    "personal",
                    map(vec![
                        ("current_epoch", Value::UInt(u64::from(self.personal.current_epoch))),
                        ("rotation_pending", Value::Bool(self.personal.rotation_pending)),
                        (
                            "epochs",
                            Value::Array(
                                self.personal
                                    .epochs
                                    .iter()
                                    .map(|e| {
                                        map(vec![
                                            ("epoch", Value::UInt(u64::from(e.epoch))),
                                            ("wrapped_key", bytes(&e.wrapped_key)),
                                        ])
                                    })
                                    .collect(),
                            ),
                        ),
                    ]),
                ),
            ]),
            super::MAX_ACCOUNT_BOOTSTRAP_BYTES,
        )
    }

    /// Decode the exact complete snapshot; no protected extension is accepted.
    /// # Errors
    /// Rejects canonicality, bounds, signatures, recipient or epoch failures.
    pub fn from_cbor(input: &[u8]) -> Result<Self, Error> {
        let mut f = decode(input, super::MAX_ACCOUNT_BOOTSTRAP_BYTES)?;
        one(&mut f, "version")?;
        one(&mut f, "password_profile")?;
        let mut personal = fields(f.remove("personal").ok_or(Error::InvalidProtected)?)?;
        let current_epoch = u32::try_from(uint(&mut personal, "current_epoch")?)
            .map_err(|_| Error::InvalidProtected)?;
        let Some(Value::Bool(rotation_pending)) = personal.remove("rotation_pending") else {
            return Err(Error::InvalidProtected);
        };
        let Some(Value::Array(values)) = personal.remove("epochs") else {
            return Err(Error::InvalidProtected);
        };
        if values.is_empty() || values.len() > 1_024 {
            return Err(Error::TooLarge);
        }
        let epochs = values
            .into_iter()
            .map(|v| {
                let mut e = fields(v)?;
                let epoch = AccountPersonalEpoch {
                    epoch: u32::try_from(uint(&mut e, "epoch")?)
                        .map_err(|_| Error::InvalidProtected)?,
                    wrapped_key: fixed(&mut e, "wrapped_key")?,
                };
                empty(&e)?;
                Ok(epoch)
            })
            .collect::<Result<Vec<_>, Error>>()?;
        empty(&personal)?;
        let value = Self {
            origin: string(&mut f, "origin")?,
            username: string(&mut f, "username")?,
            account_id: uuid(&mut f, "account_id")?,
            personal_vault_id: uuid(&mut f, "personal_vault_id")?,
            account_signing_public_key: fixed(&mut f, "account_signing_public_key")?,
            account_kem_public_key: fixed(&mut f, "account_kem_public_key")?,
            credential_generation: uint(&mut f, "credential_generation")?,
            password_salt: fixed(&mut f, "password_salt")?,
            password_ark: fixed(&mut f, "password_ark")?,
            key_bundle: blob(&mut f, "key_bundle", 4_194_304)?,
            certificates: artifacts(&mut f, "certificates")?,
            revocations: artifacts(&mut f, "revocations")?,
            personal: AccountPersonalBootstrap { current_epoch, rotation_pending, epochs },
        };
        empty(&f)?;
        value.validate()?;
        Ok(value)
    }

    /// Reject unsupported pending rotation before deriving a new admission payload.
    /// # Errors
    /// Pending rotation is an explicit admission conflict, never a partial snapshot admission.
    pub fn validate_admission_state(&self) -> Result<(), Error> {
        self.validate()?;
        if self.personal.rotation_pending {
            return Err(Error::AdmissionConflict);
        }
        Ok(())
    }
}

impl AccountDeviceAdmissionPayload {
    /// Validate stable syntax and publicly checkable original artifact shapes.
    /// # Errors
    /// Rejects malformed identifiers, generation, certificate or bundle encoding.
    pub fn validate(&self) -> Result<(), Error> {
        validate_origin_username(&self.origin, &self.username)?;
        ids(&[self.operation_id, self.account_id, self.personal_vault_id, self.device_id])?;
        if self.credential_generation == 0 {
            return Err(Error::InvalidProtected);
        }
        if self.device_certificate.is_empty() || self.key_bundle.is_empty() {
            return Err(Error::InvalidProtected);
        }
        if self.device_certificate.len() > 65_536 || self.key_bundle.len() > 4_194_304 {
            return Err(Error::TooLarge);
        }
        preflight(&self.device_certificate)?;
        let cert = DeviceCertificate::decode(&self.device_certificate)
            .map_err(|_| Error::InvalidProtected)?;
        if cert.account_id != self.account_id || cert.device_id != self.device_id {
            return Err(Error::Binding);
        }
        distinct_device_keys(&cert)?;
        preflight(&self.key_bundle)?;
        SyncAccountKeyBundleUpdate::from_cbor(&self.key_bundle)
            .map_err(|_| Error::InvalidProtected)?;
        Ok(())
    }

    /// Bind one proposed admission to the exact verified current snapshot and raw capability.
    ///
    /// The durable consumer additionally checks all admission rows/receipts and transaction CAS.
    /// # Errors
    /// Rejects binding mismatch, stale snapshot, reused keys or any changed old artifact/wrap.
    pub fn validate_for_snapshot(
        &self,
        snapshot: &AccountBootstrapSnapshot,
        snapshot_bytes: &[u8],
        token: &[u8; 32],
    ) -> Result<(), Error> {
        self.validate()?;
        snapshot.validate_admission_state()?;
        if snapshot.to_cbor()? != snapshot_bytes
            || self.origin != snapshot.origin
            || self.username != snapshot.username
            || self.account_id != snapshot.account_id
            || self.personal_vault_id != snapshot.personal_vault_id
            || self.credential_generation != snapshot.credential_generation
            || self.snapshot_digest != scoplen_crypto::account_bootstrap_digest(snapshot_bytes)
            || self.capability_digest != scoplen_crypto::account_capability_digest(token)
        {
            return Err(Error::Binding);
        }
        let cert = certificate(
            &self.device_certificate,
            self.account_id,
            &snapshot.account_signing_public_key,
        )?;
        let new_keys = distinct_device_keys(&cert)?;
        for old in &snapshot.certificates {
            let old = DeviceCertificate::decode(old).map_err(|_| Error::InvalidProtected)?;
            if old.device_id == self.device_id {
                return Err(Error::AdmissionConflict);
            }
            let old_keys = distinct_device_keys(&old)?;
            if new_keys.iter().any(|k| old_keys.contains(k)) {
                return Err(Error::AdmissionConflict);
            }
        }
        for old in &snapshot.revocations {
            if RevocationStatement::decode(old).map_err(|_| Error::InvalidProtected)?.device_id
                == self.device_id
            {
                return Err(Error::AdmissionConflict);
            }
        }
        let old = signed_bundle(&snapshot.key_bundle, &snapshot.account_signing_public_key)?;
        let new = signed_bundle(&self.key_bundle, &snapshot.account_signing_public_key)?;
        if new.revision != old.revision.checked_add(1).ok_or(Error::AdmissionConflict)?
            || new.account_signing_key != old.account_signing_key
            || new.account_kem_key != old.account_kem_key
            || new.recovery_blob != old.recovery_blob
            || new.device_wraps.len() != old.device_wraps.len() + 1
        {
            return Err(Error::AdmissionConflict);
        }
        let retained: Vec<_> =
            new.device_wraps.iter().filter(|w| w.device_id != self.device_id).collect();
        if !new.device_wraps.iter().any(|w| w.device_id == self.device_id)
            || retained.iter().zip(&old.device_wraps).any(|(a, b)| *a != b)
        {
            return Err(Error::AdmissionConflict);
        }
        Ok(())
    }

    /// Encode exact retained protected admission bytes.
    /// # Errors
    /// Rejects invalid fields or the complete protected-payload bound.
    pub fn to_cbor(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        encode(
            &map(vec![
                ("version", Value::UInt(1)),
                ("operation_id", id(self.operation_id)),
                ("origin", text(&self.origin)),
                ("username", text(&self.username)),
                ("account_id", id(self.account_id)),
                ("personal_vault_id", id(self.personal_vault_id)),
                ("device_id", id(self.device_id)),
                ("credential_generation", Value::UInt(self.credential_generation)),
                ("snapshot_digest", bytes(&self.snapshot_digest)),
                ("capability_digest", bytes(&self.capability_digest)),
                ("device_certificate", bytes(&self.device_certificate)),
                ("key_bundle", bytes(&self.key_bundle)),
            ]),
            super::MAX_ACCOUNT_ADMISSION_PAYLOAD_BYTES,
        )
    }

    /// Decode exact canonical admission bytes without manufacturing current authorization.
    /// # Errors
    /// Rejects malformed, oversized, unknown or noncanonical protected fields.
    pub fn from_cbor(input: &[u8]) -> Result<Self, Error> {
        let mut f = decode(input, super::MAX_ACCOUNT_ADMISSION_PAYLOAD_BYTES)?;
        one(&mut f, "version")?;
        let value = Self {
            operation_id: uuid(&mut f, "operation_id")?,
            origin: string(&mut f, "origin")?,
            username: string(&mut f, "username")?,
            account_id: uuid(&mut f, "account_id")?,
            personal_vault_id: uuid(&mut f, "personal_vault_id")?,
            device_id: uuid(&mut f, "device_id")?,
            credential_generation: uint(&mut f, "credential_generation")?,
            snapshot_digest: fixed(&mut f, "snapshot_digest")?,
            capability_digest: fixed(&mut f, "capability_digest")?,
            device_certificate: blob(&mut f, "device_certificate", 65_536)?,
            key_bundle: blob(&mut f, "key_bundle", 4_194_304)?,
        };
        empty(&f)?;
        value.validate()?;
        Ok(value)
    }
}

fn password_wrap(bytes: &[u8; 73]) -> Result<(), Error> {
    PasswordArkWrap::decode(bytes).map(|_| ()).map_err(|_| Error::InvalidProtected)
}
fn ids(values: &[Uuid]) -> Result<(), Error> {
    for id in values {
        validate_uuid_v7(*id).map_err(|_| Error::InvalidProtected)?;
    }
    Ok(())
}
fn certificate(bytes: &[u8], account: Uuid, root: &[u8; 32]) -> Result<DeviceCertificate, Error> {
    if bytes.is_empty() {
        return Err(Error::InvalidProtected);
    }
    if bytes.len() > 65_536 {
        return Err(Error::TooLarge);
    }
    preflight(bytes)?;
    let value = DeviceCertificate::decode(bytes).map_err(|_| Error::InvalidProtected)?;
    if value.account_id != account {
        return Err(Error::Binding);
    }
    value.verify(root).map_err(|_| Error::Binding)?;
    Ok(value)
}
fn distinct_device_keys(cert: &DeviceCertificate) -> Result<[[u8; 65]; 2], Error> {
    let a = canonical_device_public_key(&cert.signing_public_key)
        .map_err(|_| Error::InvalidProtected)?;
    let b =
        canonical_device_public_key(&cert.kem_public_key).map_err(|_| Error::InvalidProtected)?;
    if a == b {
        return Err(Error::AdmissionConflict);
    }
    Ok([a, b])
}
fn signed_bundle(bytes: &[u8], root: &[u8; 32]) -> Result<SyncAccountKeyBundleUpdate, Error> {
    if bytes.is_empty() {
        return Err(Error::InvalidProtected);
    }
    if bytes.len() > 4_194_304 {
        return Err(Error::TooLarge);
    }
    preflight(bytes)?;
    let value =
        SyncAccountKeyBundleUpdate::from_cbor(bytes).map_err(|_| Error::InvalidProtected)?;
    ed25519_verify(
        root,
        &value.signature_input().map_err(|_| Error::InvalidProtected)?,
        &value.signature,
    )
    .map_err(|_| Error::Binding)?;
    AccountSigningKeyWrap::decode(&value.account_signing_key)
        .map_err(|_| Error::InvalidProtected)?;
    AccountKemKeyWrap::decode(&value.account_kem_key).map_err(|_| Error::InvalidProtected)?;
    RecoveryBlob::decode(&value.recovery_blob).map_err(|_| Error::InvalidProtected)?;
    for wrap in &value.device_wraps {
        DeviceArkWrap::decode(&wrap.wrapped_ark).map_err(|_| Error::InvalidProtected)?;
    }
    Ok(value)
}

type Fields = BTreeMap<String, Value>;
fn map(v: Vec<(&str, Value)>) -> Value {
    Value::Map(v.into_iter().map(|(k, v)| (text(k), v)).collect())
}
fn text(v: &str) -> Value {
    Value::Text(v.to_owned())
}
fn bytes(v: &[u8]) -> Value {
    Value::Bytes(v.to_vec())
}
fn id(v: Uuid) -> Value {
    bytes(v.as_bytes())
}
fn encode(value: &Value, limit: usize) -> Result<Vec<u8>, Error> {
    let b = cbor::encode(value).map_err(|_| Error::InvalidProtected)?;
    if b.len() > limit {
        return Err(Error::TooLarge);
    }
    Ok(b)
}
fn decode(input: &[u8], limit: usize) -> Result<Fields, Error> {
    if input.len() > limit {
        return Err(Error::TooLarge);
    }
    preflight(input)?;
    fields(cbor::decode(input).map_err(|_| Error::InvalidProtected)?)
}
fn fields(value: Value) -> Result<Fields, Error> {
    let Value::Map(v) = value else {
        return Err(Error::InvalidProtected);
    };
    v.into_iter()
        .map(|(k, v)| match k {
            Value::Text(k) => Ok((k, v)),
            _ => Err(Error::InvalidProtected),
        })
        .collect()
}
fn empty(f: &Fields) -> Result<(), Error> {
    if f.is_empty() { Ok(()) } else { Err(Error::InvalidProtected) }
}
fn uint(f: &mut Fields, key: &str) -> Result<u64, Error> {
    match f.remove(key) {
        Some(Value::UInt(v)) => Ok(v),
        _ => Err(Error::InvalidProtected),
    }
}
fn one(f: &mut Fields, key: &str) -> Result<(), Error> {
    if uint(f, key)? == 1 { Ok(()) } else { Err(Error::InvalidProtected) }
}
fn string(f: &mut Fields, key: &str) -> Result<String, Error> {
    match f.remove(key) {
        Some(Value::Text(v)) => Ok(v),
        _ => Err(Error::InvalidProtected),
    }
}
fn blob(f: &mut Fields, key: &str, limit: usize) -> Result<Vec<u8>, Error> {
    match f.remove(key) {
        Some(Value::Bytes(v)) if !v.is_empty() && v.len() <= limit => Ok(v),
        _ => Err(Error::InvalidProtected),
    }
}
fn fixed<const N: usize>(f: &mut Fields, key: &str) -> Result<[u8; N], Error> {
    blob(f, key, N)?.try_into().map_err(|_| Error::InvalidProtected)
}
fn uuid(f: &mut Fields, key: &str) -> Result<Uuid, Error> {
    let v = Uuid::from_bytes(fixed(f, key)?);
    ids(&[v])?;
    Ok(v)
}
fn artifacts(f: &mut Fields, key: &str) -> Result<Vec<Vec<u8>>, Error> {
    let Some(Value::Array(v)) = f.remove(key) else {
        return Err(Error::InvalidProtected);
    };
    if v.len() > 65_536 {
        return Err(Error::TooLarge);
    }
    v.into_iter()
        .map(|b| match b {
            Value::Bytes(b) if !b.is_empty() && b.len() <= 65_536 => Ok(b),
            _ => Err(Error::InvalidProtected),
        })
        .collect()
}

// This allocation-free pass rejects attacker-declared collection counts before the common
// deterministic decoder reserves vectors. Opaque K-4 bytes receive the same pass separately.
fn preflight(input: &[u8]) -> Result<(), Error> {
    struct Scan<'a> {
        bytes: &'a [u8],
        pos: usize,
        nodes: usize,
    }
    impl<'a> Scan<'a> {
        fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
            let end = self.pos.checked_add(n).ok_or(Error::TooLarge)?;
            let v = self.bytes.get(self.pos..end).ok_or(Error::InvalidProtected)?;
            self.pos = end;
            Ok(v)
        }
        fn argument(&mut self, additional: u8) -> Result<u64, Error> {
            match additional {
                0..=23 => Ok(u64::from(additional)),
                24 => Ok(u64::from(self.take(1)?[0])),
                25 => Ok(u64::from(u16::from_be_bytes(
                    self.take(2)?.try_into().map_err(|_| Error::InvalidProtected)?,
                ))),
                26 => Ok(u64::from(u32::from_be_bytes(
                    self.take(4)?.try_into().map_err(|_| Error::InvalidProtected)?,
                ))),
                27 => Ok(u64::from_be_bytes(
                    self.take(8)?.try_into().map_err(|_| Error::InvalidProtected)?,
                )),
                _ => Err(Error::InvalidProtected),
            }
        }
        fn value(&mut self, depth: usize, key: Option<&str>) -> Result<Option<&'a str>, Error> {
            self.nodes += 1;
            if depth > 6 || self.nodes > 200_000 {
                return Err(Error::TooLarge);
            }
            let first = self.take(1)?[0];
            let n = self.argument(first & 31)?;
            match first >> 5 {
                0 | 1 => Ok(None),
                2 | 3 => {
                    let b = self.take(usize::try_from(n).map_err(|_| Error::TooLarge)?)?;
                    if first >> 5 == 3 {
                        Ok(Some(std::str::from_utf8(b).map_err(|_| Error::InvalidProtected)?))
                    } else {
                        Ok(None)
                    }
                }
                4 => {
                    let limit = match key {
                        Some("epochs") => 1_024,
                        Some("device_wraps") => 1_000,
                        Some("certificates" | "revocations") => 65_536,
                        _ => 0,
                    };
                    if n > limit {
                        return Err(Error::TooLarge);
                    }
                    for _ in 0..n {
                        self.value(depth + 1, None)?;
                    }
                    Ok(None)
                }
                5 => {
                    if n > 20 {
                        return Err(Error::TooLarge);
                    }
                    for _ in 0..n {
                        let key = self.value(depth + 1, None)?;
                        self.value(depth + 1, key)?;
                    }
                    Ok(None)
                }
                7 if matches!(first, 0xf4..=0xf6) => Ok(None),
                _ => Err(Error::InvalidProtected),
            }
        }
    }
    let mut scan = Scan { bytes: input, pos: 0, nodes: 0 };
    scan.value(0, None)?;
    if scan.pos != input.len() {
        return Err(Error::InvalidProtected);
    }
    Ok(())
}
