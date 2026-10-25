// SPDX-License-Identifier: Apache-2.0
//! Cryptographic formats shared by Scoplen clients and services.
//!
//! Implementations are kept in this crate so callers do not compose primitives independently.

#![forbid(unsafe_code)]

mod account_request;
mod certificate;
mod device_access_token;
mod device_auth;
mod dpop;
mod envelope;
mod escrow;
mod gateway_proof;
mod gateway_ticket;
mod hierarchy;
mod hpke;
mod keys;
mod operator_access_token;
mod password_bootstrap;
mod primitives;
mod recovery;
mod secret;
mod shamir;
mod signature;

pub use account_request::{
    AccountProbeKey, AccountRequestError, AccountRequestIntent, AccountRequestKind,
    AccountRequestProof, AccountRequestSignatureInput, account_bootstrap_digest,
    account_capability_digest, canonical_device_public_key,
};
pub use certificate::{DeviceCertificate, RevocationStatement, verify_device_list};
pub use device_access_token::{
    DEVICE_ACCESS_TOKEN_LIFETIME_SECONDS, DeviceAccessToken, DeviceAccessTokenClaims,
    DeviceAccessTokenError, DeviceAccessTokenSigner, DeviceOrganizationSnapshot,
    MAX_DEVICE_ACCESS_TOKEN_BYTES, TrustedDeviceAccessTokenKeys, VerifiedDeviceAccessToken,
};
pub use device_auth::{
    DeviceAuthContext, DeviceAuthError, validate_origin as validate_server_origin,
};
pub use dpop::{
    DpopError, DpopProof, DpopTarget, DpopToken, VerifiedDpopProof, dpop_jwk_thumbprint,
};
pub use envelope::ObjectEnvelope;
pub use escrow::{
    escrow_account_context, escrow_device_context, escrow_verification_code,
    open_escrow_share_from_account, open_escrow_share_from_device, rewrap_escrow_share_to_device,
    verify_escrow_verification_code, wrap_escrow_share_to_account,
};
pub use gateway_proof::{GatewayProof, GatewayProofError, VerifiedGatewayProof};
pub use gateway_ticket::{
    GatewayTicket, GatewayTicketClaims, GatewayTicketError, GatewayTicketSigner,
    TrustedGatewayTicketKeys, VerifiedGatewayTicket, gateway_ssh_key_sha256,
};
pub use hierarchy::{
    AccountKemKeyWrap, AccountSigningKeyWrap, DeviceArkWrap, PersonalVaultKeyWrap,
};
pub use hpke::{
    AccountKemKeyPair, DeviceKemKeyPair, HpkeCiphertext, hpke_open_account, hpke_open_device,
    hpke_seal_account, hpke_seal_device,
};
pub use keys::{
    AccountKeys, AccountRootKey, DeviceKeys, LocalDatabaseKey, LocalDatabaseKeyEnvelope, VaultKey,
    VaultKeyEpoch, generate_account_keys, generate_device_keys, generate_symmetric_key,
    generate_vault_epoch, unwrap_key_from_device, wrap_key_to_device,
};
pub use operator_access_token::{
    MAX_OPERATOR_ACCESS_TOKEN_BYTES, OPERATOR_ACCESS_TOKEN_LIFETIME_SECONDS, OperatorAccessToken,
    OperatorAccessTokenClaims, OperatorAccessTokenError, OperatorAccessTokenSigner,
    TrustedOperatorAccessTokenKeys, VerifiedOperatorAccessToken,
};
pub use password_bootstrap::{
    PASSWORD_ARK_WRAP_BYTES, PASSWORD_BOOTSTRAP_PROFILE, PasswordArkWrap, PasswordBootstrap,
    PasswordBootstrapContext, PasswordBootstrapError, PasswordKdfContext, PasswordSecrets,
    PasswordVerifier, normalize_account_password,
};
pub use primitives::{
    ARGON2_MEMORY_KIB, ARGON2_PARALLELISM, ARGON2_TIME_COST, Argon2idParams, PrimitiveError,
    argon2id_derive, argon2id_derive_with_params, hkdf_sha256, random_bytes, random_key,
    random_nonce, xchacha20poly1305_open, xchacha20poly1305_seal,
};
pub use recovery::{RecoveryBlob, RecoveryKey};
pub use recovery::{safety_fingerprint, safety_number, safety_qr, verify_safety_qr};
pub use secret::{SecretBytes, SecretVec, SymmetricKey, XChaChaNonce};
pub use shamir::{ShamirShare, combine_shamir, split_shamir, split_shamir_with_randomness};
pub use signature::{
    DeviceSigner, Ed25519SigningKey, P256SigningKey, ed25519_verify, generate_ed25519_signing_key,
    generate_p256_signing_key, p256_verify,
};

/// The contract identifier implemented by this crate.
pub const CONTRACT: &str = "K-2";
