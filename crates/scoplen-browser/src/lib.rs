// SPDX-License-Identifier: Apache-2.0
//! Pure browser capabilities over the existing native contracts, without network transport.
//!
//! These helpers establish syntax and cryptographic bytes, never current Account/team authority.
//! No bootstrap opening, Personal keys, Device identity or SSH execution is exposed.

#![forbid(unsafe_code)]

use scoplen_api::{group_policy::SimpleRuleInput, organization::OrganizationCodecError};
use scoplen_crypto::{
    PasswordBootstrapError, PasswordKdfContext, SecretBytes, SecretVec, TeamInvitationError,
    TeamInvitationPassword, TeamInvitationVerifier, validate_server_origin,
};
use scoplen_model::validate_uuid_v7;
use uuid::Uuid;

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
mod wasm;

/// Derive only D-127's authentication secret, dropping its private KEK inside Rust.
///
/// # Errors
/// Rejects malformed context/profile/password or fixed-profile resource failure, without fallback.
pub fn password_auth(
    origin: &str,
    username: &str,
    profile: u8,
    salt: &[u8],
    password: SecretVec,
) -> Result<SecretBytes<32>, PasswordBootstrapError> {
    let secrets = PasswordKdfContext::new(origin, username, profile, salt)?.derive(password)?;
    Ok(secrets.auth_secret().clone())
}

/// Generated invitation material for one explicit transient creation operation.
#[derive(Debug)]
pub struct InvitationSecrets {
    password: TeamInvitationPassword,
    verifier: TeamInvitationVerifier,
}

impl InvitationSecrets {
    /// Borrow only for the dedicated in-memory invitation operation and deliberate reveal/copy.
    #[must_use]
    pub const fn password(&self) -> &TeamInvitationPassword {
        &self.password
    }

    /// Borrow only for the captured invitation request, never general application state/logs.
    #[must_use]
    pub const fn verifier(&self) -> &TeamInvitationVerifier {
        &self.verifier
    }
}

/// Generate the existing D-136 password and its exact context-bound verifier.
///
/// # Errors
/// Rejects noncanonical origin/UUIDv7 context or unavailable CSPRNG, with no random fallback.
pub fn create_team_invitation(
    origin: &str,
    organization: &str,
    invitation: &str,
) -> Result<InvitationSecrets, TeamInvitationError> {
    validate_server_origin(origin).map_err(|_| TeamInvitationError::InvalidContext)?;
    let organization = canonical_uuid(organization)?;
    let invitation = canonical_uuid(invitation)?;
    let password = TeamInvitationPassword::generate()?;
    let verifier = password.verifier(origin, &organization, &invitation)?;
    Ok(InvitationSecrets { password, verifier })
}

/// Parse the existing exact uppercase eight-symbol password from owned secret bytes.
///
/// # Errors
/// Rejects every noncanonical length/alphabet; no trimming, aliases or case folding.
pub fn parse_team_invitation(
    password: SecretVec,
) -> Result<TeamInvitationPassword, TeamInvitationError> {
    let parsed = TeamInvitationPassword::parse(password.as_bytes());
    drop(password);
    parsed
}

/// Compute the existing D-136 verifier for one canonical captured invitation context.
///
/// # Errors
/// Rejects noncanonical context/password. This grants no membership or Account authentication.
pub fn team_invitation_verifier(
    origin: &str,
    organization: &str,
    invitation: &str,
    password: SecretVec,
) -> Result<TeamInvitationVerifier, TeamInvitationError> {
    let organization = canonical_uuid(organization)?;
    let invitation = canonical_uuid(invitation)?;
    parse_team_invitation(password)?.verifier(origin, &organization, &invitation)
}

/// Run the shared strict D-137 parser and pure generator, including schema/reference checks.
///
/// # Errors
/// Rejects malformed/bounded input or invalid generated source. Preview grants no authority.
pub fn simple_rule(input: &[u8]) -> Result<String, OrganizationCodecError> {
    SimpleRuleInput::from_json(input)?.generate()
}

fn canonical_uuid(text: &str) -> Result<Uuid, TeamInvitationError> {
    let id = Uuid::parse_str(text).map_err(|_| TeamInvitationError::InvalidContext)?;
    if id.to_string() != text || validate_uuid_v7(id).is_err() {
        return Err(TeamInvitationError::InvalidContext);
    }
    Ok(id)
}
