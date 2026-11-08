// SPDX-License-Identifier: Apache-2.0
//! Bindings copy secrets directly from zeroizing Rust owners into explicit JS byte buffers.

use js_sys::Uint8Array;
use scoplen_crypto::{PASSWORD_BOOTSTRAP_PROFILE, PasswordBootstrapError, SecretVec};
use wasm_bindgen::{JsValue, prelude::wasm_bindgen};

fn output(buffer: &Uint8Array, length: u32) -> Result<(), JsValue> {
    if buffer.length() != length {
        return Err(JsValue::from_str("invalid output buffer length"));
    }
    let _ = buffer.fill(0, 0, length);
    Ok(())
}

/// The Worker owns and erases both JS byte buffers; no raw secret Vec is returned through the ABI.
///
/// # Errors
/// Rejects the output width or any shared fixed-profile derivation failure.
#[wasm_bindgen(js_name = derivePasswordAuth)]
pub fn password_auth(
    origin: &str,
    username: &str,
    profile: f64,
    salt: &[u8],
    password: Vec<u8>,
    auth_output: &Uint8Array,
) -> Result<(), JsValue> {
    let password = SecretVec::new(password);
    output(auth_output, 32)?;
    if profile.to_bits() != f64::from(PASSWORD_BOOTSTRAP_PROFILE).to_bits() {
        return Err(JsValue::from_str(&PasswordBootstrapError::UnsupportedProfile.to_string()));
    }
    let auth = super::password_auth(origin, username, PASSWORD_BOOTSTRAP_PROFILE, salt, password)
        .map_err(|error| JsValue::from_str(&error.to_string()))?;
    auth_output.copy_from(auth.as_bytes());
    Ok(())
}

/// Generate the shared invitation password/verifier into the dedicated operation's buffers.
///
/// # Errors
/// Rejects output widths, noncanonical context or a failed CSPRNG without fallback.
#[wasm_bindgen(js_name = generateTeamInvitation)]
pub fn create_team_invitation(
    origin: &str,
    organization: &str,
    invitation: &str,
    password_output: &Uint8Array,
    verifier_output: &Uint8Array,
) -> Result<(), JsValue> {
    output(password_output, 8)?;
    output(verifier_output, 32)?;
    let secrets = super::create_team_invitation(origin, organization, invitation)
        .map_err(|error| JsValue::from_str(&error.to_string()))?;
    password_output.copy_from(secrets.password().as_bytes());
    verifier_output.copy_from(secrets.verifier().as_bytes());
    Ok(())
}

/// Validate an owned invitation password without returning or normalizing it.
///
/// # Errors
/// Rejects any noncanonical invitation password.
#[wasm_bindgen(js_name = parseTeamInvitationPassword)]
pub fn parse_team_invitation(password: Vec<u8>) -> Result<(), JsValue> {
    super::parse_team_invitation(SecretVec::new(password))
        .map(drop)
        .map_err(|error| JsValue::from_str(&error.to_string()))
}

/// Copy only the exact shared invitation verifier to the captured operation's buffer.
///
/// # Errors
/// Rejects the output width or invalid password/context.
#[wasm_bindgen(js_name = teamInvitationVerifier)]
pub fn team_invitation_verifier(
    origin: &str,
    organization: &str,
    invitation: &str,
    password: Vec<u8>,
    verifier_output: &Uint8Array,
) -> Result<(), JsValue> {
    let password = SecretVec::new(password);
    output(verifier_output, 32)?;
    let verifier = super::team_invitation_verifier(origin, organization, invitation, password)
        .map_err(|error| JsValue::from_str(&error.to_string()))?;
    verifier_output.copy_from(verifier.as_bytes());
    Ok(())
}

/// Generate and strictly validate the existing shared simple-rule source.
///
/// # Errors
/// Rejects invalid input or shared schema/reference validation failure.
#[wasm_bindgen(js_name = generateSimpleRule)]
pub fn simple_rule(input: &[u8]) -> Result<String, JsValue> {
    super::simple_rule(input).map_err(|error| JsValue::from_str(&error.to_string()))
}
