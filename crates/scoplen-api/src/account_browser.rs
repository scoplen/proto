// SPDX-License-Identifier: Apache-2.0
//! D-140 bounded Account-browser wire. Parsing establishes no authenticated identity.
//!
//! Current Account/family, proof, credential generation, admission, transaction and audit
//! checks remain consumer duties. This profile never supplies a Device or Personal keys.

use std::fmt;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use scoplen_crypto::SecretVec;
use sha2::{Digest as _, Sha256};

use crate::{
    account_admission::{
        AccountPasswordLoginRequest, AccountPasswordOptionsRequest, AccountPasswordOptionsResponse,
    },
    auth::{BrowserAuthRefreshRequest, BrowserAuthTokenResponse},
    operator_auth::{OperatorLogoutRequest, OperatorLogoutResponse},
    request_wire::{clear_json_value, decode_unique_object},
};

mod scope;
pub use scope::*;
pub mod reference;

/// Exact access-record lifetime, in seconds.
pub const ACCOUNT_BROWSER_ACCESS_SECONDS: u64 = 600;
/// Absolute family lifetime from the original login, in seconds.
pub const ACCOUNT_BROWSER_FAMILY_SECONDS: u64 = 2_592_000;
/// Cookie name independent of the Operator refresh cookie.
pub const ACCOUNT_BROWSER_REFRESH_COOKIE: &str = "__Secure-spl-account-refresh";
/// The refresh cookie's only permitted path.
pub const ACCOUNT_BROWSER_REFRESH_PATH: &str = "/api/v1/auth/accounts/browser/refresh";

/// Fetch credential mode fixed by the endpoint, independent of caller preference.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccountBrowserFetchCredentials {
    /// Do not send browser cookies.
    Omit,
    /// Allow only same-origin cookie receipt/rotation.
    SameOrigin,
}

/// Content-free lexical, bounds and HTTP metadata errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum AccountBrowserCodecError {
    /// Complete encoded input exceeds its endpoint bound.
    #[error("Account browser message exceeds its bound")]
    TooLarge,
    /// Malformed, duplicate, forbidden or noncanonical fields.
    #[error("invalid Account browser message")]
    Invalid,
    /// Unsupported JSON/content encoding.
    #[error("unsupported Account browser media type")]
    MediaType,
    /// Missing, mixed or forbidden HTTP metadata.
    #[error("invalid Account browser HTTP metadata")]
    HttpMetadata,
    /// Missing or incorrect trusted Origin.
    #[error("Account browser origin denied")]
    OriginDenied,
}

/// The four exact same-origin authentication endpoints; never native entry routes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccountBrowserOperation {
    /// Fixed-profile, browser-purpose password attempt.
    PasswordOptions,
    /// Password verification followed only by browser-session creation.
    PasswordLogin,
    /// Cookie-only, single-use browser refresh.
    Refresh,
    /// Explicit current-family terminal confirmation.
    Logout,
}

impl AccountBrowserOperation {
    /// Every endpoint in the profile.
    pub const ALL: [Self; 4] =
        [Self::PasswordOptions, Self::PasswordLogin, Self::Refresh, Self::Logout];

    /// Exact canonical path; HTTP adapters accept only POST.
    #[must_use]
    pub const fn route(self) -> &'static str {
        match self {
            Self::PasswordOptions => "/api/v1/auth/accounts/browser/password/options",
            Self::PasswordLogin => "/api/v1/auth/accounts/browser/password/login",
            Self::Refresh => ACCOUNT_BROWSER_REFRESH_PATH,
            Self::Logout => "/api/v1/auth/accounts/browser/logout",
        }
    }

    /// Match exact router-owned method/path, with no aliases or query normalization.
    #[must_use]
    pub fn from_route(method: &str, path: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|operation| method == "POST" && operation.route() == path)
    }

    /// Complete request/response limits, including extensions and whitespace.
    #[must_use]
    pub const fn body_limits(self) -> (usize, usize) {
        match self {
            Self::PasswordOptions => (256, 1_024),
            Self::PasswordLogin => (512, 8_192),
            Self::Refresh => (256, 8_192),
            Self::Logout => (256, 256),
        }
    }

    /// Browser credential carriage for the exact endpoint.
    #[must_use]
    pub const fn fetch_credentials(self) -> AccountBrowserFetchCredentials {
        match self {
            Self::PasswordOptions | Self::Logout => AccountBrowserFetchCredentials::Omit,
            Self::PasswordLogin | Self::Refresh => AccountBrowserFetchCredentials::SameOrigin,
        }
    }
}

/// Construct only this profile's scoped cookie after a confirmed login/refresh commit.
/// # Errors
/// Rejects zero/overlong remaining absolute family lifetime. This creates no session authority.
pub fn account_browser_refresh_cookie(
    token: &AccountBrowserRefreshToken,
    remaining_seconds: u64,
) -> Result<SecretVec, AccountBrowserCodecError> {
    if !(1..=ACCOUNT_BROWSER_FAMILY_SECONDS).contains(&remaining_seconds) {
        return Err(AccountBrowserCodecError::Invalid);
    }
    Ok(SecretVec::new(format!("{ACCOUNT_BROWSER_REFRESH_COOKIE}={}; Path={ACCOUNT_BROWSER_REFRESH_PATH}; HttpOnly; Secure; SameSite=Strict; Max-Age={remaining_seconds}", token.as_str()).into_bytes()))
}

macro_rules! opaque_token {
    ($name:ident, $prefix:literal, $domain:literal) => {
        /// Redacting, zeroizing opaque credential. Lexical acceptance grants no authority.
        #[derive(Clone, Eq, PartialEq)]
        pub struct $name(SecretVec);

        impl $name {
            /// Parse exactly 47 ASCII bytes, with canonical base64url of 32 bytes.
            /// # Errors
            /// Rejects alternate profiles, padding, noncanonical tail bits and wrong lengths.
            pub fn parse(value: &str) -> Result<Self, AccountBrowserCodecError> {
                let encoded =
                    value.strip_prefix($prefix).ok_or(AccountBrowserCodecError::Invalid)?;
                if value.len() != 47 {
                    return Err(AccountBrowserCodecError::Invalid);
                }
                let bytes = SecretVec::new(
                    URL_SAFE_NO_PAD
                        .decode(encoded)
                        .map_err(|_| AccountBrowserCodecError::Invalid)?,
                );
                if bytes.as_bytes().len() != 32
                    || URL_SAFE_NO_PAD.encode(bytes.as_bytes()) != encoded
                {
                    return Err(AccountBrowserCodecError::Invalid);
                }
                Ok(Self(SecretVec::new(value.as_bytes().to_vec())))
            }

            /// Encode caller-supplied independent OS-random bytes; this function generates no entropy.
            #[must_use]
            pub fn from_random_bytes(bytes: &[u8; 32]) -> Self {
                Self(SecretVec::new(
                    format!("{}{}", $prefix, URL_SAFE_NO_PAD.encode(bytes)).into_bytes(),
                ))
            }

            /// Borrow the exact credential only for its explicit transport/proof operation.
            #[must_use]
            pub fn as_str(&self) -> &str {
                std::str::from_utf8(self.0.as_bytes()).expect("validated ASCII credential")
            }

            /// Domain-separated digest over the complete ASCII token, including its prefix.
            #[must_use]
            pub fn digest(&self) -> [u8; 32] {
                Sha256::new()
                    .chain_update($domain)
                    .chain_update([0])
                    .chain_update(self.0.as_bytes())
                    .finalize()
                    .into()
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($name), "([REDACTED])"))
            }
        }
    };
}

opaque_token!(AccountBrowserAccessToken, "ab1_", b"spl-account-browser-access-v1");
opaque_token!(AccountBrowserRefreshToken, "ar1_", b"spl-account-browser-refresh-v1");

/// Endpoint-specific options wrapper over the single shared password request shape.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccountBrowserPasswordOptionsRequest(pub AccountPasswordOptionsRequest);
/// Endpoint-specific options wrapper over the single shared profile-one response shape.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccountBrowserPasswordOptionsResponse(pub AccountPasswordOptionsResponse);
/// Endpoint-specific login wrapper; contains only one attempt and transient `AuthSecret`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccountBrowserPasswordLoginRequest(pub AccountPasswordLoginRequest);
/// Initial session response wrapper; refresh credentials never appear in JSON.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccountBrowserPasswordLoginResponse(pub BrowserAuthTokenResponse);
/// Strict 256-byte empty refresh request, separate from the generic refresh parser.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AccountBrowserRefreshRequest;
/// Rotated session response with a positive, bounded remaining family lifetime.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccountBrowserRefreshResponse(pub BrowserAuthTokenResponse);
/// Separate Account-browser empty logout request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AccountBrowserLogoutRequest;
/// Separate Account-browser true-only terminal logout confirmation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AccountBrowserLogoutResponse;

macro_rules! reused_codec {
    ($name:ident, $inner:ty, $limit:literal, $output:ty) => {
        impl $name {
            /// Decode complete bounded UTF-8 JSON, checking recursive duplicates first.
            /// # Errors
            /// Rejects exceeded bounds, invalid JSON or invalid shared fields.
            pub fn from_json(input: &[u8]) -> Result<Self, AccountBrowserCodecError> {
                check_object(input, $limit, false)?;
                <$inner>::from_json(input).map(Self).map_err(|_| AccountBrowserCodecError::Invalid)
            }
            /// Encode through the existing shared codec.
            /// # Errors
            /// Rejects invalid fields or complete-body overflow.
            pub fn to_json(&self) -> Result<$output, AccountBrowserCodecError> {
                self.0.to_json().map_err(|_| AccountBrowserCodecError::Invalid)
            }
        }
    };
}

reused_codec!(AccountBrowserPasswordOptionsRequest, AccountPasswordOptionsRequest, 256, Vec<u8>);
reused_codec!(AccountBrowserPasswordOptionsResponse, AccountPasswordOptionsResponse, 1024, Vec<u8>);
reused_codec!(AccountBrowserPasswordLoginRequest, AccountPasswordLoginRequest, 512, SecretVec);

macro_rules! session_codec {
    ($name:ident, $initial:literal) => {
        impl $name {
            /// Decode the existing browser shape under D-140 bounds/profile and native-field bans.
            /// # Errors
            /// Rejects duplicate/forbidden fields, wrong opaque token or incorrect lifetimes.
            pub fn from_json(input: &[u8]) -> Result<Self, AccountBrowserCodecError> {
                check_object(input, 8192, true)?;
                let text =
                    std::str::from_utf8(input).map_err(|_| AccountBrowserCodecError::Invalid)?;
                let response = BrowserAuthTokenResponse::from_json(text)
                    .map_err(|_| AccountBrowserCodecError::Invalid)?;
                validate_session(&response, $initial)?;
                Ok(Self(response))
            }
            /// Encode only the existing four fields after validating the endpoint profile.
            /// # Errors
            /// Rejects invalid fields or lifetimes.
            pub fn to_json(&self) -> Result<Vec<u8>, AccountBrowserCodecError> {
                validate_session(&self.0, $initial)?;
                self.0
                    .to_json()
                    .map(String::into_bytes)
                    .map_err(|_| AccountBrowserCodecError::Invalid)
            }
        }
    };
}
session_codec!(AccountBrowserPasswordLoginResponse, true);
session_codec!(AccountBrowserRefreshResponse, false);

fn validate_session(
    response: &BrowserAuthTokenResponse,
    initial: bool,
) -> Result<(), AccountBrowserCodecError> {
    response.validate().map_err(|_| AccountBrowserCodecError::Invalid)?;
    AccountBrowserAccessToken::parse(&response.access_token)?;
    if response.expires_in != ACCOUNT_BROWSER_ACCESS_SECONDS
        || response.refresh_expires_in > ACCOUNT_BROWSER_FAMILY_SECONDS
        || (initial && response.refresh_expires_in != ACCOUNT_BROWSER_FAMILY_SECONDS)
    {
        return Err(AccountBrowserCodecError::Invalid);
    }
    Ok(())
}

fn check_object(input: &[u8], limit: usize, session: bool) -> Result<(), AccountBrowserCodecError> {
    if input.len() > limit {
        return Err(AccountBrowserCodecError::TooLarge);
    }
    let fields = decode_unique_object(input).map_err(|()| AccountBrowserCodecError::Invalid)?;
    let forbidden = session
        && ["refresh_token", "admission_token", "snapshot"]
            .iter()
            .any(|name| fields.contains_key(*name));
    clear_json_value(serde_json::Value::Object(fields));
    if forbidden {
        return Err(AccountBrowserCodecError::Invalid);
    }
    Ok(())
}

impl AccountBrowserRefreshRequest {
    /// Decode exactly the bounded empty request with recursive duplicate checks.
    /// # Errors
    /// Rejects invalid, nonempty or oversized input.
    pub fn from_json(input: &[u8]) -> Result<Self, AccountBrowserCodecError> {
        check_object(input, 256, false)?;
        let text = std::str::from_utf8(input).map_err(|_| AccountBrowserCodecError::Invalid)?;
        BrowserAuthRefreshRequest::from_json(text)
            .map_err(|_| AccountBrowserCodecError::Invalid)?;
        Ok(Self)
    }
    /// Exact empty request; no cookie/token is carried in JSON.
    #[must_use]
    pub const fn to_json(self) -> &'static [u8] {
        b"{}"
    }
}
impl AccountBrowserLogoutRequest {
    /// Decode the existing D-124 exact empty request under the separate browser name.
    /// # Errors
    /// Rejects invalid, nonempty or oversized input.
    pub fn from_json(input: &[u8]) -> Result<Self, AccountBrowserCodecError> {
        check_object(input, 256, false)?;
        OperatorLogoutRequest::from_json(input).map_err(|_| AccountBrowserCodecError::Invalid)?;
        Ok(Self)
    }
    /// Exact empty request.
    #[must_use]
    pub const fn to_json(self) -> &'static [u8] {
        b"{}"
    }
}
impl AccountBrowserLogoutResponse {
    /// Decode only D-124's true-only response, with no response extensions.
    /// # Errors
    /// Rejects missing, false, extra, duplicate or oversized fields.
    pub fn from_json(input: &[u8]) -> Result<Self, AccountBrowserCodecError> {
        check_object(input, 256, false)?;
        OperatorLogoutResponse::from_json(input).map_err(|_| AccountBrowserCodecError::Invalid)?;
        Ok(Self)
    }
    /// Exact terminal confirmation; this supplies no current-session authority.
    #[must_use]
    pub const fn to_json(self) -> &'static [u8] {
        b"{\"revoked\":true}"
    }
}

/// Authentication metadata after the HTTP adapter rejects duplicate headers.
#[derive(Clone, Copy, Default)]
#[allow(clippy::struct_excessive_bools)]
pub struct AccountBrowserHttpMetadata<'a> {
    /// Exact JSON media type, optionally one UTF-8 charset.
    pub content_type: &'a str,
    /// Absent or identity encoding only.
    pub content_encoding: Option<&'a str>,
    /// Required exact trusted origin for all four endpoints.
    pub origin: Option<&'a str>,
    /// One bounded `DPoP` header; cryptographic proof/ath validation is separate.
    pub dpop: Option<&'a str>,
    /// Only logout accepts an Authorization header, with an opaque access token.
    pub authorization: Option<&'a str>,
    /// Exact Account refresh-cookie count; password/logout ignore all cookies.
    pub refresh_cookie_count: usize,
    /// Refresh rejects mixed native/Operator authentication credentials.
    pub has_other_refresh_credentials: bool,
    /// Presence includes an empty query suffix.
    pub has_query: bool,
    /// Not used for authentication or retry receipts.
    pub has_if_match: bool,
    /// Authentication responses are never replayable receipts.
    pub has_idempotency_key: bool,
}

impl fmt::Debug for AccountBrowserHttpMetadata<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("AccountBrowserHttpMetadata").finish_non_exhaustive()
    }
}

impl AccountBrowserHttpMetadata<'_> {
    /// Validate transport shape without treating headers or cookie counts as authentication.
    /// # Errors
    /// Rejects forbidden media, missing/excessive proof, Origin or mixed credential profiles.
    pub fn validate(
        self,
        operation: AccountBrowserOperation,
        trusted_origin: &str,
    ) -> Result<(), AccountBrowserCodecError> {
        scoplen_crypto::validate_server_origin(trusted_origin)
            .map_err(|_| AccountBrowserCodecError::OriginDenied)?;
        if self.origin != Some(trusted_origin) {
            return Err(AccountBrowserCodecError::OriginDenied);
        }
        if !matches!(self.content_type, "application/json" | "application/json; charset=utf-8")
            || !matches!(self.content_encoding, None | Some("identity"))
        {
            return Err(AccountBrowserCodecError::MediaType);
        }
        if self.has_query
            || self.has_if_match
            || self.has_idempotency_key
            || !self.dpop.is_some_and(|proof| {
                !proof.is_empty()
                    && proof.len() <= 8192
                    && proof.is_ascii()
                    && !proof.bytes().any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
            })
        {
            return Err(AccountBrowserCodecError::HttpMetadata);
        }
        match operation {
            AccountBrowserOperation::Logout => {
                let value = self
                    .authorization
                    .and_then(|value| value.strip_prefix("DPoP "))
                    .ok_or(AccountBrowserCodecError::HttpMetadata)?;
                AccountBrowserAccessToken::parse(value)?;
            }
            _ if self.authorization.is_some() => {
                return Err(AccountBrowserCodecError::HttpMetadata);
            }
            AccountBrowserOperation::Refresh
                if self.refresh_cookie_count != 1 || self.has_other_refresh_credentials =>
            {
                return Err(AccountBrowserCodecError::HttpMetadata);
            }
            _ => {}
        }
        Ok(())
    }
}

/// Protected business metadata; cookies never select this principal and are ignored.
#[derive(Clone, Copy, Default)]
pub struct AccountBrowserProtectedHttpMetadata<'a> {
    /// Exact opaque access Authorization; no Device/Operator/native capability fallback.
    pub authorization: &'a str,
    /// One bounded proof; the consumer verifies its signature, JKT, ath and replay separately.
    pub dpop: &'a str,
    /// Every supplied Origin must match; mutations require one, same-origin GET may omit it.
    pub origin: Option<&'a str>,
}

impl fmt::Debug for AccountBrowserProtectedHttpMetadata<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("AccountBrowserProtectedHttpMetadata").finish_non_exhaustive()
    }
}

impl AccountBrowserProtectedHttpMetadata<'_> {
    /// Validate the registered browser operation's lexical metadata before identity lookup.
    /// The adapter rejects duplicate headers and uses credentials=omit for every business fetch.
    /// # Errors
    /// Rejects wrong credential profile, missing/excessive proof or absent/mismatched Origin.
    pub fn validate(
        self,
        operation: AccountBrowserAccessOperation,
        trusted_origin: &str,
    ) -> Result<AccountBrowserAccessToken, AccountBrowserCodecError> {
        scoplen_crypto::validate_server_origin(trusted_origin)
            .map_err(|_| AccountBrowserCodecError::OriginDenied)?;
        if self.origin.is_some_and(|origin| origin != trusted_origin)
            || (operation.http_method() != "GET" && self.origin != Some(trusted_origin))
        {
            return Err(AccountBrowserCodecError::OriginDenied);
        }
        if self.dpop.is_empty()
            || self.dpop.len() > 8192
            || !self.dpop.is_ascii()
            || self.dpop.bytes().any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
        {
            return Err(AccountBrowserCodecError::HttpMetadata);
        }
        AccountBrowserAccessToken::parse(
            self.authorization
                .strip_prefix("DPoP ")
                .ok_or(AccountBrowserCodecError::HttpMetadata)?,
        )
    }
}
