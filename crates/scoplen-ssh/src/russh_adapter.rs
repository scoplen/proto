// SPDX-License-Identifier: Apache-2.0
//! Concrete SSH client integration backed by `russh`.
//!
//! This module is the first concrete S4 slice.  It owns the `russh` event loop and translates its
//! connection and channel handles into an opaque API for the rest of Scoplen.  No `russh` type is
//! part of the public surface, so the engine can be replaced without changing consumers.

#![allow(clippy::missing_errors_doc, clippy::missing_panics_doc)]

use std::{
    borrow::Cow,
    ffi::{OsStr, OsString},
    fmt,
    future::Future,
    io,
    net::{Shutdown, TcpStream as StdTcpStream},
    pin::Pin,
    str,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use russh::{
    ChannelMsg, Pty, Signer as RusshSigner,
    client::{self, Handler},
    keys::agent::AgentIdentity,
    keys::{Algorithm, EcdsaCurve, HashAlg, PublicKeyOrCertificate},
};
use scoplen_crypto::SecretVec;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc, oneshot, watch};
use tokio::time::{Instant, timeout as async_timeout};
use zeroize::Zeroize;

use crate::{
    AgentError, AgentForwardingAdapter, AgentForwardingAuthorizer, AgentForwardingPolicy,
    AgentKeyStore, AgentServer, AlgorithmCategory, AsyncGatewayTransport,
    AsyncGatewayTransportError, CertificateValidationPolicy, ExtendedDataType,
    GatewayTlsClientConfig, GatewayTlsConnectError, HostAlgorithmPolicy, HostKeyVerificationError,
    HostKeyVerifier, HttpConnectTransport, KeyboardInteractiveInfoRequest,
    KeyboardInteractivePrompt, KeyboardInteractiveResponse, MAX_CHANNEL_ADDRESS, MAX_CHANNEL_NAME,
    MAX_CHANNEL_STRING, MAX_CHANNEL_TEXT, ProxyCredentials, ProxyTransportError, PtyRequest,
    PublicKeyAuthContext, PublicKeyAuthRequest, PublicKeyIdentity, Signal, SignatureAlgorithm,
    Signer, SignerError, Socks5Transport, TcpTransport, TransportError, UserCertificate,
    WindowChangeRequest,
    channels::validate_text as validate_channel_text,
    process::{ProxyCommandError, ProxyCommandStream, ProxyCommandTransport},
    verify_host_key,
};

const MAX_CLIENT_HOST: usize = 4096;
const MAX_CERTIFICATE_PRINCIPAL: usize = 4096;
const MAX_PUBLICKEY_AUTH_PAYLOAD: usize = 256 * 1024;
const MAX_KEYBOARD_SUBMETHODS: usize = 4096;
const DEFAULT_CLIENT_CHANNEL_LIMIT: usize = 64;
const DEFAULT_DIRECT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const RSA_SHA2_SELECTION_TIMEOUT: Duration = Duration::from_secs(2);
const DEFAULT_REKEY_WRITE_LIMIT: usize = 1 << 30;
const DEFAULT_REKEY_READ_LIMIT: usize = 1 << 30;
const DEFAULT_REKEY_TIME_LIMIT: Duration = Duration::from_secs(3600);
/// Maximum number of channels that one client connection may keep open.
pub const MAX_CLIENT_CHANNEL_LIMIT: usize = 256;
const USERAUTH_REQUEST: u8 = 50;

/// Errors raised while creating a concrete SSH client configuration.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ClientConfigError {
    /// A required text field is empty or contains a NUL byte.
    #[error("invalid SSH client configuration field: {0}")]
    InvalidField(&'static str),
    /// A configuration text field exceeds its bounded input limit.
    #[error("SSH client configuration field is too large: {0}")]
    FieldTooLarge(&'static str),
    /// The TCP destination port is not valid for an SSH endpoint.
    #[error("SSH client configuration port must be non-zero")]
    InvalidPort,
    /// The simultaneous channel limit is zero or exceeds the supported bound.
    #[error("SSH client channel limit must be between 1 and {MAX_CLIENT_CHANNEL_LIMIT}")]
    InvalidChannelLimit,
    /// An enabled inactivity timeout must make progress and fit an event-loop deadline.
    #[error("SSH inactivity timeout must be positive and representable as a deadline")]
    InvalidInactivityTimeout,
    /// Rekey limits must fit a deadline and byte limits must not exceed one GiB.
    #[error(
        "SSH rekey limits require 1..=1073741824 payload bytes and a positive representable duration"
    )]
    InvalidRekeyLimits,
    /// Enabled keepalive settings cannot spin or disable missed-reply detection.
    #[error(
        "SSH keepalive requires a positive representable interval and missed count in 1..usize::MAX"
    )]
    InvalidKeepalive,
}

/// Host-certificate policy used by the concrete host-key callback.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostKeyPolicy {
    expected_principal: String,
    now: u64,
}

impl HostKeyPolicy {
    /// Build a policy requiring `expected_principal` and evaluating validity at `now`.
    pub fn new(expected_principal: impl Into<String>, now: u64) -> Result<Self, ClientConfigError> {
        let expected_principal = expected_principal.into();
        validate_text(
            expected_principal.as_bytes(),
            MAX_CERTIFICATE_PRINCIPAL,
            "certificate principal",
            true,
        )?;
        Ok(Self { expected_principal, now })
    }

    /// Return the certificate principal checked before the trust callback.
    #[must_use]
    pub fn expected_principal(&self) -> &str {
        &self.expected_principal
    }

    /// Return the Unix timestamp used for certificate validity.
    #[must_use]
    pub const fn now(&self) -> u64 {
        self.now
    }
}

/// A concrete SSH client configuration.
///
/// The config deliberately accepts a trust callback rather than a known-hosts file.  Storage and
/// policy for host keys belong to the caller; the callback is invoked only after the shared
/// certificate and key parser has validated the presented bytes.
pub struct ClientConfig {
    host: String,
    port: u16,
    host_key_policy: HostKeyPolicy,
    verifier: Arc<dyn HostKeyVerifier + Send + Sync>,
    inactivity_timeout: Option<Duration>,
    keepalive_interval: Option<Duration>,
    keepalive_max: usize,
    rekey_write_limit: usize,
    rekey_read_limit: usize,
    rekey_time_limit: Duration,
    channel_limit: usize,
    algorithm_policy: HostAlgorithmPolicy,
    #[cfg(test)]
    completed_key_exchanges: Arc<std::sync::atomic::AtomicUsize>,
    #[cfg(test)]
    completed_key_exchange_times: Arc<std::sync::Mutex<Vec<Instant>>>,
    #[cfg(test)]
    event_loop_stopped: Arc<std::sync::atomic::AtomicBool>,
}

impl fmt::Debug for ClientConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClientConfig")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("host_key_policy", &self.host_key_policy)
            .field("inactivity_timeout", &self.inactivity_timeout)
            .field("keepalive_interval", &self.keepalive_interval)
            .field("keepalive_max", &self.keepalive_max)
            .field("rekey_write_limit", &self.rekey_write_limit)
            .field("rekey_read_limit", &self.rekey_read_limit)
            .field("rekey_time_limit", &self.rekey_time_limit)
            .field("channel_limit", &self.channel_limit)
            .field("algorithm_policy", &self.algorithm_policy)
            .finish_non_exhaustive()
    }
}

impl Clone for ClientConfig {
    fn clone(&self) -> Self {
        Self {
            host: self.host.clone(),
            port: self.port,
            host_key_policy: self.host_key_policy.clone(),
            verifier: Arc::clone(&self.verifier),
            inactivity_timeout: self.inactivity_timeout,
            keepalive_interval: self.keepalive_interval,
            keepalive_max: self.keepalive_max,
            rekey_write_limit: self.rekey_write_limit,
            rekey_read_limit: self.rekey_read_limit,
            rekey_time_limit: self.rekey_time_limit,
            channel_limit: self.channel_limit,
            algorithm_policy: self.algorithm_policy.clone(),
            #[cfg(test)]
            completed_key_exchanges: Arc::clone(&self.completed_key_exchanges),
            #[cfg(test)]
            completed_key_exchange_times: Arc::clone(&self.completed_key_exchange_times),
            #[cfg(test)]
            event_loop_stopped: Arc::clone(&self.event_loop_stopped),
        }
    }
}

impl ClientConfig {
    /// Build a client configuration with the host name as the default certificate principal.
    pub fn new<V>(
        host: impl Into<String>,
        port: u16,
        verifier: V,
    ) -> Result<Self, ClientConfigError>
    where
        V: HostKeyVerifier + Send + Sync + 'static,
    {
        let host = host.into();
        validate_text(host.as_bytes(), MAX_CLIENT_HOST, "host", true)?;
        if port == 0 {
            return Err(ClientConfigError::InvalidPort);
        }
        let host_key_policy = HostKeyPolicy::new(host.clone(), unix_time_seconds())?;
        Ok(Self {
            host,
            port,
            host_key_policy,
            verifier: Arc::new(verifier),
            inactivity_timeout: None,
            keepalive_interval: None,
            keepalive_max: 3,
            rekey_write_limit: DEFAULT_REKEY_WRITE_LIMIT,
            rekey_read_limit: DEFAULT_REKEY_READ_LIMIT,
            rekey_time_limit: DEFAULT_REKEY_TIME_LIMIT,
            channel_limit: DEFAULT_CLIENT_CHANNEL_LIMIT,
            algorithm_policy: HostAlgorithmPolicy::default(),
            #[cfg(test)]
            completed_key_exchanges: Arc::default(),
            #[cfg(test)]
            completed_key_exchange_times: Arc::default(),
            #[cfg(test)]
            event_loop_stopped: Arc::default(),
        })
    }

    /// Replace the host-certificate policy while retaining the endpoint and trust callback.
    #[must_use]
    pub fn with_host_key_policy(mut self, policy: HostKeyPolicy) -> Self {
        self.host_key_policy = policy;
        self
    }

    /// Configure the inactivity timeout used by the underlying event loop.
    ///
    /// `None` disables the timeout. An enabled timeout must be positive and representable as an
    /// event-loop deadline, including after received traffic resets the timer.
    pub fn with_inactivity_timeout(
        mut self,
        timeout: Option<Duration>,
    ) -> Result<Self, ClientConfigError> {
        if timeout.is_some_and(|timeout| {
            timeout.is_zero() || Instant::now().checked_add(timeout).is_none()
        }) {
            return Err(ClientConfigError::InvalidInactivityTimeout);
        }
        self.inactivity_timeout = timeout;
        Ok(self)
    }

    /// Configure periodic keepalives used by the underlying event loop.
    ///
    /// `None` disables probes regardless of `max_missed`. An enabled interval must be positive
    /// and representable as an event-loop deadline; its missed-reply count must be positive and
    /// less than `usize::MAX` so the engine's saturating counter can expire the connection.
    pub fn with_keepalive(
        mut self,
        interval: Option<Duration>,
        max_missed: usize,
    ) -> Result<Self, ClientConfigError> {
        if let Some(interval) = interval
            && (interval.is_zero()
                || Instant::now().checked_add(interval).is_none()
                || max_missed == 0
                || max_missed == usize::MAX)
        {
            return Err(ClientConfigError::InvalidKeepalive);
        }
        self.keepalive_interval = interval;
        self.keepalive_max = max_missed;
        Ok(self)
    }

    /// Request rekeying after this many outgoing SSH payload bytes or this elapsed duration.
    ///
    /// The byte limit must be between one byte and one GiB, inclusive; the time limit must be
    /// positive and representable as a deadline. Defaults are one GiB and one hour. After
    /// authentication, the engine also checks the elapsed limit on idle connections. A completed
    /// exchange resets the counters and deadline. Counters exclude packet headers, padding, and
    /// authentication tags. This does not change the independent incoming threshold.
    pub fn with_rekey_limits(
        mut self,
        write_bytes: usize,
        elapsed: Duration,
    ) -> Result<Self, ClientConfigError> {
        if !(1..=DEFAULT_REKEY_WRITE_LIMIT).contains(&write_bytes)
            || elapsed.is_zero()
            || Instant::now().checked_add(elapsed).is_none()
        {
            return Err(ClientConfigError::InvalidRekeyLimits);
        }
        self.rekey_write_limit = write_bytes;
        self.rekey_time_limit = elapsed;
        Ok(self)
    }

    /// Request rekeying after this many incoming SSH payload bytes, independently per Host.
    ///
    /// The limit is between one byte and one GiB, inclusive, and defaults to one GiB. After
    /// authentication, the engine initiates an exchange when received payloads reach the limit;
    /// packet lengths, padding, and authentication tags are excluded from the counter.
    pub fn with_rekey_read_limit(mut self, read_bytes: usize) -> Result<Self, ClientConfigError> {
        if !(1..=DEFAULT_REKEY_READ_LIMIT).contains(&read_bytes) {
            return Err(ClientConfigError::InvalidRekeyLimits);
        }
        self.rekey_read_limit = read_bytes;
        Ok(self)
    }

    /// Bound simultaneous session and forwarding channels on one SSH connection.
    pub fn with_channel_limit(mut self, limit: usize) -> Result<Self, ClientConfigError> {
        if !(1..=MAX_CLIENT_CHANNEL_LIMIT).contains(&limit) {
            return Err(ClientConfigError::InvalidChannelLimit);
        }
        self.channel_limit = limit;
        Ok(self)
    }

    /// Replace the per-Host algorithm policy used by the concrete SSH engine.
    #[must_use]
    pub fn with_algorithm_policy(mut self, policy: HostAlgorithmPolicy) -> Self {
        self.algorithm_policy = policy;
        self
    }

    /// Return the per-Host algorithm policy used by this connection.
    #[must_use]
    pub fn algorithm_policy(&self) -> &HostAlgorithmPolicy {
        &self.algorithm_policy
    }

    /// Return the configured host name.
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// Return the configured TCP port.
    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }

    fn russh_config(&self) -> client::Config {
        // Keep the concrete engine offer as the ordered intersection of the K-7 policy and the
        // algorithms implemented by russh.  In particular, sntrup and umac remain in the shared
        // policy but are not advertised here because this russh release cannot negotiate them.
        let preferred = russh::Preferred {
            kex: Cow::Owned(
                self.algorithm_policy
                    .offers(AlgorithmCategory::KeyExchange)
                    .iter()
                    .filter_map(|name| russh_kex(name))
                    .chain([
                        russh::kex::EXTENSION_SUPPORT_AS_CLIENT,
                        russh::kex::EXTENSION_OPENSSH_STRICT_KEX_AS_CLIENT,
                    ])
                    .collect(),
            ),
            key: Cow::Owned(
                self.algorithm_policy
                    .offers(AlgorithmCategory::HostKey)
                    .iter()
                    .filter_map(|name| russh_key(name))
                    .collect(),
            ),
            cipher: Cow::Owned(
                self.algorithm_policy
                    .offers(AlgorithmCategory::Cipher)
                    .iter()
                    .filter_map(|name| russh_cipher(name))
                    .collect(),
            ),
            mac: Cow::Owned(
                self.algorithm_policy
                    .offers(AlgorithmCategory::Mac)
                    .iter()
                    .filter_map(|name| russh_mac(name))
                    .collect(),
            ),
            compression: Cow::Owned(
                self.algorithm_policy
                    .offers(AlgorithmCategory::Compression)
                    .iter()
                    .filter_map(|name| russh_compression(name))
                    .collect(),
            ),
            // Certificate algorithms precede raw keys on the wire (D-42).  russh derives the
            // certificate names from this separate list.
            host_key_certificates: Cow::Owned(
                self.algorithm_policy
                    .offers(AlgorithmCategory::HostKey)
                    .iter()
                    .filter_map(|name| russh_certificate(name))
                    .collect(),
            ),
        };
        client::Config {
            preferred,
            inactivity_timeout: self.inactivity_timeout,
            keepalive_interval: self.keepalive_interval,
            keepalive_max: self.keepalive_max,
            limits: russh::Limits::new(
                self.rekey_write_limit,
                self.rekey_read_limit,
                self.rekey_time_limit,
            ),
            nodelay: true,
            ..client::Config::default()
        }
    }
}

fn russh_kex(name: &str) -> Option<russh::kex::Name> {
    match name {
        "mlkem768x25519-sha256" => Some(russh::kex::MLKEM768X25519_SHA256),
        "curve25519-sha256" => Some(russh::kex::CURVE25519),
        "ecdh-sha2-nistp256" => Some(russh::kex::ECDH_SHA2_NISTP256),
        "ecdh-sha2-nistp384" => Some(russh::kex::ECDH_SHA2_NISTP384),
        "ecdh-sha2-nistp521" => Some(russh::kex::ECDH_SHA2_NISTP521),
        "diffie-hellman-group16-sha512" => Some(russh::kex::DH_G16_SHA512),
        "diffie-hellman-group18-sha512" => Some(russh::kex::DH_G18_SHA512),
        "diffie-hellman-group14-sha256" => Some(russh::kex::DH_G14_SHA256),
        "diffie-hellman-group14-sha1" => Some(russh::kex::DH_G14_SHA1),
        "diffie-hellman-group-exchange-sha256" => Some(russh::kex::DH_GEX_SHA256),
        "diffie-hellman-group-exchange-sha1" => Some(russh::kex::DH_GEX_SHA1),
        _ => None,
    }
}

fn russh_key(name: &str) -> Option<Algorithm> {
    match name {
        "ssh-ed25519" => Some(Algorithm::Ed25519),
        "ecdsa-sha2-nistp256" => Some(Algorithm::Ecdsa { curve: EcdsaCurve::NistP256 }),
        "ecdsa-sha2-nistp384" => Some(Algorithm::Ecdsa { curve: EcdsaCurve::NistP384 }),
        "ecdsa-sha2-nistp521" => Some(Algorithm::Ecdsa { curve: EcdsaCurve::NistP521 }),
        "sk-ssh-ed25519@openssh.com" => Some(Algorithm::SkEd25519),
        "sk-ecdsa-sha2-nistp256@openssh.com" => Some(Algorithm::SkEcdsaSha2NistP256),
        "rsa-sha2-512" => Some(Algorithm::Rsa { hash: Some(HashAlg::Sha512) }),
        "rsa-sha2-256" => Some(Algorithm::Rsa { hash: Some(HashAlg::Sha256) }),
        "ssh-rsa" => Some(Algorithm::Rsa { hash: None }),
        _ => None,
    }
}

fn russh_certificate(name: &str) -> Option<Algorithm> {
    match name {
        "ssh-ed25519-cert-v01@openssh.com" => Some(Algorithm::Ed25519),
        "ecdsa-sha2-nistp256-cert-v01@openssh.com" => {
            Some(Algorithm::Ecdsa { curve: EcdsaCurve::NistP256 })
        }
        "ecdsa-sha2-nistp384-cert-v01@openssh.com" => {
            Some(Algorithm::Ecdsa { curve: EcdsaCurve::NistP384 })
        }
        "ecdsa-sha2-nistp521-cert-v01@openssh.com" => {
            Some(Algorithm::Ecdsa { curve: EcdsaCurve::NistP521 })
        }
        "sk-ssh-ed25519-cert-v01@openssh.com" => Some(Algorithm::SkEd25519),
        "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com" => Some(Algorithm::SkEcdsaSha2NistP256),
        "rsa-sha2-512-cert-v01@openssh.com" => Some(Algorithm::Rsa { hash: Some(HashAlg::Sha512) }),
        "rsa-sha2-256-cert-v01@openssh.com" => Some(Algorithm::Rsa { hash: Some(HashAlg::Sha256) }),
        "ssh-rsa-cert-v01@openssh.com" => Some(Algorithm::Rsa { hash: None }),
        _ => None,
    }
}

fn russh_cipher(name: &str) -> Option<russh::cipher::Name> {
    match name {
        "chacha20-poly1305@openssh.com" => Some(russh::cipher::CHACHA20_POLY1305),
        "aes256-gcm@openssh.com" => Some(russh::cipher::AES_256_GCM),
        "aes128-gcm@openssh.com" => Some(russh::cipher::AES_128_GCM),
        "aes256-ctr" => Some(russh::cipher::AES_256_CTR),
        "aes192-ctr" => Some(russh::cipher::AES_192_CTR),
        "aes128-ctr" => Some(russh::cipher::AES_128_CTR),
        "aes256-cbc" => Some(russh::cipher::AES_256_CBC),
        "aes192-cbc" => Some(russh::cipher::AES_192_CBC),
        "aes128-cbc" => Some(russh::cipher::AES_128_CBC),
        "3des-cbc" => Some(russh::cipher::TRIPLE_DES_CBC),
        _ => None,
    }
}

fn russh_mac(name: &str) -> Option<russh::mac::Name> {
    match name {
        "hmac-sha2-512-etm@openssh.com" => Some(russh::mac::HMAC_SHA512_ETM),
        "hmac-sha2-256-etm@openssh.com" => Some(russh::mac::HMAC_SHA256_ETM),
        "hmac-sha2-512" => Some(russh::mac::HMAC_SHA512),
        "hmac-sha2-256" => Some(russh::mac::HMAC_SHA256),
        "hmac-sha1" => Some(russh::mac::HMAC_SHA1),
        _ => None,
    }
}

fn russh_compression(name: &str) -> Option<russh::compression::Name> {
    match name {
        "none" => Some(russh::compression::NONE),
        "zlib@openssh.com" => Some(russh::compression::ZLIB_LEGACY),
        "zlib" => Some(russh::compression::ZLIB),
        _ => None,
    }
}

/// Errors returned by the concrete SSH client.
#[derive(Debug, Error)]
pub enum ClientError {
    /// Configuration validation failed before a connection was opened.
    #[error(transparent)]
    Config(#[from] ClientConfigError),
    /// The server key was malformed, failed certificate validation, or was rejected by policy.
    #[error("SSH host-key verification failed: {0}")]
    HostKey(#[from] HostKeyVerificationError),
    /// The supplied password cannot be represented by the current `russh` password API.
    #[error("SSH password must be valid UTF-8")]
    PasswordEncoding,
    /// The server rejected an authentication method or requires another factor.
    #[error("SSH authentication was rejected")]
    AuthenticationRejected {
        /// Whether the server accepted the method as a partial multi-factor step.
        partial_success: bool,
        /// Remaining methods recognized by the SSH engine, in server order. Unknown methods are omitted.
        remaining_methods: Vec<String>,
    },
    /// Authentication has already completed on this connection.
    #[error("SSH connection is already authenticated")]
    AlreadyAuthenticated,
    /// The server signature-algorithm query did not complete within its fixed deadline.
    #[error("SSH server RSA signature selection timed out")]
    RsaSelectionTimeout,
    /// The SSH engine could not complete the server signature-algorithm query.
    #[error("SSH server RSA signature selection failed")]
    RsaSelectionEngine,
    /// A prior server signature-algorithm query was cancelled.
    #[error("SSH server RSA signature selection was interrupted")]
    RsaSelectionInterrupted,
    /// The public-key signer or its session-bound request was invalid.
    #[error("SSH public-key authentication could not be completed: {0}")]
    PublicKey(#[from] PublicKeyAuthError),
    /// The server requires authentication before the requested channel operation.
    #[error("SSH authentication is required")]
    NotAuthenticated,
    /// A TCP or stream I/O operation failed.
    #[error("SSH transport I/O failed: {0}")]
    Transport(#[source] std::io::Error),
    /// Direct name resolution, TCP connection, or socket configuration failed.
    #[error("SSH direct TCP connection failed: {0}")]
    DirectTcp(#[source] TransportError),
    /// The direct TCP connection succeeded, but SSH key exchange did not finish in time.
    #[error("SSH direct handshake timed out after {timeout:?}")]
    DirectSshHandshakeTimeout { timeout: Duration },
    /// A SOCKS5 or HTTP CONNECT route failed before the SSH stream was opened.
    #[error("SSH proxy route failed: {0}")]
    Proxy(#[from] ProxyTransportError),
    /// A proxy accepted the route, but the SSH handshake did not finish in time.
    #[error("SSH handshake through proxy timed out after {timeout:?}")]
    ProxySshHandshakeTimeout { timeout: Duration },
    /// A desktop `ProxyCommand` could not be started or configured.
    #[error("SSH ProxyCommand failed: {0}")]
    ProxyCommand(#[from] ProxyCommandError),
    /// The `ProxyCommand` started, but the SSH handshake did not finish in time.
    #[error("SSH handshake through ProxyCommand timed out after {timeout:?}")]
    ProxyCommandHandshakeTimeout { timeout: Duration },
    /// The peer refused a channel open request.
    #[error("SSH channel open failed ({code}): {reason}")]
    ChannelOpen { code: u32, reason: String },
    /// A channel operation could not be delivered or completed.
    #[error("SSH channel operation failed")]
    Channel,
    /// The gateway client hello could not be composed over the caller's stream.
    #[error("SSH gateway prelude failed: {0}")]
    Gateway(#[from] AsyncGatewayTransportError),
    /// The gateway edge TCP connection failed before TLS could start.
    #[error("SSH gateway TCP connection failed: {0}")]
    GatewayTcp(#[from] TransportError),
    /// The gateway TLS or ALPN handshake failed.
    #[error("SSH gateway TLS connection failed: {0}")]
    GatewayTls(#[from] GatewayTlsConnectError),
    /// The gateway TLS, K-6 prelude, or SSH handshake exceeded its timeout.
    #[error("SSH gateway handshake timed out after {timeout:?}")]
    GatewayHandshakeTimeout { timeout: Duration },
    /// A forwarded SSH agent request or lifecycle event failed the bounded agent boundary.
    #[error("SSH forwarded agent channel failed: {0}")]
    Agent(#[from] AgentError),
    /// The configured number of simultaneous channels is already open.
    #[error("SSH channel limit of {max} has been reached")]
    ChannelLimitReached { max: usize },
    /// The peer closed the connection or the event loop stopped.
    #[error("SSH connection closed")]
    ConnectionClosed,
    /// The SSH protocol negotiation or packet validation failed.
    #[error("SSH protocol negotiation failed")]
    Protocol,
    /// A peer extended-data type is outside the shared channel contract.
    #[error("unsupported SSH extended-data type: {0}")]
    UnsupportedExtendedData(u32),
    /// A local channel request exceeded the shared channel boundary.
    #[error("invalid SSH channel input: {0}")]
    InvalidInput(&'static str),
    /// A channel event belongs to an engine-internal request rather than a peer response.
    #[error("unexpected SSH channel event")]
    UnexpectedChannelEvent,
}

fn authentication_rejected(
    remaining_methods: &russh::MethodSet,
    partial_success: bool,
) -> ClientError {
    ClientError::AuthenticationRejected {
        partial_success,
        remaining_methods: remaining_methods.iter().map(String::from).collect(),
    }
}

/// Result of an RFC 4252 `none` probe. The server may accept `none` or advertise further
/// methods. Methods recognized by the SSH engine retain server order; unknown names are omitted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NoneAuthOutcome {
    /// The server accepted `none`; the connection is authenticated.
    Authenticated,
    /// The server rejected `none` and supplied its remaining methods.
    Rejected { methods: Vec<String>, partial_success: bool },
}

/// The strongest compatible RSA authentication signature advertised by this server.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServerRsaSha2Selection {
    /// The server advertises `rsa-sha2-512`.
    Sha512,
    /// The server advertises `rsa-sha2-256`, but not `rsa-sha2-512`.
    Sha256,
    /// The only recognized advertised RSA signature is legacy `ssh-rsa`.
    Sha1OnlyAdvertised,
    /// No RSA choice can be established from the available extension information.
    Undetermined,
}

#[derive(Clone, Copy)]
enum RsaSelectionFailure {
    Timeout,
    Engine,
    Interrupted,
}

impl From<RsaSelectionFailure> for ClientError {
    fn from(failure: RsaSelectionFailure) -> Self {
        match failure {
            RsaSelectionFailure::Timeout => Self::RsaSelectionTimeout,
            RsaSelectionFailure::Engine => Self::RsaSelectionEngine,
            RsaSelectionFailure::Interrupted => Self::RsaSelectionInterrupted,
        }
    }
}

type RsaSelectionCache = Option<Result<ServerRsaSha2Selection, RsaSelectionFailure>>;

async fn select_server_rsa_sha2<F>(
    cache: &mut RsaSelectionCache,
    query: F,
) -> Result<ServerRsaSha2Selection, ClientError>
where
    F: Future<Output = Result<Option<Option<HashAlg>>, russh::Error>>,
{
    if let Some(result) = cache {
        return result.map_err(ClientError::from);
    }
    *cache = Some(Err(RsaSelectionFailure::Interrupted));
    let result = match async_timeout(RSA_SHA2_SELECTION_TIMEOUT, query).await {
        Err(_) => Err(RsaSelectionFailure::Timeout),
        Ok(Err(_)) => Err(RsaSelectionFailure::Engine),
        Ok(Ok(advertised)) => Ok(match advertised {
            Some(Some(HashAlg::Sha512)) => ServerRsaSha2Selection::Sha512,
            Some(Some(HashAlg::Sha256)) => ServerRsaSha2Selection::Sha256,
            Some(None) => ServerRsaSha2Selection::Sha1OnlyAdvertised,
            None | Some(Some(_)) => ServerRsaSha2Selection::Undetermined,
        }),
    };
    *cache = Some(result);
    result.map_err(ClientError::from)
}

/// Errors raised while adapting the engine-independent signer to `russh`.
#[derive(Debug, Error)]
pub enum PublicKeyAuthError {
    /// The signer failed while producing a key or signature.
    #[error(transparent)]
    Signer(#[from] SignerError),
    /// The russh event loop could not receive the signature response.
    #[error("SSH event loop is unavailable")]
    Send(#[from] russh::SendError),
    /// A payload supplied by russh did not have the RFC 4252 shape expected by the shared core.
    #[error("malformed russh public-key signing payload: {0}")]
    MalformedPayload(&'static str),
    /// The engine asked the signer to sign with a different key than the offered identity.
    #[error("russh public-key identity does not match the signer")]
    KeyMismatch,
}

impl From<russh::Error> for ClientError {
    fn from(error: russh::Error) -> Self {
        match error {
            russh::Error::IO(error) => Self::Transport(error),
            russh::Error::ChannelOpenFailure(failure) => {
                Self::ChannelOpen { code: failure.code(), reason: failure.description().to_owned() }
            }
            russh::Error::WrongChannel
            | russh::Error::SendError
            | russh::Error::RecvError
            | russh::Error::RequestDenied
            | russh::Error::Pending => Self::Channel,
            russh::Error::NotAuthenticated => Self::NotAuthenticated,
            russh::Error::Disconnect
            | russh::Error::HUP
            | russh::Error::ConnectionTimeout
            | russh::Error::KeepaliveTimeout
            | russh::Error::InactivityTimeout => Self::ConnectionClosed,
            russh::Error::UnknownKey | russh::Error::WrongServerSig => {
                Self::HostKey(HostKeyVerificationError::InvalidEncoding)
            }
            _ => Self::Protocol,
        }
    }
}

/// A connected and authenticated-capable SSH client.
pub struct ClientConnection {
    handle: client::Handle<ClientHandler>,
    authenticated: AtomicBool,
    rsa_selection: RsaSelectionCache,
    transport_lifetime: Mutex<Option<oneshot::Sender<()>>>,
    stopped: watch::Receiver<bool>,
    channel_slots: Arc<Semaphore>,
    channel_limit: usize,
    forwarded_channels: mpsc::Receiver<ForwardedChannel>,
}

// Channel handles retain the engine's sender. Closing this owner must still wake blocked I/O
// and stop the session, even when those handles or a window-blocked send remain alive.
struct ConnectionTransport<S> {
    inner: S,
    lifetime: oneshot::Receiver<()>,
    closed: bool,
}

impl<S> ConnectionTransport<S> {
    fn check_open(&mut self, context: &mut Context<'_>) -> io::Result<()> {
        if self.closed || Pin::new(&mut self.lifetime).poll(context).is_ready() {
            self.closed = true;
            return Err(io::Error::new(io::ErrorKind::ConnectionAborted, "SSH connection closed"));
        }
        Ok(())
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for ConnectionTransport<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.check_open(context)?;
        Pin::new(&mut self.inner).poll_read(context, buffer)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for ConnectionTransport<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.check_open(context)?;
        Pin::new(&mut self.inner).poll_write(context, buffer)
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.check_open(context)?;
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.check_open(context)?;
        Pin::new(&mut self.inner).poll_shutdown(context)
    }
}

// russh moves the socket into its key-exchange task before connect_stream returns. Shutting down
// this duplicate wakes that task if the handshake future times out or its caller is canceled.
struct HandshakeSocketGuard {
    socket: Option<StdTcpStream>,
}

impl Drop for HandshakeSocketGuard {
    fn drop(&mut self) {
        if let Some(socket) = &self.socket {
            let _ = socket.shutdown(Shutdown::Both);
        }
    }
}

impl fmt::Debug for ClientConnection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("ClientConnection").finish_non_exhaustive()
    }
}

impl ClientConnection {
    /// Connect to the configured TCP endpoint and complete SSH key exchange.
    /// Resolve and dial within ten seconds, then allow ten seconds for the SSH handshake.
    pub async fn connect(config: ClientConfig) -> Result<Self, ClientError> {
        Self::connect_with_timeout(config, DEFAULT_DIRECT_CONNECT_TIMEOUT).await
    }

    /// Connect directly with separate resolve-and-TCP and SSH handshake budgets.
    ///
    /// Each stage receives the same positive, representable `timeout`. Pending address attempts
    /// are canceled on timeout or caller cancellation. A stalled SSH handshake closes its socket.
    pub async fn connect_with_timeout(
        config: ClientConfig,
        timeout: Duration,
    ) -> Result<Self, ClientError> {
        let stream = TcpTransport::connect_async(&config.host, config.port, timeout)
            .await
            .map_err(ClientError::DirectTcp)?
            .into_stream();
        Self::connect_via_tcp_socket(
            config,
            stream,
            timeout,
            ClientError::DirectSshHandshakeTimeout { timeout },
        )
        .await
    }

    /// Connect over a caller-provided byte stream and complete SSH key exchange.
    pub async fn connect_stream<S>(config: ClientConfig, stream: S) -> Result<Self, ClientError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let channel_slots = Arc::new(Semaphore::new(config.channel_limit));
        let (forwarded_tx, forwarded_channels) = mpsc::channel(config.channel_limit);
        let (stopped_tx, stopped) = watch::channel(false);
        let handler =
            ClientHandler::new(&config, Arc::clone(&channel_slots), forwarded_tx, stopped_tx);
        let (owner, lifetime) = oneshot::channel();
        let stream = ConnectionTransport { inner: stream, lifetime, closed: false };
        let handle =
            client::connect_stream(Arc::new(config.russh_config()), stream, handler).await?;
        Ok(Self {
            handle,
            authenticated: AtomicBool::new(false),
            rsa_selection: None,
            transport_lifetime: Mutex::new(Some(owner)),
            stopped,
            channel_slots,
            channel_limit: config.channel_limit,
            forwarded_channels,
        })
    }

    /// Discover the strongest advertised RSA SHA-2 signature before or between auth factors.
    ///
    /// The query is limited to two seconds and runs only once per connection. Its result or
    /// terminal failure is cached. Cancellation permanently interrupts discovery on this
    /// connection, while other authentication methods and channels remain available.
    pub async fn server_rsa_sha2_selection(
        &mut self,
    ) -> Result<ServerRsaSha2Selection, ClientError> {
        select_server_rsa_sha2(&mut self.rsa_selection, self.handle.best_supported_rsa_hash()).await
    }

    /// Write the K-6 gateway client hello over an already negotiated TLS/ALPN stream, then start
    /// the SSH client on the same stream.
    ///
    /// The caller owns TLS certificate verification and ALPN selection. This method only composes
    /// the bounded one-shot gateway prelude before the ordinary SSH version exchange.
    pub async fn connect_via_gateway_stream<S>(
        config: ClientConfig,
        stream: S,
        hello: &scoplen_api::gateway::GatewayClientHello,
    ) -> Result<Self, ClientError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let stream = AsyncGatewayTransport::handshake(stream, hello).await?;
        Self::connect_stream(config, stream).await
    }

    /// Connect directly to a gateway edge, negotiate TLS 1.3 and `spl-gw/1`, send the bounded
    /// K-6 client hello, and complete the SSH handshake on the resulting stream.
    ///
    /// The edge TCP connection uses the same bounded Happy Eyeballs and socket policy as direct
    /// SSH transport. The blocking resolver and connect work runs off the async runtime; TLS,
    /// gateway framing, and SSH remain ordered on the returned stream. The timeout applies to
    /// the TCP dial and again to the combined TLS, prelude, and SSH handshake, so an accepted edge
    /// that stops responding cannot leave the connection attempt pending indefinitely.
    pub async fn connect_via_gateway(
        config: ClientConfig,
        edge_host: &str,
        edge_port: u16,
        timeout: Duration,
        tls: &GatewayTlsClientConfig,
        hello: &scoplen_api::gateway::GatewayClientHello,
    ) -> Result<Self, ClientError> {
        if edge_port == 0 {
            return Err(ClientError::InvalidInput("gateway edge port must be non-zero"));
        }
        let edge_host = edge_host.to_owned();
        let stream = tokio::task::spawn_blocking(move || {
            TcpTransport::connect(&edge_host, edge_port, timeout).map(TcpTransport::into_stream)
        })
        .await
        .map_err(|_| ClientError::Transport(io::Error::other("gateway TCP route task stopped")))?
        .map_err(ClientError::GatewayTcp)?;
        stream.set_nonblocking(true).map_err(ClientError::Transport)?;
        let stream = tokio::net::TcpStream::from_std(stream).map_err(ClientError::Transport)?;
        async_timeout(timeout, async {
            let stream = tls.connect_and_handshake(stream, hello).await?;
            Self::connect_stream(config, stream).await
        })
        .await
        .map_err(|_| ClientError::GatewayHandshakeTimeout { timeout })?
    }

    /// Connect through a SOCKS5 proxy and complete the SSH handshake over the resulting stream.
    ///
    /// The existing bounded SOCKS5 transport performs DNS, proxy negotiation, and socket setup
    /// on a blocking worker so the caller's async runtime is not stalled. The resulting socket is
    /// then handed to the same `russh` stream boundary used by [`Self::connect_stream`]. The
    /// timeout applies separately to proxy setup and the subsequent SSH handshake.
    pub async fn connect_via_socks5(
        config: ClientConfig,
        proxy_host: &str,
        proxy_port: u16,
        credentials: Option<&ProxyCredentials>,
        timeout: Duration,
    ) -> Result<Self, ClientError> {
        let proxy_host = proxy_host.to_owned();
        let target_host = config.host.clone();
        let target_port = config.port;
        let credentials = credentials.cloned();
        let stream = tokio::task::spawn_blocking(move || {
            Socks5Transport::connect_with_credentials(
                &proxy_host,
                proxy_port,
                &target_host,
                target_port,
                credentials.as_ref(),
                timeout,
            )
            .map(Socks5Transport::into_stream)
        })
        .await
        .map_err(|_| ClientError::Transport(io::Error::other("SSH proxy route task stopped")))?
        .map_err(ClientError::Proxy)?;
        Self::connect_via_tcp_socket(
            config,
            stream,
            timeout,
            ClientError::ProxySshHandshakeTimeout { timeout },
        )
        .await
    }

    /// Connect through an HTTP CONNECT proxy and complete the SSH handshake over the stream.
    ///
    /// The existing bounded HTTP CONNECT transport performs the proxy handshake on a blocking
    /// worker, clears handshake-only socket timeouts, and then reuses the common async SSH stream
    /// boundary. The timeout applies separately to proxy setup and the subsequent SSH handshake.
    pub async fn connect_via_http_connect(
        config: ClientConfig,
        proxy_host: &str,
        proxy_port: u16,
        credentials: Option<&ProxyCredentials>,
        timeout: Duration,
    ) -> Result<Self, ClientError> {
        let proxy_host = proxy_host.to_owned();
        let target_host = config.host.clone();
        let target_port = config.port;
        let credentials = credentials.cloned();
        let stream = tokio::task::spawn_blocking(move || {
            HttpConnectTransport::connect_with_credentials(
                &proxy_host,
                proxy_port,
                &target_host,
                target_port,
                credentials.as_ref(),
                timeout,
            )
            .map(HttpConnectTransport::into_stream)
        })
        .await
        .map_err(|_| ClientError::Transport(io::Error::other("SSH proxy route task stopped")))?
        .map_err(ClientError::Proxy)?;
        Self::connect_via_tcp_socket(
            config,
            stream,
            timeout,
            ClientError::ProxySshHandshakeTimeout { timeout },
        )
        .await
    }

    /// Spawn a bounded desktop `ProxyCommand` and complete the SSH handshake over its standard
    /// input and output. Arguments are passed directly without shell interpolation. `timeout`
    /// bounds the SSH handshake after the process starts; a stalled child is terminated and reaped.
    pub async fn connect_via_proxy_command(
        config: ClientConfig,
        program: impl AsRef<OsStr>,
        args: &[OsString],
        timeout: Duration,
    ) -> Result<Self, ClientError> {
        if timeout.is_zero() {
            return Err(ClientError::InvalidInput(
                "ProxyCommand handshake timeout must be non-zero",
            ));
        }
        let program = program.as_ref().to_os_string();
        let args = args.to_vec();
        let transport =
            tokio::task::spawn_blocking(move || ProxyCommandTransport::spawn(program, args))
                .await
                .map_err(|_| ClientError::Transport(io::Error::other("ProxyCommand task stopped")))?
                .map_err(ClientError::ProxyCommand)?;
        let stream = ProxyCommandStream::new(transport);
        let mut termination_guard = stream.termination_guard();
        match async_timeout(timeout, Self::connect_stream(config, stream)).await {
            Ok(Ok(connection)) => {
                termination_guard.disarm();
                Ok(connection)
            }
            Ok(Err(error)) => Err(error),
            Err(_) => Err(ClientError::ProxyCommandHandshakeTimeout { timeout }),
        }
    }

    async fn connect_via_tcp_socket(
        config: ClientConfig,
        stream: StdTcpStream,
        timeout: Duration,
        timeout_error: ClientError,
    ) -> Result<Self, ClientError> {
        stream.set_nonblocking(true).map_err(ClientError::Transport)?;
        let mut shutdown_guard = HandshakeSocketGuard {
            socket: Some(stream.try_clone().map_err(ClientError::Transport)?),
        };
        let stream = tokio::net::TcpStream::from_std(stream).map_err(ClientError::Transport)?;
        match async_timeout(timeout, Self::connect_stream(config, stream)).await {
            Ok(Ok(connection)) => {
                shutdown_guard.socket = None;
                Ok(connection)
            }
            Ok(Err(error)) => Err(error),
            Err(_) => Err(timeout_error),
        }
    }

    /// Connect to a target through an already connected and authenticated jump host.
    ///
    /// The jump host opens an RFC 4254 `direct-tcpip` channel to the target. The channel is
    /// adapted to the same asynchronous stream boundary as [`Self::connect_stream`], so the
    /// target performs its own key exchange, host-key verification, and authentication. Retain
    /// the `jump` connection for as long as the returned target connection is in use. Calling
    /// this method again with the returned connection composes another hop, allowing arbitrary
    /// chain depth without exposing `russh` types.
    pub async fn connect_via_direct_tcpip(
        config: ClientConfig,
        jump: &ClientConnection,
        originator_address: &str,
        originator_port: u32,
    ) -> Result<Self, ClientError> {
        let channel = jump
            .open_direct_tcpip(
                &config.host,
                u32::from(config.port),
                originator_address,
                originator_port,
            )
            .await?;
        Self::connect_stream(config, channel.into_stream()).await
    }

    /// Authenticate with a session-bound RFC 4252 public-key request.
    ///
    /// The private key stays behind [`Signer`]. `russh` supplies the exact bytes it is about to
    /// sign; the adapter parses those bytes into [`PublicKeyAuthRequest`] before asking the signer
    /// to produce the signature. This keeps the concrete engine on the same algorithm, identity,
    /// and session-binding boundary as the engine-independent implementation.
    pub async fn authenticate_publickey<S>(
        &mut self,
        username: &str,
        signer: &S,
    ) -> Result<(), ClientError>
    where
        S: Signer + Sync,
    {
        self.reject_if_authenticated()?;
        validate_text(username.as_bytes(), MAX_CLIENT_HOST, "username", true)
            .map_err(ClientError::Config)?;
        let identity =
            PublicKeyIdentity::from_signer(signer).map_err(PublicKeyAuthError::Signer)?;
        let key = ssh_key::PublicKey::from_bytes(identity.key_blob())
            .map_err(|_| PublicKeyAuthError::MalformedPayload("signer public key"))?;
        let hash_alg = rsa_hash_algorithm(signer.algorithm());
        let mut adapter = RusshSignerAdapter { signer, identity, username: username.to_owned() };
        let result = self
            .handle
            .authenticate_publickey_with(username.to_owned(), key, hash_alg, &mut adapter)
            .await
            .map_err(ClientError::PublicKey)?;
        match result {
            russh::client::AuthResult::Success => {
                self.authenticated.store(true, Ordering::Release);
                Ok(())
            }
            russh::client::AuthResult::Failure { remaining_methods, partial_success } => {
                Err(authentication_rejected(&remaining_methods, partial_success))
            }
        }
    }

    /// Authenticate with a previously validated OpenSSH user certificate.
    ///
    /// Certificate parsing, CA validation, validity, principals, and critical options are
    /// completed by [`UserCertificate`] before this method is called. The private subject key
    /// remains behind [`Signer`], while the concrete engine receives only the validated
    /// certificate bytes and a session-bound signing callback.
    pub async fn authenticate_certificate<S>(
        &mut self,
        username: &str,
        user_certificate: &UserCertificate,
        signer: &S,
    ) -> Result<(), ClientError>
    where
        S: Signer + Sync,
    {
        self.reject_if_authenticated()?;
        validate_text(username.as_bytes(), MAX_CLIENT_HOST, "username", true)
            .map_err(ClientError::Config)?;
        if !user_certificate
            .certificate()
            .principals()
            .iter()
            .any(|principal| principal == username)
        {
            return Err(ClientError::InvalidInput("certificate principal does not match username"));
        }
        let identity = user_certificate.identity();
        if PublicKeyIdentity::from_signer(signer).map_err(PublicKeyAuthError::Signer)?.key_blob()
            != identity.signing_key_blob()
        {
            return Err(ClientError::PublicKey(PublicKeyAuthError::KeyMismatch));
        }
        let identity = PublicKeyIdentity::for_certificate(
            signer.algorithm().certificate_name(),
            identity.key_blob().to_vec(),
            identity.signing_key_blob().to_vec(),
        )
        .map_err(PublicKeyAuthError::Signer)?;
        let certificate =
            ssh_key::Certificate::from_bytes(user_certificate.certificate().as_bytes())
                .map_err(|_| PublicKeyAuthError::MalformedPayload("user certificate"))?;
        let hash_alg = rsa_hash_algorithm(signer.algorithm());
        let mut adapter = RusshSignerAdapter { signer, identity, username: username.to_owned() };
        let result = self
            .handle
            .authenticate_certificate_with(username.to_owned(), certificate, hash_alg, &mut adapter)
            .await
            .map_err(ClientError::PublicKey)?;
        match result {
            russh::client::AuthResult::Success => {
                self.authenticated.store(true, Ordering::Release);
                Ok(())
            }
            russh::client::AuthResult::Failure { remaining_methods, partial_success } => {
                Err(authentication_rejected(&remaining_methods, partial_success))
            }
        }
    }

    /// Authenticate with RFC 4252 password authentication.
    pub async fn authenticate_password(
        &mut self,
        username: &str,
        password: &[u8],
    ) -> Result<(), ClientError> {
        self.reject_if_authenticated()?;
        validate_text(username.as_bytes(), MAX_CLIENT_HOST, "username", true)
            .map_err(ClientError::Config)?;
        let secret = SecretVec::new(password.to_vec());
        let mut password = str::from_utf8(secret.as_bytes())
            .map(str::to_owned)
            .map_err(|_| ClientError::PasswordEncoding)?;
        let result = self
            .handle
            .authenticate_password(username.to_owned(), password.clone())
            .await
            .map_err(ClientError::from);
        password.zeroize();
        match result? {
            russh::client::AuthResult::Success => {
                self.authenticated.store(true, Ordering::Release);
                Ok(())
            }
            russh::client::AuthResult::Failure { remaining_methods, partial_success } => {
                Err(authentication_rejected(&remaining_methods, partial_success))
            }
        }
    }

    /// Probe RFC 4252 `none` without attempting a credential method.
    ///
    /// A rejection is returned as data so callers can select one of the server-advertised methods
    /// without treating the probe as a failed connection.
    pub async fn probe_authentication(
        &mut self,
        username: &str,
    ) -> Result<NoneAuthOutcome, ClientError> {
        self.reject_if_authenticated()?;
        validate_text(username.as_bytes(), MAX_CLIENT_HOST, "username", true)
            .map_err(ClientError::Config)?;
        match self.handle.authenticate_none(username.to_owned()).await.map_err(ClientError::from)? {
            russh::client::AuthResult::Success => {
                self.authenticated.store(true, Ordering::Release);
                Ok(NoneAuthOutcome::Authenticated)
            }
            russh::client::AuthResult::Failure { remaining_methods, partial_success } => {
                Ok(NoneAuthOutcome::Rejected {
                    methods: remaining_methods.iter().map(String::from).collect(),
                    partial_success,
                })
            }
        }
    }

    /// Authenticate with RFC 4256 keyboard-interactive prompts.
    ///
    /// The responder is called once for each bounded server information request. Prompt text and
    /// response strings are validated through the shared K-7 authentication boundary before any
    /// response is sent to `russh`; prompt order and response count are preserved exactly. The
    /// engine defers automatic rekey until authentication completes, then handles any expired
    /// elapsed limit without waiting for channel traffic.
    pub async fn authenticate_keyboard_interactive<F>(
        &mut self,
        username: &str,
        submethods: Option<&str>,
        mut responder: F,
    ) -> Result<(), ClientError>
    where
        F: FnMut(&KeyboardInteractiveInfoRequest) -> Result<Vec<String>, ClientError> + Send,
    {
        self.reject_if_authenticated()?;
        validate_text(username.as_bytes(), MAX_CLIENT_HOST, "username", true)
            .map_err(ClientError::Config)?;
        if let Some(submethods) = submethods {
            validate_text(
                submethods.as_bytes(),
                MAX_KEYBOARD_SUBMETHODS,
                "keyboard submethods",
                false,
            )
            .map_err(ClientError::Config)?;
        }
        let mut reply = {
            let handle = &mut self.handle;
            handle
                .authenticate_keyboard_interactive_start(
                    username.to_owned(),
                    submethods.map(str::to_owned),
                )
                .await
                .map_err(ClientError::from)?
        };
        loop {
            reply = match reply {
                russh::client::KeyboardInteractiveAuthResponse::Success => {
                    self.authenticated.store(true, Ordering::Release);
                    return Ok(());
                }
                russh::client::KeyboardInteractiveAuthResponse::Failure {
                    remaining_methods,
                    partial_success,
                } => return Err(authentication_rejected(&remaining_methods, partial_success)),
                russh::client::KeyboardInteractiveAuthResponse::InfoRequest {
                    name,
                    instructions,
                    prompts,
                } => {
                    let prompts = prompts
                        .into_iter()
                        .map(|prompt| {
                            KeyboardInteractivePrompt::new(prompt.prompt.into_bytes(), prompt.echo)
                                .map_err(|_| {
                                    ClientError::InvalidInput("keyboard prompt is invalid")
                                })
                        })
                        .collect::<Result<Vec<_>, _>>()?;
                    let info = KeyboardInteractiveInfoRequest::new(
                        name.into_bytes(),
                        instructions.into_bytes(),
                        Vec::new(),
                        prompts,
                    )
                    .map_err(|_| {
                        ClientError::InvalidInput("keyboard information request is invalid")
                    })?;
                    info.encode().map_err(|_| {
                        ClientError::InvalidInput("keyboard information request is invalid")
                    })?;
                    let responses = responder(&info)?;
                    if responses.len() != info.prompts().len() {
                        return Err(ClientError::InvalidInput(
                            "keyboard response count does not match prompts",
                        ));
                    }
                    let response_bytes = responses
                        .iter()
                        .map(|response| response.as_bytes().to_vec())
                        .collect::<Vec<_>>();
                    KeyboardInteractiveResponse::new(response_bytes)
                        .and_then(|response| response.encode())
                        .map_err(|_| {
                            ClientError::InvalidInput("keyboard response count or size is invalid")
                        })?;
                    self.handle
                        .authenticate_keyboard_interactive_respond(responses)
                        .await
                        .map_err(ClientError::from)?
                }
            };
        }
    }

    /// Open an RFC 4254 `session` channel.
    pub async fn open_session(&self) -> Result<ClientChannel, ClientError> {
        let permit = self.channel_permit()?;
        self.handle
            .channel_open_session()
            .await
            .map(|channel| ClientChannel::new(channel, permit))
            .map_err(ClientError::from)
    }

    /// Open an RFC 4254 `direct-tcpip` channel through this connection.
    pub async fn open_direct_tcpip(
        &self,
        target_address: &str,
        target_port: u32,
        originator_address: &str,
        originator_port: u32,
    ) -> Result<ClientChannel, ClientError> {
        validate_text(target_address.as_bytes(), MAX_CLIENT_HOST, "target address", true)
            .map_err(ClientError::Config)?;
        validate_text(originator_address.as_bytes(), MAX_CLIENT_HOST, "originator address", true)
            .map_err(ClientError::Config)?;
        let permit = self.channel_permit()?;
        self.handle
            .channel_open_direct_tcpip(
                target_address.to_owned(),
                target_port,
                originator_address.to_owned(),
                originator_port,
            )
            .await
            .map(|channel| ClientChannel::new(channel, permit))
            .map_err(ClientError::from)
    }

    /// Open an RFC 4254 `direct-streamlocal@openssh.com` channel through this connection.
    pub async fn open_direct_streamlocal(
        &self,
        socket_path: &str,
    ) -> Result<ClientChannel, ClientError> {
        validate_text(socket_path.as_bytes(), MAX_CHANNEL_ADDRESS, "socket path", true)
            .map_err(ClientError::Config)?;
        let permit = self.channel_permit()?;
        self.handle
            .channel_open_direct_streamlocal(socket_path.to_owned())
            .await
            .map(|channel| ClientChannel::new(channel, permit))
            .map_err(ClientError::from)
    }

    /// Ask the server to listen for a remote TCP forwarding definition.
    ///
    /// A zero `port` asks the server to allocate an available port. An empty address follows
    /// RFC 4254 and asks the server to bind all suitable interfaces.
    pub async fn request_tcpip_forward(
        &self,
        address: &str,
        port: u32,
    ) -> Result<u32, ClientError> {
        self.require_authenticated()?;
        validate_text(address.as_bytes(), MAX_CHANNEL_ADDRESS, "forward address", false)
            .map_err(ClientError::Config)?;
        self.handle.tcpip_forward(address.to_owned(), port).await.map_err(ClientError::from)
    }

    /// Cancel a remote TCP forwarding definition.
    pub async fn cancel_tcpip_forward(&self, address: &str, port: u32) -> Result<(), ClientError> {
        self.require_authenticated()?;
        validate_text(address.as_bytes(), MAX_CHANNEL_ADDRESS, "forward address", false)
            .map_err(ClientError::Config)?;
        self.handle.cancel_tcpip_forward(address.to_owned(), port).await.map_err(ClientError::from)
    }

    /// Ask the server to listen for a remote Unix-socket forwarding definition.
    pub async fn request_streamlocal_forward(&self, socket_path: &str) -> Result<(), ClientError> {
        self.require_authenticated()?;
        validate_text(socket_path.as_bytes(), MAX_CHANNEL_ADDRESS, "socket path", true)
            .map_err(ClientError::Config)?;
        self.handle.streamlocal_forward(socket_path.to_owned()).await.map_err(ClientError::from)
    }

    /// Cancel a remote Unix-socket forwarding definition.
    pub async fn cancel_streamlocal_forward(&self, socket_path: &str) -> Result<(), ClientError> {
        self.require_authenticated()?;
        validate_text(socket_path.as_bytes(), MAX_CHANNEL_ADDRESS, "socket path", true)
            .map_err(ClientError::Config)?;
        self.handle
            .cancel_streamlocal_forward(socket_path.to_owned())
            .await
            .map_err(ClientError::from)
    }

    /// Wait for the next channel opened by the server for an active remote forwarding request.
    ///
    /// The queue is bounded by the configured channel limit.  When the caller does not drain
    /// it, new forwarded channels are rejected with `resource shortage` instead of accumulating
    /// unbounded channel state in the event loop.  `None` means that the SSH event loop closed.
    pub async fn next_forwarded_channel(&mut self) -> Option<ForwardedChannel> {
        self.forwarded_channels.recv().await
    }

    fn channel_permit(&self) -> Result<OwnedSemaphorePermit, ClientError> {
        self.require_authenticated()?;
        Arc::clone(&self.channel_slots)
            .try_acquire_owned()
            .map_err(|_| ClientError::ChannelLimitReached { max: self.channel_limit })
    }

    fn reject_if_authenticated(&self) -> Result<(), ClientError> {
        if self.authenticated.load(Ordering::Acquire) {
            Err(ClientError::AlreadyAuthenticated)
        } else {
            Ok(())
        }
    }

    fn require_authenticated(&self) -> Result<(), ClientError> {
        if self.authenticated.load(Ordering::Acquire) {
            Ok(())
        } else {
            Err(ClientError::NotAuthenticated)
        }
    }

    /// Close this SSH connection, including when surviving channels have blocked output.
    ///
    /// Allow up to one second for a protocol disconnect and engine shutdown. Then close the
    /// transport even if a peer window, a saturated queue, or surviving channels prevent progress.
    pub async fn disconnect(&self) -> Result<(), ClientError> {
        let mut stopped = self.stopped.clone();
        let result = async_timeout(Duration::from_secs(1), async {
            self.handle.disconnect(russh::Disconnect::ByApplication, "", "en").await?;
            let _ = stopped.wait_for(|stopped| *stopped).await;
            Ok::<_, russh::Error>(())
        })
        .await;
        self.transport_lifetime.lock().unwrap_or_else(std::sync::PoisonError::into_inner).take();
        result.unwrap_or(Ok(())).map_err(ClientError::from)
    }
}

/// Kind and peer metadata for a server-opened remote forwarding channel.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ForwardedChannelKind {
    /// A connection accepted by a remote TCP forwarding listener.
    Tcp {
        /// Address that accepted the forwarded connection.
        connected_address: String,
        /// Port that accepted the forwarded connection.
        connected_port: u32,
        /// Address reported by the remote originator.
        originator_address: String,
        /// Port reported by the remote originator.
        originator_port: u32,
    },
    /// A connection accepted by a remote Unix-socket forwarding listener.
    Streamlocal {
        /// Socket path that accepted the forwarded connection.
        socket_path: String,
    },
    /// An OpenSSH `auth-agent@openssh.com` channel opened by the server.
    Agent,
}

/// A bounded server-opened channel delivered for a remote forwarding listener.
///
/// The caller must consume the channel with [`Self::into_channel`] and then apply its own local
/// forwarding policy.  Dropping the value closes the engine channel and releases the shared
/// channel slot.
pub struct ForwardedChannel {
    channel: ClientChannel,
    kind: ForwardedChannelKind,
}

impl fmt::Debug for ForwardedChannel {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ForwardedChannel")
            .field("channel", &self.channel)
            .field("kind", &self.kind)
            .finish()
    }
}

impl ForwardedChannel {
    fn new(channel: ClientChannel, kind: ForwardedChannelKind) -> Self {
        Self { channel, kind }
    }

    /// Return the engine-local channel number for diagnostics and recorder correlation.
    #[must_use]
    pub fn id(&self) -> u32 {
        self.channel.id()
    }

    /// Return the bounded metadata supplied by the remote forwarding open.
    #[must_use]
    pub const fn kind(&self) -> &ForwardedChannelKind {
        &self.kind
    }

    /// Consume the wrapper and return the ordinary channel API.
    #[must_use]
    pub fn into_channel(self) -> ClientChannel {
        self.channel
    }

    /// Serve one server-opened `auth-agent@openssh.com` channel.
    ///
    /// The shared bounded adapter remains the sole request parser and applies the supplied
    /// fail-closed forwarding policy to every signature. Channel data is reassembled across russh
    /// fragments, bounded responses are written back to the same channel, and EOF or close is
    /// mapped to clean versus truncated agent-stream outcomes.
    pub async fn serve_agent<S, A>(
        mut self,
        server: AgentServer<S>,
        policy: AgentForwardingPolicy<A>,
    ) -> Result<(), ClientError>
    where
        S: AgentKeyStore,
        A: AgentForwardingAuthorizer,
    {
        if !matches!(self.kind, ForwardedChannelKind::Agent) {
            return Err(ClientError::InvalidInput("channel is not an auth-agent channel"));
        }
        let response_channel = self.channel.id();
        let mut adapter = AgentForwardingAdapter::new(server, policy, response_channel);
        loop {
            match self.channel.next_event().await? {
                Some(ChannelEvent::Data(data)) => {
                    for response in adapter.push(&data)? {
                        self.channel.send_data(&response.data).await?;
                    }
                }
                Some(ChannelEvent::Eof) => {
                    adapter.finish()?;
                    self.channel.close().await?;
                    return Ok(());
                }
                Some(ChannelEvent::Close) | None => {
                    adapter.finish()?;
                    return Ok(());
                }
                Some(_) => return Err(ClientError::UnexpectedChannelEvent),
            }
        }
    }
}

/// Peer events surfaced by a concrete SSH channel.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ChannelEvent {
    /// Standard channel data.
    Data(Vec<u8>),
    /// Extended channel data, normally standard error.
    ExtendedData { data_type: ExtendedDataType, data: Vec<u8> },
    /// The peer sent channel EOF.
    Eof,
    /// The peer sent channel close.
    Close,
    /// The remote process exited with a status.
    ExitStatus(u32),
    /// The remote process exited because of a signal.
    ExitSignal {
        /// Signal name without the `SIG` prefix.
        signal: String,
        /// Whether the remote process produced a core dump.
        core_dumped: bool,
        /// Remote diagnostic text.
        error_message: String,
        /// RFC 3066 language tag.
        language_tag: String,
    },
    /// A channel request succeeded.
    Success,
    /// A channel request failed.
    Failure,
    /// The peer refused a channel open request after the channel wrapper was created.
    OpenFailure { code: u32, reason: String },
}

/// A concrete session or forwarding channel.
pub struct ClientChannel {
    channel: russh::Channel<client::Msg>,
    permit: OwnedSemaphorePermit,
}

impl fmt::Debug for ClientChannel {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("ClientChannel").finish_non_exhaustive()
    }
}

impl ClientChannel {
    fn new(channel: russh::Channel<client::Msg>, permit: OwnedSemaphorePermit) -> Self {
        Self { channel, permit }
    }

    /// Return the engine-local channel number for diagnostics and recorder correlation.
    #[must_use]
    pub fn id(&self) -> u32 {
        self.channel.id().number()
    }

    /// Request a pseudo-terminal using the shared bounded PTY request shape.
    pub async fn request_pty(
        &self,
        request: &PtyRequest,
        want_reply: bool,
    ) -> Result<(), ClientError> {
        let term = str::from_utf8(&request.term)
            .map_err(|_| ClientError::InvalidInput("terminal type must be UTF-8"))?;
        validate_text(&request.term, MAX_CHANNEL_TEXT, "terminal type", true)
            .map_err(ClientError::Config)?;
        let modes = decode_terminal_modes(&request.modes)?;
        self.channel
            .request_pty(
                want_reply,
                term,
                request.columns,
                request.rows,
                request.pixel_width,
                request.pixel_height,
                &modes,
            )
            .await
            .map_err(ClientError::from)
    }

    /// Request the remote login shell.
    pub async fn request_shell(&self, want_reply: bool) -> Result<(), ClientError> {
        self.channel.request_shell(want_reply).await.map_err(ClientError::from)
    }

    /// Set one bounded remote environment variable before starting a session.
    pub async fn set_env(
        &self,
        name: &[u8],
        value: &[u8],
        want_reply: bool,
    ) -> Result<(), ClientError> {
        validate_text(name, MAX_CHANNEL_TEXT, "environment name", true)
            .map_err(ClientError::Config)?;
        validate_text(value, MAX_CHANNEL_TEXT, "environment value", false)
            .map_err(ClientError::Config)?;
        let name = str::from_utf8(name)
            .map_err(|_| ClientError::InvalidInput("environment name must be UTF-8"))?;
        let value = str::from_utf8(value)
            .map_err(|_| ClientError::InvalidInput("environment value must be UTF-8"))?;
        self.channel.set_env(want_reply, name, value).await.map_err(ClientError::from)
    }

    /// Send one RFC 4254 signal to the remote session.
    pub async fn signal(&self, signal: Signal) -> Result<(), ClientError> {
        self.channel.signal(to_russh_signal(signal)).await.map_err(ClientError::from)
    }

    /// Start a bounded subsystem on this session channel.
    pub async fn request_subsystem(&self, name: &str, want_reply: bool) -> Result<(), ClientError> {
        validate_text(name.as_bytes(), MAX_CHANNEL_TEXT, "subsystem", true)
            .map_err(ClientError::Config)?;
        self.channel.request_subsystem(want_reply, name).await.map_err(ClientError::from)
    }

    /// Request OpenSSH agent forwarding on this session channel.
    ///
    /// A requested reply is surfaced as [`ChannelEvent::Success`] or
    /// [`ChannelEvent::Failure`] by [`Self::next_event`]. The caller must enable
    /// a forwarded-agent service before using this request; forwarding remains
    /// disabled by default.
    pub async fn request_agent_forward(&self, want_reply: bool) -> Result<(), ClientError> {
        self.channel.agent_forward(want_reply).await.map_err(ClientError::from)
    }

    /// Notify the remote PTY of a bounded terminal resize.
    ///
    /// The dimensions use the same RFC 4254 `window-change` shape as the engine-independent
    /// channel codec. The four fields are fixed-width protocol values, so the request cannot
    /// allocate based on peer-controlled input.
    pub async fn window_change(&self, request: &WindowChangeRequest) -> Result<(), ClientError> {
        self.channel
            .window_change(request.columns, request.rows, request.pixel_width, request.pixel_height)
            .await
            .map_err(ClientError::from)
    }

    /// Execute one bounded remote command.
    pub async fn exec(&self, want_reply: bool, command: &[u8]) -> Result<(), ClientError> {
        validate_text(command, MAX_CHANNEL_TEXT, "command", true).map_err(ClientError::Config)?;
        self.channel.exec(want_reply, command.to_vec()).await.map_err(ClientError::from)
    }

    /// Send channel data in bounded packet-sized chunks.
    ///
    /// Each chunk is copied into the engine queue only after the previous chunk has been
    /// accepted. This keeps the caller-facing path bounded even when a large buffer is supplied.
    pub async fn send_data(&self, data: &[u8]) -> Result<(), ClientError> {
        for chunk in data.chunks(MAX_CHANNEL_STRING) {
            self.channel.data_bytes(chunk.to_vec()).await.map_err(ClientError::from)?;
        }
        Ok(())
    }

    /// Send channel EOF.
    pub async fn send_eof(&self) -> Result<(), ClientError> {
        self.channel.eof().await.map_err(ClientError::from)
    }

    /// Request channel close.
    pub async fn close(&self) -> Result<(), ClientError> {
        self.channel.close().await.map_err(ClientError::from)
    }

    /// Consume the channel as a bidirectional asynchronous byte stream.
    ///
    /// The stream carries `direct-tcpip` or session-subsystem data and lifecycle bytes. It is
    /// intended for [`ClientConnection::connect_stream`],
    /// [`ClientConnection::connect_via_direct_tcpip`], and framed subsystems such as SFTP.
    #[must_use]
    pub fn into_stream(self) -> ClientChannelStream {
        ClientChannelStream { inner: self.channel.into_stream(), _permit: self.permit }
    }

    /// Wait for the next peer event. `Ok(None)` means the engine closed the event stream.
    pub async fn next_event(&mut self) -> Result<Option<ChannelEvent>, ClientError> {
        loop {
            let Some(message) = self.channel.wait().await else {
                return Ok(None);
            };
            let event = match message {
                ChannelMsg::Data { data } => ChannelEvent::Data(data.to_vec()),
                ChannelMsg::ExtendedData { data, ext } => ChannelEvent::ExtendedData {
                    data_type: ExtendedDataType::try_from(ext)
                        .map_err(|_| ClientError::UnsupportedExtendedData(ext))?,
                    data: data.to_vec(),
                },
                ChannelMsg::Eof => ChannelEvent::Eof,
                ChannelMsg::Close => ChannelEvent::Close,
                ChannelMsg::ExitStatus { exit_status } => ChannelEvent::ExitStatus(exit_status),
                ChannelMsg::ExitSignal { signal_name, core_dumped, error_message, lang_tag } => {
                    exit_signal_event(&signal_name, core_dumped, error_message, lang_tag)?
                }
                ChannelMsg::Success => ChannelEvent::Success,
                ChannelMsg::Failure => ChannelEvent::Failure,
                ChannelMsg::OpenFailure(failure) => ChannelEvent::OpenFailure {
                    code: failure.code(),
                    reason: failure.description().to_owned(),
                },
                // Window updates and request echoes are consumed by the engine and are not
                // user-visible channel events.
                ChannelMsg::WindowAdjusted { .. }
                | ChannelMsg::RequestPty { .. }
                | ChannelMsg::RequestShell { .. }
                | ChannelMsg::Exec { .. }
                | ChannelMsg::Signal { .. }
                | ChannelMsg::RequestSubsystem { .. }
                | ChannelMsg::RequestX11 { .. }
                | ChannelMsg::SetEnv { .. }
                | ChannelMsg::WindowChange { .. }
                | ChannelMsg::AgentForward { .. }
                | ChannelMsg::XonXoff { .. }
                | ChannelMsg::Open { .. } => continue,
                _ => return Err(ClientError::UnexpectedChannelEvent),
            };
            return Ok(Some(event));
        }
    }
}

/// Opaque asynchronous stream backed by one SSH channel.
pub struct ClientChannelStream {
    inner: russh::ChannelStream<client::Msg>,
    _permit: OwnedSemaphorePermit,
}

impl fmt::Debug for ClientChannelStream {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("ClientChannelStream").finish_non_exhaustive()
    }
}

impl AsyncRead for ClientChannelStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(context, buffer)
    }
}

impl AsyncWrite for ClientChannelStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(context, buffer)
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(context)
    }
}

struct RusshSignerAdapter<'a, S: Signer + Sync> {
    signer: &'a S,
    identity: PublicKeyIdentity,
    username: String,
}

impl<S: Signer + Sync> RusshSignerAdapter<'_, S> {
    fn sign_request(
        &self,
        presented_key: &AgentIdentity,
        payload: Vec<u8>,
    ) -> Result<Vec<u8>, PublicKeyAuthError> {
        let presented_key = presented_key
            .public_key()
            .to_bytes()
            .map_err(|_| PublicKeyAuthError::MalformedPayload("presented public key"))?;
        if presented_key != self.identity.signing_key_blob() {
            return Err(PublicKeyAuthError::KeyMismatch);
        }
        let (context, identity) = decode_publickey_payload(&payload)?;
        if context.username() != self.username || context.service() != "ssh-connection" {
            return Err(PublicKeyAuthError::MalformedPayload("authentication context changed"));
        }
        if identity.algorithm() != self.identity.algorithm()
            || identity.key_blob() != self.identity.key_blob()
        {
            return Err(PublicKeyAuthError::KeyMismatch);
        }
        let request = PublicKeyAuthRequest::signed(context, self.identity.clone(), self.signer)?;
        if request.signature_payload() != payload {
            return Err(PublicKeyAuthError::MalformedPayload("session-bound payload changed"));
        }
        let signature = request
            .signature()
            .ok_or(PublicKeyAuthError::MalformedPayload("missing SSH signature"))?;
        let mut signed = payload;
        append_ssh_string(&mut signed, signature)?;
        Ok(signed)
    }
}

impl<S: Signer + Sync> RusshSigner for RusshSignerAdapter<'_, S> {
    type Error = PublicKeyAuthError;

    fn auth_sign(
        &mut self,
        key: &AgentIdentity,
        _hash_alg: Option<HashAlg>,
        to_sign: Vec<u8>,
    ) -> impl std::future::Future<Output = Result<Vec<u8>, Self::Error>> + Send {
        let result = self.sign_request(key, to_sign);
        async move { result }
    }
}

fn rsa_hash_algorithm(algorithm: SignatureAlgorithm) -> Option<HashAlg> {
    match algorithm {
        SignatureAlgorithm::RsaSha2_256 => Some(HashAlg::Sha256),
        SignatureAlgorithm::RsaSha2_512 => Some(HashAlg::Sha512),
        SignatureAlgorithm::Ed25519
        | SignatureAlgorithm::EcdsaSha2Nistp256
        | SignatureAlgorithm::EcdsaSha2Nistp384
        | SignatureAlgorithm::EcdsaSha2Nistp521
        | SignatureAlgorithm::SkEd25519
        | SignatureAlgorithm::SkEcdsaSha2Nistp256 => None,
    }
}

fn decode_publickey_payload(
    payload: &[u8],
) -> Result<(PublicKeyAuthContext, PublicKeyIdentity), PublicKeyAuthError> {
    if payload.len() > MAX_PUBLICKEY_AUTH_PAYLOAD {
        return Err(PublicKeyAuthError::MalformedPayload("payload is too large"));
    }
    let mut rest = payload;
    let session_id = read_ssh_string(&mut rest, "session identifier")?;
    let message = rest
        .first()
        .copied()
        .ok_or(PublicKeyAuthError::MalformedPayload("missing userauth message"))?;
    rest = &rest[1..];
    if message != USERAUTH_REQUEST {
        return Err(PublicKeyAuthError::MalformedPayload("unexpected userauth message"));
    }
    let username = read_ssh_string(&mut rest, "username")?;
    let service = read_ssh_string(&mut rest, "service")?;
    let method = read_ssh_string(&mut rest, "method")?;
    if method != b"publickey" {
        return Err(PublicKeyAuthError::MalformedPayload("unexpected authentication method"));
    }
    if rest.first().copied() != Some(1) {
        return Err(PublicKeyAuthError::MalformedPayload("unsigned public-key payload"));
    }
    rest = &rest[1..];
    let algorithm = read_ssh_string(&mut rest, "algorithm")?;
    let algorithm = str::from_utf8(algorithm)
        .map_err(|_| PublicKeyAuthError::MalformedPayload("algorithm is not UTF-8"))?;
    let key_blob = read_ssh_string(&mut rest, "public key")?;
    if !rest.is_empty() {
        return Err(PublicKeyAuthError::MalformedPayload("payload has trailing bytes"));
    }
    let username = str::from_utf8(username)
        .map_err(|_| PublicKeyAuthError::MalformedPayload("username is not UTF-8"))?;
    let service = str::from_utf8(service)
        .map_err(|_| PublicKeyAuthError::MalformedPayload("service is not UTF-8"))?;
    let context = PublicKeyAuthContext::new(session_id.to_vec(), username, service)
        .map_err(PublicKeyAuthError::Signer)?;
    let identity =
        PublicKeyIdentity::new(algorithm, key_blob.to_vec()).map_err(PublicKeyAuthError::Signer)?;
    Ok((context, identity))
}

fn read_ssh_string<'a>(
    input: &mut &'a [u8],
    field: &'static str,
) -> Result<&'a [u8], PublicKeyAuthError> {
    let length = input
        .get(..4)
        .ok_or(PublicKeyAuthError::MalformedPayload("truncated SSH string length"))?;
    let length = u32::from_be_bytes(
        length
            .try_into()
            .map_err(|_| PublicKeyAuthError::MalformedPayload("invalid SSH string length"))?,
    ) as usize;
    if length > MAX_PUBLICKEY_AUTH_PAYLOAD {
        return Err(PublicKeyAuthError::MalformedPayload(field));
    }
    let end = 4usize.checked_add(length).ok_or(PublicKeyAuthError::MalformedPayload(field))?;
    let value = input.get(4..end).ok_or(PublicKeyAuthError::MalformedPayload(field))?;
    *input = &input[end..];
    Ok(value)
}

fn append_ssh_string(output: &mut Vec<u8>, value: &[u8]) -> Result<(), PublicKeyAuthError> {
    let length = u32::try_from(value.len())
        .map_err(|_| PublicKeyAuthError::MalformedPayload("signature is too large"))?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}

struct ClientHandler {
    host: String,
    host_key_policy: HostKeyPolicy,
    verifier: Arc<dyn HostKeyVerifier + Send + Sync>,
    channel_slots: Arc<Semaphore>,
    forwarded_tx: mpsc::Sender<ForwardedChannel>,
    stopped: watch::Sender<bool>,
    #[cfg(test)]
    completed_key_exchanges: Arc<std::sync::atomic::AtomicUsize>,
    #[cfg(test)]
    completed_key_exchange_times: Arc<std::sync::Mutex<Vec<Instant>>>,
    #[cfg(test)]
    event_loop_stopped: Arc<std::sync::atomic::AtomicBool>,
}

impl Drop for ClientHandler {
    fn drop(&mut self) {
        self.stopped.send_replace(true);
        #[cfg(test)]
        self.event_loop_stopped.store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

impl ClientHandler {
    fn new(
        config: &ClientConfig,
        channel_slots: Arc<Semaphore>,
        forwarded_tx: mpsc::Sender<ForwardedChannel>,
        stopped: watch::Sender<bool>,
    ) -> Self {
        Self {
            host: config.host.clone(),
            host_key_policy: config.host_key_policy.clone(),
            verifier: Arc::clone(&config.verifier),
            channel_slots,
            forwarded_tx,
            stopped,
            #[cfg(test)]
            completed_key_exchanges: Arc::clone(&config.completed_key_exchanges),
            #[cfg(test)]
            completed_key_exchange_times: Arc::clone(&config.completed_key_exchange_times),
            #[cfg(test)]
            event_loop_stopped: Arc::clone(&config.event_loop_stopped),
        }
    }
}

impl ClientHandler {
    async fn deliver_forwarded_channel(
        &mut self,
        channel: russh::Channel<client::Msg>,
        kind: ForwardedChannelKind,
        reply: russh::client::ChannelOpenHandle,
    ) {
        let Ok(permit) = Arc::clone(&self.channel_slots).try_acquire_owned() else {
            reply.reject(russh::ChannelOpenFailure::ResourceShortage).await;
            return;
        };
        let forwarded = ForwardedChannel::new(ClientChannel::new(channel, permit), kind);
        if self.forwarded_tx.try_send(forwarded).is_err() {
            reply.reject(russh::ChannelOpenFailure::ResourceShortage).await;
            return;
        }
        reply.accept().await;
    }

    async fn reject_invalid_forwarded_channel(reply: russh::client::ChannelOpenHandle) {
        reply.reject(russh::ChannelOpenFailure::AdministrativelyProhibited).await;
    }

    #[allow(clippy::too_many_arguments)]
    async fn queue_forwarded_tcpip(
        &mut self,
        channel: russh::Channel<client::Msg>,
        connected_address: &str,
        connected_port: u32,
        originator_address: &str,
        originator_port: u32,
        reply: russh::client::ChannelOpenHandle,
    ) {
        if validate_text(
            connected_address.as_bytes(),
            MAX_CLIENT_HOST,
            "forwarded connected address",
            true,
        )
        .is_err()
            || validate_text(
                originator_address.as_bytes(),
                MAX_CLIENT_HOST,
                "forwarded originator address",
                true,
            )
            .is_err()
        {
            Self::reject_invalid_forwarded_channel(reply).await;
            return;
        }
        self.deliver_forwarded_channel(
            channel,
            ForwardedChannelKind::Tcp {
                connected_address: connected_address.to_owned(),
                connected_port,
                originator_address: originator_address.to_owned(),
                originator_port,
            },
            reply,
        )
        .await;
    }

    async fn queue_forwarded_streamlocal(
        &mut self,
        channel: russh::Channel<client::Msg>,
        socket_path: &str,
        reply: russh::client::ChannelOpenHandle,
    ) {
        if validate_text(socket_path.as_bytes(), MAX_CHANNEL_ADDRESS, "forwarded socket path", true)
            .is_err()
        {
            Self::reject_invalid_forwarded_channel(reply).await;
            return;
        }
        self.deliver_forwarded_channel(
            channel,
            ForwardedChannelKind::Streamlocal { socket_path: socket_path.to_owned() },
            reply,
        )
        .await;
    }

    #[allow(clippy::too_many_arguments)]
    async fn forwarded_tcpip_callback(
        &mut self,
        channel: russh::Channel<client::Msg>,
        connected_address: &str,
        connected_port: u32,
        originator_address: &str,
        originator_port: u32,
        reply: russh::client::ChannelOpenHandle,
    ) {
        self.queue_forwarded_tcpip(
            channel,
            connected_address,
            connected_port,
            originator_address,
            originator_port,
            reply,
        )
        .await;
    }

    async fn forwarded_streamlocal_callback(
        &mut self,
        channel: russh::Channel<client::Msg>,
        socket_path: &str,
        reply: russh::client::ChannelOpenHandle,
    ) {
        self.queue_forwarded_streamlocal(channel, socket_path, reply).await;
    }

    async fn forwarded_agent_callback(
        &mut self,
        channel: russh::Channel<client::Msg>,
        reply: russh::client::ChannelOpenHandle,
    ) {
        self.deliver_forwarded_channel(channel, ForwardedChannelKind::Agent, reply).await;
    }
}

impl Handler for ClientHandler {
    type Error = ClientError;

    async fn kex_done(
        &mut self,
        _shared_secret: Option<&[u8]>,
        _names: &russh::Names,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        #[cfg(test)]
        {
            self.completed_key_exchange_times
                .lock()
                .expect("exchange times lock")
                .push(Instant::now());
            self.completed_key_exchanges.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
        Ok(())
    }

    async fn disconnected(
        &mut self,
        reason: russh::client::DisconnectReason<Self::Error>,
    ) -> Result<(), Self::Error> {
        match reason {
            russh::client::DisconnectReason::ReceivedDisconnect(_) => Ok(()),
            russh::client::DisconnectReason::Error(error) => Err(error),
        }
    }

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        let encoded = match server_public_key {
            PublicKeyOrCertificate::PublicKey { key, .. } => key
                .to_bytes()
                .map_err(|_| ClientError::HostKey(HostKeyVerificationError::InvalidEncoding))?,
            PublicKeyOrCertificate::Certificate(certificate) => certificate
                .to_bytes()
                .map_err(|_| ClientError::HostKey(HostKeyVerificationError::InvalidEncoding))?,
        };
        let certificate_policy = CertificateValidationPolicy::host(
            &self.host_key_policy.expected_principal,
            self.host_key_policy.now,
        );
        verify_host_key(&self.host, &encoded, &certificate_policy, self.verifier.as_ref())
            .map(|_| true)
            .map_err(ClientError::HostKey)
    }

    async fn server_channel_open_forwarded_tcpip(
        &mut self,
        channel: russh::Channel<client::Msg>,
        connected_address: &str,
        connected_port: u32,
        originator_address: &str,
        originator_port: u32,
        reply: russh::client::ChannelOpenHandle,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        self.forwarded_tcpip_callback(
            channel,
            connected_address,
            connected_port,
            originator_address,
            originator_port,
            reply,
        )
        .await;
        Ok(())
    }

    async fn server_channel_open_forwarded_streamlocal(
        &mut self,
        channel: russh::Channel<client::Msg>,
        socket_path: &str,
        reply: russh::client::ChannelOpenHandle,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        self.forwarded_streamlocal_callback(channel, socket_path, reply).await;
        Ok(())
    }

    async fn server_channel_open_agent_forward(
        &mut self,
        channel: russh::Channel<client::Msg>,
        reply: russh::client::ChannelOpenHandle,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        self.forwarded_agent_callback(channel, reply).await;
        Ok(())
    }
}

fn decode_terminal_modes(input: &[u8]) -> Result<Vec<(Pty, u32)>, ClientError> {
    if input.is_empty() {
        return Err(ClientError::InvalidInput("terminal modes must end with TTY_OP_END"));
    }
    let mut modes = Vec::new();
    let mut offset = 0;
    while offset < input.len() {
        let opcode = input[offset];
        offset += 1;
        if opcode == 0 {
            if offset != input.len() {
                return Err(ClientError::InvalidInput("terminal modes have trailing bytes"));
            }
            return Ok(modes);
        }
        let end = offset
            .checked_add(4)
            .ok_or(ClientError::InvalidInput("terminal modes length overflow"))?;
        let value = input
            .get(offset..end)
            .ok_or(ClientError::InvalidInput("terminal mode value is truncated"))?;
        let pty = Pty::from_u8(opcode)
            .ok_or(ClientError::InvalidInput("terminal mode opcode is unsupported"))?;
        let value = u32::from_be_bytes([value[0], value[1], value[2], value[3]]);
        modes.push((pty, value));
        offset = end;
    }
    Err(ClientError::InvalidInput("terminal modes must end with TTY_OP_END"))
}

fn signal_name_text(signal: &russh::Sig) -> &str {
    match signal {
        russh::Sig::ABRT => "ABRT",
        russh::Sig::ALRM => "ALRM",
        russh::Sig::FPE => "FPE",
        russh::Sig::HUP => "HUP",
        russh::Sig::ILL => "ILL",
        russh::Sig::INT => "INT",
        russh::Sig::KILL => "KILL",
        russh::Sig::PIPE => "PIPE",
        russh::Sig::QUIT => "QUIT",
        russh::Sig::SEGV => "SEGV",
        russh::Sig::TERM => "TERM",
        russh::Sig::USR1 => "USR1",
        russh::Sig::Custom(name) => name,
    }
}

fn exit_signal_event(
    signal_name: &russh::Sig,
    core_dumped: bool,
    error_message: String,
    language_tag: String,
) -> Result<ChannelEvent, ClientError> {
    let signal = Signal::parse(signal_name_text(signal_name).as_bytes())
        .map_err(|_| ClientError::Protocol)?;
    validate_channel_text(error_message.as_bytes(), MAX_CHANNEL_TEXT, "error message", false)
        .map_err(|_| ClientError::Protocol)?;
    validate_channel_text(language_tag.as_bytes(), MAX_CHANNEL_NAME, "language tag", false)
        .map_err(|_| ClientError::Protocol)?;
    Ok(ChannelEvent::ExitSignal {
        signal: signal.name().to_owned(),
        core_dumped,
        error_message,
        language_tag,
    })
}

fn to_russh_signal(signal: Signal) -> russh::Sig {
    match signal {
        Signal::Abrt => russh::Sig::ABRT,
        Signal::Alrm => russh::Sig::ALRM,
        Signal::Fpe => russh::Sig::FPE,
        Signal::Hup => russh::Sig::HUP,
        Signal::Ill => russh::Sig::ILL,
        Signal::Int => russh::Sig::INT,
        Signal::Kill => russh::Sig::KILL,
        Signal::Pipe => russh::Sig::PIPE,
        Signal::Quit => russh::Sig::QUIT,
        Signal::Segv => russh::Sig::SEGV,
        Signal::Term => russh::Sig::TERM,
        Signal::Usr1 => russh::Sig::USR1,
        Signal::Usr2 => russh::Sig::Custom("USR2".to_owned()),
        Signal::Stop => russh::Sig::Custom("STOP".to_owned()),
        Signal::Tstp => russh::Sig::Custom("TSTP".to_owned()),
        Signal::Ttin => russh::Sig::Custom("TTIN".to_owned()),
        Signal::Ttou => russh::Sig::Custom("TTOU".to_owned()),
    }
}

fn validate_text(
    value: &[u8],
    limit: usize,
    field: &'static str,
    non_empty: bool,
) -> Result<(), ClientConfigError> {
    if value.len() > limit {
        return Err(ClientConfigError::FieldTooLarge(field));
    }
    if non_empty && value.is_empty() || value.contains(&0) {
        return Err(ClientConfigError::InvalidField(field));
    }
    Ok(())
}

fn unix_time_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, SocketAddr, TcpListener as StdTcpListener},
        thread,
    };

    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use russh::keys::PrivateKey;
    use scoplen_crypto::{Ed25519SigningKey, P256SigningKey};
    use ssh_key::{Algorithm, EcdsaCurve, certificate};
    use tokio::io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional, duplex};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::mpsc;
    use tokio::time::{Duration, timeout};

    use super::*;
    use crate::{
        AgentChannel, AgentClient, AgentError, AgentForwardingAuthorizer, AgentForwardingPolicy,
        AgentKeyStore, AgentMessage, AgentServer, AgentSshSigner, EcdsaSshSigner, Ed25519SshSigner,
        HostKey, P256SshSigner, ProxyError, ProxyOperation, ProxyProtocol, ProxyTransportError,
        RsaSshSigner,
    };

    #[tokio::test]
    async fn rsa_selection_success_and_terminal_failures_are_cached() {
        let mut success_cache = None;
        assert!(matches!(
            select_server_rsa_sha2(&mut success_cache, async { Ok(Some(Some(HashAlg::Sha512))) })
                .await,
            Ok(ServerRsaSha2Selection::Sha512)
        ));
        assert!(matches!(
            select_server_rsa_sha2(&mut success_cache, async { panic!("query repeated") }).await,
            Ok(ServerRsaSha2Selection::Sha512)
        ));

        let mut timeout_cache = None;
        assert!(matches!(
            select_server_rsa_sha2(&mut timeout_cache, std::future::pending()).await,
            Err(ClientError::RsaSelectionTimeout)
        ));
        assert!(matches!(
            select_server_rsa_sha2(&mut timeout_cache, async { panic!("query repeated") }).await,
            Err(ClientError::RsaSelectionTimeout)
        ));

        let mut engine_cache = None;
        assert!(matches!(
            select_server_rsa_sha2(&mut engine_cache, async { Err(russh::Error::SendError) }).await,
            Err(ClientError::RsaSelectionEngine)
        ));
        assert!(matches!(
            select_server_rsa_sha2(&mut engine_cache, async { panic!("query repeated") }).await,
            Err(ClientError::RsaSelectionEngine)
        ));
    }

    #[tokio::test]
    async fn cancelled_rsa_selection_keeps_interrupted_sentinel() {
        let mut cache = None;
        {
            let selection = select_server_rsa_sha2(&mut cache, std::future::pending());
            tokio::pin!(selection);
            tokio::select! {
                _ = &mut selection => panic!("pending query completed"),
                () = tokio::time::sleep(Duration::from_millis(10)) => {}
            }
        }
        assert!(matches!(
            select_server_rsa_sha2(&mut cache, async { panic!("query repeated") }).await,
            Err(ClientError::RsaSelectionInterrupted)
        ));
    }

    #[derive(Clone)]
    struct KeyboardServer {
        round: u8,
        accept_none: bool,
    }

    #[derive(Clone)]
    struct PublicKeyServer {
        expected_key: Vec<u8>,
    }

    struct SigningAgent {
        key: Ed25519SigningKey,
        key_blob: Vec<u8>,
    }

    impl AgentChannel for SigningAgent {
        fn exchange(&mut self, request: &[u8]) -> Result<Vec<u8>, AgentError> {
            let AgentMessage::SignRequest { key_blob, data, .. } =
                AgentMessage::decode_frame(request)?
            else {
                return Err(AgentError::UnexpectedResponse);
            };
            if key_blob != self.key_blob {
                return Err(AgentError::AgentFailure);
            }
            let signature = self.key.sign(&data);
            let mut ssh_signature = Vec::with_capacity(4 + 11 + 4 + signature.len());
            ssh_signature.extend_from_slice(&11_u32.to_be_bytes());
            ssh_signature.extend_from_slice(b"ssh-ed25519");
            ssh_signature.extend_from_slice(
                &(u32::try_from(signature.len()).expect("signature length")).to_be_bytes(),
            );
            ssh_signature.extend_from_slice(&signature);
            AgentMessage::SignResponse { signature: ssh_signature }.encode_frame()
        }
    }

    impl russh::server::Handler for PublicKeyServer {
        type Error = russh::Error;

        async fn auth_publickey(
            &mut self,
            _user: &str,
            key: &ssh_key::PublicKey,
        ) -> Result<russh::server::Auth, Self::Error> {
            let accepted = key.to_bytes().is_ok_and(|encoded| encoded == self.expected_key);
            Ok(if accepted { russh::server::Auth::Accept } else { russh::server::Auth::reject() })
        }

        async fn auth_openssh_certificate(
            &mut self,
            _user: &str,
            certificate: &ssh_key::Certificate,
        ) -> Result<russh::server::Auth, Self::Error> {
            let accepted = certificate.to_bytes().is_ok_and(|encoded| encoded == self.expected_key);
            Ok(if accepted { russh::server::Auth::Accept } else { russh::server::Auth::reject() })
        }
    }

    impl russh::server::Handler for KeyboardServer {
        type Error = russh::Error;

        async fn channel_open_session(
            &mut self,
            _channel: russh::Channel<russh::server::Msg>,
            reply: russh::server::ChannelOpenHandle,
            _session: &mut russh::server::Session,
        ) -> Result<(), Self::Error> {
            reply.accept().await;
            Ok(())
        }

        async fn data(
            &mut self,
            channel: russh::ChannelId,
            data: &[u8],
            session: &mut russh::server::Session,
        ) -> Result<(), Self::Error> {
            session.data(channel, data.to_vec())
        }

        async fn auth_none(&mut self, _user: &str) -> Result<russh::server::Auth, Self::Error> {
            if self.accept_none {
                return Ok(russh::server::Auth::Accept);
            }
            Ok(russh::server::Auth::Reject {
                proceed_with_methods: Some((&[russh::MethodKind::KeyboardInteractive][..]).into()),
                partial_success: false,
            })
        }

        async fn auth_keyboard_interactive<'a>(
            &'a mut self,
            user: &str,
            submethods: &str,
            response: Option<russh::server::Response<'a>>,
        ) -> Result<russh::server::Auth, Self::Error> {
            if user != "user" || submethods != "otp" {
                return Ok(russh::server::Auth::reject());
            }
            if let Some(mut response) = response {
                let expected =
                    if self.round == 0 { b"123456".as_slice() } else { b"yes".as_slice() };
                if response.next().is_none_or(|answer| answer.as_ref() != expected)
                    || response.next().is_some()
                {
                    return Ok(russh::server::Auth::reject());
                }
                if self.round == 1 {
                    return Ok(russh::server::Auth::Accept);
                }
                self.round += 1;
            }
            Ok(russh::server::Auth::Partial {
                name: Cow::Borrowed("Scoplen test"),
                instructions: Cow::Borrowed("Enter the one-time code"),
                prompts: if self.round == 0 {
                    Cow::Borrowed(&[(Cow::Borrowed("Code: "), false)])
                } else {
                    Cow::Borrowed(&[(Cow::Borrowed("Continue? "), true)])
                },
            })
        }
    }

    #[derive(Clone)]
    struct ResizeServer {
        changes: mpsc::Sender<WindowChangeRequest>,
    }

    impl russh::server::Handler for ResizeServer {
        type Error = russh::Error;

        async fn auth_password(
            &mut self,
            _user: &str,
            _password: &str,
        ) -> Result<russh::server::Auth, Self::Error> {
            Ok(russh::server::Auth::Accept)
        }

        async fn channel_open_session(
            &mut self,
            _channel: russh::Channel<russh::server::Msg>,
            reply: russh::server::ChannelOpenHandle,
            _session: &mut russh::server::Session,
        ) -> Result<(), Self::Error> {
            reply.accept().await;
            Ok(())
        }

        async fn window_change_request(
            &mut self,
            channel: russh::ChannelId,
            columns: u32,
            rows: u32,
            pixel_width: u32,
            pixel_height: u32,
            session: &mut russh::server::Session,
        ) -> Result<(), Self::Error> {
            let _ = self
                .changes
                .send(WindowChangeRequest { columns, rows, pixel_width, pixel_height })
                .await;
            let _ = session.channel_success(channel);
            Ok(())
        }

        async fn data(
            &mut self,
            channel: russh::ChannelId,
            data: &[u8],
            session: &mut russh::server::Session,
        ) -> Result<(), Self::Error> {
            session.data(channel, data.to_vec())
        }
    }

    #[derive(Clone)]
    struct JumpServer {
        allowed_host: &'static str,
        session_channels: Vec<russh::ChannelId>,
    }

    impl russh::server::Handler for JumpServer {
        type Error = russh::Error;

        async fn auth_password(
            &mut self,
            _user: &str,
            _password: &str,
        ) -> Result<russh::server::Auth, Self::Error> {
            Ok(russh::server::Auth::Accept)
        }

        async fn channel_open_session(
            &mut self,
            channel: russh::Channel<russh::server::Msg>,
            reply: russh::server::ChannelOpenHandle,
            _session: &mut russh::server::Session,
        ) -> Result<(), Self::Error> {
            self.session_channels.push(channel.id());
            reply.accept().await;
            Ok(())
        }

        async fn channel_open_direct_tcpip(
            &mut self,
            channel: russh::Channel<russh::server::Msg>,
            host_to_connect: &str,
            port_to_connect: u32,
            _originator_address: &str,
            _originator_port: u32,
            reply: russh::server::ChannelOpenHandle,
            _session: &mut russh::server::Session,
        ) -> Result<(), Self::Error> {
            if host_to_connect != self.allowed_host {
                reply.reject(russh::ChannelOpenFailure::AdministrativelyProhibited).await;
                return Ok(());
            }
            let Ok(port) = u16::try_from(port_to_connect) else {
                reply.reject(russh::ChannelOpenFailure::ConnectFailed).await;
                return Ok(());
            };
            let Ok(mut target) = TcpStream::connect(("127.0.0.1", port)).await else {
                reply.reject(russh::ChannelOpenFailure::ConnectFailed).await;
                return Ok(());
            };
            reply.accept().await;
            tokio::spawn(async move {
                let mut channel = channel.into_stream();
                let _ = copy_bidirectional(&mut channel, &mut target).await;
            });
            Ok(())
        }

        async fn data(
            &mut self,
            channel: russh::ChannelId,
            data: &[u8],
            session: &mut russh::server::Session,
        ) -> Result<(), Self::Error> {
            if self.session_channels.contains(&channel) {
                session.data(channel, data.to_vec())?;
            }
            Ok(())
        }
    }

    #[derive(Clone)]
    struct SessionRequestServer {
        environments: mpsc::Sender<(String, String)>,
        signals: mpsc::Sender<String>,
    }

    impl russh::server::Handler for SessionRequestServer {
        type Error = russh::Error;

        async fn auth_password(
            &mut self,
            _user: &str,
            _password: &str,
        ) -> Result<russh::server::Auth, Self::Error> {
            Ok(russh::server::Auth::Accept)
        }

        async fn channel_open_session(
            &mut self,
            _channel: russh::Channel<russh::server::Msg>,
            reply: russh::server::ChannelOpenHandle,
            _session: &mut russh::server::Session,
        ) -> Result<(), Self::Error> {
            reply.accept().await;
            Ok(())
        }

        async fn env_request(
            &mut self,
            channel: russh::ChannelId,
            variable_name: &str,
            variable_value: &str,
            session: &mut russh::server::Session,
        ) -> Result<(), Self::Error> {
            let _ =
                self.environments.send((variable_name.to_owned(), variable_value.to_owned())).await;
            session.channel_success(channel)?;
            Ok(())
        }

        async fn signal(
            &mut self,
            _channel: russh::ChannelId,
            signal: russh::Sig,
            _session: &mut russh::server::Session,
        ) -> Result<(), Self::Error> {
            let _ = self.signals.send(signal_name_text(&signal).to_owned()).await;
            Ok(())
        }
    }

    #[derive(Clone)]
    struct ExitSignalServer {
        signal: russh::Sig,
        core_dumped: bool,
        error_message: String,
        language_tag: String,
    }

    impl russh::server::Handler for ExitSignalServer {
        type Error = russh::Error;

        async fn auth_password(
            &mut self,
            _user: &str,
            _password: &str,
        ) -> Result<russh::server::Auth, Self::Error> {
            Ok(russh::server::Auth::Accept)
        }

        async fn channel_open_session(
            &mut self,
            _channel: russh::Channel<russh::server::Msg>,
            reply: russh::server::ChannelOpenHandle,
            _session: &mut russh::server::Session,
        ) -> Result<(), Self::Error> {
            reply.accept().await;
            Ok(())
        }

        async fn exec_request(
            &mut self,
            channel: russh::ChannelId,
            _data: &[u8],
            session: &mut russh::server::Session,
        ) -> Result<(), Self::Error> {
            session.exit_signal_request(
                channel,
                self.signal.clone(),
                self.core_dumped,
                &self.error_message,
                &self.language_tag,
            )?;
            Ok(())
        }
    }

    #[derive(Clone)]
    struct AgentForwardServer {
        allow: bool,
        requests: mpsc::Sender<bool>,
    }

    impl russh::server::Handler for AgentForwardServer {
        type Error = russh::Error;

        async fn auth_password(
            &mut self,
            _user: &str,
            _password: &str,
        ) -> Result<russh::server::Auth, Self::Error> {
            Ok(russh::server::Auth::Accept)
        }

        async fn channel_open_session(
            &mut self,
            _channel: russh::Channel<russh::server::Msg>,
            reply: russh::server::ChannelOpenHandle,
            _session: &mut russh::server::Session,
        ) -> Result<(), Self::Error> {
            reply.accept().await;
            Ok(())
        }

        async fn agent_request(
            &mut self,
            channel: russh::ChannelId,
            session: &mut russh::server::Session,
        ) -> Result<bool, Self::Error> {
            let _ = self.requests.send(self.allow).await;
            if self.allow {
                session.channel_success(channel)?;
            } else {
                session.channel_failure(channel)?;
            }
            Ok(self.allow)
        }
    }

    #[derive(Clone)]
    struct ForwardedAgentServer {
        responses: mpsc::Sender<Vec<u8>>,
    }

    impl russh::server::Handler for ForwardedAgentServer {
        type Error = russh::Error;

        async fn auth_password(
            &mut self,
            _user: &str,
            _password: &str,
        ) -> Result<russh::server::Auth, Self::Error> {
            Ok(russh::server::Auth::Accept)
        }

        async fn channel_open_session(
            &mut self,
            _channel: russh::Channel<russh::server::Msg>,
            reply: russh::server::ChannelOpenHandle,
            _session: &mut russh::server::Session,
        ) -> Result<(), Self::Error> {
            reply.accept().await;
            Ok(())
        }

        async fn agent_request(
            &mut self,
            channel: russh::ChannelId,
            session: &mut russh::server::Session,
        ) -> Result<bool, Self::Error> {
            session.channel_success(channel)?;
            let handle = session.handle();
            let responses = self.responses.clone();
            tokio::spawn(async move {
                let Ok(mut agent) = handle.channel_open_agent().await else {
                    return;
                };
                let Ok(request) = AgentMessage::RequestIdentities.encode_frame() else {
                    return;
                };
                if agent.data_bytes(request).await.is_err() {
                    return;
                }
                while let Some(message) = agent.wait().await {
                    match message {
                        russh::ChannelMsg::Data { data } => {
                            let _ = responses.send(data.to_vec()).await;
                            break;
                        }
                        russh::ChannelMsg::Eof | russh::ChannelMsg::Close => break,
                        _ => {}
                    }
                }
                let _ = agent.eof().await;
            });
            Ok(true)
        }
    }

    #[derive(Clone)]
    struct EmptyAgentStore;

    impl AgentKeyStore for EmptyAgentStore {
        fn identities(&self) -> Result<Vec<crate::AgentIdentity>, AgentError> {
            Ok(Vec::new())
        }

        fn sign(&self, _key_blob: &[u8], _data: &[u8], _flags: u32) -> Result<Vec<u8>, AgentError> {
            Err(AgentError::AgentFailure)
        }
    }

    struct AllowAgent;

    impl AgentForwardingAuthorizer for AllowAgent {
        fn authorize_signature(
            &self,
            _key_blob: &[u8],
            _data: &[u8],
            _flags: u32,
        ) -> Result<(), AgentError> {
            Ok(())
        }
    }

    #[derive(Clone)]
    struct DirectStreamlocalServer {
        paths: mpsc::Sender<String>,
    }

    impl russh::server::Handler for DirectStreamlocalServer {
        type Error = russh::Error;

        async fn auth_password(
            &mut self,
            _user: &str,
            _password: &str,
        ) -> Result<russh::server::Auth, Self::Error> {
            Ok(russh::server::Auth::Accept)
        }

        async fn channel_open_direct_streamlocal(
            &mut self,
            mut channel: russh::Channel<russh::server::Msg>,
            socket_path: &str,
            reply: russh::server::ChannelOpenHandle,
            _session: &mut russh::server::Session,
        ) -> Result<(), Self::Error> {
            let _ = self.paths.send(socket_path.to_owned()).await;
            reply.accept().await;
            tokio::spawn(async move {
                while let Some(message) = channel.wait().await {
                    match message {
                        russh::ChannelMsg::Data { data } => {
                            if channel.data_bytes(data).await.is_err() {
                                break;
                            }
                        }
                        russh::ChannelMsg::Eof => {
                            let _ = channel.eof().await;
                            break;
                        }
                        russh::ChannelMsg::Close => break,
                        _ => {}
                    }
                }
            });
            Ok(())
        }
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    enum ForwardEvent {
        Tcp { address: String, port: u32 },
        CancelTcp { address: String, port: u32 },
        Streamlocal { path: String },
        CancelStreamlocal { path: String },
    }

    #[derive(Clone)]
    struct ForwardServer {
        allow: bool,
        events: mpsc::Sender<ForwardEvent>,
    }

    impl russh::server::Handler for ForwardServer {
        type Error = russh::Error;

        async fn auth_password(
            &mut self,
            _user: &str,
            _password: &str,
        ) -> Result<russh::server::Auth, Self::Error> {
            Ok(russh::server::Auth::Accept)
        }

        async fn tcpip_forward(
            &mut self,
            address: &str,
            port: &mut u32,
            _session: &mut russh::server::Session,
        ) -> Result<bool, Self::Error> {
            if self.allow && *port == 0 {
                *port = 4242;
            }
            let _ = self
                .events
                .send(ForwardEvent::Tcp { address: address.to_owned(), port: *port })
                .await;
            Ok(self.allow)
        }

        async fn cancel_tcpip_forward(
            &mut self,
            address: &str,
            port: u32,
            _session: &mut russh::server::Session,
        ) -> Result<bool, Self::Error> {
            let _ = self
                .events
                .send(ForwardEvent::CancelTcp { address: address.to_owned(), port })
                .await;
            Ok(self.allow)
        }

        async fn streamlocal_forward(
            &mut self,
            socket_path: &str,
            _session: &mut russh::server::Session,
        ) -> Result<bool, Self::Error> {
            let _ =
                self.events.send(ForwardEvent::Streamlocal { path: socket_path.to_owned() }).await;
            Ok(self.allow)
        }

        async fn cancel_streamlocal_forward(
            &mut self,
            socket_path: &str,
            _session: &mut russh::server::Session,
        ) -> Result<bool, Self::Error> {
            let _ = self
                .events
                .send(ForwardEvent::CancelStreamlocal { path: socket_path.to_owned() })
                .await;
            Ok(self.allow)
        }
    }

    #[derive(Clone)]
    struct ForwardDeliveryServer {
        opened: mpsc::Sender<&'static str>,
    }

    impl russh::server::Handler for ForwardDeliveryServer {
        type Error = russh::Error;

        async fn auth_password(
            &mut self,
            _user: &str,
            _password: &str,
        ) -> Result<russh::server::Auth, Self::Error> {
            Ok(russh::server::Auth::Accept)
        }

        async fn channel_open_session(
            &mut self,
            _channel: russh::Channel<russh::server::Msg>,
            reply: russh::server::ChannelOpenHandle,
            _session: &mut russh::server::Session,
        ) -> Result<(), Self::Error> {
            reply.accept().await;
            Ok(())
        }

        async fn tcpip_forward(
            &mut self,
            _address: &str,
            _port: &mut u32,
            session: &mut russh::server::Session,
        ) -> Result<bool, Self::Error> {
            let handle = session.handle();
            let opened = self.opened.clone();
            tokio::spawn(async move {
                match handle.channel_open_forwarded_tcpip("127.0.0.1", 4242, "10.0.0.5", 5151).await
                {
                    Ok(channel) => {
                        let _ = opened.send("tcp").await;
                        let _ = channel.data(&b"forwarded tcp payload"[..]).await;
                        let _ = channel.eof().await;
                    }
                    Err(_) => {
                        let _ = opened.send("tcp-rejected").await;
                    }
                }
            });
            Ok(true)
        }

        async fn streamlocal_forward(
            &mut self,
            _socket_path: &str,
            session: &mut russh::server::Session,
        ) -> Result<bool, Self::Error> {
            let handle = session.handle();
            let opened = self.opened.clone();
            tokio::spawn(async move {
                let Ok(channel) =
                    handle.channel_open_forwarded_streamlocal("/run/scoplen-forward.sock").await
                else {
                    return;
                };
                let _ = opened.send("streamlocal").await;
                let _ = channel.data(&b"forwarded streamlocal payload"[..]).await;
                let _ = channel.eof().await;
            });
            Ok(true)
        }
    }

    #[derive(Clone, Copy)]
    enum RouteProxyKind {
        Socks5,
        HttpConnect,
    }

    async fn start_echo_server() -> (SocketAddr, tokio::task::JoinHandle<()>) {
        start_echo_server_with_control(None).await
    }

    async fn start_echo_server_with_control(
        control: Option<mpsc::Sender<russh::server::Handle>>,
    ) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let (changes, _received) = mpsc::channel(1);
        let mut server_config = russh::server::Config::default();
        server_config.keys.push(
            PrivateKey::random(
                &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
                Algorithm::Ed25519,
            )
            .expect("server key"),
        );
        let server_config = Arc::new(server_config);
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind SSH server");
        let address = listener.local_addr().expect("SSH server address");
        let task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept SSH client");
            let running =
                russh::server::run_stream(server_config, stream, ResizeServer { changes })
                    .await
                    .expect("start SSH server session");
            if let Some(control) = control {
                control.send(running.handle()).await.expect("send server handle");
            }
            let _ = running.await;
        });
        (address, task)
    }

    async fn start_jump_server(
        allowed_host: &'static str,
    ) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let mut server_config = russh::server::Config::default();
        server_config.keys.push(
            PrivateKey::random(
                &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
                Algorithm::Ed25519,
            )
            .expect("server key"),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind jump server");
        let address = listener.local_addr().expect("jump server address");
        let task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept jump client");
            let _ = russh::server::run_stream(
                Arc::new(server_config),
                stream,
                JumpServer { allowed_host, session_channels: Vec::new() },
            )
            .await;
        });
        (address, task)
    }

    async fn start_route_proxy(
        kind: RouteProxyKind,
        target: SocketAddr,
        expected_host: &'static str,
        expected_port: u16,
    ) -> (u16, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind proxy");
        let port = listener.local_addr().expect("proxy address").port();
        let task = tokio::spawn(async move {
            let (mut client, _) = listener.accept().await.expect("accept proxy client");
            match kind {
                RouteProxyKind::Socks5 => {
                    socks5_proxy_handshake(&mut client, expected_host, expected_port, 0).await;
                }
                RouteProxyKind::HttpConnect => {
                    http_connect_proxy_handshake(&mut client, expected_host, expected_port, 200)
                        .await;
                }
            }
            let mut target_stream = TcpStream::connect(target).await.expect("connect SSH target");
            let _ = copy_bidirectional(&mut client, &mut target_stream).await;
        });
        (port, task)
    }

    async fn start_reject_proxy(
        kind: RouteProxyKind,
        expected_host: &'static str,
        expected_port: u16,
    ) -> (u16, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind rejecting proxy");
        let port = listener.local_addr().expect("rejecting proxy address").port();
        let task = tokio::spawn(async move {
            let (mut client, _) = listener.accept().await.expect("accept rejecting proxy client");
            match kind {
                RouteProxyKind::Socks5 => {
                    socks5_proxy_handshake(&mut client, expected_host, expected_port, 5).await;
                }
                RouteProxyKind::HttpConnect => {
                    http_connect_proxy_handshake(&mut client, expected_host, expected_port, 407)
                        .await;
                }
            }
        });
        (port, task)
    }

    async fn start_stalled_ssh_proxy(
        kind: RouteProxyKind,
        expected_host: &'static str,
        expected_port: u16,
    ) -> (u16, mpsc::Receiver<()>, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind stalled proxy");
        let port = listener.local_addr().expect("stalled proxy address").port();
        let (ready, ready_rx) = mpsc::channel(1);
        let task = tokio::spawn(async move {
            let (mut client, _) = listener.accept().await.expect("accept stalled proxy client");
            match kind {
                RouteProxyKind::Socks5 => {
                    socks5_proxy_handshake(&mut client, expected_host, expected_port, 0).await;
                }
                RouteProxyKind::HttpConnect => {
                    http_connect_proxy_handshake(&mut client, expected_host, expected_port, 200)
                        .await;
                }
            }
            let mut banner = Vec::new();
            while !banner.ends_with(b"\n") {
                let mut byte = [0];
                client.read_exact(&mut byte).await.expect("client SSH banner");
                banner.push(byte[0]);
                assert!(banner.len() <= 255, "SSH banner is bounded");
            }
            assert!(banner.starts_with(b"SSH-2.0-"));
            client.write_all(b"SSH-2.0-stalled-proxy-test\r\n").await.expect("server SSH banner");
            let mut kex = [0];
            client.read_exact(&mut kex).await.expect("client key exchange started");
            let _ = ready.send(()).await;
            tokio::io::copy(&mut client, &mut tokio::io::sink()).await.expect("read until close");
        });
        (port, ready_rx, task)
    }

    async fn socks5_proxy_handshake(
        client: &mut TcpStream,
        expected_host: &str,
        expected_port: u16,
        reply_code: u8,
    ) {
        let mut greeting = [0; 2];
        client.read_exact(&mut greeting).await.expect("SOCKS greeting header");
        assert_eq!(greeting[0], 5);
        let mut methods = vec![0; usize::from(greeting[1])];
        client.read_exact(&mut methods).await.expect("SOCKS methods");
        assert!(methods.contains(&0), "route test requires no-auth SOCKS");
        client.write_all(&[5, 0]).await.expect("SOCKS method response");

        let mut header = [0; 4];
        client.read_exact(&mut header).await.expect("SOCKS request header");
        assert_eq!(header[..3], [5, 1, 0]);
        let host = match header[3] {
            1 => {
                let mut address = [0; 4];
                client.read_exact(&mut address).await.expect("SOCKS IPv4 address");
                IpAddr::from(address).to_string()
            }
            3 => {
                let mut length = [0; 1];
                client.read_exact(&mut length).await.expect("SOCKS domain length");
                let mut domain = vec![0; usize::from(length[0])];
                client.read_exact(&mut domain).await.expect("SOCKS domain");
                String::from_utf8(domain).expect("SOCKS domain text")
            }
            4 => {
                let mut address = [0; 16];
                client.read_exact(&mut address).await.expect("SOCKS IPv6 address");
                IpAddr::from(address).to_string()
            }
            address_type => panic!("unexpected SOCKS address type {address_type}"),
        };
        let mut port = [0; 2];
        client.read_exact(&mut port).await.expect("SOCKS target port");
        assert_eq!(host, expected_host);
        assert_eq!(u16::from_be_bytes(port), expected_port);
        client.write_all(&[5, reply_code, 0, 1, 0, 0, 0, 0, 0, 0]).await.expect("SOCKS response");
    }

    async fn http_connect_proxy_handshake(
        client: &mut TcpStream,
        expected_host: &str,
        expected_port: u16,
        status: u16,
    ) {
        let mut request = Vec::new();
        let mut byte = [0; 1];
        while !request.ends_with(b"\r\n\r\n") {
            client.read_exact(&mut byte).await.expect("HTTP CONNECT request");
            request.push(byte[0]);
            assert!(request.len() <= 4096, "HTTP CONNECT request is bounded");
        }
        let request = String::from_utf8(request).expect("HTTP CONNECT request text");
        assert!(
            request.starts_with(&format!("CONNECT {expected_host}:{expected_port} HTTP/1.1\r\n"))
        );
        let response = if status == 200 {
            "HTTP/1.1 200 Connection Established\r\n\r\n".to_owned()
        } else {
            format!("HTTP/1.1 {status} Proxy Rejected\r\n\r\n")
        };
        client.write_all(response.as_bytes()).await.expect("HTTP CONNECT response");
    }

    #[test]
    fn rekey_limits_validate_bounds_and_remain_per_host() {
        let config = ClientConfig::new("host.example", 22, |_host: &str, _key: &HostKey| Ok(()))
            .expect("client configuration");
        for (bytes, elapsed) in [
            (0, Duration::from_secs(1)),
            (DEFAULT_REKEY_WRITE_LIMIT + 1, Duration::from_secs(1)),
            (1, Duration::ZERO),
            (1, Duration::MAX),
        ] {
            assert!(matches!(
                config.clone().with_rekey_limits(bytes, elapsed),
                Err(ClientConfigError::InvalidRekeyLimits)
            ));
        }
        for bytes in [1, DEFAULT_REKEY_WRITE_LIMIT] {
            config.clone().with_rekey_limits(bytes, Duration::from_nanos(1)).expect("valid bounds");
        }
        for bytes in [0, DEFAULT_REKEY_READ_LIMIT + 1, usize::MAX] {
            assert!(matches!(
                config.clone().with_rekey_read_limit(bytes),
                Err(ClientConfigError::InvalidRekeyLimits)
            ));
        }
        for bytes in [1, DEFAULT_REKEY_READ_LIMIT] {
            config.clone().with_rekey_read_limit(bytes).expect("valid incoming bound");
        }
        let configured = config
            .clone()
            .with_rekey_limits(32 * 1024, Duration::from_secs(60))
            .expect("Host override")
            .with_rekey_read_limit(64 * 1024)
            .expect("incoming Host override")
            .clone()
            .russh_config()
            .limits;
        assert_eq!(configured.rekey_write_limit, 32 * 1024);
        assert_eq!(configured.rekey_read_limit, 64 * 1024);
        assert_eq!(configured.rekey_time_limit, Duration::from_secs(60));
        let defaults = config.russh_config().limits;
        assert_eq!(defaults.rekey_write_limit, DEFAULT_REKEY_WRITE_LIMIT);
        assert_eq!(defaults.rekey_read_limit, DEFAULT_REKEY_READ_LIMIT);
        assert_eq!(defaults.rekey_time_limit, DEFAULT_REKEY_TIME_LIMIT);
    }

    async fn assert_transfer_across_rekey(write_limit: usize, time_limit: Duration) {
        let deadline = Duration::from_secs(10);
        let (address, server) = start_echo_server().await;
        let config =
            ClientConfig::new("127.0.0.1", address.port(), |_host: &str, _key: &HostKey| Ok(()))
                .expect("client configuration")
                .with_rekey_limits(write_limit, time_limit)
                .expect("valid rekey limits");
        let completed = Arc::clone(&config.completed_key_exchanges);
        let mut connection = timeout(deadline, ClientConnection::connect(config))
            .await
            .expect("bounded SSH handshake")
            .expect("connect SSH client");
        assert_eq!(completed.load(Ordering::SeqCst), 1, "initial exchange completed");
        timeout(deadline, connection.authenticate_password("user", b"disposable-test-password"))
            .await
            .expect("bounded authentication")
            .expect("authenticate");
        let mut channel = timeout(deadline, connection.open_session())
            .await
            .expect("bounded session open")
            .expect("open session");
        let before = completed.load(Ordering::SeqCst);
        if time_limit < Duration::from_secs(1) {
            tokio::time::sleep(time_limit).await;
        }
        timeout(deadline, async {
            // The peer retains its default one-GiB/one-hour policy, so only the client can
            // initiate these exchanges. Check exact data on the same channel across a rekey.
            for marker in 0_u8..16 {
                let payload = vec![marker; 16 * 1024];
                channel.send_data(&payload).await.expect("send echo payload");
                let mut received = Vec::new();
                while received.len() < payload.len() {
                    match channel.next_event().await.expect("read echo").expect("channel open") {
                        ChannelEvent::Data(data) => received.extend_from_slice(&data),
                        event => panic!("unexpected echo event: {event:?}"),
                    }
                }
                assert_eq!(received, payload, "rekey preserves exact channel bytes");
            }
            while completed.load(Ordering::SeqCst) <= before {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("transfer and client-initiated rekey complete before deadline");
        connection.disconnect().await.expect("disconnect");
        timeout(deadline, server).await.expect("server exits").expect("server task");
    }

    #[tokio::test]
    async fn outgoing_byte_limit_rekeys_an_authenticated_session_without_data_loss() {
        assert_transfer_across_rekey(32 * 1024, DEFAULT_REKEY_TIME_LIMIT).await;
    }

    #[tokio::test]
    async fn elapsed_time_limit_rekeys_an_authenticated_session_without_data_loss() {
        assert_transfer_across_rekey(DEFAULT_REKEY_WRITE_LIMIT, Duration::from_millis(100)).await;
    }

    #[derive(Clone)]
    struct PushServer {
        channels: mpsc::Sender<russh::Channel<russh::server::Msg>>,
    }

    impl russh::server::Handler for PushServer {
        type Error = russh::Error;

        async fn auth_password(
            &mut self,
            _user: &str,
            _password: &str,
        ) -> Result<russh::server::Auth, Self::Error> {
            Ok(russh::server::Auth::Accept)
        }

        async fn channel_open_session(
            &mut self,
            channel: russh::Channel<russh::server::Msg>,
            reply: russh::server::ChannelOpenHandle,
            _session: &mut russh::server::Session,
        ) -> Result<(), Self::Error> {
            reply.accept().await;
            self.channels.send(channel).await.expect("test receiver remains open");
            Ok(())
        }
    }

    #[tokio::test]
    async fn incoming_only_bytes_rekey_reset_counters_and_preserve_channel_data() {
        let (channels, mut received_channels) = mpsc::channel(1);
        let mut server_config = russh::server::Config::default();
        server_config.keys.push(
            PrivateKey::random(
                &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
                Algorithm::Ed25519,
            )
            .expect("server key"),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind SSH server");
        let address = listener.local_addr().expect("server address");
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept client");
            let running =
                russh::server::run_stream(Arc::new(server_config), stream, PushServer { channels })
                    .await
                    .expect("server session");
            let _ = running.await;
        });
        let config =
            ClientConfig::new("127.0.0.1", address.port(), |_host: &str, _key: &HostKey| Ok(()))
                .expect("client configuration")
                .with_rekey_read_limit(32 * 1024)
                .expect("incoming rekey limit");
        let completed = Arc::clone(&config.completed_key_exchanges);
        let mut connection = ClientConnection::connect(config).await.expect("connect");
        connection
            .authenticate_password("user", b"disposable-test-password")
            .await
            .expect("authenticate");
        let mut channel = connection.open_session().await.expect("open channel");
        let mut server_channel = received_channels.recv().await.expect("server channel");
        timeout(Duration::from_secs(10), async {
            // No client application data is sent; the peer keeps its one-GiB/one-hour limits.
            // A small payload after each exchange must not inherit the previous read counter.
            for marker in 0_u8..2 {
                let baseline = completed.load(Ordering::SeqCst);
                for size in [8 * 1024, 32 * 1024] {
                    let payload = vec![marker; size];
                    server_channel.data_bytes(payload.clone()).await.expect("push data");
                    let mut received = Vec::new();
                    while received.len() < payload.len() {
                        match channel.next_event().await.expect("read data").expect("open channel")
                        {
                            ChannelEvent::Data(bytes) => received.extend_from_slice(&bytes),
                            event => panic!("unexpected channel event: {event:?}"),
                        }
                    }
                    assert_eq!(received, payload, "incoming rekey preserves exact bytes");
                    if size == 8 * 1024 {
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        assert_eq!(
                            completed.load(Ordering::SeqCst),
                            baseline,
                            "sub-threshold traffic does not rekey after counter reset"
                        );
                    }
                }
                wait_for_exchanges(&completed, baseline + 1).await;
            }
            let payload = b"same channel remains writable after incoming rekeys";
            channel.send_data(payload).await.expect("send after rekey");
            let received = loop {
                if let Some(russh::ChannelMsg::Data { data }) = server_channel.wait().await {
                    break data;
                }
            };
            assert_eq!(&received[..], payload);
        })
        .await
        .expect("incoming transfers and rekeys finish before deadline");
        connection.disconnect().await.expect("disconnect");
        drop(channel);
        drop(server_channel);
        timeout(Duration::from_secs(5), server).await.expect("server exits").expect("server task");
    }

    async fn wait_for_exchanges(completed: &AtomicUsize, count: usize) {
        timeout(Duration::from_secs(5), async {
            while completed.load(Ordering::SeqCst) < count {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("key exchange completed before deadline");
    }

    #[tokio::test]
    async fn idle_timer_rekeys_twice_and_preserves_open_channel_bytes() {
        let limit = Duration::from_millis(300);
        let (address, server) = start_echo_server().await;
        let config =
            ClientConfig::new("127.0.0.1", address.port(), |_host: &str, _key: &HostKey| Ok(()))
                .expect("client configuration")
                .with_rekey_limits(DEFAULT_REKEY_WRITE_LIMIT, limit)
                .expect("rekey limits");
        let completed = Arc::clone(&config.completed_key_exchanges);
        let exchange_times = Arc::clone(&config.completed_key_exchange_times);
        let mut connection = ClientConnection::connect(config).await.expect("connect SSH client");
        connection
            .authenticate_password("user", b"disposable-test-password")
            .await
            .expect("authenticate");
        let mut channel = connection.open_session().await.expect("open session");
        let baseline = completed.load(Ordering::SeqCst);
        wait_for_exchanges(&completed, baseline + 2).await;
        {
            let times = exchange_times.lock().expect("exchange times lock");
            assert!(
                times[baseline + 1].duration_since(times[baseline]) >= limit,
                "completed exchange restarts the idle timer"
            );
        }
        let payload = b"channel payload after two idle key exchanges";
        channel.send_data(payload).await.expect("send channel data");
        let mut received = Vec::new();
        while received.len() < payload.len() {
            match timeout(Duration::from_secs(5), channel.next_event())
                .await
                .expect("echo deadline")
                .expect("read echo")
                .expect("channel open")
            {
                ChannelEvent::Data(bytes) => received.extend_from_slice(&bytes),
                event => panic!("unexpected echo event: {event:?}"),
            }
        }
        assert_eq!(received, payload);
        connection.disconnect().await.expect("disconnect");
        timeout(Duration::from_secs(5), server).await.expect("server exits").expect("server task");
    }

    #[tokio::test]
    async fn outgoing_byte_rekey_restarts_idle_timer() {
        let limit = Duration::from_secs(2);
        let (address, server) = start_echo_server().await;
        let config =
            ClientConfig::new("127.0.0.1", address.port(), |_host: &str, _key: &HostKey| Ok(()))
                .expect("client configuration")
                .with_rekey_limits(8 * 1024, limit)
                .expect("rekey limits");
        let completed = Arc::clone(&config.completed_key_exchanges);
        let exchange_times = Arc::clone(&config.completed_key_exchange_times);
        let mut connection = ClientConnection::connect(config).await.expect("connect SSH client");
        connection
            .authenticate_password("user", b"disposable-test-password")
            .await
            .expect("authenticate");
        let mut channel = connection.open_session().await.expect("open session");
        let baseline = completed.load(Ordering::SeqCst);
        let payload = vec![0x55; 8 * 1024];
        channel.send_data(&payload).await.expect("send payload");
        let mut received = Vec::new();
        while received.len() < payload.len() {
            match timeout(Duration::from_secs(5), channel.next_event())
                .await
                .expect("echo deadline")
                .expect("read echo")
                .expect("channel open")
            {
                ChannelEvent::Data(bytes) => received.extend_from_slice(&bytes),
                event => panic!("unexpected echo event: {event:?}"),
            }
        }
        assert_eq!(received, payload);
        wait_for_exchanges(&completed, baseline + 1).await;
        wait_for_exchanges(&completed, baseline + 2).await;
        {
            let times = exchange_times.lock().expect("exchange times lock");
            assert!(
                times[baseline].duration_since(times[baseline - 1]) < limit,
                "outgoing bytes trigger the first exchange before the idle deadline"
            );
            assert!(
                times[baseline + 1].duration_since(times[baseline]) >= limit,
                "byte-triggered exchange restarts the idle timer"
            );
        }
        connection.disconnect().await.expect("disconnect");
        timeout(Duration::from_secs(5), server).await.expect("server exits").expect("server task");
    }

    #[tokio::test]
    async fn rekey_event_loop_stops_on_disconnect_drop_and_remote_disconnect() {
        for ending in 0..3 {
            let (control_tx, mut control_rx) = mpsc::channel(1);
            let (address, server) = start_echo_server_with_control(Some(control_tx)).await;
            let config = ClientConfig::new(
                "127.0.0.1",
                address.port(),
                |_host: &str, _key: &HostKey| Ok(()),
            )
            .expect("client configuration")
            .with_rekey_limits(DEFAULT_REKEY_WRITE_LIMIT, Duration::from_millis(100))
            .expect("rekey limits");
            let stopped = Arc::clone(&config.event_loop_stopped);
            let mut connection =
                ClientConnection::connect(config).await.expect("connect SSH client");
            connection
                .authenticate_password("user", b"disposable-test-password")
                .await
                .expect("authenticate");
            let channel = connection.open_session().await.expect("keep a channel handle alive");
            let stream =
                connection.open_session().await.expect("keep a channel stream alive").into_stream();
            match ending {
                0 => {
                    connection.disconnect().await.expect("disconnect");
                    drop(connection);
                    timeout(Duration::from_secs(5), server)
                        .await
                        .expect("server exits")
                        .expect("server task");
                }
                1 => {
                    drop(connection);
                    timeout(Duration::from_secs(5), server)
                        .await
                        .expect("server exits")
                        .expect("server task");
                }
                _ => {
                    let server_handle = control_rx.recv().await.expect("server session handle");
                    server_handle
                        .disconnect(russh::Disconnect::ByApplication, String::new(), String::new())
                        .await
                        .expect("server disconnect");
                    timeout(Duration::from_secs(5), server)
                        .await
                        .expect("server exits")
                        .expect("server task");
                    timeout(Duration::from_secs(5), async {
                        while !stopped.load(Ordering::SeqCst) {
                            tokio::task::yield_now().await;
                        }
                    })
                    .await
                    .expect("remote disconnect stops event loop");
                    drop(connection);
                }
            }
            timeout(Duration::from_secs(5), async {
                while !stopped.load(Ordering::SeqCst) {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("event loop stopped");
            drop(channel);
            drop(stream);
        }
    }

    #[tokio::test]
    async fn connection_shutdown_preserves_graceful_disconnect_and_cancels_blocked_streams() {
        for mode in 0..3 {
            let mut server_config = russh::server::Config::default();
            server_config.keys.push(
                PrivateKey::random(
                    &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
                    Algorithm::Ed25519,
                )
                .expect("server key"),
            );
            server_config.window_size = if mode == 0 { 2 * 1024 * 1024 } else { 0 };
            let (client_stream, server_stream) = duplex(64 * 1024);
            let (channels, mut opened) = mpsc::channel(1);
            let server = tokio::spawn(async move {
                russh::server::run_stream(
                    Arc::new(server_config),
                    server_stream,
                    PushServer { channels },
                )
                .await
                .expect("server session")
                .await
            });
            let config =
                ClientConfig::new("stream.example", 22, |_host: &str, _key: &HostKey| Ok(()))
                    .expect("client configuration");
            let stopped = Arc::clone(&config.event_loop_stopped);
            let mut connection =
                ClientConnection::connect_stream(config, client_stream).await.expect("connect");
            connection
                .authenticate_password("user", b"disposable-test-password")
                .await
                .expect("authenticate");
            let mut stream = connection.open_session().await.expect("channel").into_stream();
            let _server_channel = opened.recv().await.expect("server channel");
            {
                let write = stream.write_all(b"blocked by the peer receive window");
                tokio::pin!(write);
                if mode != 0 {
                    assert!(timeout(Duration::from_millis(50), &mut write).await.is_err());
                }
                if mode == 2 {
                    drop(connection);
                } else {
                    timeout(Duration::from_secs(2), connection.disconnect())
                        .await
                        .expect("disconnect is bounded")
                        .expect("disconnect");
                }
                timeout(Duration::from_secs(5), async {
                    while !stopped.load(Ordering::SeqCst) {
                        tokio::task::yield_now().await;
                    }
                })
                .await
                .expect("shutdown stops event loop with a retained stream");
            }
            let result = timeout(Duration::from_secs(5), server)
                .await
                .expect("peer session exits")
                .expect("server task");
            if mode == 0 {
                result.expect("peer receives protocol disconnect instead of abrupt EOF");
            }
            drop(stream);
        }
    }

    #[tokio::test]
    async fn rekey_event_loop_stops_when_transport_fails() {
        let (server_address, server) = start_echo_server().await;
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind relay");
        let relay_address = listener.local_addr().expect("relay address");
        let relay = tokio::spawn(async move {
            let (mut client, _) = listener.accept().await.expect("accept relay client");
            let mut upstream = TcpStream::connect(server_address).await.expect("connect server");
            let _ = copy_bidirectional(&mut client, &mut upstream).await;
        });
        let config =
            ClientConfig::new("127.0.0.1", relay_address.port(), |_host: &str, _key: &HostKey| {
                Ok(())
            })
            .expect("client configuration")
            .with_rekey_limits(DEFAULT_REKEY_WRITE_LIMIT, Duration::from_millis(100))
            .expect("rekey limits");
        let stopped = Arc::clone(&config.event_loop_stopped);
        let connection = ClientConnection::connect(config).await.expect("connect through relay");
        relay.abort();
        let _ = relay.await;
        timeout(Duration::from_secs(5), async {
            while !stopped.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("transport error stops event loop");
        drop(connection);
        timeout(Duration::from_secs(5), server).await.expect("server exits").expect("server task");
    }

    #[tokio::test]
    async fn expired_elapsed_limit_rekeys_after_delayed_authentication() {
        let (address, server) = start_echo_server().await;
        let config =
            ClientConfig::new("127.0.0.1", address.port(), |_host: &str, _key: &HostKey| Ok(()))
                .expect("client configuration")
                .with_rekey_limits(DEFAULT_REKEY_WRITE_LIMIT, Duration::from_millis(50))
                .expect("rekey limits");
        let completed = Arc::clone(&config.completed_key_exchanges);
        let mut connection = ClientConnection::connect(config).await.expect("connect SSH client");
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert_eq!(completed.load(Ordering::SeqCst), 1, "automatic rekey waits for authentication");
        timeout(
            Duration::from_secs(5),
            connection.authenticate_password("user", b"disposable-test-password"),
        )
        .await
        .expect("authentication deadline")
        .expect("authenticate after rekey");
        wait_for_exchanges(&completed, 2).await;
        connection.disconnect().await.expect("disconnect");
        timeout(Duration::from_secs(5), server).await.expect("server exits").expect("server task");
    }

    #[test]
    fn config_rejects_empty_host_and_zero_port() {
        let verifier = |_host: &str, _key: &HostKey| Ok(());
        assert!(matches!(
            ClientConfig::new("", 22, verifier),
            Err(ClientConfigError::InvalidField("host"))
        ));
        let verifier = |_host: &str, _key: &HostKey| Ok(());
        assert!(matches!(
            ClientConfig::new("example.test", 0, verifier),
            Err(ClientConfigError::InvalidPort)
        ));
        let verifier = |_host: &str, _key: &HostKey| Ok(());
        let config = ClientConfig::new("example.test", 22, verifier).expect("config");
        assert!(matches!(
            config.clone().with_channel_limit(0),
            Err(ClientConfigError::InvalidChannelLimit)
        ));
        assert!(matches!(
            config.with_channel_limit(MAX_CLIENT_CHANNEL_LIMIT + 1),
            Err(ClientConfigError::InvalidChannelLimit)
        ));
    }

    #[test]
    fn algorithm_policy_controls_russh_preference_lists() {
        let verifier = |_host: &str, _key: &HostKey| Ok(());
        let config = ClientConfig::new("example.test", 22, verifier).expect("config");
        let preferred = config.russh_config().preferred;
        assert!(preferred.kex.iter().any(|name| name.as_ref() == "curve25519-sha256"));
        assert!(!preferred.kex.iter().any(|name| name.as_ref() == "diffie-hellman-group14-sha256"));
        assert!(!preferred.cipher.iter().any(|name| name.as_ref() == "3des-cbc"));
        assert!(
            preferred
                .host_key_certificates
                .iter()
                .any(|algorithm| algorithm.to_certificate_type()
                    == "ssh-ed25519-cert-v01@openssh.com")
        );
        assert!(
            preferred
                .key
                .iter()
                .any(|algorithm| algorithm.as_str() == "sk-ssh-ed25519@openssh.com")
        );
        assert!(preferred.host_key_certificates.iter().any(|algorithm| {
            algorithm.to_certificate_type() == "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com"
        }));
        assert!(preferred.compression.iter().any(|name| name.as_ref() == "zlib@openssh.com"));

        let policy = HostAlgorithmPolicy::with_legacy(&[
            (AlgorithmCategory::KeyExchange, "diffie-hellman-group14-sha256"),
            (AlgorithmCategory::HostKey, "ssh-rsa"),
            (AlgorithmCategory::Cipher, "aes256-cbc"),
            (AlgorithmCategory::Cipher, "3des-cbc"),
            (AlgorithmCategory::Mac, "hmac-sha1"),
            (AlgorithmCategory::Compression, "zlib"),
        ])
        .expect("legacy policy");
        let preferred = config.with_algorithm_policy(policy).russh_config().preferred;
        let modern_kex = preferred
            .kex
            .iter()
            .position(|name| name.as_ref() == "curve25519-sha256")
            .expect("modern kex");
        let legacy_kex = preferred
            .kex
            .iter()
            .position(|name| name.as_ref() == "diffie-hellman-group14-sha256")
            .expect("legacy kex");
        assert!(modern_kex < legacy_kex);
        assert!(preferred.key.iter().any(|algorithm| algorithm.as_str() == "ssh-rsa"));
        assert!(preferred.cipher.iter().any(|name| name.as_ref() == "aes256-cbc"));
        assert!(preferred.cipher.iter().any(|name| name.as_ref() == "3des-cbc"));
        assert!(preferred.mac.iter().any(|name| name.as_ref() == "hmac-sha1"));
        assert!(preferred.compression.iter().any(|name| name.as_ref() == "zlib"));
    }

    #[test]
    fn terminal_modes_are_bounded_and_require_end_marker() {
        assert!(matches!(decode_terminal_modes(&[0]), Ok(modes) if modes.is_empty()));
        assert!(matches!(
            decode_terminal_modes(&[Pty::ECHO as u8, 0, 0, 0, 1, 0]),
            Ok(modes) if modes == vec![(Pty::ECHO, 1)]
        ));
        assert!(matches!(
            decode_terminal_modes(&[Pty::ECHO as u8, 0, 0]),
            Err(ClientError::InvalidInput("terminal mode value is truncated"))
        ));
        assert!(matches!(
            decode_terminal_modes(&[Pty::ECHO as u8, 0, 0, 0, 1]),
            Err(ClientError::InvalidInput("terminal modes must end with TTY_OP_END"))
        ));
    }

    #[tokio::test]
    async fn host_key_callback_validates_before_invoking_trust_callback() {
        let key = PrivateKey::random(
            &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
            Algorithm::Ed25519,
        )
        .expect("test key");
        let public_key = key.public_key().clone();
        let calls = Arc::new(AtomicUsize::new(0));
        let callback_calls = Arc::clone(&calls);
        let verifier = move |host: &str, presented: &HostKey| {
            assert_eq!(host, "host.example");
            assert!(matches!(presented, HostKey::Raw { .. }));
            callback_calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        };
        let config = ClientConfig::new("host.example", 22, verifier).expect("config");
        let (forwarded_tx, _forwarded_rx) = mpsc::channel(1);
        let (stopped, _receiver) = watch::channel(false);
        let mut handler =
            ClientHandler::new(&config, Arc::new(Semaphore::new(1)), forwarded_tx, stopped);
        assert!(
            handler
                .check_server_key(&PublicKeyOrCertificate::PublicKey {
                    key: public_key,
                    hash_alg: None,
                })
                .await
                .expect("callback accepts key")
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn connect_stream_reaches_server_banner_before_protocol_error() {
        let verifier = |_host: &str, _key: &HostKey| Ok(());
        let config = ClientConfig::new("host.example", 22, verifier).expect("config");
        let (client, mut peer) = duplex(128);
        let task =
            tokio::spawn(async move { ClientConnection::connect_stream(config, client).await });
        tokio::io::AsyncWriteExt::write_all(&mut peer, b"not-ssh\r\n").await.expect("write banner");
        drop(peer);
        let result =
            timeout(Duration::from_secs(5), task).await.expect("bounded handshake").expect("join");
        assert!(matches!(
            result,
            Err(ClientError::Protocol | ClientError::ConnectionClosed | ClientError::Transport(_))
        ));
    }

    #[tokio::test]
    async fn proxy_command_route_reaches_ssh_engine() {
        let verifier = |_host: &str, _key: &HostKey| Ok(());
        let config = ClientConfig::new("host.example", 22, verifier).expect("config");
        let (program, args) = proxy_command_echo();
        let result = timeout(
            Duration::from_secs(5),
            ClientConnection::connect_via_proxy_command(
                config,
                program,
                &args,
                Duration::from_secs(2),
            ),
        )
        .await
        .expect("bounded ProxyCommand handshake");
        assert!(matches!(
            result,
            Err(ClientError::Protocol | ClientError::ConnectionClosed | ClientError::Transport(_))
        ));
    }

    fn proxy_command_echo() -> (OsString, Vec<OsString>) {
        #[cfg(windows)]
        {
            (
                std::env::var_os("ComSpec").unwrap_or_else(|| OsString::from("cmd.exe")),
                vec![OsString::from("/C"), OsString::from("more")],
            )
        }
        #[cfg(not(windows))]
        {
            (OsString::from("/bin/sh"), vec![OsString::from("-c"), OsString::from("cat")])
        }
    }

    fn proxy_command_stalled_ssh() -> (OsString, Vec<OsString>) {
        #[cfg(windows)]
        {
            (
                OsString::from("powershell.exe"),
                vec![
                    OsString::from("-NoProfile"),
                    OsString::from("-NonInteractive"),
                    OsString::from("-Command"),
                    OsString::from(
                        "$null = [Console]::In.ReadLine(); [Console]::Out.WriteLine('SSH-2.0-stalled-proxy-command'); $null = [Console]::In.ReadToEnd()",
                    ),
                ],
            )
        }
        #[cfg(not(windows))]
        {
            (
                OsString::from("/bin/sh"),
                vec![
                    OsString::from("-c"),
                    OsString::from(
                        "IFS= read -r banner; printf 'SSH-2.0-stalled-proxy-command\\r\\n'; while IFS= read -r line; do :; done",
                    ),
                ],
            )
        }
    }

    #[tokio::test]
    async fn proxy_command_route_times_out_stalled_ssh_handshake() {
        let verifier = |_host: &str, _key: &HostKey| Ok(());
        let config = ClientConfig::new("host.example", 22, verifier).expect("config");
        let (program, args) = proxy_command_stalled_ssh();
        assert!(matches!(
            ClientConnection::connect_via_proxy_command(
                config.clone(),
                &program,
                &args,
                Duration::ZERO,
            )
            .await,
            Err(ClientError::InvalidInput("ProxyCommand handshake timeout must be non-zero"))
        ));

        let handshake_timeout = Duration::from_millis(250);
        let error = timeout(
            Duration::from_secs(5),
            ClientConnection::connect_via_proxy_command(config, program, &args, handshake_timeout),
        )
        .await
        .expect("ProxyCommand handshake deadline")
        .expect_err("stalled SSH handshake");
        assert!(matches!(
            error,
            ClientError::ProxyCommandHandshakeTimeout { timeout } if timeout == handshake_timeout
        ));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn canceling_proxy_command_handshake_stops_the_child() {
        let verifier = |_host: &str, _key: &HostKey| Ok(());
        let config = ClientConfig::new("host.example", 22, verifier).expect("config");
        let (program, args) = proxy_command_stalled_ssh();
        let connection = tokio::spawn(async move {
            ClientConnection::connect_via_proxy_command(
                config,
                program,
                &args,
                Duration::from_secs(5),
            )
            .await
        });
        tokio::time::sleep(Duration::from_millis(250)).await;
        connection.abort();
        assert!(
            timeout(Duration::from_secs(5), connection)
                .await
                .expect("cancellation completes")
                .expect_err("connection task was canceled")
                .is_cancelled()
        );
    }

    #[tokio::test]
    async fn gateway_stream_writes_prelude_before_ssh_handoff() {
        let verifier = |_host: &str, _key: &HostKey| Ok(());
        let config = ClientConfig::new("host.example", 22, verifier).expect("config");
        let hello = scoplen_api::gateway::GatewayClientHello::new(
            "header.payload.signature",
            "proof.body.signature",
        )
        .expect("hello");
        let expected = hello.clone();
        let (client, mut peer) = duplex(4096);
        let task = tokio::spawn(async move {
            ClientConnection::connect_via_gateway_stream(config, client, &hello).await
        });

        let mut prefix = [0; 4];
        peer.read_exact(&mut prefix).await.expect("gateway prefix");
        let body_length = u32::from_be_bytes(prefix) as usize;
        let mut body = vec![0; body_length];
        peer.read_exact(&mut body).await.expect("gateway body");
        let mut frame = prefix.to_vec();
        frame.extend_from_slice(&body);
        assert_eq!(
            scoplen_api::gateway::GatewayClientHello::from_frame(&frame).expect("frame"),
            expected
        );

        peer.write_all(b"not-ssh\r\n").await.expect("server banner");
        drop(peer);
        let result =
            timeout(Duration::from_secs(5), task).await.expect("bounded handoff").expect("join");
        assert!(matches!(
            result,
            Err(ClientError::Protocol | ClientError::ConnectionClosed | ClientError::Transport(_))
        ));
    }

    async fn keyboard_server(accept_none: bool) -> (ClientConnection, tokio::task::JoinHandle<()>) {
        let (connection, server, _) =
            keyboard_server_with_rekey(accept_none, DEFAULT_REKEY_TIME_LIMIT).await;
        (connection, server)
    }

    async fn keyboard_server_with_rekey(
        accept_none: bool,
        rekey_time_limit: Duration,
    ) -> (ClientConnection, tokio::task::JoinHandle<()>, Arc<AtomicUsize>) {
        let mut server_config = russh::server::Config::default();
        server_config.keys.push(
            PrivateKey::random(
                &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
                Algorithm::Ed25519,
            )
            .expect("server key"),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("server listener");
        let address = listener.local_addr().expect("server address");
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept client");
            let _ = russh::server::run_stream(
                Arc::new(server_config),
                stream,
                KeyboardServer { round: 0, accept_none },
            )
            .await;
        });
        let verifier = |_host: &str, _key: &HostKey| Ok(());
        let config = ClientConfig::new("127.0.0.1", address.port(), verifier)
            .expect("SSH config")
            .with_rekey_limits(DEFAULT_REKEY_WRITE_LIMIT, rekey_time_limit)
            .expect("rekey limits");
        let completed = Arc::clone(&config.completed_key_exchanges);
        (ClientConnection::connect(config).await.expect("connect client"), server, completed)
    }

    #[tokio::test]
    async fn keyboard_interactive_authenticates_and_bounds_responses() {
        let (mut connection, server) = keyboard_server(false).await;
        let calls = Arc::new(AtomicUsize::new(0));
        let callback_calls = Arc::clone(&calls);
        connection
            .authenticate_keyboard_interactive("user", Some("otp"), move |info| {
                callback_calls.fetch_add(1, Ordering::SeqCst);
                assert_eq!(info.prompts().len(), 1);
                let round = callback_calls.load(Ordering::SeqCst);
                if round == 1 {
                    assert_eq!(info.prompts()[0].text(), b"Code: ");
                    assert!(!info.prompts()[0].echo());
                    Ok(vec!["123456".to_owned()])
                } else {
                    assert_eq!(round, 2);
                    assert_eq!(info.prompts()[0].text(), b"Continue? ");
                    assert!(info.prompts()[0].echo());
                    Ok(vec!["yes".to_owned()])
                }
            })
            .await
            .expect("keyboard authentication");
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        connection.disconnect().await.expect("disconnect");
        server.await.expect("server task");

        let (mut connection, server) = keyboard_server(false).await;
        let error = connection
            .authenticate_keyboard_interactive("user", Some("otp"), |_| Ok(Vec::new()))
            .await
            .expect_err("wrong response count");
        assert!(matches!(
            error,
            ClientError::InvalidInput("keyboard response count does not match prompts")
        ));
        connection.disconnect().await.expect("disconnect");
        server.await.expect("server task");

        let (mut connection, server) = keyboard_server(false).await;
        let error = connection
            .authenticate_keyboard_interactive("user", Some("otp"), |_| {
                Ok(vec!["x".repeat(65_537)])
            })
            .await
            .expect_err("oversized response");
        assert!(matches!(
            error,
            ClientError::InvalidInput("keyboard response count or size is invalid")
        ));
        connection.disconnect().await.expect("disconnect");
        server.await.expect("server task");

        let (mut connection, server) = keyboard_server(false).await;
        let error = connection
            .authenticate_keyboard_interactive("user", Some("otp"), |_| {
                Ok(vec!["wrong".to_owned()])
            })
            .await
            .expect_err("rejected response");
        assert!(matches!(error, ClientError::AuthenticationRejected { .. }));
        connection.disconnect().await.expect("disconnect");
        server.await.expect("server task");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn keyboard_prompt_defers_automatic_rekey_until_authentication_completes() {
        let (mut connection, server, completed) =
            keyboard_server_with_rekey(false, Duration::from_millis(80)).await;
        let baseline = completed.load(Ordering::SeqCst);
        let observed = Arc::clone(&completed);
        timeout(
            Duration::from_secs(5),
            connection.authenticate_keyboard_interactive("user", Some("otp"), move |info| {
                if info.prompts()[0].text() == b"Code: " {
                    tokio::task::block_in_place(|| {
                        std::thread::sleep(Duration::from_millis(200));
                    });
                    assert_eq!(
                        observed.load(Ordering::SeqCst),
                        baseline,
                        "automatic rekey does not interrupt an authentication prompt"
                    );
                    Ok(vec!["123456".to_owned()])
                } else {
                    Ok(vec!["yes".to_owned()])
                }
            }),
        )
        .await
        .expect("authentication deadline")
        .expect("keyboard authentication after idle timeout");
        wait_for_exchanges(&completed, baseline + 1).await;
        let mut channel = connection.open_session().await.expect("open session");
        let payload = b"keyboard authentication after idle rekey";
        channel.send_data(payload).await.expect("send payload");
        let mut received = Vec::new();
        while received.len() < payload.len() {
            match timeout(Duration::from_secs(5), channel.next_event())
                .await
                .expect("channel deadline")
                .expect("read channel event")
                .expect("channel open")
            {
                ChannelEvent::Data(bytes) => received.extend_from_slice(&bytes),
                event => panic!("unexpected echo event: {event:?}"),
            }
        }
        assert_eq!(received, payload);
        connection.disconnect().await.expect("disconnect");
        server.await.expect("server task");
    }

    #[tokio::test]
    async fn none_probe_reports_advertised_methods_without_authenticating() {
        let (mut connection, server) = keyboard_server(false).await;
        let outcome = connection.probe_authentication("user").await.expect("none probe");
        assert_eq!(
            outcome,
            NoneAuthOutcome::Rejected {
                methods: vec!["keyboard-interactive".to_owned()],
                partial_success: false,
            }
        );
        connection
            .authenticate_keyboard_interactive("user", Some("otp"), |info| {
                if info.prompts()[0].text() == b"Code: " {
                    Ok(vec!["123456".to_owned()])
                } else {
                    Ok(vec!["yes".to_owned()])
                }
            })
            .await
            .expect("authenticate after probe");
        connection.disconnect().await.expect("disconnect");
        server.await.expect("server task");

        let (mut connection, server) = keyboard_server(true).await;
        assert_eq!(
            connection.probe_authentication("user").await.expect("accepted none probe"),
            NoneAuthOutcome::Authenticated
        );
        let channel = connection.open_session().await.expect("none-authenticated session");
        drop(channel);
        connection.disconnect().await.expect("disconnect");
        server.await.expect("server task");
    }

    async fn proxy_route_round_trip(kind: RouteProxyKind) {
        let (target, server_task) = start_echo_server().await;
        let (proxy_port, proxy_task) =
            start_route_proxy(kind, target, "target.example", target.port()).await;
        let verifier = |_host: &str, _key: &HostKey| Ok(());
        let config = ClientConfig::new("target.example", target.port(), verifier).expect("config");
        let mut connection = match kind {
            RouteProxyKind::Socks5 => timeout(
                Duration::from_secs(5),
                ClientConnection::connect_via_socks5(
                    config,
                    "127.0.0.1",
                    proxy_port,
                    None,
                    Duration::from_secs(2),
                ),
            )
            .await
            .expect("SOCKS route handshake")
            .expect("SOCKS route connection"),
            RouteProxyKind::HttpConnect => timeout(
                Duration::from_secs(5),
                ClientConnection::connect_via_http_connect(
                    config,
                    "127.0.0.1",
                    proxy_port,
                    None,
                    Duration::from_secs(2),
                ),
            )
            .await
            .expect("HTTP CONNECT route handshake")
            .expect("HTTP CONNECT route connection"),
        };
        connection.authenticate_password("user", b"password").await.expect("authenticate route");
        let mut channel = connection.open_session().await.expect("open route session");
        channel.send_data(b"proxy route payload").await.expect("send route payload");
        assert!(matches!(
            timeout(Duration::from_secs(5), channel.next_event())
                .await
                .expect("route response")
                .expect("route response result"),
            Some(ChannelEvent::Data(data)) if data == b"proxy route payload"
        ));
        channel.close().await.expect("close route session");
        drop(channel);
        connection.disconnect().await.expect("disconnect route connection");
        proxy_task.await.expect("proxy task");
        timeout(Duration::from_secs(5), server_task)
            .await
            .expect("SSH server task")
            .expect("SSH server");
    }

    #[tokio::test]
    async fn proxy_routes_complete_real_russh_handshake_and_data_round_trip() {
        proxy_route_round_trip(RouteProxyKind::Socks5).await;
        proxy_route_round_trip(RouteProxyKind::HttpConnect).await;
    }

    #[tokio::test]
    async fn channel_data_is_fragmented_before_engine_queueing() {
        let (target, server_task) = start_echo_server().await;
        let verifier = |_host: &str, _key: &HostKey| Ok(());
        let config = ClientConfig::new("127.0.0.1", target.port(), verifier).expect("SSH config");
        let mut connection = ClientConnection::connect(config).await.expect("connect client");
        connection.authenticate_password("user", b"password").await.expect("authenticate client");
        let mut channel = connection.open_session().await.expect("open session");
        let payload: Vec<u8> = (0..(MAX_CHANNEL_STRING * 2 + 17))
            .map(|index| u8::try_from(index % 251).expect("payload pattern fits in one byte"))
            .collect();
        channel.send_data(&payload).await.expect("send fragmented data");

        let mut received = Vec::with_capacity(payload.len());
        while received.len() < payload.len() {
            match timeout(Duration::from_secs(5), channel.next_event())
                .await
                .expect("echo response")
                .expect("echo event")
            {
                Some(ChannelEvent::Data(data)) => received.extend(data),
                Some(event) => panic!("unexpected echo event: {event:?}"),
                None => panic!("echo channel closed before all data arrived"),
            }
        }
        assert_eq!(received, payload);
        channel.close().await.expect("close session");
        connection.disconnect().await.expect("disconnect client");
        timeout(Duration::from_secs(5), server_task)
            .await
            .expect("SSH server task")
            .expect("SSH server");
    }

    #[tokio::test]
    async fn proxy_routes_map_rejection_and_socks_auth_downgrade() {
        for kind in [RouteProxyKind::Socks5, RouteProxyKind::HttpConnect] {
            let (proxy_port, proxy_task) = start_reject_proxy(kind, "target.example", 22).await;
            let verifier = |_host: &str, _key: &HostKey| Ok(());
            let config = ClientConfig::new("target.example", 22, verifier).expect("config");
            let error = match kind {
                RouteProxyKind::Socks5 => ClientConnection::connect_via_socks5(
                    config,
                    "127.0.0.1",
                    proxy_port,
                    None,
                    Duration::from_secs(2),
                )
                .await
                .expect_err("SOCKS route rejection"),
                RouteProxyKind::HttpConnect => ClientConnection::connect_via_http_connect(
                    config,
                    "127.0.0.1",
                    proxy_port,
                    None,
                    Duration::from_secs(2),
                )
                .await
                .expect_err("HTTP CONNECT route rejection"),
            };
            let expected = match kind {
                RouteProxyKind::Socks5 => {
                    ProxyError::Rejected { protocol: ProxyProtocol::Socks5, code: 5 }
                }
                RouteProxyKind::HttpConnect => {
                    ProxyError::Rejected { protocol: ProxyProtocol::HttpConnect, code: 407 }
                }
            };
            assert!(matches!(
                error,
                ClientError::Proxy(ProxyTransportError::Proxy(actual)) if actual == expected
            ));
            proxy_task.await.expect("rejecting proxy task");
        }

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind downgrade proxy");
        let proxy_port = listener.local_addr().expect("downgrade proxy address").port();
        let proxy_task = tokio::spawn(async move {
            let (mut client, _) = listener.accept().await.expect("accept downgrade client");
            let mut greeting = [0; 2];
            client.read_exact(&mut greeting).await.expect("downgrade greeting header");
            assert_eq!(greeting, [5, 1]);
            let mut method = [0; 1];
            client.read_exact(&mut method).await.expect("downgrade greeting method");
            assert_eq!(method, [2]);
            client.write_all(&[5, 0]).await.expect("downgrade response");
        });
        let credentials = ProxyCredentials::new("user", "pass").expect("proxy credentials");
        let verifier = |_host: &str, _key: &HostKey| Ok(());
        let config = ClientConfig::new("target.example", 22, verifier).expect("config");
        let error = ClientConnection::connect_via_socks5(
            config,
            "127.0.0.1",
            proxy_port,
            Some(&credentials),
            Duration::from_secs(2),
        )
        .await
        .expect_err("SOCKS credentials must not downgrade");
        assert!(matches!(
            error,
            ClientError::Proxy(ProxyTransportError::Proxy(ProxyError::Rejected {
                protocol: ProxyProtocol::Socks5,
                code: 0
            }))
        ));
        proxy_task.await.expect("downgrade proxy task");
    }

    #[tokio::test]
    async fn proxy_route_maps_handshake_timeout() {
        let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind timeout proxy");
        let proxy_port = listener.local_addr().expect("timeout proxy address").port();
        let proxy_task = thread::spawn(move || {
            let (_client, _) = listener.accept().expect("accept timeout client");
            thread::sleep(std::time::Duration::from_millis(500));
        });
        let verifier = |_host: &str, _key: &HostKey| Ok(());
        let config = ClientConfig::new("target.example", 22, verifier).expect("config");
        let error = ClientConnection::connect_via_http_connect(
            config,
            "127.0.0.1",
            proxy_port,
            None,
            Duration::from_millis(100),
        )
        .await
        .expect_err("HTTP CONNECT timeout");
        assert!(matches!(
            error,
            ClientError::Proxy(ProxyTransportError::Proxy(ProxyError::Io {
                protocol: ProxyProtocol::HttpConnect,
                operation: ProxyOperation::Read,
                kind: std::io::ErrorKind::TimedOut
            }))
        ));
        proxy_task.join().expect("timeout proxy task");
    }

    #[tokio::test]
    async fn proxy_routes_time_out_stalled_ssh_handshake_and_close_socket() {
        let handshake_timeout = Duration::from_millis(200);
        for kind in [RouteProxyKind::Socks5, RouteProxyKind::HttpConnect] {
            let (proxy_port, _ready, proxy_task) =
                start_stalled_ssh_proxy(kind, "target.example", 22).await;
            let verifier = |_host: &str, _key: &HostKey| Ok(());
            let config = ClientConfig::new("target.example", 22, verifier).expect("config");
            let error = timeout(Duration::from_secs(3), async {
                match kind {
                    RouteProxyKind::Socks5 => {
                        ClientConnection::connect_via_socks5(
                            config,
                            "127.0.0.1",
                            proxy_port,
                            None,
                            handshake_timeout,
                        )
                        .await
                    }
                    RouteProxyKind::HttpConnect => {
                        ClientConnection::connect_via_http_connect(
                            config,
                            "127.0.0.1",
                            proxy_port,
                            None,
                            handshake_timeout,
                        )
                        .await
                    }
                }
            })
            .await
            .expect("SSH handshake has a deadline")
            .expect_err("stalled SSH handshake");
            assert!(matches!(
                error,
                ClientError::ProxySshHandshakeTimeout { timeout } if timeout == handshake_timeout
            ));
            timeout(Duration::from_secs(3), proxy_task)
                .await
                .expect("SSH socket closes on timeout")
                .expect("stalled proxy task");
        }
    }

    #[tokio::test]
    async fn canceling_proxy_ssh_handshake_closes_spawned_engine_socket() {
        let (proxy_port, mut ready, proxy_task) =
            start_stalled_ssh_proxy(RouteProxyKind::Socks5, "target.example", 22).await;
        let verifier = |_host: &str, _key: &HostKey| Ok(());
        let config = ClientConfig::new("target.example", 22, verifier).expect("config");
        let connection = tokio::spawn(async move {
            ClientConnection::connect_via_socks5(
                config,
                "127.0.0.1",
                proxy_port,
                None,
                Duration::from_secs(5),
            )
            .await
        });
        timeout(Duration::from_secs(3), ready.recv())
            .await
            .expect("key exchange starts")
            .expect("stalled proxy signals key exchange");
        connection.abort();
        assert!(connection.await.expect_err("connection task was canceled").is_cancelled());
        timeout(Duration::from_secs(3), proxy_task)
            .await
            .expect("SSH socket closes on cancellation")
            .expect("stalled proxy task");
    }

    #[tokio::test]
    async fn window_change_forwards_bounded_dimensions() {
        let (changes, mut received) = mpsc::channel(1);
        let mut server_config = russh::server::Config::default();
        server_config.keys.push(
            PrivateKey::random(
                &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
                Algorithm::Ed25519,
            )
            .expect("server key"),
        );
        let server_config = Arc::new(server_config);
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind server");
        let address = listener.local_addr().expect("server address");
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept client");
            let _ =
                russh::server::run_stream(server_config, stream, ResizeServer { changes }).await;
        });

        let verifier = |_host: &str, _key: &HostKey| Ok(());
        let config = ClientConfig::new("127.0.0.1", address.port(), verifier).expect("config");
        let mut connection = ClientConnection::connect(config).await.expect("connect client");
        connection.authenticate_password("user", b"password").await.expect("authenticate client");
        let channel = connection.open_session().await.expect("open session");
        let expected = WindowChangeRequest {
            columns: u32::MAX,
            rows: u32::MAX - 1,
            pixel_width: u32::MAX - 2,
            pixel_height: u32::MAX - 3,
        };
        channel.window_change(&expected).await.expect("send resize");
        let observed = timeout(Duration::from_secs(5), received.recv())
            .await
            .expect("resize callback")
            .expect("resize event");
        assert_eq!(observed, expected);
        connection.disconnect().await.expect("disconnect client");
    }

    #[tokio::test]
    async fn session_environment_and_signal_requests_reach_server() {
        let (environment_tx, mut environments) = mpsc::channel(1);
        let (signal_tx, mut signals) = mpsc::channel(1);
        let mut server_config = russh::server::Config::default();
        server_config.keys.push(
            PrivateKey::random(
                &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
                Algorithm::Ed25519,
            )
            .expect("server key"),
        );
        let server_config = Arc::new(server_config);
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind server");
        let address = listener.local_addr().expect("server address");
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept client");
            let _ = russh::server::run_stream(
                server_config,
                stream,
                SessionRequestServer { environments: environment_tx, signals: signal_tx },
            )
            .await;
        });

        let verifier = |_host: &str, _key: &HostKey| Ok(());
        let config = ClientConfig::new("127.0.0.1", address.port(), verifier).expect("config");
        let mut connection = ClientConnection::connect(config).await.expect("connect client");
        connection.authenticate_password("user", b"password").await.expect("authenticate client");
        let mut channel = connection.open_session().await.expect("open session");

        channel.set_env(b"LANG", b"C.UTF-8", true).await.expect("set environment");
        assert_eq!(
            timeout(Duration::from_secs(5), environments.recv())
                .await
                .expect("environment callback")
                .expect("environment event"),
            ("LANG".to_owned(), "C.UTF-8".to_owned())
        );
        assert_eq!(
            timeout(Duration::from_secs(5), channel.next_event())
                .await
                .expect("environment response")
                .expect("environment response result")
                .expect("environment response event"),
            ChannelEvent::Success
        );

        channel.signal(Signal::Tstp).await.expect("send signal");
        assert_eq!(
            timeout(Duration::from_secs(5), signals.recv())
                .await
                .expect("signal callback")
                .expect("signal event"),
            "TSTP"
        );
        connection.disconnect().await.expect("disconnect client");
    }

    async fn peer_exit_signal_event(
        exit_signal: ExitSignalServer,
    ) -> Result<Option<ChannelEvent>, ClientError> {
        let mut server_config = russh::server::Config::default();
        server_config.keys.push(
            PrivateKey::random(
                &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
                Algorithm::Ed25519,
            )
            .expect("server key"),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind server");
        let address = listener.local_addr().expect("server address");
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept client");
            let _ = russh::server::run_stream(Arc::new(server_config), stream, exit_signal).await;
        });

        let verifier = |_host: &str, _key: &HostKey| Ok(());
        let config = ClientConfig::new("127.0.0.1", address.port(), verifier).expect("config");
        let mut connection = ClientConnection::connect(config).await.expect("connect client");
        connection.authenticate_password("user", b"password").await.expect("authenticate client");
        let mut channel = connection.open_session().await.expect("open session");
        channel.exec(false, b"exit").await.expect("request exit signal");
        let event = timeout(Duration::from_secs(5), channel.next_event())
            .await
            .expect("exit-signal response");
        connection.disconnect().await.expect("disconnect client");
        server.await.expect("server task");
        event
    }

    #[tokio::test]
    async fn peer_exit_signal_uses_shared_channel_boundary() {
        let event = peer_exit_signal_event(ExitSignalServer {
            signal: russh::Sig::Custom("USR2".to_owned()),
            core_dumped: true,
            error_message: "interrupted".to_owned(),
            language_tag: "en".to_owned(),
        })
        .await
        .expect("valid exit signal");
        assert_eq!(
            event,
            Some(ChannelEvent::ExitSignal {
                signal: "USR2".to_owned(),
                core_dumped: true,
                error_message: "interrupted".to_owned(),
                language_tag: "en".to_owned(),
            })
        );

        for exit_signal in [
            ExitSignalServer {
                signal: russh::Sig::Custom("INVALID".to_owned()),
                core_dumped: false,
                error_message: String::new(),
                language_tag: String::new(),
            },
            ExitSignalServer {
                signal: russh::Sig::TERM,
                core_dumped: false,
                error_message: "bad\0diagnostic".to_owned(),
                language_tag: String::new(),
            },
            ExitSignalServer {
                signal: russh::Sig::TERM,
                core_dumped: false,
                error_message: String::new(),
                language_tag: "bad\0language".to_owned(),
            },
            ExitSignalServer {
                signal: russh::Sig::TERM,
                core_dumped: false,
                error_message: String::new(),
                language_tag: "x".repeat(MAX_CHANNEL_NAME + 1),
            },
        ] {
            assert!(matches!(
                peer_exit_signal_event(exit_signal).await,
                Err(ClientError::Protocol)
            ));
        }
    }

    #[test]
    fn peer_exit_signal_rejects_oversized_diagnostic() {
        assert!(matches!(
            exit_signal_event(
                &russh::Sig::TERM,
                false,
                "x".repeat(MAX_CHANNEL_TEXT + 1),
                String::new()
            ),
            Err(ClientError::Protocol)
        ));
    }

    async fn agent_forward_request_case(allow: bool) -> ChannelEvent {
        let (requests, mut received) = mpsc::channel(1);
        let mut server_config = russh::server::Config::default();
        server_config.keys.push(
            PrivateKey::random(
                &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
                Algorithm::Ed25519,
            )
            .expect("server key"),
        );
        let server_config = Arc::new(server_config);
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind server");
        let address = listener.local_addr().expect("server address");
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept client");
            let _ = russh::server::run_stream(
                server_config,
                stream,
                AgentForwardServer { allow, requests },
            )
            .await;
        });

        let verifier = |_host: &str, _key: &HostKey| Ok(());
        let config = ClientConfig::new("127.0.0.1", address.port(), verifier).expect("config");
        let mut connection = ClientConnection::connect(config).await.expect("connect client");
        connection.authenticate_password("user", b"password").await.expect("authenticate client");
        let mut channel = connection.open_session().await.expect("open session");
        channel.request_agent_forward(true).await.expect("request agent forwarding");
        assert_eq!(
            timeout(Duration::from_secs(5), received.recv())
                .await
                .expect("agent request callback")
                .expect("agent request event"),
            allow
        );
        let event = timeout(Duration::from_secs(5), channel.next_event())
            .await
            .expect("agent request response")
            .expect("agent request response result")
            .expect("agent request response event");
        connection.disconnect().await.expect("disconnect client");
        event
    }

    #[tokio::test]
    async fn agent_forward_request_surfaces_server_success_and_failure() {
        assert_eq!(agent_forward_request_case(true).await, ChannelEvent::Success);
        assert_eq!(agent_forward_request_case(false).await, ChannelEvent::Failure);
    }

    #[tokio::test]
    async fn forwarded_agent_channel_uses_bounded_adapter_and_returns_response() {
        let (responses, mut received) = mpsc::channel(1);
        let mut server_config = russh::server::Config::default();
        server_config.keys.push(
            PrivateKey::random(
                &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
                Algorithm::Ed25519,
            )
            .expect("server key"),
        );
        let server_config = Arc::new(server_config);
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind server");
        let address = listener.local_addr().expect("server address");
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept client");
            let _ = russh::server::run_stream(
                server_config,
                stream,
                ForwardedAgentServer { responses },
            )
            .await;
        });

        let verifier = |_host: &str, _key: &HostKey| Ok(());
        let config = ClientConfig::new("127.0.0.1", address.port(), verifier).expect("config");
        let mut connection = ClientConnection::connect(config).await.expect("connect client");
        connection.authenticate_password("user", b"password").await.expect("authenticate client");
        let channel = connection.open_session().await.expect("open session");
        channel.request_agent_forward(true).await.expect("request agent forwarding");

        let forwarded = timeout(Duration::from_secs(5), connection.next_forwarded_channel())
            .await
            .expect("forwarded channel callback")
            .expect("forwarded agent channel");
        assert_eq!(forwarded.kind(), &ForwardedChannelKind::Agent);
        forwarded
            .serve_agent(
                AgentServer::new(EmptyAgentStore),
                AgentForwardingPolicy::enabled(AllowAgent),
            )
            .await
            .expect("serve forwarded agent");

        let response = timeout(Duration::from_secs(5), received.recv())
            .await
            .expect("agent response")
            .expect("agent response frame");
        assert_eq!(
            AgentMessage::decode_frame(&response).expect("decode response"),
            AgentMessage::IdentitiesAnswer { identities: Vec::new() }
        );
        connection.disconnect().await.expect("disconnect client");
    }

    #[tokio::test]
    async fn direct_streamlocal_channel_round_trips_bounded_path_and_data() {
        let (paths, mut received) = mpsc::channel(1);
        let mut server_config = russh::server::Config::default();
        server_config.keys.push(
            PrivateKey::random(
                &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
                Algorithm::Ed25519,
            )
            .expect("server key"),
        );
        let server_config = Arc::new(server_config);
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind server");
        let address = listener.local_addr().expect("server address");
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept client");
            let _ =
                russh::server::run_stream(server_config, stream, DirectStreamlocalServer { paths })
                    .await;
        });

        let verifier = |_host: &str, _key: &HostKey| Ok(());
        let config = ClientConfig::new("127.0.0.1", address.port(), verifier).expect("config");
        let mut connection = ClientConnection::connect(config).await.expect("connect client");
        connection.authenticate_password("user", b"password").await.expect("authenticate client");
        let mut channel = connection
            .open_direct_streamlocal("/run/scoplen.sock")
            .await
            .expect("open direct streamlocal");
        assert_eq!(
            timeout(Duration::from_secs(5), received.recv())
                .await
                .expect("streamlocal open callback")
                .expect("streamlocal path"),
            "/run/scoplen.sock"
        );
        channel.send_data(b"streamlocal payload").await.expect("send streamlocal data");
        assert!(matches!(
            timeout(Duration::from_secs(5), channel.next_event())
                .await
                .expect("streamlocal response")
                .expect("streamlocal response result"),
            Some(ChannelEvent::Data(bytes)) if bytes == b"streamlocal payload"
        ));
        channel.close().await.expect("close streamlocal channel");
        connection.disconnect().await.expect("disconnect client");
    }

    async fn connect_forward_server(
        allow: bool,
    ) -> (ClientConnection, mpsc::Receiver<ForwardEvent>) {
        let (events, received) = mpsc::channel(8);
        let mut server_config = russh::server::Config::default();
        server_config.keys.push(
            PrivateKey::random(
                &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
                Algorithm::Ed25519,
            )
            .expect("server key"),
        );
        let server_config = Arc::new(server_config);
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind server");
        let address = listener.local_addr().expect("server address");
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept client");
            let _ =
                russh::server::run_stream(server_config, stream, ForwardServer { allow, events })
                    .await;
        });

        let verifier = |_host: &str, _key: &HostKey| Ok(());
        let config = ClientConfig::new("127.0.0.1", address.port(), verifier).expect("config");
        let mut connection = ClientConnection::connect(config).await.expect("connect client");
        connection.authenticate_password("user", b"password").await.expect("authenticate client");
        (connection, received)
    }

    #[tokio::test]
    async fn remote_forward_requests_round_trip_and_fail_closed() {
        let (connection, mut events) = connect_forward_server(true).await;
        assert_eq!(
            connection
                .request_tcpip_forward("127.0.0.1", 0)
                .await
                .expect("allocate remote TCP port"),
            4242
        );
        assert_eq!(
            timeout(Duration::from_secs(5), events.recv())
                .await
                .expect("TCP forward callback")
                .expect("TCP forward event"),
            ForwardEvent::Tcp { address: "127.0.0.1".to_owned(), port: 4242 }
        );
        connection
            .cancel_tcpip_forward("127.0.0.1", 4242)
            .await
            .expect("cancel remote TCP forward");
        assert_eq!(
            timeout(Duration::from_secs(5), events.recv())
                .await
                .expect("TCP cancel callback")
                .expect("TCP cancel event"),
            ForwardEvent::CancelTcp { address: "127.0.0.1".to_owned(), port: 4242 }
        );
        connection
            .request_streamlocal_forward("/run/scoplen.sock")
            .await
            .expect("create remote streamlocal forward");
        assert_eq!(
            timeout(Duration::from_secs(5), events.recv())
                .await
                .expect("streamlocal forward callback")
                .expect("streamlocal forward event"),
            ForwardEvent::Streamlocal { path: "/run/scoplen.sock".to_owned() }
        );
        connection
            .cancel_streamlocal_forward("/run/scoplen.sock")
            .await
            .expect("cancel remote streamlocal forward");
        assert_eq!(
            timeout(Duration::from_secs(5), events.recv())
                .await
                .expect("streamlocal cancel callback")
                .expect("streamlocal cancel event"),
            ForwardEvent::CancelStreamlocal { path: "/run/scoplen.sock".to_owned() }
        );
        connection.disconnect().await.expect("disconnect client");

        let (connection, mut events) = connect_forward_server(false).await;
        assert!(matches!(
            connection.request_tcpip_forward("127.0.0.1", 0).await,
            Err(ClientError::Channel)
        ));
        assert_eq!(
            timeout(Duration::from_secs(5), events.recv())
                .await
                .expect("rejected TCP callback")
                .expect("rejected TCP event"),
            ForwardEvent::Tcp { address: "127.0.0.1".to_owned(), port: 0 }
        );
        assert!(matches!(
            connection.cancel_tcpip_forward("127.0.0.1", 4242).await,
            Err(ClientError::Channel)
        ));
        assert_eq!(
            timeout(Duration::from_secs(5), events.recv())
                .await
                .expect("rejected TCP cancel callback")
                .expect("rejected TCP cancel event"),
            ForwardEvent::CancelTcp { address: "127.0.0.1".to_owned(), port: 4242 }
        );
        assert!(matches!(
            connection.request_streamlocal_forward("/run/scoplen.sock").await,
            Err(ClientError::Channel)
        ));
        assert_eq!(
            timeout(Duration::from_secs(5), events.recv())
                .await
                .expect("rejected streamlocal callback")
                .expect("rejected streamlocal event"),
            ForwardEvent::Streamlocal { path: "/run/scoplen.sock".to_owned() }
        );
        assert!(matches!(
            connection.cancel_streamlocal_forward("/run/scoplen.sock").await,
            Err(ClientError::Channel)
        ));
        assert_eq!(
            timeout(Duration::from_secs(5), events.recv())
                .await
                .expect("rejected streamlocal cancel callback")
                .expect("rejected streamlocal cancel event"),
            ForwardEvent::CancelStreamlocal { path: "/run/scoplen.sock".to_owned() }
        );
        connection.disconnect().await.expect("disconnect client");
    }

    #[tokio::test]
    async fn forwarded_tcpip_and_streamlocal_channels_are_delivered_with_metadata_and_data() {
        let (opened, mut opened_events) = mpsc::channel(2);
        let mut server_config = russh::server::Config::default();
        server_config.keys.push(
            PrivateKey::random(
                &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
                Algorithm::Ed25519,
            )
            .expect("server key"),
        );
        let server_config = Arc::new(server_config);
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind server");
        let address = listener.local_addr().expect("server address");
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept client");
            let _ =
                russh::server::run_stream(server_config, stream, ForwardDeliveryServer { opened })
                    .await;
        });

        let verifier = |_host: &str, _key: &HostKey| Ok(());
        let config = ClientConfig::new("127.0.0.1", address.port(), verifier).expect("config");
        let mut connection = ClientConnection::connect(config).await.expect("connect client");
        connection.authenticate_password("user", b"password").await.expect("authenticate");

        connection.request_tcpip_forward("127.0.0.1", 4242).await.expect("request TCP forwarding");
        assert_eq!(
            timeout(Duration::from_secs(5), opened_events.recv())
                .await
                .expect("TCP channel opened")
                .expect("TCP open event"),
            "tcp"
        );
        let forwarded = timeout(Duration::from_secs(5), connection.next_forwarded_channel())
            .await
            .expect("TCP forwarded channel")
            .expect("TCP forwarded channel remains open");
        assert!(matches!(
            forwarded.kind(),
            ForwardedChannelKind::Tcp {
                connected_address,
                connected_port: 4242,
                originator_address,
                originator_port: 5151,
            } if connected_address == "127.0.0.1" && originator_address == "10.0.0.5"
        ));
        let mut channel = forwarded.into_channel();
        assert!(matches!(
            timeout(Duration::from_secs(5), channel.next_event())
                .await
                .expect("TCP data")
                .expect("TCP data result"),
            Some(ChannelEvent::Data(data)) if data == b"forwarded tcp payload"
        ));
        assert_eq!(
            timeout(Duration::from_secs(5), channel.next_event())
                .await
                .expect("TCP EOF")
                .expect("TCP EOF result"),
            Some(ChannelEvent::Eof)
        );
        drop(channel);

        connection
            .request_streamlocal_forward("/run/scoplen-forward.sock")
            .await
            .expect("request streamlocal forwarding");
        assert_eq!(
            timeout(Duration::from_secs(5), opened_events.recv())
                .await
                .expect("streamlocal channel opened")
                .expect("streamlocal open event"),
            "streamlocal"
        );
        let forwarded = timeout(Duration::from_secs(5), connection.next_forwarded_channel())
            .await
            .expect("streamlocal forwarded channel")
            .expect("streamlocal forwarded channel remains open");
        assert_eq!(
            forwarded.kind(),
            &ForwardedChannelKind::Streamlocal {
                socket_path: "/run/scoplen-forward.sock".to_owned()
            }
        );
        let mut channel = forwarded.into_channel();
        assert!(matches!(
            timeout(Duration::from_secs(5), channel.next_event())
                .await
                .expect("streamlocal data")
                .expect("streamlocal data result"),
            Some(ChannelEvent::Data(data)) if data == b"forwarded streamlocal payload"
        ));
        assert_eq!(
            timeout(Duration::from_secs(5), channel.next_event())
                .await
                .expect("streamlocal EOF")
                .expect("streamlocal EOF result"),
            Some(ChannelEvent::Eof)
        );
        connection.disconnect().await.expect("disconnect client");
    }

    #[tokio::test]
    async fn forwarded_channel_respects_the_shared_channel_limit() {
        let (opened, mut opened_events) = mpsc::channel(1);
        let mut server_config = russh::server::Config::default();
        server_config.keys.push(
            PrivateKey::random(
                &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
                Algorithm::Ed25519,
            )
            .expect("server key"),
        );
        let server_config = Arc::new(server_config);
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind server");
        let address = listener.local_addr().expect("server address");
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept client");
            let _ =
                russh::server::run_stream(server_config, stream, ForwardDeliveryServer { opened })
                    .await;
        });

        let verifier = |_host: &str, _key: &HostKey| Ok(());
        let config = ClientConfig::new("127.0.0.1", address.port(), verifier)
            .expect("config")
            .with_channel_limit(1)
            .expect("channel limit");
        let mut connection = ClientConnection::connect(config).await.expect("connect client");
        connection.authenticate_password("user", b"password").await.expect("authenticate");
        let session = connection.open_session().await.expect("reserve channel slot");
        connection.request_tcpip_forward("127.0.0.1", 4242).await.expect("request TCP forwarding");
        assert_eq!(
            timeout(Duration::from_secs(5), opened_events.recv())
                .await
                .expect("rejection event")
                .expect("rejection event remains open"),
            "tcp-rejected"
        );
        assert!(
            timeout(Duration::from_millis(100), connection.next_forwarded_channel()).await.is_err(),
            "a channel rejected for a full quota must not reach the delivery queue"
        );
        drop(session);
        connection.disconnect().await.expect("disconnect client");
    }

    #[tokio::test]
    async fn one_connection_multiplexes_and_bounds_independent_channels() {
        let (changes, _received) = mpsc::channel(1);
        let mut server_config = russh::server::Config::default();
        server_config.keys.push(
            PrivateKey::random(
                &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
                Algorithm::Ed25519,
            )
            .expect("server key"),
        );
        let server_config = Arc::new(server_config);
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind server");
        let address = listener.local_addr().expect("server address");
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept client");
            let _ =
                russh::server::run_stream(server_config, stream, ResizeServer { changes }).await;
        });

        let verifier = |_host: &str, _key: &HostKey| Ok(());
        let config = ClientConfig::new("127.0.0.1", address.port(), verifier)
            .expect("config")
            .with_channel_limit(2)
            .expect("channel limit");
        let mut connection = ClientConnection::connect(config).await.expect("connect client");
        connection.authenticate_password("user", b"password").await.expect("authenticate client");

        let mut first = connection.open_session().await.expect("first channel");
        let mut second = connection.open_session().await.expect("second channel");
        assert_ne!(first.id(), second.id());
        assert!(matches!(
            connection.open_session().await,
            Err(ClientError::ChannelLimitReached { max: 2 })
        ));
        assert!(matches!(
            connection.open_direct_tcpip("example.test", 22, "127.0.0.1", 1).await,
            Err(ClientError::ChannelLimitReached { max: 2 })
        ));

        first.send_data(b"first").await.expect("send first");
        second.send_data(b"second").await.expect("send second");
        assert!(matches!(
            timeout(Duration::from_secs(5), first.next_event()).await.expect("first response"),
            Ok(Some(ChannelEvent::Data(bytes))) if bytes == b"first"
        ));
        assert!(matches!(
            timeout(Duration::from_secs(5), second.next_event()).await.expect("second response"),
            Ok(Some(ChannelEvent::Data(bytes))) if bytes == b"second"
        ));

        drop(first);
        let rejected = timeout(
            Duration::from_secs(5),
            connection.open_direct_tcpip("example.test", 22, "127.0.0.1", 1),
        )
        .await
        .expect("direct channel rejection");
        assert!(matches!(rejected, Err(ClientError::ChannelOpen { .. })));
        let third = connection.open_session().await.expect("slot released on channel drop");
        drop(third);
        let stream = second.into_stream();
        let extra = connection.open_session().await.expect("one stream still reserves one slot");
        assert!(matches!(
            connection.open_session().await,
            Err(ClientError::ChannelLimitReached { max: 2 })
        ));
        drop(stream);
        let fourth = connection.open_session().await.expect("stream drop releases slot");
        drop(fourth);
        drop(extra);
        connection.disconnect().await.expect("disconnect client");
    }

    async fn assert_channel_echo(channel: &mut ClientChannel, payload: &[u8]) {
        channel.send_data(payload).await.expect("send channel data");
        assert!(matches!(
            timeout(Duration::from_secs(5), channel.next_event()).await.expect("channel echo"),
            Ok(Some(ChannelEvent::Data(data))) if data == payload
        ));
    }

    #[tokio::test]
    async fn two_hop_jump_chain_handles_data_failures_and_channel_reuse() {
        let (target_address, target_server) = start_echo_server().await;
        let (second_address, second_server) = start_jump_server("target.test").await;
        let (first_address, first_server) = start_jump_server("hop-b.test").await;
        let verifier = |_host: &str, _key: &HostKey| Ok(());

        let first_config = ClientConfig::new("127.0.0.1", first_address.port(), verifier)
            .expect("first-hop config")
            .with_channel_limit(2)
            .expect("first-hop channel limit");
        let mut first = ClientConnection::connect(first_config).await.expect("connect first hop");
        first.authenticate_password("user", b"password").await.expect("authenticate first hop");

        let second_config = ClientConfig::new("hop-b.test", second_address.port(), verifier)
            .expect("second-hop config")
            .with_channel_limit(2)
            .expect("second-hop channel limit");
        let mut second = timeout(
            Duration::from_secs(5),
            ClientConnection::connect_via_direct_tcpip(second_config, &first, "127.0.0.1", 5000),
        )
        .await
        .expect("second-hop handshake")
        .expect("connect second hop");
        second.authenticate_password("user", b"password").await.expect("authenticate second hop");

        let target_config = ClientConfig::new("target.test", target_address.port(), verifier)
            .expect("target config");
        let mut target = timeout(
            Duration::from_secs(5),
            ClientConnection::connect_via_direct_tcpip(target_config, &second, "127.0.0.1", 5001),
        )
        .await
        .expect("target handshake")
        .expect("connect target");
        target.authenticate_password("user", b"password").await.expect("authenticate target");

        let mut target_channel = target.open_session().await.expect("target session");
        assert_channel_echo(&mut target_channel, b"through two SSH jumps").await;
        let mut first_channel = first.open_session().await.expect("first-hop session");
        assert_channel_echo(&mut first_channel, b"first hop stays usable").await;

        let denied = ClientConfig::new("denied.test", target_address.port(), verifier)
            .expect("denied target config");
        assert!(matches!(
            timeout(
                Duration::from_secs(5),
                ClientConnection::connect_via_direct_tcpip(denied, &second, "127.0.0.1", 5002)
            )
            .await
            .expect("denied target response"),
            Err(ClientError::ChannelOpen { code: 1, .. })
        ));

        let closed_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind closed target");
        let closed_port = closed_listener.local_addr().expect("closed target address").port();
        drop(closed_listener);
        let closed =
            ClientConfig::new("target.test", closed_port, verifier).expect("closed target config");
        assert!(matches!(
            timeout(
                Duration::from_secs(5),
                ClientConnection::connect_via_direct_tcpip(closed, &second, "127.0.0.1", 5003)
            )
            .await
            .expect("closed target response"),
            Err(ClientError::ChannelOpen { code: 2, .. })
        ));

        let mut second_channel = second.open_session().await.expect("failed opens released slot");
        assert!(matches!(
            second.open_session().await,
            Err(ClientError::ChannelLimitReached { max: 2 })
        ));
        assert_channel_echo(&mut second_channel, b"second hop stays usable").await;
        drop(second_channel);
        let reused = second.open_session().await.expect("second-hop slot reused");
        drop(reused);
        drop(first_channel);
        drop(target_channel);
        target.disconnect().await.expect("disconnect target");
        second.disconnect().await.expect("disconnect second hop");
        first.disconnect().await.expect("disconnect first hop");
        for server in [target_server, second_server, first_server] {
            timeout(Duration::from_secs(5), server)
                .await
                .expect("SSH server shutdown")
                .expect("SSH server task");
        }
    }

    #[test]
    fn channel_stream_is_sendable_async_byte_transport() {
        fn assert_stream<T: AsyncRead + AsyncWrite + Unpin + Send + 'static>() {}

        assert_stream::<ClientChannelStream>();
    }

    async fn assert_publickey_adapter_round_trip<S>(signer: &S)
    where
        S: Signer + Sync,
    {
        let identity = PublicKeyIdentity::from_signer(signer).expect("identity");
        let context =
            PublicKeyAuthContext::new([3; 32], "alice", "ssh-connection").expect("context");
        let probe = PublicKeyAuthRequest::probe(context.clone(), identity.clone()).expect("probe");
        let payload = probe.signature_payload();
        let expected = PublicKeyAuthRequest::signed(context, identity.clone(), signer)
            .expect("signed request");
        let expected_signature = expected.signature().expect("signature");
        let public_key =
            ssh_key::PublicKey::from_bytes(identity.signing_key_blob()).expect("public key");
        let agent_identity = AgentIdentity::from(public_key);
        let mut adapter = RusshSignerAdapter { signer, identity, username: "alice".to_owned() };
        let signed_payload = <RusshSignerAdapter<'_, S> as RusshSigner>::auth_sign(
            &mut adapter,
            &agent_identity,
            rsa_hash_algorithm(signer.algorithm()),
            payload.clone(),
        )
        .await
        .expect("adapter signs");
        assert!(signed_payload.starts_with(&payload));
        let suffix = &signed_payload[payload.len()..];
        let length = u32::from_be_bytes(suffix[..4].try_into().expect("length")) as usize;
        assert_eq!(length, expected_signature.len());
        assert_eq!(&suffix[4..], expected_signature);
    }

    #[tokio::test]
    async fn publickey_adapter_uses_shared_boundary_for_ed25519_and_p256() {
        let ed25519 =
            Ed25519SshSigner::new(Ed25519SigningKey::from_bytes(&[9; 32]).expect("Ed25519 key"));
        assert_publickey_adapter_round_trip(&ed25519).await;
        let p256 = P256SshSigner::new(P256SigningKey::from_bytes(&[1; 32]).expect("P-256 key"));
        assert_publickey_adapter_round_trip(&p256).await;
    }

    #[tokio::test]
    async fn publickey_authentication_completes_against_real_russh_server() {
        let signer =
            Ed25519SshSigner::new(Ed25519SigningKey::from_bytes(&[9; 32]).expect("Ed25519 key"));
        assert_real_publickey_authentication(&signer).await;
    }

    #[tokio::test]
    async fn agent_signer_authentication_completes_against_real_russh_server() {
        let software_key = Ed25519SigningKey::from_bytes(&[9; 32]).expect("Ed25519 key");
        let software_signer = Ed25519SshSigner::new(software_key);
        let key_blob = software_signer.public_key_blob().expect("agent key blob");
        let agent = AgentSshSigner::new(
            AgentClient::new(SigningAgent {
                key: Ed25519SigningKey::from_bytes(&[9; 32]).expect("agent key"),
                key_blob: key_blob.clone(),
            }),
            SignatureAlgorithm::Ed25519,
            key_blob,
        )
        .expect("agent signer");
        assert_real_publickey_authentication(&agent).await;
    }

    async fn assert_real_publickey_authentication<S>(signer: &S)
    where
        S: Signer + Sync,
    {
        let expected_key = signer.public_key_blob().expect("signer public key");
        let mut server_config = russh::server::Config::default();
        server_config.keys.push(
            PrivateKey::random(
                &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
                Algorithm::Ed25519,
            )
            .expect("server key"),
        );
        let server_config = Arc::new(server_config);
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind server");
        let address = listener.local_addr().expect("server address");
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept client");
            let _ =
                russh::server::run_stream(server_config, stream, PublicKeyServer { expected_key })
                    .await;
        });

        let verifier = |_host: &str, _key: &HostKey| Ok(());
        let config = ClientConfig::new("127.0.0.1", address.port(), verifier).expect("SSH config");
        let mut connection = ClientConnection::connect(config).await.expect("connect client");
        connection
            .authenticate_publickey("alice", signer)
            .await
            .expect("public-key authentication");
        connection.disconnect().await.expect("disconnect client");
        timeout(Duration::from_secs(5), server)
            .await
            .expect("SSH server task")
            .expect("SSH server");
    }

    #[tokio::test]
    async fn publickey_authentication_completes_for_ecdsa_and_rsa_sha2() {
        let p256 = P256SshSigner::new(P256SigningKey::from_bytes(&[1; 32]).expect("P-256 key"));
        assert_real_publickey_authentication(&p256).await;

        for curve in [EcdsaCurve::NistP384, EcdsaCurve::NistP521] {
            let key = PrivateKey::random(
                &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
                Algorithm::Ecdsa { curve },
            )
            .expect("ECDSA key");
            let signer = EcdsaSshSigner::new(key).expect("ECDSA signer");
            assert_publickey_adapter_round_trip(&signer).await;
            assert_real_publickey_authentication(&signer).await;
        }

        let mut rng = ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng);
        let rsa_key = PrivateKey::random(&mut rng, Algorithm::Rsa { hash: None }).expect("RSA key");
        let rsa_sha256 = RsaSshSigner::new(rsa_key.clone(), SignatureAlgorithm::RsaSha2_256)
            .expect("RSA SHA-256 signer");
        assert_real_publickey_authentication(&rsa_sha256).await;
        let rsa_sha512 = RsaSshSigner::new(rsa_key, SignatureAlgorithm::RsaSha2_512)
            .expect("RSA SHA-512 signer");
        assert_real_publickey_authentication(&rsa_sha512).await;
    }

    #[tokio::test]
    async fn user_certificate_authentication_completes_against_real_russh_server() {
        let signer =
            Ed25519SshSigner::new(Ed25519SigningKey::from_bytes(&[9; 32]).expect("Ed25519 key"));
        let subject =
            ssh_key::PublicKey::from_bytes(&signer.public_key_blob().expect("subject public key"))
                .expect("subject key");
        let mut rng = ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng);
        let ca = PrivateKey::random(&mut rng, Algorithm::Ed25519).expect("CA key");
        let now = unix_time_seconds();
        let mut builder = certificate::Builder::new(vec![8; 16], subject, now - 60, now + 60)
            .expect("certificate builder");
        builder.cert_type(certificate::CertType::User).expect("user certificate");
        builder.valid_principal("alice").expect("certificate principal");
        let certificate = builder.sign(&ca).expect("signed certificate");
        let encoded_certificate = certificate.to_bytes().expect("certificate bytes");
        let user_certificate = UserCertificate::parse_and_validate(
            &encoded_certificate,
            &CertificateValidationPolicy::user("alice", now),
        )
        .expect("validated user certificate");

        let mut server_config = russh::server::Config::default();
        server_config.keys.push(
            PrivateKey::random(
                &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
                Algorithm::Ed25519,
            )
            .expect("server key"),
        );
        let server_config = Arc::new(server_config);
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind server");
        let address = listener.local_addr().expect("server address");
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept client");
            let _ = russh::server::run_stream(
                server_config,
                stream,
                PublicKeyServer { expected_key: encoded_certificate },
            )
            .await;
        });

        let verifier = |_host: &str, _key: &HostKey| Ok(());
        let config = ClientConfig::new("127.0.0.1", address.port(), verifier).expect("SSH config");
        let mut connection = ClientConnection::connect(config).await.expect("connect client");
        assert!(matches!(
            connection.authenticate_certificate("bob", &user_certificate, &signer).await,
            Err(ClientError::InvalidInput("certificate principal does not match username"))
        ));
        let wrong_signer =
            Ed25519SshSigner::new(Ed25519SigningKey::from_bytes(&[8; 32]).expect("other key"));
        assert!(matches!(
            connection.authenticate_certificate("alice", &user_certificate, &wrong_signer).await,
            Err(ClientError::PublicKey(PublicKeyAuthError::KeyMismatch))
        ));
        connection
            .authenticate_certificate("alice", &user_certificate, &signer)
            .await
            .expect("certificate authentication");
        connection.disconnect().await.expect("disconnect client");
        timeout(Duration::from_secs(5), server)
            .await
            .expect("SSH server task")
            .expect("SSH server");
    }

    fn assert_rsa_certificate_payload_binding(
        signer: &RsaSshSigner,
        identity: &PublicKeyIdentity,
        presented_key: &AgentIdentity,
        other_certificate: &[u8],
    ) {
        let adapter =
            RusshSignerAdapter { signer, identity: identity.clone(), username: "alice".to_owned() };
        let context =
            PublicKeyAuthContext::new([3; 32], "alice", "ssh-connection").expect("context");
        let other_algorithm = match signer.algorithm() {
            SignatureAlgorithm::RsaSha2_256 => SignatureAlgorithm::RsaSha2_512,
            SignatureAlgorithm::RsaSha2_512 => SignatureAlgorithm::RsaSha2_256,
            _ => unreachable!(),
        };
        let changed_hash = PublicKeyIdentity::for_certificate(
            other_algorithm.certificate_name(),
            identity.key_blob().to_vec(),
            identity.signing_key_blob().to_vec(),
        )
        .expect("other RSA hash identity");
        let changed_hash_payload = PublicKeyAuthRequest::probe(context.clone(), changed_hash)
            .expect("probe")
            .signature_payload();
        assert!(matches!(
            adapter.sign_request(presented_key, changed_hash_payload),
            Err(PublicKeyAuthError::KeyMismatch)
        ));
        let changed_certificate = PublicKeyIdentity::for_certificate(
            signer.algorithm().certificate_name(),
            other_certificate.to_vec(),
            identity.signing_key_blob().to_vec(),
        )
        .expect("other certificate identity");
        let changed_certificate_payload = PublicKeyAuthRequest::probe(context, changed_certificate)
            .expect("probe")
            .signature_payload();
        assert!(matches!(
            adapter.sign_request(presented_key, changed_certificate_payload),
            Err(PublicKeyAuthError::KeyMismatch)
        ));
    }

    #[tokio::test]
    async fn rsa_sha2_user_certificates_authenticate_against_real_russh_server() {
        let mut rng = ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng);
        let subject =
            PrivateKey::random(&mut rng, Algorithm::Rsa { hash: None }).expect("RSA subject key");
        let ca = PrivateKey::random(&mut rng, Algorithm::Ed25519).expect("CA key");
        let now = unix_time_seconds();
        let mut builder = certificate::Builder::new(
            vec![8; 16],
            subject.public_key().clone(),
            now - 60,
            now + 60,
        )
        .expect("certificate builder");
        builder.cert_type(certificate::CertType::User).expect("user certificate");
        builder.valid_principal("alice").expect("certificate principal");
        let certificate = builder.sign(&ca).expect("signed certificate");
        let encoded_certificate = certificate.to_bytes().expect("certificate bytes");
        let user_certificate = UserCertificate::parse_and_validate(
            &encoded_certificate,
            &CertificateValidationPolicy::user("alice", now),
        )
        .expect("validated user certificate");
        let mut other_builder = certificate::Builder::new(
            vec![9; 16],
            subject.public_key().clone(),
            now - 60,
            now + 60,
        )
        .expect("other certificate builder");
        other_builder.cert_type(certificate::CertType::User).expect("user certificate");
        other_builder.valid_principal("alice").expect("certificate principal");
        let other_certificate = other_builder
            .sign(&ca)
            .expect("other signed certificate")
            .to_bytes()
            .expect("other certificate bytes");

        for algorithm in [SignatureAlgorithm::RsaSha2_256, SignatureAlgorithm::RsaSha2_512] {
            let signer = RsaSshSigner::new(subject.clone(), algorithm).expect("RSA signer");
            let validated_identity = user_certificate.identity();
            let identity = PublicKeyIdentity::for_certificate(
                algorithm.certificate_name(),
                validated_identity.key_blob().to_vec(),
                validated_identity.signing_key_blob().to_vec(),
            )
            .expect("RSA SHA-2 certificate identity");
            let presented_key = AgentIdentity::from(subject.public_key().clone());
            assert_rsa_certificate_payload_binding(
                &signer,
                &identity,
                &presented_key,
                &other_certificate,
            );
            let mut server_config = russh::server::Config::default();
            server_config.keys.push(
                PrivateKey::random(
                    &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
                    Algorithm::Ed25519,
                )
                .expect("server key"),
            );
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind server");
            let address = listener.local_addr().expect("server address");
            let expected_key = encoded_certificate.clone();
            let server = tokio::spawn(async move {
                let (stream, _) = listener.accept().await.expect("accept client");
                let session = russh::server::run_stream(
                    Arc::new(server_config),
                    stream,
                    PublicKeyServer { expected_key },
                )
                .await
                .expect("start server session");
                let _ = session.await;
            });
            let config = ClientConfig::new(
                "127.0.0.1",
                address.port(),
                |_host: &str, _key: &HostKey| Ok(()),
            )
            .expect("SSH config");
            let mut connection = ClientConnection::connect(config).await.expect("connect client");
            connection
                .authenticate_certificate("alice", &user_certificate, &signer)
                .await
                .expect("RSA SHA-2 certificate authentication");
            connection.disconnect().await.expect("disconnect client");
            timeout(Duration::from_secs(5), server)
                .await
                .expect("SSH server deadline")
                .expect("SSH server task");
        }
    }

    #[tokio::test]
    async fn publickey_adapter_uses_selected_rsa_sha2_algorithm() {
        let mut rng = ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng);
        let key = PrivateKey::random(&mut rng, Algorithm::Rsa { hash: None }).expect("RSA key");
        let signer = RsaSshSigner::new(key, SignatureAlgorithm::RsaSha2_512).expect("RSA signer");
        assert_publickey_adapter_round_trip(&signer).await;
    }

    #[tokio::test]
    async fn publickey_adapter_rejects_malformed_payload_and_key_substitution() {
        let signer =
            Ed25519SshSigner::new(Ed25519SigningKey::from_bytes(&[9; 32]).expect("Ed25519 key"));
        let identity = PublicKeyIdentity::from_signer(&signer).expect("identity");
        let public_key =
            ssh_key::PublicKey::from_bytes(identity.signing_key_blob()).expect("public key");
        let agent_identity = AgentIdentity::from(public_key);
        let mut adapter =
            RusshSignerAdapter { signer: &signer, identity, username: "alice".to_owned() };
        assert!(matches!(
            <RusshSignerAdapter<'_, Ed25519SshSigner> as RusshSigner>::auth_sign(
                &mut adapter,
                &agent_identity,
                None,
                vec![0; 4],
            )
            .await,
            Err(PublicKeyAuthError::MalformedPayload(_))
        ));

        let other = Ed25519SshSigner::new(
            Ed25519SigningKey::from_bytes(&[8; 32]).expect("other Ed25519 key"),
        );
        let identity = PublicKeyIdentity::from_signer(&signer).expect("identity");
        let context =
            PublicKeyAuthContext::new([3; 32], "alice", "ssh-connection").expect("context");
        let payload = PublicKeyAuthRequest::probe(context, identity.clone())
            .expect("probe")
            .signature_payload();
        let other_identity = PublicKeyIdentity::from_signer(&other).expect("other identity");
        let other_key = ssh_key::PublicKey::from_bytes(other_identity.signing_key_blob())
            .expect("other public key");
        let mut adapter =
            RusshSignerAdapter { signer: &signer, identity, username: "alice".to_owned() };
        assert!(matches!(
            <RusshSignerAdapter<'_, Ed25519SshSigner> as RusshSigner>::auth_sign(
                &mut adapter,
                &AgentIdentity::from(other_key),
                None,
                payload,
            )
            .await,
            Err(PublicKeyAuthError::KeyMismatch)
        ));
    }
}
