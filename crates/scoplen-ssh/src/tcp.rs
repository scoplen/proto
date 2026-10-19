// SPDX-License-Identifier: Apache-2.0
//! A bounded direct TCP byte transport for the SSH protocol core.
//!
//! This module owns only the byte-stream connection boundary. It does not perform SSH version
//! exchange, key exchange, authentication, channel allocation, or channel scheduling. Those
//! layers consume [`Transport`] after a connection has been established.

use std::{
    io::{self, Read, Write},
    net::{Shutdown, SocketAddr, TcpStream, ToSocketAddrs},
    thread,
    time::Duration,
};

use thiserror::Error;

/// Maximum host name length accepted by [`TcpTransport::connect`].
pub const MAX_TCP_HOST: usize = 255;
/// Maximum number of addresses accepted from one DNS resolution.
pub const MAX_TCP_ADDRESSES: usize = 16;
/// Delay between starting successive Happy Eyeballs connection attempts.
pub const DEFAULT_TCP_FALLBACK_DELAY: Duration = Duration::from_millis(250);

/// The operation that produced a typed transport I/O error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportOperation {
    /// Reading bytes from the transport.
    Read,
    /// Writing bytes to the transport.
    Write,
    /// Flushing buffered bytes.
    Flush,
    /// Shutting down one or both directions.
    Shutdown,
    /// Reading the local socket address.
    LocalAddress,
    /// Reading the peer socket address.
    PeerAddress,
}

/// Errors raised while opening or using a direct TCP transport.
///
/// The error contains the operation and OS error kind without retaining an OS error object. This
/// keeps the public error typed, comparable in failure-path tests, and free of platform-specific
/// diagnostic text that could expose more connection detail than a caller needs.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum TransportError {
    /// The host name was empty.
    #[error("TCP host is empty")]
    EmptyHost,
    /// The host name exceeded [`MAX_TCP_HOST`].
    #[error("TCP host exceeds the {max}-byte limit")]
    HostTooLong { max: usize },
    /// The host name contained a NUL byte.
    #[error("TCP host contains a NUL byte")]
    HostContainsNul,
    /// The caller supplied a zero or otherwise unusable connection timeout.
    #[error("TCP connection timeout must be non-zero")]
    InvalidTimeout,
    /// Name resolution failed before any connection attempt.
    #[error("TCP host resolution failed: {kind:?}")]
    Resolution { kind: io::ErrorKind },
    /// Resolution returned more addresses than the bounded connection policy permits.
    #[error("TCP resolution returned more than {max} addresses")]
    AddressLimitExceeded { max: usize },
    /// Resolution returned no addresses.
    #[error("TCP host resolution returned no addresses")]
    NoAddresses,
    /// A connection attempt failed before it could establish a stream.
    #[error("TCP connection to {address} failed: {kind:?}")]
    Connect { address: SocketAddr, kind: io::ErrorKind },
    /// A connection attempt consumed its timeout budget.
    #[error("TCP connection to {address} timed out after {timeout:?}")]
    ConnectTimeout { address: SocketAddr, timeout: Duration },
    /// A required socket option could not be applied.
    #[error("TCP socket option {option} failed: {kind:?}")]
    Configure { option: &'static str, kind: io::ErrorKind },
    /// An established transport operation failed.
    #[error("TCP {operation:?} failed: {kind:?}")]
    Io { operation: TransportOperation, kind: io::ErrorKind },
    /// A composed proxy transport failed during its handshake.
    #[error("proxy handshake failed: {error}")]
    Proxy { error: crate::proxy::ProxyError, kind: io::ErrorKind },
}

impl TransportError {
    fn from_io(operation: TransportOperation, error: &io::Error) -> Self {
        Self::Io { operation, kind: error.kind() }
    }

    fn io_kind(&self) -> io::ErrorKind {
        match self {
            Self::EmptyHost | Self::HostTooLong { .. } | Self::HostContainsNul => {
                io::ErrorKind::InvalidInput
            }
            Self::InvalidTimeout | Self::AddressLimitExceeded { .. } => io::ErrorKind::InvalidInput,
            Self::Resolution { kind }
            | Self::Connect { kind, .. }
            | Self::Configure { kind, .. }
            | Self::Io { kind, .. }
            | Self::Proxy { kind, .. } => *kind,
            Self::NoAddresses => io::ErrorKind::NotFound,
            Self::ConnectTimeout { .. } => io::ErrorKind::TimedOut,
        }
    }
}

impl From<TransportError> for io::Error {
    fn from(error: TransportError) -> Self {
        Self::new(error.io_kind(), error)
    }
}

/// A byte transport suitable for an SSH engine.
///
/// Implementations expose typed operations so an engine can preserve transport failure classes.
/// [`TcpTransport`] also implements [`Read`] and [`Write`] for APIs that use the standard I/O
/// traits. The trait does not imply that any SSH handshake or authentication has completed.
pub trait Transport: Send {
    /// Read bytes from the peer.
    ///
    /// A return value of `0` is an orderly end-of-stream indication, matching [`Read`].
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::Io`] when the underlying stream cannot be read.
    fn read(&mut self, buffer: &mut [u8]) -> Result<usize, TransportError>;
    /// Write bytes to the peer.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::Io`] when the underlying stream cannot be written.
    fn write(&mut self, buffer: &[u8]) -> Result<usize, TransportError>;
    /// Flush bytes pending in the transport.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::Io`] when the underlying stream cannot be flushed.
    fn flush(&mut self) -> Result<(), TransportError>;
    /// Shut down one or both directions of the transport.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::Io`] when the underlying stream rejects the shutdown.
    fn shutdown(&self, how: Shutdown) -> Result<(), TransportError>;
    /// Return the local socket address.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::Io`] when the underlying stream cannot report its address.
    fn local_addr(&self) -> Result<SocketAddr, TransportError>;
    /// Return the peer socket address.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::Io`] when the underlying stream cannot report its address.
    fn peer_addr(&self) -> Result<SocketAddr, TransportError>;
}

/// A connected, direct TCP byte transport.
///
/// `TcpTransport` enables `TCP_NODELAY` before returning to the caller. It is intentionally
/// limited to direct TCP; proxy composition, jump chains, and SSH protocol state remain separate
/// S4 outcomes.
#[derive(Debug)]
pub struct TcpTransport {
    stream: TcpStream,
}

impl TcpTransport {
    /// Connect to a host and TCP port with one timeout for all connection attempts.
    ///
    /// The synchronous system resolver is not cancellable and can outlast `timeout`. Resolution
    /// is bounded to [`MAX_TCP_ADDRESSES`] raw results. Candidates are interleaved by address
    /// family and use staggered Happy Eyeballs attempts under one post-resolution timeout.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError`] for invalid host input, resolution failure, address-limit
    /// violations, connection refusal, timeout, or socket-option failure.
    pub fn connect(host: &str, port: u16, timeout: Duration) -> Result<Self, TransportError> {
        validate_host(host)?;
        validate_timeout(timeout)?;

        let resolved = (host, port)
            .to_socket_addrs()
            .map_err(|error| TransportError::Resolution { kind: error.kind() })?;
        let addresses = collect_addresses(resolved)?;
        Self::connect_addresses(&addresses, timeout)
    }

    /// Resolve and dial under one async deadline without blocking the caller's executor.
    /// Dropping the operation aborts pending connection attempts; a platform resolver worker may
    /// finish later, but its result cannot start another attempt.
    pub(crate) async fn connect_async(
        host: &str,
        port: u16,
        timeout: Duration,
    ) -> Result<Self, TransportError> {
        validate_host(host)?;
        validate_timeout(timeout)?;
        let deadline = tokio::time::Instant::now()
            .checked_add(timeout)
            .ok_or(TransportError::InvalidTimeout)?;
        let resolved = tokio::time::timeout_at(deadline, tokio::net::lookup_host((host, port)))
            .await
            .map_err(|_| TransportError::Resolution { kind: io::ErrorKind::TimedOut })?
            .map_err(|error| TransportError::Resolution { kind: error.kind() })?;
        let addresses = collect_addresses(resolved)?;
        if addresses.is_empty() {
            return Err(TransportError::NoAddresses);
        }
        connect_happy_eyeballs(&addresses, deadline, timeout, DEFAULT_TCP_FALLBACK_DELAY).await
    }

    /// Connect to one resolved address with a bounded timeout.
    ///
    /// This method is useful when the caller owns DNS resolution or wants a deterministic
    /// loopback address in a test. It performs one direct blocking attempt and does not schedule
    /// other candidates; it still applies the same socket policy as [`Self::connect`].
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::Connect`] or [`TransportError::ConnectTimeout`] when the peer
    /// cannot be reached, and [`TransportError::Configure`] if `TCP_NODELAY` cannot be enabled.
    pub fn connect_addr(address: SocketAddr, timeout: Duration) -> Result<Self, TransportError> {
        validate_timeout(timeout)?;
        let stream = TcpStream::connect_timeout(&address, timeout).map_err(|error| {
            if error.kind() == io::ErrorKind::TimedOut {
                TransportError::ConnectTimeout { address, timeout }
            } else {
                TransportError::Connect { address, kind: error.kind() }
            }
        })?;
        Self::from_stream(stream)
    }

    /// Connect to a bounded list of already-resolved addresses with Happy Eyeballs scheduling.
    ///
    /// The first candidate starts immediately. Further candidates are started after a bounded
    /// [`DEFAULT_TCP_FALLBACK_DELAY`] while earlier attempts are still pending. Every attempt
    /// shares one absolute timeout deadline. Attempts run in one bounded runtime and are
    /// cancelled and joined before this method returns, so no abandoned connection attempts run
    /// in the background.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::NoAddresses`] for an empty list or
    /// [`TransportError::AddressLimitExceeded`] when the list is too large. Otherwise the last
    /// typed connection failure is returned after all candidates fail.
    pub fn connect_addresses(
        addresses: &[SocketAddr],
        timeout: Duration,
    ) -> Result<Self, TransportError> {
        Self::connect_addresses_with_delay(addresses, timeout, DEFAULT_TCP_FALLBACK_DELAY)
    }

    /// Connect to resolved addresses with an explicit Happy Eyeballs fallback delay.
    ///
    /// A zero delay starts all candidates immediately, still subject to
    /// [`MAX_TCP_ADDRESSES`]. Both overloads interleave address families while preserving each
    /// family's candidate order.
    ///
    /// # Errors
    ///
    /// Returns the same validation, connection, timeout, and socket-configuration errors as
    /// [`Self::connect_addresses`].
    pub fn connect_addresses_with_delay(
        addresses: &[SocketAddr],
        timeout: Duration,
        fallback_delay: Duration,
    ) -> Result<Self, TransportError> {
        validate_timeout(timeout)?;
        if addresses.is_empty() {
            return Err(TransportError::NoAddresses);
        }
        if addresses.len() > MAX_TCP_ADDRESSES {
            return Err(TransportError::AddressLimitExceeded { max: MAX_TCP_ADDRESSES });
        }

        let candidates = addresses.to_vec();
        let runtime_thread = thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_io()
                .enable_time()
                .build()
                .map_err(|_| TransportError::Connect {
                    address: candidates[0],
                    kind: io::ErrorKind::Other,
                })?;
            runtime.block_on(async {
                let deadline = tokio::time::Instant::now()
                    .checked_add(timeout)
                    .ok_or(TransportError::InvalidTimeout)?;
                connect_happy_eyeballs(&candidates, deadline, timeout, fallback_delay).await
            })
        });
        runtime_thread.join().unwrap_or_else(|_| {
            Err(TransportError::Connect { address: addresses[0], kind: io::ErrorKind::Other })
        })
    }

    /// Wrap an already-connected TCP stream and apply the transport socket policy.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::Configure`] if `TCP_NODELAY` cannot be enabled.
    pub fn from_stream(stream: TcpStream) -> Result<Self, TransportError> {
        stream.set_nodelay(true).map_err(|error| TransportError::Configure {
            option: "TCP_NODELAY",
            kind: error.kind(),
        })?;
        Ok(Self { stream })
    }

    /// Borrow the underlying TCP stream.
    #[must_use]
    pub const fn as_stream(&self) -> &TcpStream {
        &self.stream
    }

    /// Borrow the underlying TCP stream mutably.
    #[must_use]
    pub const fn as_stream_mut(&mut self) -> &mut TcpStream {
        &mut self.stream
    }

    /// Consume the transport and return its TCP stream.
    #[must_use]
    pub fn into_stream(self) -> TcpStream {
        self.stream
    }
}

impl Transport for TcpTransport {
    fn read(&mut self, buffer: &mut [u8]) -> Result<usize, TransportError> {
        self.stream
            .read(buffer)
            .map_err(|error| TransportError::from_io(TransportOperation::Read, &error))
    }

    fn write(&mut self, buffer: &[u8]) -> Result<usize, TransportError> {
        self.stream
            .write(buffer)
            .map_err(|error| TransportError::from_io(TransportOperation::Write, &error))
    }

    fn flush(&mut self) -> Result<(), TransportError> {
        self.stream
            .flush()
            .map_err(|error| TransportError::from_io(TransportOperation::Flush, &error))
    }

    fn shutdown(&self, how: Shutdown) -> Result<(), TransportError> {
        self.stream
            .shutdown(how)
            .map_err(|error| TransportError::from_io(TransportOperation::Shutdown, &error))
    }

    fn local_addr(&self) -> Result<SocketAddr, TransportError> {
        self.stream
            .local_addr()
            .map_err(|error| TransportError::from_io(TransportOperation::LocalAddress, &error))
    }

    fn peer_addr(&self) -> Result<SocketAddr, TransportError> {
        self.stream
            .peer_addr()
            .map_err(|error| TransportError::from_io(TransportOperation::PeerAddress, &error))
    }
}

impl Read for TcpTransport {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        Transport::read(self, buffer).map_err(Into::into)
    }
}

impl Write for TcpTransport {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        Transport::write(self, buffer).map_err(Into::into)
    }

    fn flush(&mut self) -> io::Result<()> {
        Transport::flush(self).map_err(Into::into)
    }
}

async fn connect_happy_eyeballs(
    addresses: &[SocketAddr],
    deadline: tokio::time::Instant,
    timeout: Duration,
    fallback_delay: Duration,
) -> Result<TcpTransport, TransportError> {
    let candidates = interleave_addresses(addresses);
    if tokio::time::Instant::now() >= deadline {
        return Err(TransportError::ConnectTimeout { address: candidates[0], timeout });
    }
    let mut attempts = tokio::task::JoinSet::new();
    for (index, &address) in candidates.iter().enumerate() {
        let delay = u32::try_from(index)
            .ok()
            .and_then(|index| fallback_delay.checked_mul(index))
            .unwrap_or(timeout);
        attempts.spawn(async move {
            if !delay.is_zero() {
                tokio::time::sleep(delay).await;
            }
            if tokio::time::Instant::now() >= deadline {
                return (index, Err(TransportError::ConnectTimeout { address, timeout }));
            }
            let result = tokio::net::TcpStream::connect(address)
                .await
                .map_err(|error| {
                    if error.kind() == io::ErrorKind::TimedOut {
                        TransportError::ConnectTimeout { address, timeout }
                    } else {
                        TransportError::Connect { address, kind: error.kind() }
                    }
                })
                .and_then(|stream| {
                    let stream = stream.into_std().map_err(|error| TransportError::Configure {
                        option: "TCP stream mode",
                        kind: error.kind(),
                    })?;
                    stream.set_nonblocking(false).map_err(|error| TransportError::Configure {
                        option: "TCP blocking mode",
                        kind: error.kind(),
                    })?;
                    Ok(stream)
                })
                .and_then(TcpTransport::from_stream);
            (index, result)
        });
    }

    let result = tokio::time::timeout_at(deadline, async {
        let mut errors = Vec::with_capacity(candidates.len());
        errors.resize_with(candidates.len(), || None);
        while let Some(joined) = attempts.join_next().await {
            let (index, result) = joined.map_err(|_| TransportError::Connect {
                address: candidates[0],
                kind: io::ErrorKind::Other,
            })?;
            if tokio::time::Instant::now() >= deadline {
                return Err(TransportError::ConnectTimeout { address: candidates[0], timeout });
            }
            match result {
                Ok(transport) => return Ok(transport),
                Err(error) => errors[index] = Some(error),
            }
        }
        errors
            .into_iter()
            .rev()
            .flatten()
            .next()
            .map_or_else(|| Err(TransportError::NoAddresses), Err)
    })
    .await;

    attempts.abort_all();
    while attempts.join_next().await.is_some() {}

    match result {
        Ok(result) => result,
        Err(_) => Err(TransportError::ConnectTimeout { address: candidates[0], timeout }),
    }
}

fn collect_addresses(
    resolved: impl IntoIterator<Item = SocketAddr>,
) -> Result<Vec<SocketAddr>, TransportError> {
    let mut addresses = Vec::new();
    for (index, address) in resolved.into_iter().enumerate() {
        if index >= MAX_TCP_ADDRESSES {
            return Err(TransportError::AddressLimitExceeded { max: MAX_TCP_ADDRESSES });
        }
        if !addresses.contains(&address) {
            addresses.push(address);
        }
    }
    Ok(addresses)
}

fn interleave_addresses(addresses: &[SocketAddr]) -> Vec<SocketAddr> {
    let first_is_ipv4 = addresses[0].is_ipv4();
    let mut first_family = Vec::new();
    let mut second_family = Vec::new();
    for &address in addresses {
        if address.is_ipv4() == first_is_ipv4 {
            first_family.push(address);
        } else {
            second_family.push(address);
        }
    }
    let mut ordered = Vec::with_capacity(addresses.len());
    for index in 0..first_family.len().max(second_family.len()) {
        if let Some(&address) = first_family.get(index) {
            ordered.push(address);
        }
        if let Some(&address) = second_family.get(index) {
            ordered.push(address);
        }
    }
    ordered
}

fn validate_host(host: &str) -> Result<(), TransportError> {
    if host.is_empty() {
        return Err(TransportError::EmptyHost);
    }
    if host.len() > MAX_TCP_HOST {
        return Err(TransportError::HostTooLong { max: MAX_TCP_HOST });
    }
    if host.as_bytes().contains(&0) {
        return Err(TransportError::HostContainsNul);
    }
    Ok(())
}

fn validate_timeout(timeout: Duration) -> Result<(), TransportError> {
    if timeout.is_zero() || tokio::time::Instant::now().checked_add(timeout).is_none() {
        return Err(TransportError::InvalidTimeout);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        net::{TcpListener, TcpStream},
        thread,
    };

    use super::*;

    #[test]
    fn loopback_transport_round_trips_fragmented_data_and_eof() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind listener");
        let address = listener.local_addr().expect("listener address");
        let server = thread::spawn(move || {
            let (mut stream, peer) = listener.accept().expect("accept connection");
            assert_eq!(peer.ip(), address.ip());
            let mut request = [0; 5];
            stream.read_exact(&mut request).expect("read request");
            assert_eq!(&request, b"hello");
            stream.write_all(b"hel").expect("write first fragment");
            stream.write_all(b"lo").expect("write second fragment");
            stream.shutdown(Shutdown::Write).expect("shutdown server write");
        });

        let mut transport =
            TcpTransport::connect("127.0.0.1", address.port(), Duration::from_secs(2))
                .expect("resolve and connect loopback");
        assert!(transport.as_stream().nodelay().expect("read TCP_NODELAY"));
        assert_eq!(Transport::peer_addr(&transport).expect("peer address").ip(), address.ip());
        assert_eq!(Transport::local_addr(&transport).expect("local address").ip(), address.ip());
        transport.write_all(b"hello").expect("write request");
        Transport::flush(&mut transport).expect("flush request");
        let mut response = [0; 5];
        transport.read_exact(&mut response).expect("read fragmented response");
        assert_eq!(&response, b"hello");
        let mut eof = [0; 1];
        assert_eq!(Transport::read(&mut transport, &mut eof).expect("read EOF"), 0);
        server.join().expect("server thread");
    }

    #[test]
    fn unusable_destination_is_typed() {
        // A released ephemeral port can self-connect on Windows when the source port is reused.
        let address = SocketAddr::from(([127, 0, 0, 1], 0));
        let error = TcpTransport::connect_addr(address, Duration::from_secs(1))
            .expect_err("port zero cannot identify a listening peer");
        let actual = match error {
            TransportError::Connect { address, .. }
            | TransportError::ConnectTimeout { address, .. } => address,
            other => panic!("unexpected connection failure: {other:?}"),
        };
        assert_eq!(actual, address);
    }

    #[test]
    fn happy_eyeballs_falls_back_from_ipv6_to_ipv4() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind listener");
        let address = listener.local_addr().expect("listener address");
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept connection");
            stream.write_all(b"ok").expect("write response");
        });

        let ipv6_candidate = SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 1], address.port()));
        let mut transport = TcpTransport::connect_addresses_with_delay(
            &[ipv6_candidate, address],
            Duration::from_secs(2),
            Duration::from_millis(20),
        )
        .expect("fall back to IPv4 listener");
        let mut response = [0; 2];
        transport.read_exact(&mut response).expect("read response");
        assert_eq!(&response, b"ok");
        server.join().expect("server thread");
    }

    #[test]
    fn happy_eyeballs_timeout_is_typed_and_bounded() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind listener");
        let address = listener.local_addr().expect("listener address");
        drop(listener);
        let started = std::time::Instant::now();
        let error = TcpTransport::connect_addresses_with_delay(
            &[address, address],
            Duration::from_millis(100),
            Duration::from_secs(1),
        )
        .expect_err("closed listener and delayed candidate must time out");
        assert!(matches!(error, TransportError::ConnectTimeout { .. }));
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn candidates_interleave_families_without_reordering_either_family() {
        let addresses = [
            SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 1], 1)),
            SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 2], 2)),
            SocketAddr::from(([127, 0, 0, 1], 3)),
            SocketAddr::from(([127, 0, 0, 2], 4)),
            SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 3], 5)),
        ];
        assert_eq!(
            interleave_addresses(&addresses),
            [addresses[0], addresses[2], addresses[1], addresses[3], addresses[4]]
        );
        let reversed = [addresses[2], addresses[3], addresses[0], addresses[1]];
        assert_eq!(
            interleave_addresses(&reversed),
            [addresses[2], addresses[0], addresses[3], addresses[1]]
        );
    }

    #[test]
    fn raw_address_limit_is_checked_before_deduplication() {
        let address = SocketAddr::from(([127, 0, 0, 1], 22));
        assert_eq!(
            collect_addresses(vec![address; MAX_TCP_ADDRESSES]).expect("at limit"),
            [address]
        );
        assert!(matches!(
            collect_addresses(vec![address; MAX_TCP_ADDRESSES + 1]),
            Err(TransportError::AddressLimitExceeded { max: MAX_TCP_ADDRESSES })
        ));
    }

    #[tokio::test]
    async fn canceling_pending_fallback_does_not_open_a_late_socket() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("listener");
        let address = listener.local_addr().expect("listener address");
        let unavailable = SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 1], address.port()));
        let dial = tokio::spawn(async move {
            connect_happy_eyeballs(
                &[unavailable, address],
                tokio::time::Instant::now() + Duration::from_secs(2),
                Duration::from_secs(2),
                Duration::from_millis(300),
            )
            .await
        });
        tokio::time::sleep(Duration::from_millis(30)).await;
        dial.abort();
        assert!(dial.await.expect_err("dial was canceled").is_cancelled());
        assert!(tokio::time::timeout(Duration::from_millis(450), listener.accept()).await.is_err());
    }

    #[tokio::test]
    async fn expired_shared_deadline_never_starts_a_tcp_attempt() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("listener");
        let address = listener.local_addr().expect("listener address");
        let error = connect_happy_eyeballs(
            &[address],
            tokio::time::Instant::now() - Duration::from_millis(1),
            Duration::from_millis(100),
            DEFAULT_TCP_FALLBACK_DELAY,
        )
        .await
        .expect_err("shared deadline expired during resolution");
        assert!(
            matches!(error, TransportError::ConnectTimeout { address: timed_out, .. } if timed_out == address)
        );
        assert!(tokio::time::timeout(Duration::from_millis(100), listener.accept()).await.is_err());
    }

    #[tokio::test]
    async fn async_dial_refusal_retains_the_candidate_address() {
        let address = SocketAddr::from(([127, 0, 0, 1], 0));
        let error = connect_happy_eyeballs(
            &[address],
            tokio::time::Instant::now() + Duration::from_secs(1),
            Duration::from_secs(1),
            DEFAULT_TCP_FALLBACK_DELAY,
        )
        .await
        .expect_err("port zero cannot have a listening peer");
        assert!(matches!(
            error,
            TransportError::Connect { address: failed, .. }
                | TransportError::ConnectTimeout { address: failed, .. }
                if failed == address
        ));
    }

    #[test]
    fn address_resolution_and_timeout_inputs_are_bounded() {
        assert!(matches!(
            TcpTransport::connect("", 22, Duration::from_secs(1)),
            Err(TransportError::EmptyHost)
        ));
        assert!(matches!(
            TcpTransport::connect(&"a".repeat(MAX_TCP_HOST + 1), 22, Duration::from_secs(1)),
            Err(TransportError::HostTooLong { max: MAX_TCP_HOST })
        ));
        assert!(matches!(
            TcpTransport::connect("127.0.0.1", 22, Duration::ZERO),
            Err(TransportError::InvalidTimeout)
        ));
        assert!(matches!(
            TcpTransport::connect_addresses(&[], Duration::from_secs(1)),
            Err(TransportError::NoAddresses)
        ));
        let addresses = vec![SocketAddr::from(([127, 0, 0, 1], 1)); MAX_TCP_ADDRESSES + 1];
        assert!(matches!(
            TcpTransport::connect_addresses(&addresses, Duration::from_secs(1)),
            Err(TransportError::AddressLimitExceeded { max: MAX_TCP_ADDRESSES })
        ));
    }

    #[test]
    fn typed_read_failure_reports_operation() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind listener");
        let address = listener.local_addr().expect("listener address");
        let server = thread::spawn(move || {
            let (_stream, _) = listener.accept().expect("accept connection");
            thread::sleep(Duration::from_millis(100));
        });
        let mut transport =
            TcpTransport::connect_addr(address, Duration::from_secs(2)).expect("connect loopback");
        transport.as_stream().set_nonblocking(true).expect("set nonblocking");
        let mut buffer = [0; 1];
        let error = Transport::read(&mut transport, &mut buffer).expect_err("read would block");
        assert_eq!(
            error,
            TransportError::Io {
                operation: TransportOperation::Read,
                kind: io::ErrorKind::WouldBlock,
            }
        );
        server.join().expect("server thread");
    }

    #[test]
    fn from_stream_applies_nodelay() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind listener");
        let address = listener.local_addr().expect("listener address");
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept connection");
            drop(stream);
        });
        let stream = TcpStream::connect(address).expect("connect loopback");
        let transport = TcpTransport::from_stream(stream).expect("wrap stream");
        assert!(transport.as_stream().nodelay().expect("read TCP_NODELAY"));
        server.join().expect("server thread");
    }
}
