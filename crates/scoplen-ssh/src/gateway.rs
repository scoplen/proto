// SPDX-License-Identifier: Apache-2.0
//! K-6 gateway client-hello composition over an established byte transport.
//!
//! TLS and ALPN negotiation are owned by the platform or gateway connector. This module keeps the
//! bounded, one-shot client-hello framing adjacent to the SSH [`Transport`] boundary so the SSH
//! engine receives the stream only after the K-6 prelude has been written successfully.

use std::{
    fmt, io,
    net::{Shutdown, SocketAddr},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use rustls::{ClientConfig, RootCertStore, pki_types::ServerName};
use scoplen_api::gateway::{GatewayClientHello, GatewayCodecError};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio_rustls::{TlsConnector, client::TlsStream};

use crate::tcp::{Transport, TransportError, TransportOperation};

/// ALPN protocol advertised by a Scoplen gateway edge.
pub const GATEWAY_ALPN: &[u8] = b"spl-gw/1";

const MAX_TLS_DOMAIN_BYTES: usize = 253;

/// Errors raised while building a gateway TLS client configuration.
#[derive(Debug, Error)]
pub enum GatewayTlsConfigError {
    /// A required configuration value was empty.
    #[error("gateway TLS {0} must not be empty")]
    Empty(&'static str),
    /// The server name is not a valid DNS name or IP address for rustls.
    #[error("gateway TLS server name is invalid")]
    InvalidServerName,
    /// The server name exceeded the DNS wire bound.
    #[error("gateway TLS server name exceeds 253 bytes")]
    DomainTooLong,
}

/// Errors raised while connecting to a gateway over TLS.
#[derive(Debug, Error)]
pub enum GatewayTlsConnectError {
    /// The TLS handshake failed.
    #[error("gateway TLS handshake failed: {0}")]
    Tls(#[source] io::Error),
    /// The edge did not negotiate the required `spl-gw/1` ALPN protocol.
    #[error("gateway TLS ALPN is not spl-gw/1")]
    AlpnMismatch,
    /// The gateway hello could not be written after TLS completed.
    #[error("gateway hello failed: {0}")]
    Prelude(#[from] AsyncGatewayTransportError),
}

/// TLS 1.3 client configuration for the gateway edge.
#[derive(Clone)]
pub struct GatewayTlsClientConfig {
    config: Arc<ClientConfig>,
    server_name: ServerName<'static>,
}

impl fmt::Debug for GatewayTlsClientConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("GatewayTlsClientConfig").finish_non_exhaustive()
    }
}

impl GatewayTlsClientConfig {
    /// Build a client configuration that requires trusted edge certificate roots.
    ///
    /// The resulting config enables only TLS 1.3 and advertises exactly `spl-gw/1` through
    /// ALPN. `roots` must contain the deployment or operating-system trust anchors selected by
    /// the caller; no implicit public CA set is installed here. Client-to-edge TLS is one-way;
    /// the internal gateway links use mutual TLS separately.
    ///
    /// # Errors
    ///
    /// Returns a typed error when roots or the server name is missing or invalid.
    pub fn new(roots: RootCertStore, domain: &str) -> Result<Self, GatewayTlsConfigError> {
        if roots.is_empty() {
            return Err(GatewayTlsConfigError::Empty("root certificates"));
        }
        if domain.is_empty() {
            return Err(GatewayTlsConfigError::Empty("server name"));
        }
        if domain.len() > MAX_TLS_DOMAIN_BYTES {
            return Err(GatewayTlsConfigError::DomainTooLong);
        }
        let server_name = ServerName::try_from(domain.to_owned())
            .map_err(|_| GatewayTlsConfigError::InvalidServerName)?;
        let mut config = ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_root_certificates(roots)
            .with_no_client_auth();
        config.alpn_protocols = vec![GATEWAY_ALPN.to_vec()];
        Ok(Self { config: Arc::new(config), server_name })
    }

    /// Connect and complete the TLS 1.3 handshake over an established byte stream.
    ///
    /// The returned stream has negotiated and verified the configured server name and CA. It is
    /// ready for [`AsyncGatewayTransport::handshake`] to write the K-6 client hello.
    ///
    /// # Errors
    ///
    /// Returns [`GatewayTlsConnectError::Tls`] if the handshake or certificate verification fails.
    pub async fn connect<IO>(&self, stream: IO) -> Result<TlsStream<IO>, GatewayTlsConnectError>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
    {
        let tls = TlsConnector::from(self.config.clone())
            .connect(self.server_name.clone(), stream)
            .await
            .map_err(GatewayTlsConnectError::Tls)?;
        if tls.get_ref().1.alpn_protocol() != Some(GATEWAY_ALPN) {
            return Err(GatewayTlsConnectError::AlpnMismatch);
        }
        Ok(tls)
    }

    /// Connect with TLS 1.3 and write the bounded K-6 gateway client hello.
    ///
    /// # Errors
    ///
    /// Returns a typed TLS or prelude error if either step fails.
    pub async fn connect_and_handshake<IO>(
        &self,
        stream: IO,
        hello: &GatewayClientHello,
    ) -> Result<AsyncGatewayTransport<TlsStream<IO>>, GatewayTlsConnectError>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
    {
        let tls = self.connect(stream).await?;
        AsyncGatewayTransport::handshake(tls, hello).await.map_err(GatewayTlsConnectError::Prelude)
    }
}

/// Errors raised while composing a gateway stream.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum GatewayTransportError {
    /// The hello failed K-6 validation or could not be encoded.
    #[error("gateway client hello is invalid: {0}")]
    Codec(#[from] GatewayCodecError),
    /// The underlying byte transport rejected the hello write or flush.
    #[error("gateway client hello transport failed: {0}")]
    Transport(#[from] TransportError),
}

/// Errors raised while composing a gateway stream over an asynchronous transport.
#[derive(Debug, Error)]
pub enum AsyncGatewayTransportError {
    /// The hello failed K-6 validation or could not be encoded.
    #[error("gateway client hello is invalid: {0}")]
    Codec(#[from] GatewayCodecError),
    /// The underlying asynchronous stream rejected the hello write or flush.
    #[error("gateway client hello transport failed: {0}")]
    Io(#[source] io::Error),
}

/// A byte transport after the bounded K-6 client hello has been sent.
///
/// The constructor writes exactly one length-prefixed `GatewayClientHello`, handling partial
/// writes and flushing before returning. It does not perform TLS or ALPN negotiation; callers must
/// establish that boundary before passing the resulting stream to this adapter.
pub struct GatewayTransport<T> {
    inner: T,
}

/// An asynchronous byte transport after the bounded K-6 client hello has been sent.
pub struct AsyncGatewayTransport<T> {
    inner: T,
}

impl<T> fmt::Debug for GatewayTransport<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("GatewayTransport").finish_non_exhaustive()
    }
}

impl<T> fmt::Debug for AsyncGatewayTransport<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("AsyncGatewayTransport").finish_non_exhaustive()
    }
}

impl<T: Transport> GatewayTransport<T> {
    /// Write and flush one validated K-6 client hello over `inner`.
    ///
    /// # Errors
    ///
    /// Returns [`GatewayTransportError::Codec`] before touching `inner` when the hello is invalid,
    /// or [`GatewayTransportError::Transport`] when the underlying stream cannot accept the
    /// complete frame.
    pub fn handshake(
        mut inner: T,
        hello: &GatewayClientHello,
    ) -> Result<Self, GatewayTransportError> {
        let frame = hello.encode_frame()?;
        write_all(&mut inner, &frame)?;
        inner.flush()?;
        Ok(Self { inner })
    }

    /// Return the underlying transport after the gateway prelude has been sent.
    #[must_use]
    pub fn into_inner(self) -> T {
        self.inner
    }

    /// Borrow the underlying transport.
    #[must_use]
    pub fn get_ref(&self) -> &T {
        &self.inner
    }

    /// Mutably borrow the underlying transport.
    #[must_use]
    pub fn get_mut(&mut self) -> &mut T {
        &mut self.inner
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> AsyncGatewayTransport<T> {
    /// Write and flush one validated K-6 client hello over `inner`.
    ///
    /// TLS 1.3 and ALPN must already have been negotiated by the caller. The returned stream is
    /// ready for the SSH engine to perform its version exchange.
    ///
    /// # Errors
    ///
    /// Returns [`AsyncGatewayTransportError::Codec`] for an invalid hello or
    /// [`AsyncGatewayTransportError::Io`] when the stream rejects the frame or flush.
    pub async fn handshake(
        mut inner: T,
        hello: &GatewayClientHello,
    ) -> Result<Self, AsyncGatewayTransportError> {
        let frame = hello.encode_frame()?;
        inner.write_all(&frame).await.map_err(AsyncGatewayTransportError::Io)?;
        inner.flush().await.map_err(AsyncGatewayTransportError::Io)?;
        Ok(Self { inner })
    }

    /// Return the underlying asynchronous transport after the gateway prelude has been sent.
    #[must_use]
    pub fn into_inner(self) -> T {
        self.inner
    }

    /// Borrow the underlying asynchronous transport.
    #[must_use]
    pub fn get_ref(&self) -> &T {
        &self.inner
    }

    /// Mutably borrow the underlying asynchronous transport.
    #[must_use]
    pub fn get_mut(&mut self) -> &mut T {
        &mut self.inner
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> AsyncRead for AsyncGatewayTransport<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buffer)
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> AsyncWrite for AsyncGatewayTransport<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buffer)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

fn write_all<T: Transport>(transport: &mut T, mut buffer: &[u8]) -> Result<(), TransportError> {
    while !buffer.is_empty() {
        let written = transport.write(buffer)?;
        if written > buffer.len() {
            return Err(TransportError::Io {
                operation: TransportOperation::Write,
                kind: io::ErrorKind::InvalidData,
            });
        }
        if written == 0 {
            return Err(TransportError::Io {
                operation: TransportOperation::Write,
                kind: io::ErrorKind::WriteZero,
            });
        }
        buffer = &buffer[written..];
    }
    Ok(())
}

impl<T: Transport> Transport for GatewayTransport<T> {
    fn read(&mut self, buffer: &mut [u8]) -> Result<usize, TransportError> {
        self.inner.read(buffer)
    }

    fn write(&mut self, buffer: &[u8]) -> Result<usize, TransportError> {
        self.inner.write(buffer)
    }

    fn flush(&mut self) -> Result<(), TransportError> {
        self.inner.flush()
    }

    fn shutdown(&self, how: Shutdown) -> Result<(), TransportError> {
        self.inner.shutdown(how)
    }

    fn local_addr(&self) -> Result<SocketAddr, TransportError> {
        self.inner.local_addr()
    }

    fn peer_addr(&self) -> Result<SocketAddr, TransportError> {
        self.inner.peer_addr()
    }
}

impl<T: Transport> io::Read for GatewayTransport<T> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        Transport::read(self, buffer).map_err(io::Error::from)
    }
}

impl<T: Transport> io::Write for GatewayTransport<T> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        Transport::write(self, buffer).map_err(io::Error::from)
    }

    fn flush(&mut self) -> io::Result<()> {
        Transport::flush(self).map_err(io::Error::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ClientConfig, ClientConnection, ClientError, HostKey, HostKeyVerificationError};
    use rustls::{
        RootCertStore, ServerConfig, ServerConnection,
        pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
    };
    use std::{io::ErrorKind, sync::Arc};
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::time::sleep;
    use tokio_rustls::TlsAcceptor;

    mod test_certs {
        include!("gateway_test_certs.rs");
    }

    #[derive(Debug)]
    struct FakeTransport {
        written: Vec<u8>,
        incoming: Vec<u8>,
        max_write: usize,
        flushes: usize,
        zero_write: bool,
        over_report: bool,
    }

    impl FakeTransport {
        fn new(max_write: usize) -> Self {
            Self {
                written: Vec::new(),
                incoming: b"ssh-bytes".to_vec(),
                max_write,
                flushes: 0,
                zero_write: false,
                over_report: false,
            }
        }
    }

    impl Transport for FakeTransport {
        fn read(&mut self, buffer: &mut [u8]) -> Result<usize, TransportError> {
            let count = self.incoming.len().min(buffer.len());
            buffer[..count].copy_from_slice(&self.incoming[..count]);
            self.incoming.drain(..count);
            Ok(count)
        }

        fn write(&mut self, buffer: &[u8]) -> Result<usize, TransportError> {
            if self.zero_write {
                return Ok(0);
            }
            if self.over_report {
                return Ok(buffer.len() + 1);
            }
            let count = buffer.len().min(self.max_write);
            self.written.extend_from_slice(&buffer[..count]);
            Ok(count)
        }

        fn flush(&mut self) -> Result<(), TransportError> {
            self.flushes += 1;
            Ok(())
        }

        fn shutdown(&self, _how: Shutdown) -> Result<(), TransportError> {
            Ok(())
        }

        fn local_addr(&self) -> Result<SocketAddr, TransportError> {
            Ok(SocketAddr::from(([127, 0, 0, 1], 1000)))
        }

        fn peer_addr(&self) -> Result<SocketAddr, TransportError> {
            Ok(SocketAddr::from(([127, 0, 0, 1], 2000)))
        }
    }

    fn hello() -> GatewayClientHello {
        GatewayClientHello::new("header.payload.signature", "proof.body.signature")
            .expect("valid hello")
    }

    fn certs(pem: &str) -> Vec<CertificateDer<'static>> {
        CertificateDer::pem_slice_iter(pem.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .expect("certificates")
    }

    fn private_key(pem: &str) -> PrivateKeyDer<'static> {
        PrivateKeyDer::from_pem_slice(pem.as_bytes()).expect("private key")
    }

    fn server_config() -> Arc<ServerConfig> {
        let mut config = ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_no_client_auth()
            .with_single_cert(certs(test_certs::SERVER_CERT), private_key(test_certs::SERVER_KEY))
            .expect("server config");
        config.alpn_protocols = vec![GATEWAY_ALPN.to_vec()];
        Arc::new(config)
    }

    fn client_config() -> GatewayTlsClientConfig {
        let mut roots = RootCertStore::empty();
        roots.add(certs(test_certs::CA_CERT).remove(0)).expect("CA");
        GatewayTlsClientConfig::new(roots, "localhost").expect("client config")
    }

    #[test]
    fn handshake_writes_one_complete_frame_across_partial_writes() {
        let transport = FakeTransport::new(2);
        let wrapped = GatewayTransport::handshake(transport, &hello()).expect("handshake");
        let inner = wrapped.into_inner();
        assert_eq!(GatewayClientHello::from_frame(&inner.written).expect("frame"), hello());
        assert_eq!(inner.flushes, 1);
    }

    #[test]
    fn invalid_hello_is_rejected_before_writing() {
        let invalid = GatewayClientHello {
            ticket: "not-a-jws".into(),
            dpop_proof: "proof.body.signature".into(),
        };
        let transport = FakeTransport::new(16);
        let error = GatewayTransport::handshake(transport, &invalid).expect_err("invalid hello");
        assert!(matches!(error, GatewayTransportError::Codec(GatewayCodecError::Invalid(_))));
    }

    #[test]
    fn zero_length_write_is_typed() {
        let mut transport = FakeTransport::new(16);
        transport.zero_write = true;
        let error = GatewayTransport::handshake(transport, &hello()).expect_err("write failure");
        assert_eq!(
            error,
            GatewayTransportError::Transport(TransportError::Io {
                operation: TransportOperation::Write,
                kind: ErrorKind::WriteZero,
            })
        );
    }

    #[test]
    fn over_reporting_write_is_typed_without_panicking() {
        let mut transport = FakeTransport::new(16);
        transport.over_report = true;
        let error = GatewayTransport::handshake(transport, &hello()).expect_err("write failure");
        assert_eq!(
            error,
            GatewayTransportError::Transport(TransportError::Io {
                operation: TransportOperation::Write,
                kind: ErrorKind::InvalidData,
            })
        );
    }

    #[test]
    fn wrapped_transport_delegates_ssh_bytes_and_addresses() {
        let wrapped =
            GatewayTransport::handshake(FakeTransport::new(64), &hello()).expect("handshake");
        assert_eq!(wrapped.local_addr().expect("local"), SocketAddr::from(([127, 0, 0, 1], 1000)));
        assert_eq!(wrapped.peer_addr().expect("peer"), SocketAddr::from(([127, 0, 0, 1], 2000)));
        let mut wrapped = wrapped;
        let mut bytes = [0; 4];
        assert_eq!(wrapped.read(&mut bytes).expect("read"), 4);
        assert_eq!(&bytes, b"ssh-");
        assert_eq!(wrapped.write(b"next").expect("write"), 4);
    }

    #[tokio::test]
    async fn async_handshake_writes_frame_and_delegates_bytes() {
        let hello = hello();
        let (client, mut peer) = duplex(4096);
        let expected = hello.clone();
        let handshake = tokio::spawn(async move {
            AsyncGatewayTransport::handshake(client, &hello).await.expect("handshake")
        });

        let mut prefix = [0; 4];
        peer.read_exact(&mut prefix).await.expect("frame prefix");
        let length = u32::from_be_bytes(prefix) as usize;
        let mut body = vec![0; length];
        peer.read_exact(&mut body).await.expect("frame body");
        let mut frame = prefix.to_vec();
        frame.extend_from_slice(&body);
        assert_eq!(GatewayClientHello::from_frame(&frame).expect("frame"), expected);

        peer.write_all(b"ssh").await.expect("peer write");
        peer.flush().await.expect("peer flush");
        let mut wrapped = handshake.await.expect("join");
        let mut incoming = [0; 3];
        wrapped.read_exact(&mut incoming).await.expect("wrapped read");
        assert_eq!(&incoming, b"ssh");
        wrapped.write_all(b"reply").await.expect("wrapped write");
        wrapped.flush().await.expect("wrapped flush");
        let mut outgoing = [0; 5];
        peer.read_exact(&mut outgoing).await.expect("peer read");
        assert_eq!(&outgoing, b"reply");
    }

    #[tokio::test]
    async fn tls_connector_negotiates_tls13_alpn_before_prelude() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
        let address = listener.local_addr().expect("address");
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept");
            let acceptor = TlsAcceptor::from(server_config());
            let mut tls = acceptor.accept(stream).await.expect("TLS");
            let (_, connection): (&TcpStream, &ServerConnection) = tls.get_ref();
            assert_eq!(connection.protocol_version(), Some(rustls::version::TLS13.version));
            assert_eq!(connection.alpn_protocol(), Some(GATEWAY_ALPN));
            let mut prefix = [0; 4];
            tls.read_exact(&mut prefix).await.expect("prefix");
            let length = u32::from_be_bytes(prefix) as usize;
            let mut body = vec![0; length];
            tls.read_exact(&mut body).await.expect("body");
            let mut frame = prefix.to_vec();
            frame.extend_from_slice(&body);
            assert_eq!(GatewayClientHello::from_frame(&frame).expect("hello"), hello());
            tls.write_all(b"ssh-server-banner").await.expect("banner");
            tls.flush().await.expect("flush");
        });

        let config = client_config();
        let stream = TcpStream::connect(address).await.expect("connect");
        let mut gateway = config.connect_and_handshake(stream, &hello()).await.expect("gateway");
        let (_, connection) = gateway.get_ref().get_ref();
        assert_eq!(connection.protocol_version(), Some(rustls::version::TLS13.version));
        assert_eq!(connection.alpn_protocol(), Some(GATEWAY_ALPN));
        let mut banner = [0; 17];
        gateway.read_exact(&mut banner).await.expect("banner");
        assert_eq!(&banner, b"ssh-server-banner");
        server.await.expect("server task");
    }

    #[test]
    fn tls_client_configuration_rejects_empty_roots_and_invalid_names() {
        let error = GatewayTlsClientConfig::new(RootCertStore::empty(), "localhost")
            .expect_err("empty roots");
        assert!(matches!(error, GatewayTlsConfigError::Empty("root certificates")));

        let mut roots = RootCertStore::empty();
        roots.add(certs(test_certs::CA_CERT).remove(0)).expect("CA");
        let error = GatewayTlsClientConfig::new(roots, &"a".repeat(MAX_TLS_DOMAIN_BYTES + 1))
            .expect_err("long name");
        assert!(matches!(error, GatewayTlsConfigError::DomainTooLong));
    }

    #[tokio::test]
    async fn tls_connector_rejects_wrong_alpn_before_hello() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
        let address = listener.local_addr().expect("address");
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept");
            let mut config = (*server_config()).clone();
            config.alpn_protocols = vec![b"h2".to_vec()];
            let acceptor = TlsAcceptor::from(Arc::new(config));
            acceptor.accept(stream).await
        });

        let stream = TcpStream::connect(address).await.expect("connect");
        let error = client_config()
            .connect_and_handshake(stream, &hello())
            .await
            .expect_err("ALPN mismatch");
        assert!(matches!(
            error,
            GatewayTlsConnectError::AlpnMismatch | GatewayTlsConnectError::Tls(_)
        ));
        let _ = server.await.expect("server task");
    }

    #[tokio::test]
    async fn tls_connector_rejects_absent_alpn_before_hello() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
        let address = listener.local_addr().expect("address");
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept");
            let mut config = (*server_config()).clone();
            config.alpn_protocols.clear();
            TlsAcceptor::from(Arc::new(config)).accept(stream).await
        });

        let stream = TcpStream::connect(address).await.expect("connect");
        let error = client_config()
            .connect_and_handshake(stream, &hello())
            .await
            .expect_err("ALPN missing");
        assert!(matches!(error, GatewayTlsConnectError::AlpnMismatch));
        let _ = server.await.expect("server task");
    }

    #[tokio::test]
    async fn tls_connector_rejects_wrong_server_name_before_hello() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
        let address = listener.local_addr().expect("address");
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept");
            TlsAcceptor::from(server_config()).accept(stream).await
        });

        let mut roots = RootCertStore::empty();
        roots.add(certs(test_certs::CA_CERT).remove(0)).expect("CA");
        let config =
            GatewayTlsClientConfig::new(roots, "not-localhost.test").expect("client config");
        let stream = TcpStream::connect(address).await.expect("connect");
        let error =
            config.connect_and_handshake(stream, &hello()).await.expect_err("name mismatch");
        assert!(matches!(error, GatewayTlsConnectError::Tls(_)));
        let _ = server.await.expect("server task");
    }

    #[tokio::test]
    async fn client_connection_gateway_route_orders_tcp_tls_prelude_and_ssh() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
        let address = listener.local_addr().expect("address");
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept");
            let acceptor = TlsAcceptor::from(server_config());
            let mut tls = acceptor.accept(stream).await.expect("TLS");
            let (_, connection): (&TcpStream, &ServerConnection) = tls.get_ref();
            assert_eq!(connection.alpn_protocol(), Some(GATEWAY_ALPN));
            let mut prefix = [0; 4];
            tls.read_exact(&mut prefix).await.expect("prefix");
            let length = u32::from_be_bytes(prefix) as usize;
            let mut body = vec![0; length];
            tls.read_exact(&mut body).await.expect("body");
            let mut frame = prefix.to_vec();
            frame.extend_from_slice(&body);
            assert_eq!(GatewayClientHello::from_frame(&frame).expect("hello"), hello());
            tls.write_all(b"not-ssh\r\n").await.expect("banner");
            tls.flush().await.expect("flush");
        });

        let verifier =
            |_host: &str, _key: &HostKey| -> Result<(), HostKeyVerificationError> { Ok(()) };
        let ssh = ClientConfig::new("localhost", 22, verifier).expect("SSH config");
        let result = ClientConnection::connect_via_gateway(
            ssh,
            "127.0.0.1",
            address.port(),
            std::time::Duration::from_secs(2),
            &client_config(),
            &hello(),
        )
        .await;
        assert!(matches!(
            result,
            Err(ClientError::Protocol | ClientError::ConnectionClosed | ClientError::Transport(_))
        ));
        server.await.expect("server task");
    }

    #[tokio::test]
    async fn client_connection_gateway_route_times_out_stalled_tls_handshake() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
        let address = listener.local_addr().expect("address");
        let server = tokio::spawn(async move {
            let (_stream, _) = listener.accept().await.expect("accept");
            sleep(std::time::Duration::from_millis(500)).await;
        });
        let verifier =
            |_host: &str, _key: &HostKey| -> Result<(), HostKeyVerificationError> { Ok(()) };
        let ssh = ClientConfig::new("localhost", 22, verifier).expect("SSH config");
        let result = ClientConnection::connect_via_gateway(
            ssh,
            "127.0.0.1",
            address.port(),
            std::time::Duration::from_millis(50),
            &client_config(),
            &hello(),
        )
        .await;
        assert!(matches!(result, Err(ClientError::GatewayHandshakeTimeout { .. })));
        server.await.expect("server task");
    }
}
