// SPDX-License-Identifier: Apache-2.0
//! K-6 gateway client-hello composition over an established byte transport.
//!
//! TLS and ALPN negotiation are owned by the platform or gateway connector. This module keeps the
//! bounded, one-shot client-hello framing adjacent to the SSH [`Transport`] boundary so the SSH
//! engine receives the stream only after the K-6 prelude has been written successfully.

use std::{
    fmt, io,
    net::{Shutdown, SocketAddr},
};

use scoplen_api::gateway::{GatewayClientHello, GatewayCodecError};
use thiserror::Error;

use crate::tcp::{Transport, TransportError, TransportOperation};

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

/// A byte transport after the bounded K-6 client hello has been sent.
///
/// The constructor writes exactly one length-prefixed `GatewayClientHello`, handling partial
/// writes and flushing before returning. It does not perform TLS or ALPN negotiation; callers must
/// establish that boundary before passing the resulting stream to this adapter.
pub struct GatewayTransport<T> {
    inner: T,
}

impl<T> fmt::Debug for GatewayTransport<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("GatewayTransport").finish_non_exhaustive()
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
    use std::io::ErrorKind;

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
}
