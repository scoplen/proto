// SPDX-License-Identifier: Apache-2.0

use std::{
    io::{self, ErrorKind},
    net::TcpListener,
    thread,
    time::Duration,
};

use scoplen_ssh::{
    HttpConnectTransport, ProxyError, ProxyOperation, ProxyProtocol, ProxyTransportError,
    Socks5Transport,
};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_millis(100);

fn stalled_proxy() -> (u16, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind proxy");
    let port = listener.local_addr().expect("proxy address").port();
    let task = thread::spawn(move || {
        let (mut client, _) = listener.accept().expect("accept proxy client");
        client.set_read_timeout(Some(Duration::from_secs(5))).expect("bound proxy read");
        let request_bytes =
            io::copy(&mut client, &mut io::sink()).expect("read until client close");
        assert!(request_bytes > 0, "client sent a proxy request");
    });
    (port, task)
}

#[test]
fn public_http_connect_read_timeout_is_timed_out() {
    let (port, proxy) = stalled_proxy();
    let error =
        HttpConnectTransport::connect("127.0.0.1", port, "target.example", 22, HANDSHAKE_TIMEOUT)
            .expect_err("proxy does not reply");
    assert_eq!(
        error,
        ProxyTransportError::Proxy(ProxyError::Io {
            protocol: ProxyProtocol::HttpConnect,
            operation: ProxyOperation::Read,
            kind: ErrorKind::TimedOut,
        })
    );
    proxy.join().expect("proxy thread");
}

#[test]
fn public_socks5_read_timeout_is_timed_out() {
    let (port, proxy) = stalled_proxy();
    let error =
        Socks5Transport::connect("127.0.0.1", port, "target.example", 22, HANDSHAKE_TIMEOUT)
            .expect_err("proxy does not reply");
    assert_eq!(
        error,
        ProxyTransportError::Proxy(ProxyError::Io {
            protocol: ProxyProtocol::Socks5,
            operation: ProxyOperation::Read,
            kind: ErrorKind::TimedOut,
        })
    );
    proxy.join().expect("proxy thread");
}
