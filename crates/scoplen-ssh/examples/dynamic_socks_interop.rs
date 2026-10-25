// SPDX-License-Identifier: Apache-2.0
//! Exercise the concrete dynamic SOCKS listener against a disposable SSH server with TCP
//! forwarding enabled. Set `SCOPLEN_OPENSSH_HOST_KEY` to its public-key line and
//! `SCOPLEN_OPENSSH_PASSWORD` to the test account password. Optional host, port, and username
//! variables match the direct OpenSSH interoperability example.

use std::{env, net::SocketAddr, sync::Arc, time::Duration};

use scoplen_ssh::{
    ClientConfig, ClientConnection, HostKey, HostKeyVerificationError, SocksCancellation,
    SocksConnector, SocksListener, SocksListenerConfig,
};
use ssh_key::PublicKey;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::timeout,
};

#[path = "support/forwarding_fixture.rs"]
mod forwarding_fixture;

const IO_TIMEOUT: Duration = Duration::from_secs(5);
const OPENSSH_PORT: u16 = 2222;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let peer = forwarding_fixture::Peer::from_env()?;
    let port =
        env::var("SCOPLEN_OPENSSH_PORT").unwrap_or_else(|_| "22223".to_owned()).parse::<u16>()?;
    let connection = Arc::new(connect(port).await?);
    verify_listener(connection.clone(), peer, false).await?;
    connection.disconnect().await?;
    if let Some(port) = peer.denied_port()? {
        let connection = Arc::new(connect(port).await?);
        verify_listener(connection.clone(), peer, true).await?;
        connection.disconnect().await?;
    }
    println!("{} dynamic SOCKS interop ok", peer.label());
    Ok(())
}

async fn connect(port: u16) -> Result<ClientConnection, Box<dyn std::error::Error>> {
    let host = env::var("SCOPLEN_OPENSSH_HOST").unwrap_or_else(|_| "127.0.0.1".to_owned());
    let username = env::var("SCOPLEN_OPENSSH_USER").unwrap_or_else(|_| "scoplen".to_owned());
    let password = env::var("SCOPLEN_OPENSSH_PASSWORD")?;
    let expected_key =
        PublicKey::from_openssh(&env::var("SCOPLEN_OPENSSH_HOST_KEY")?)?.to_bytes()?;
    let config = ClientConfig::new(&host, port, move |_host: &str, key: &HostKey| match key {
        HostKey::Raw { key_blob, .. } if *key_blob == expected_key => Ok(()),
        _ => Err(HostKeyVerificationError::Rejected("unexpected server key".to_owned())),
    })?;
    let mut connection = timeout(Duration::from_secs(10), ClientConnection::connect(config))
        .await
        .map_err(|_| "SSH connection timed out")??;
    timeout(
        Duration::from_secs(10),
        connection.authenticate_password(&username, password.as_bytes()),
    )
    .await
    .map_err(|_| "SSH authentication timed out")??;
    Ok(connection)
}

async fn verify_listener(
    connection: Arc<ClientConnection>,
    peer: forwarding_fixture::Peer,
    denied: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let listener =
        SocksListener::bind(([127, 0, 0, 1], 0).into(), SocksListenerConfig::default()).await?;
    let address = listener.local_addr()?;
    let cancellation = SocksCancellation::new();
    let task_cancellation = cancellation.clone();
    let connector: Arc<dyn SocksConnector> = connection.clone();
    let task = tokio::spawn(async move { listener.run(connector, task_cancellation).await });

    let result = if denied {
        verify_denied_socks(address).await.map(|()| None)
    } else {
        verify_forwarding(address, &connection, peer).await.map(Some)
    };
    cancellation.cancel();
    timeout(Duration::from_secs(5), task)
        .await
        .map_err(|_| "SOCKS listener did not stop after cancellation")???;
    if let Some(mut retained) = result? {
        expect_cancelled_eof(&mut retained).await?;
    }
    let rebound = TcpListener::bind(address).await?;
    drop(rebound);
    forwarding_fixture::verify_session(&connection).await?;
    Ok(())
}

async fn verify_forwarding(
    address: SocketAddr,
    connection: &ClientConnection,
    peer: forwarding_fixture::Peer,
) -> Result<TcpStream, Box<dyn std::error::Error>> {
    let mut socks5 = socks5_connect(address, OPENSSH_PORT).await?;
    let mut socks4a = socks4a_connect(address, OPENSSH_PORT).await?;
    read_ssh_banner(&mut socks5, peer).await?;
    read_ssh_banner(&mut socks4a, peer).await?;
    socks5.shutdown().await?;
    socks4a.shutdown().await?;
    drop(socks5);
    drop(socks4a);

    let mut refused = TcpStream::connect(address).await?;
    refused.write_all(&[5, 1, 0]).await?;
    if read_exact::<2>(&mut refused).await? != [5, 0] {
        return Err("SOCKS5 method negotiation failed".into());
    }
    refused.write_all(&socks5_request(1)).await?;
    let response = read_exact::<10>(&mut refused).await?;
    if response != [5, 5, 0, 1, 0, 0, 0, 0, 0, 0] {
        return Err(
            format!("closed target produced unexpected SOCKS5 response: {response:?}").into()
        );
    }
    expect_eof(&mut refused).await?;

    if peer == forwarding_fixture::Peer::Dropbear {
        let first = socks5_connect(address, forwarding_fixture::ECHO_PORT).await?;
        let second = socks4a_connect(address, forwarding_fixture::ECHO_PORT).await?;
        forwarding_fixture::verify_binary_pair(first, second).await?;
    }

    let mut fresh_stream = socks5_connect(address, OPENSSH_PORT).await?;
    read_ssh_banner(&mut fresh_stream, peer).await?;
    fresh_stream.shutdown().await?;
    drop(fresh_stream);
    forwarding_fixture::verify_session(connection).await?;
    let mut retained = socks5_connect(address, OPENSSH_PORT).await?;
    read_ssh_banner(&mut retained, peer).await?;
    Ok(retained)
}

async fn verify_denied_socks(address: SocketAddr) -> Result<(), Box<dyn std::error::Error>> {
    let mut socks5 = TcpStream::connect(address).await?;
    socks5.write_all(&[5, 1, 0]).await?;
    if read_exact::<2>(&mut socks5).await? != [5, 0] {
        return Err("denied SOCKS5 method negotiation failed".into());
    }
    socks5.write_all(&socks5_request(forwarding_fixture::ECHO_PORT)).await?;
    if read_exact::<10>(&mut socks5).await? != [5, 2, 0, 1, 0, 0, 0, 0, 0, 0] {
        return Err("Dropbear prohibition did not become SOCKS5 connection-not-allowed".into());
    }
    expect_eof(&mut socks5).await?;

    let mut socks4a = TcpStream::connect(address).await?;
    socks4a.write_all(&socks4a_request(forwarding_fixture::ECHO_PORT)).await?;
    if read_exact::<8>(&mut socks4a).await? != [0, 91, 0, 0, 0, 0, 0, 0] {
        return Err("Dropbear prohibition did not become SOCKS4a rejection".into());
    }
    expect_eof(&mut socks4a).await?;
    Ok(())
}

async fn expect_eof(stream: &mut TcpStream) -> Result<(), Box<dyn std::error::Error>> {
    if timeout(IO_TIMEOUT, stream.read(&mut [0])).await?? != 0 {
        return Err("closed SOCKS connection returned unexpected bytes".into());
    }
    Ok(())
}

async fn expect_cancelled_eof<R: AsyncRead + Unpin>(
    stream: &mut R,
) -> Result<(), Box<dyn std::error::Error>> {
    // Already queued SSH KEX bytes precede the cancellation's TCP EOF.
    let mut queued = stream.take(65_537);
    let mut bytes = Vec::new();
    timeout(IO_TIMEOUT, queued.read_to_end(&mut bytes)).await??;
    if bytes.len() > 65_536 {
        return Err("cancelled SOCKS connection exceeded its queued-data limit".into());
    }
    Ok(())
}

async fn socks5_connect(
    address: SocketAddr,
    target_port: u16,
) -> Result<TcpStream, Box<dyn std::error::Error>> {
    let mut stream = TcpStream::connect(address).await?;
    stream.write_all(&[5, 1, 0]).await?;
    if read_exact::<2>(&mut stream).await? != [5, 0] {
        return Err("SOCKS5 method negotiation failed".into());
    }
    stream.write_all(&socks5_request(target_port)).await?;
    if read_exact::<10>(&mut stream).await? != [5, 0, 0, 1, 0, 0, 0, 0, 0, 0] {
        return Err("SOCKS5 direct-tcpip open failed".into());
    }
    Ok(stream)
}

fn socks5_request(port: u16) -> [u8; 10] {
    let [high, low] = port.to_be_bytes();
    [5, 1, 0, 1, 127, 0, 0, 1, high, low]
}

async fn socks4a_connect(
    address: SocketAddr,
    target_port: u16,
) -> Result<TcpStream, Box<dyn std::error::Error>> {
    let mut stream = TcpStream::connect(address).await?;
    stream.write_all(&socks4a_request(target_port)).await?;
    if read_exact::<8>(&mut stream).await? != [0, 90, 0, 0, 0, 0, 0, 0] {
        return Err("SOCKS4a direct-tcpip open failed".into());
    }
    Ok(stream)
}

fn socks4a_request(port: u16) -> Vec<u8> {
    let [high, low] = port.to_be_bytes();
    let mut request = vec![4, 1, high, low, 0, 0, 0, 1, 0];
    request.extend_from_slice(b"127.0.0.1\0");
    request
}

async fn read_exact<const N: usize>(
    stream: &mut TcpStream,
) -> Result<[u8; N], Box<dyn std::error::Error>> {
    let mut bytes = [0; N];
    timeout(IO_TIMEOUT, stream.read_exact(&mut bytes))
        .await
        .map_err(|_| "SOCKS response timed out")??;
    Ok(bytes)
}

async fn read_ssh_banner(
    stream: &mut TcpStream,
    peer: forwarding_fixture::Peer,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut banner = Vec::new();
    while banner.len() < 256 {
        let byte = timeout(IO_TIMEOUT, stream.read_u8())
            .await
            .map_err(|_| "forwarded SSH banner timed out")??;
        banner.push(byte);
        if byte == b'\n' {
            break;
        }
    }
    if !peer.matches_banner(&banner) {
        return Err("forwarded SSH banner did not match the selected fixture".into());
    }
    Ok(())
}

#[cfg(test)]
mod cancellation_tests {
    use super::expect_cancelled_eof;

    #[tokio::test]
    async fn cancellation_requires_eof_after_bounded_already_queued_bytes() {
        let mut queued: &[u8] = &[0; 1024];
        expect_cancelled_eof(&mut queued).await.unwrap();
        assert!(queued.is_empty());
        let mut oversized: &[u8] = &[0; 65_537];
        assert!(expect_cancelled_eof(&mut oversized).await.is_err());
    }
}
