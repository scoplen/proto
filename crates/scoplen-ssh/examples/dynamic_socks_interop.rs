// SPDX-License-Identifier: Apache-2.0
//! Exercise the concrete dynamic SOCKS listener against a disposable OpenSSH server with TCP
//! forwarding enabled. Set `SCOPLEN_OPENSSH_HOST_KEY` to its public-key line and
//! `SCOPLEN_OPENSSH_PASSWORD` to the test account password. Optional host, port, and username
//! variables match the direct OpenSSH interoperability example.

use std::{env, net::SocketAddr, sync::Arc, time::Duration};

use scoplen_ssh::{
    ChannelEvent, ClientConfig, ClientConnection, HostKey, HostKeyVerificationError,
    SocksCancellation, SocksConnector, SocksListener, SocksListenerConfig,
};
use ssh_key::PublicKey;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::timeout,
};

const IO_TIMEOUT: Duration = Duration::from_secs(5);
const OPENSSH_PORT: u16 = 2222;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let host = env::var("SCOPLEN_OPENSSH_HOST").unwrap_or_else(|_| "127.0.0.1".to_owned());
    let port =
        env::var("SCOPLEN_OPENSSH_PORT").unwrap_or_else(|_| "22223".to_owned()).parse::<u16>()?;
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
        .map_err(|_| "OpenSSH connection timed out")??;
    timeout(
        Duration::from_secs(10),
        connection.authenticate_password(&username, password.as_bytes()),
    )
    .await
    .map_err(|_| "OpenSSH authentication timed out")??;
    let connection = Arc::new(connection);

    let listener =
        SocksListener::bind(([127, 0, 0, 1], 0).into(), SocksListenerConfig::default()).await?;
    let address = listener.local_addr()?;
    let cancellation = SocksCancellation::new();
    let task_cancellation = cancellation.clone();
    let connector: Arc<dyn SocksConnector> = connection.clone();
    let task = tokio::spawn(async move { listener.run(connector, task_cancellation).await });

    let result = verify_forwarding(address, &connection).await;
    cancellation.cancel();
    timeout(Duration::from_secs(5), task)
        .await
        .map_err(|_| "SOCKS listener did not stop after cancellation")???;
    result?;
    let rebound = TcpListener::bind(address).await?;
    drop(rebound);
    connection.disconnect().await?;
    println!("openssh dynamic SOCKS interop ok");
    Ok(())
}

async fn verify_forwarding(
    address: SocketAddr,
    connection: &ClientConnection,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut socks5 = socks5_connect(address, OPENSSH_PORT).await?;
    let mut socks4a = socks4a_connect(address, OPENSSH_PORT).await?;
    read_openssh_banner(&mut socks5).await?;
    read_openssh_banner(&mut socks4a).await?;
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
    match timeout(IO_TIMEOUT, refused.read_u8()).await {
        Ok(Err(error)) if error.kind() == std::io::ErrorKind::UnexpectedEof => {}
        Ok(Err(error)) => return Err(error.into()),
        Ok(Ok(_)) | Err(_) => return Err("rejected SOCKS5 connection stayed open".into()),
    }

    let mut fresh_stream = socks5_connect(address, OPENSSH_PORT).await?;
    read_openssh_banner(&mut fresh_stream).await?;
    fresh_stream.shutdown().await?;
    drop(fresh_stream);
    verify_session(connection).await?;
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
    let [high, low] = target_port.to_be_bytes();
    let mut request = vec![4, 1, high, low, 0, 0, 0, 1, 0];
    request.extend_from_slice(b"127.0.0.1\0");
    stream.write_all(&request).await?;
    if read_exact::<8>(&mut stream).await? != [0, 90, 0, 0, 0, 0, 0, 0] {
        return Err("SOCKS4a direct-tcpip open failed".into());
    }
    Ok(stream)
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

async fn read_openssh_banner(stream: &mut TcpStream) -> Result<(), Box<dyn std::error::Error>> {
    let mut banner = Vec::new();
    while banner.len() < 256 {
        let byte = timeout(IO_TIMEOUT, stream.read_u8())
            .await
            .map_err(|_| "forwarded OpenSSH banner timed out")??;
        banner.push(byte);
        if byte == b'\n' {
            break;
        }
    }
    if !banner.starts_with(b"SSH-2.0-OpenSSH_") || !banner.ends_with(b"\r\n") {
        return Err("forwarded OpenSSH banner was missing or invalid".into());
    }
    Ok(())
}

async fn verify_session(connection: &ClientConnection) -> Result<(), Box<dyn std::error::Error>> {
    let mut channel = connection.open_session().await?;
    channel.exec(true, b"printf scoplen-socks-ok").await?;
    let mut output = Vec::new();
    let mut exited = false;
    loop {
        let event = timeout(IO_TIMEOUT, channel.next_event())
            .await
            .map_err(|_| "OpenSSH session command timed out")??;
        match event {
            Some(ChannelEvent::Data(data)) if output.len() + data.len() <= 256 => {
                output.extend_from_slice(&data);
            }
            Some(ChannelEvent::ExitStatus(0)) => exited = true,
            Some(ChannelEvent::Success | ChannelEvent::Eof) => {}
            Some(ChannelEvent::Close) | None => break,
            _ => return Err("unexpected OpenSSH session event".into()),
        }
    }
    if !exited || output != b"scoplen-socks-ok" {
        return Err("OpenSSH session command failed".into());
    }
    Ok(())
}
