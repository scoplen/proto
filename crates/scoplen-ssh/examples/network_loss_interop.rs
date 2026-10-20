// SPDX-License-Identifier: Apache-2.0
//! Exercise established-channel termination against a disposable OpenSSH listener.

use std::{
    env, io,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use scoplen_ssh::{
    ChannelEvent, ClientConfig, ClientConnection, ClientError, HostKey, HostKeyVerificationError,
};
use ssh_key::PublicKey;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::watch,
    task::JoinHandle,
    time::timeout,
};

const DEADLINE: Duration = Duration::from_secs(10);
const PASSWORD: &[u8] = b"fixture-network-loss-password";

#[derive(Clone, Copy, PartialEq, Eq)]
enum RelayMode {
    Forward,
    Blackhole,
}

struct Relay {
    port: u16,
    mode: watch::Sender<RelayMode>,
    blackholed_client_bytes: Arc<AtomicUsize>,
    task: JoinHandle<io::Result<()>>,
}

impl Drop for Relay {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn pump<R, W>(
    mut reader: R,
    mut writer: W,
    mode: watch::Receiver<RelayMode>,
    blackholed_bytes: Option<Arc<AtomicUsize>>,
) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buffer = [0_u8; 4096];
    loop {
        let count = reader.read(&mut buffer).await?;
        if count == 0 {
            return writer.shutdown().await;
        }
        if *mode.borrow() == RelayMode::Blackhole {
            if let Some(counter) = &blackholed_bytes {
                counter.fetch_add(count, Ordering::SeqCst);
            }
        } else {
            writer.write_all(&buffer[..count]).await?;
        }
    }
}

async fn start_relay(server_port: u16, reset_on_drop: bool) -> io::Result<Relay> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let (mode, relay_mode) = watch::channel(RelayMode::Forward);
    let blackholed_client_bytes = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&blackholed_client_bytes);
    let task = tokio::spawn(async move {
        let (client, _) = listener.accept().await?;
        let client = if reset_on_drop {
            let socket = socket2::Socket::from(client.into_std()?);
            socket.set_linger(Some(Duration::ZERO))?;
            TcpStream::from_std(socket.into())?
        } else {
            client
        };
        let server = TcpStream::connect(("127.0.0.1", server_port)).await?;
        let (client_read, client_write) = client.into_split();
        let (server_read, server_write) = server.into_split();
        let (up, down) = tokio::join!(
            pump(client_read, server_write, relay_mode.clone(), Some(counter)),
            pump(server_read, client_write, relay_mode, None),
        );
        up?;
        down
    });
    Ok(Relay { port, mode, blackholed_client_bytes, task })
}

async fn connect(
    relay: &Relay,
    host_key: &[u8],
    keepalive: bool,
) -> Result<ClientConnection, Box<dyn std::error::Error>> {
    let pinned = host_key.to_vec();
    let mut config =
        ClientConfig::new("127.0.0.1", relay.port, move |_host: &str, key: &HostKey| match key {
            HostKey::Raw { key_blob, .. } if *key_blob == pinned => Ok(()),
            _ => Err(HostKeyVerificationError::Rejected("unexpected host key".to_owned())),
        })?;
    if keepalive {
        config = config.with_keepalive(Some(Duration::from_millis(150)), 2)?;
    }
    let stream = timeout(DEADLINE, TcpStream::connect(("127.0.0.1", relay.port))).await??;
    let mut connection =
        timeout(DEADLINE, ClientConnection::connect_stream(config, stream)).await??;
    timeout(DEADLINE, connection.authenticate_password("scoplen", PASSWORD)).await??;
    Ok(connection)
}

async fn assert_network_loss(
    server_port: u16,
    host_key: &[u8],
    reset: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let relay = start_relay(server_port, reset).await?;
    let connection = connect(&relay, host_key, false).await?;
    let mut channel = timeout(DEADLINE, connection.open_session()).await??;
    relay.task.abort();
    let result = timeout(DEADLINE, channel.next_event()).await?;
    if !matches!(result, Err(ClientError::NetworkLost)) {
        return Err(format!(
            "abrupt {}: expected NetworkLost, got {result:?}",
            if reset { "RST" } else { "EOF" }
        )
        .into());
    }
    println!("OpenSSH abrupt {}: NetworkLost", if reset { "RST" } else { "EOF" });
    Ok(())
}

async fn assert_keepalive_loss(
    server_port: u16,
    host_key: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    let relay = start_relay(server_port, false).await?;
    let connection = connect(&relay, host_key, true).await?;
    let mut channel = timeout(DEADLINE, connection.open_session()).await??;
    relay.mode.send_replace(RelayMode::Blackhole);
    let result = timeout(DEADLINE, channel.next_event()).await?;
    if !matches!(result, Err(ClientError::NetworkLost)) {
        return Err(format!("keepalive blackhole: expected NetworkLost, got {result:?}").into());
    }
    if relay.blackholed_client_bytes.load(Ordering::SeqCst) == 0 {
        return Err("keepalive blackhole saw no client probes".into());
    }
    println!("OpenSSH keepalive blackhole: NetworkLost");
    Ok(())
}

async fn assert_normal_exit(
    server_port: u16,
    host_key: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    let relay = start_relay(server_port, false).await?;
    let connection = connect(&relay, host_key, false).await?;
    let mut channel = timeout(DEADLINE, connection.open_session()).await??;
    timeout(DEADLINE, channel.exec(true, b"printf normal-exit")).await??;
    let mut output = Vec::new();
    let mut status = None;
    let mut closed = false;
    loop {
        match timeout(DEADLINE, channel.next_event()).await?? {
            Some(ChannelEvent::Data(data)) => output.extend_from_slice(&data),
            Some(ChannelEvent::ExitStatus(code)) => status = Some(code),
            Some(ChannelEvent::Close) => closed = true,
            Some(ChannelEvent::Eof | ChannelEvent::Success) => {}
            None => break,
            other => return Err(format!("normal exit: unexpected event {other:?}").into()),
        }
    }
    if output != b"normal-exit" || status != Some(0) || !closed {
        return Err(
            format!("normal exit: output {output:?}, status {status:?}, close {closed}").into()
        );
    }
    relay.task.abort();
    if channel.next_event().await?.is_some() {
        return Err("completed channel produced an event after termination".into());
    }
    println!("OpenSSH normal shell exit: terminal events and None");
    Ok(())
}

async fn assert_local_close(
    server_port: u16,
    host_key: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    let relay = start_relay(server_port, false).await?;
    let connection = connect(&relay, host_key, false).await?;
    let mut channel = timeout(DEADLINE, connection.open_session()).await??;
    timeout(DEADLINE, channel.close()).await??;
    relay.task.abort();
    loop {
        match timeout(DEADLINE, channel.next_event()).await?? {
            Some(ChannelEvent::Close | ChannelEvent::Eof) => {}
            None => break,
            other => return Err(format!("local close: unexpected event {other:?}").into()),
        }
    }
    println!("OpenSSH local channel close: None");
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let server_port = env::var("SCOPLEN_NETWORK_LOSS_PORT")?.parse()?;
    let host_key =
        PublicKey::from_openssh(&env::var("SCOPLEN_NETWORK_LOSS_HOST_KEY")?)?.to_bytes()?;
    assert_network_loss(server_port, &host_key, false).await?;
    assert_network_loss(server_port, &host_key, true).await?;
    assert_keepalive_loss(server_port, &host_key).await?;
    assert_normal_exit(server_port, &host_key).await?;
    assert_local_close(server_port, &host_key).await?;
    Ok(())
}
