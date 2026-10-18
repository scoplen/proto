// SPDX-License-Identifier: Apache-2.0

use std::{
    io,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicU8, AtomicUsize, Ordering},
    },
    time::Duration,
};

use russh::keys::PrivateKey;
use scoplen_ssh::{
    ChannelEvent, ClientChannel, ClientConfig, ClientConfigError, ClientConnection, HostKey,
};
use ssh_key::Algorithm;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpListener,
    task::JoinHandle,
    time::{sleep, timeout},
};

const INTERVAL: Duration = Duration::from_millis(70);
const DEADLINE: Duration = Duration::from_secs(3);
const FORWARD: u8 = 0;
const OBSERVE: u8 = 1;
const BLACKHOLE: u8 = 2;

#[derive(Clone)]
struct EchoServer;

impl russh::server::Handler for EchoServer {
    type Error = russh::Error;

    async fn auth_password(
        &mut self,
        user: &str,
        password: &str,
    ) -> Result<russh::server::Auth, Self::Error> {
        Ok(if user == "user" && password == "test-password" {
            russh::server::Auth::Accept
        } else {
            russh::server::Auth::reject()
        })
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

    async fn data(
        &mut self,
        channel: russh::ChannelId,
        data: &[u8],
        session: &mut russh::server::Session,
    ) -> Result<(), Self::Error> {
        session.data(channel, data.to_vec())
    }
}

struct RelayFixture {
    address: SocketAddr,
    mode: Arc<AtomicU8>,
    client_bytes: Arc<AtomicUsize>,
    relay: JoinHandle<()>,
    server: JoinHandle<()>,
}

impl Drop for RelayFixture {
    fn drop(&mut self) {
        self.relay.abort();
        self.server.abort();
    }
}

async fn pump<R, W>(
    mut reader: R,
    mut writer: W,
    mode: Arc<AtomicU8>,
    client_bytes: Option<Arc<AtomicUsize>>,
) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buffer = [0; 4096];
    loop {
        let count = reader.read(&mut buffer).await?;
        if count == 0 {
            break;
        }
        let current_mode = mode.load(Ordering::SeqCst);
        if current_mode >= OBSERVE
            && let Some(client_bytes) = &client_bytes
        {
            client_bytes.fetch_add(count, Ordering::SeqCst);
        }
        if current_mode != BLACKHOLE {
            writer.write_all(&buffer[..count]).await?;
        }
    }
    writer.shutdown().await
}

async fn start_fixture() -> RelayFixture {
    let mut server_config = russh::server::Config::default();
    server_config.keys.push(
        PrivateKey::random(
            &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
            Algorithm::Ed25519,
        )
        .expect("generate disposable host key"),
    );
    let server_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind SSH server");
    let server_address = server_listener.local_addr().expect("SSH server address");
    let server = tokio::spawn(async move {
        let (stream, _) = server_listener.accept().await.expect("accept SSH relay");
        let _ = russh::server::run_stream(Arc::new(server_config), stream, EchoServer).await;
    });

    let relay_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind relay");
    let address = relay_listener.local_addr().expect("relay address");
    let mode = Arc::new(AtomicU8::new(FORWARD));
    let client_bytes = Arc::new(AtomicUsize::new(0));
    let relay_mode = Arc::clone(&mode);
    let relay_client_bytes = Arc::clone(&client_bytes);
    let relay = tokio::spawn(async move {
        let (client, _) = relay_listener.accept().await.expect("accept SSH client");
        let server =
            tokio::net::TcpStream::connect(server_address).await.expect("connect SSH server");
        let (client_read, client_write) = client.into_split();
        let (server_read, server_write) = server.into_split();
        let (client_to_server, server_to_client) = tokio::join!(
            pump(client_read, server_write, Arc::clone(&relay_mode), Some(relay_client_bytes)),
            pump(server_read, client_write, relay_mode, None),
        );
        client_to_server.expect("relay client bytes");
        server_to_client.expect("relay server bytes");
    });
    RelayFixture { address, mode, client_bytes, relay, server }
}

async fn connect(fixture: &RelayFixture, keepalive: Option<Duration>) -> ClientConnection {
    let verifier = |_host: &str, _key: &HostKey| Ok(());
    let mut config =
        ClientConfig::new("127.0.0.1", fixture.address.port(), verifier).expect("client config");
    if let Some(interval) = keepalive {
        config = config.with_keepalive(Some(interval), 2).expect("valid keepalive");
    }
    connect_with_config(config).await
}

async fn connect_with_config(config: ClientConfig) -> ClientConnection {
    let mut connection = timeout(DEADLINE, ClientConnection::connect(config))
        .await
        .expect("SSH handshake completes")
        .expect("connect SSH client");
    timeout(DEADLINE, connection.authenticate_password("user", b"test-password"))
        .await
        .expect("authentication completes")
        .expect("authenticate SSH client");
    connection
}

async fn echo(channel: &mut ClientChannel, data: &[u8]) {
    timeout(DEADLINE, channel.send_data(data))
        .await
        .expect("channel send completes")
        .expect("send channel bytes");
    let event = timeout(DEADLINE, channel.next_event())
        .await
        .expect("echo arrives")
        .expect("read channel event")
        .expect("channel remains open");
    assert_eq!(event, ChannelEvent::Data(data.to_vec()));
}

#[test]
fn enabled_inactivity_and_rekey_reject_unrepresentable_deadlines() {
    let verifier = |_host: &str, _key: &HostKey| Ok(());
    let config = ClientConfig::new("127.0.0.1", 22, verifier).expect("client config");
    for timeout in [Duration::ZERO, Duration::MAX] {
        assert!(matches!(
            config.clone().with_inactivity_timeout(Some(timeout)),
            Err(ClientConfigError::InvalidInactivityTimeout)
        ));
    }
    assert!(matches!(
        config.clone().with_rekey_limits(1, Duration::MAX),
        Err(ClientConfigError::InvalidRekeyLimits)
    ));
    config.with_inactivity_timeout(None).expect("disabled inactivity timeout");
}

#[tokio::test]
async fn activity_resets_inactivity_timeout_and_silence_expires_connection() {
    let fixture = start_fixture().await;
    let config = ClientConfig::new(
        "127.0.0.1",
        fixture.address.port(),
        |_host: &str, _key: &HostKey| Ok(()),
    )
    .expect("client config")
    .with_inactivity_timeout(Some(INTERVAL * 5))
    .expect("representable inactivity timeout");
    let connection = connect_with_config(config).await;
    let mut channel = connection.open_session().await.expect("open session");
    for _ in 0..7 {
        sleep(INTERVAL).await;
        echo(&mut channel, b"active").await;
    }
    let closed = timeout(DEADLINE, channel.next_event())
        .await
        .expect("idle connection expires")
        .expect("read channel event");
    assert!(closed.is_none(), "event stream closes after inactivity");
}

#[test]
fn enabled_keepalive_rejects_unbounded_or_nonprogressing_settings() {
    let verifier = |_host: &str, _key: &HostKey| Ok(());
    let config = ClientConfig::new("127.0.0.1", 22, verifier).expect("client config");
    for (interval, max_missed) in
        [(Duration::ZERO, 2), (INTERVAL, 0), (INTERVAL, usize::MAX), (Duration::MAX, 2)]
    {
        assert!(matches!(
            config.clone().with_keepalive(Some(interval), max_missed),
            Err(ClientConfigError::InvalidKeepalive)
        ));
    }
    config.with_keepalive(None, 0).expect("disabled keepalive accepts a zero missed count");
}

#[tokio::test]
async fn explicitly_disabled_keepalive_sends_no_probes() {
    let fixture = start_fixture().await;
    let verifier = |_host: &str, _key: &HostKey| Ok(());
    let config = ClientConfig::new("127.0.0.1", fixture.address.port(), verifier)
        .expect("client config")
        .with_keepalive(None, 0)
        .expect("disabled keepalive");
    let connection = connect_with_config(config).await;
    let mut channel = connection.open_session().await.expect("open session");
    echo(&mut channel, b"ready").await;

    fixture.mode.store(BLACKHOLE, Ordering::SeqCst);
    assert!(timeout(INTERVAL * 4, channel.next_event()).await.is_err());
    assert_eq!(fixture.client_bytes.load(Ordering::SeqCst), 0, "disabled client sent no probes");
    connection.disconnect().await.expect("disabled connection remains live");
}

#[tokio::test]
async fn configured_keepalive_accepts_peer_replies_and_preserves_channel() {
    let fixture = start_fixture().await;
    let connection = connect(&fixture, Some(INTERVAL)).await;
    let mut channel = connection.open_session().await.expect("open session");
    echo(&mut channel, b"before").await;

    fixture.mode.store(OBSERVE, Ordering::SeqCst);
    sleep(INTERVAL * 5).await;
    assert!(fixture.client_bytes.load(Ordering::SeqCst) > 0, "idle client sent keepalive data");
    echo(&mut channel, b"after").await;
    connection.disconnect().await.expect("disconnect live client");
}

#[tokio::test]
async fn silent_peer_expires_only_the_host_with_keepalive_enabled() {
    let configured = start_fixture().await;
    let default = start_fixture().await;
    let configured_connection = connect(&configured, Some(INTERVAL)).await;
    let default_connection = connect(&default, None).await;
    let mut configured_channel =
        configured_connection.open_session().await.expect("open configured session");
    let mut default_channel =
        default_connection.open_session().await.expect("open default session");
    echo(&mut configured_channel, b"configured").await;
    echo(&mut default_channel, b"default").await;

    configured.mode.store(BLACKHOLE, Ordering::SeqCst);
    default.mode.store(BLACKHOLE, Ordering::SeqCst);
    let closed = timeout(DEADLINE, configured_channel.next_event())
        .await
        .expect("configured keepalive closes a silent connection")
        .expect("read configured channel");
    assert!(closed.is_none(), "the client event stream closed after keepalive timeout");
    assert!(configured.client_bytes.load(Ordering::SeqCst) > 0, "configured client sent probes");
    assert_eq!(default.client_bytes.load(Ordering::SeqCst), 0, "default keepalive is disabled");
    assert!(
        timeout(INTERVAL * 2, default_channel.next_event()).await.is_err(),
        "default connection remains open while its peer is silent"
    );
    default_connection.disconnect().await.expect("default connection remains live");
}
