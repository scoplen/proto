// SPDX-License-Identifier: Apache-2.0

use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use russh::{ChannelMsg, keys::PrivateKey};
use scoplen_ssh::{ChannelEvent, ClientConfig, ClientConnection, HostKey};
use ssh_key::Algorithm;
use tokio::{
    net::TcpListener,
    sync::mpsc,
    task::JoinHandle,
    time::{sleep, timeout},
};

const BLOCK_SIZE: usize = 32 * 1024;
const BLOCKS: usize = 256;
const TRANSFER_SIZE: usize = BLOCK_SIZE * BLOCKS;
const DEADLINE: Duration = Duration::from_secs(15);
const STALL_CHECK: Duration = Duration::from_millis(200);
const CLIENT_PAUSED_CEILING: usize = 4 * 1024 * 1024;
const SERVER_PAUSED_CEILING: usize = 6 * 1024 * 1024;

type ServerChannel = russh::Channel<russh::server::Msg>;

struct ControlledServer {
    opened: mpsc::Sender<ServerChannel>,
}

impl russh::server::Handler for ControlledServer {
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
        channel: ServerChannel,
        reply: russh::server::ChannelOpenHandle,
        _session: &mut russh::server::Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        self.opened.send(channel).await.expect("test receives opened channel");
        Ok(())
    }
}

async fn start_server(
    window_size: u32,
    channel_buffer_size: usize,
) -> (SocketAddr, mpsc::Receiver<ServerChannel>, JoinHandle<()>) {
    let mut config = russh::server::Config::default();
    config.keys.push(
        PrivateKey::random(
            &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
            Algorithm::Ed25519,
        )
        .expect("generate disposable host key"),
    );
    config.window_size = window_size;
    config.channel_buffer_size = channel_buffer_size;
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind test SSH server");
    let address = listener.local_addr().expect("test SSH address");
    let (opened, receiver) = mpsc::channel(2);
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept test SSH client");
        let _ =
            russh::server::run_stream(Arc::new(config), stream, ControlledServer { opened }).await;
    });
    (address, receiver, server)
}

async fn connect(address: SocketAddr) -> ClientConnection {
    let verifier = |_host: &str, _key: &HostKey| Ok(());
    let config = ClientConfig::new("127.0.0.1", address.port(), verifier).expect("client config");
    let mut connection = ClientConnection::connect(config).await.expect("connect SSH client");
    connection
        .authenticate_password("user", b"test-password")
        .await
        .expect("authenticate SSH client");
    connection
}

async fn opened(receiver: &mut mpsc::Receiver<ServerChannel>) -> ServerChannel {
    timeout(DEADLINE, receiver.recv())
        .await
        .expect("server accepts session before deadline")
        .expect("server reports accepted session")
}

async fn drain_server(channel: &mut ServerChannel, expected: usize, marker: u8) {
    let mut received = 0;
    while received < expected {
        match timeout(DEADLINE, channel.wait())
            .await
            .expect("server receives data before deadline")
            .expect("server channel remains open")
        {
            ChannelMsg::Data { data } => {
                assert!(data.iter().all(|&byte| byte == marker));
                received += data.len();
                assert!(received <= expected, "client exceeded requested byte count");
            }
            ChannelMsg::Close | ChannelMsg::Eof => {
                panic!("client closed before transfer completed")
            }
            _ => {}
        }
    }
    assert_eq!(received, expected);
}

async fn drain_client(channel: &mut scoplen_ssh::ClientChannel, expected: usize, marker: u8) {
    let mut received = 0;
    while received < expected {
        match timeout(DEADLINE, channel.next_event())
            .await
            .expect("client receives data before deadline")
            .expect("client channel read succeeds")
            .expect("client channel remains open")
        {
            ChannelEvent::Data(data) => {
                assert!(data.iter().all(|&byte| byte == marker));
                received += data.len();
                assert!(received <= expected, "server exceeded requested byte count");
            }
            ChannelEvent::Close | ChannelEvent::Eof => {
                panic!("server closed before transfer completed")
            }
            _ => {}
        }
    }
    assert_eq!(received, expected);
}

async fn finish(connection: &ClientConnection, server: JoinHandle<()>) {
    connection.disconnect().await.expect("disconnect test client");
    timeout(DEADLINE, server)
        .await
        .expect("test SSH server exits before deadline")
        .expect("test SSH server task succeeds");
}

async fn assert_stalled(sender: &JoinHandle<()>, sent: &AtomicUsize, ceiling: usize) -> usize {
    let mut previous = 0;
    timeout(DEADLINE, async {
        loop {
            sleep(STALL_CHECK).await;
            let current = sent.load(Ordering::Relaxed);
            assert!(current <= ceiling, "accepted {current} bytes while the receiver was paused");
            assert!(!sender.is_finished(), "sender completed while the receiver was paused");
            if current > 0 && current == previous {
                break current;
            }
            previous = current;
        }
    })
    .await
    .expect("sender reaches a bounded, stable stall")
}

#[tokio::test]
async fn client_send_stalls_without_peer_reads_and_resumes_without_losing_data() {
    let (address, mut opened_channels, server) = start_server(2 * 1024 * 1024, 8).await;
    let connection = connect(address).await;
    let client_channel = connection.open_session().await.expect("open client session");
    let mut server_channel = opened(&mut opened_channels).await;
    let sent = Arc::new(AtomicUsize::new(0));
    let progress = Arc::clone(&sent);
    let sender = tokio::spawn(async move {
        let block = vec![0x5a; BLOCK_SIZE];
        for _ in 0..BLOCKS {
            client_channel.send_data(&block).await.expect("send client block");
            progress.fetch_add(BLOCK_SIZE, Ordering::Relaxed);
        }
    });

    let accepted = assert_stalled(&sender, &sent, CLIENT_PAUSED_CEILING).await;
    eprintln!("client_to_server_accepted_before_stall_bytes={accepted}");
    drain_server(&mut server_channel, TRANSFER_SIZE, 0x5a).await;
    timeout(DEADLINE, sender)
        .await
        .expect("client send resumes")
        .expect("client send task succeeds");
    finish(&connection, server).await;
}

#[tokio::test]
async fn server_send_stalls_without_client_reads_and_resumes_without_losing_data() {
    let (address, mut opened_channels, server) = start_server(2 * 1024 * 1024, 8).await;
    let connection = connect(address).await;
    let mut client_channel = connection.open_session().await.expect("open client session");
    let server_channel = opened(&mut opened_channels).await;
    let sent = Arc::new(AtomicUsize::new(0));
    let progress = Arc::clone(&sent);
    let sender = tokio::spawn(async move {
        let block = vec![0xa5; BLOCK_SIZE];
        for _ in 0..BLOCKS {
            server_channel.data_bytes(block.clone()).await.expect("send server block");
            progress.fetch_add(BLOCK_SIZE, Ordering::Relaxed);
        }
    });

    let accepted = assert_stalled(&sender, &sent, SERVER_PAUSED_CEILING).await;
    eprintln!("server_to_client_accepted_before_stall_bytes={accepted}");
    drain_client(&mut client_channel, TRANSFER_SIZE, 0xa5).await;
    timeout(DEADLINE, sender)
        .await
        .expect("server send resumes")
        .expect("server send task succeeds");
    finish(&connection, server).await;
}

#[tokio::test]
async fn zero_window_on_one_channel_does_not_block_another_channel() {
    let (address, mut opened_channels, server) = start_server(0, 8).await;
    let connection = connect(address).await;
    let blocked_channel = connection.open_session().await.expect("open zero-window session");
    let _server_blocked_channel = opened(&mut opened_channels).await;
    let mut blocked_send = tokio::spawn(async move {
        blocked_channel.send_data(b"blocked").await.expect("send after window opens");
    });
    assert!(
        timeout(STALL_CHECK, &mut blocked_send).await.is_err(),
        "zero-window send unexpectedly completed"
    );

    let mut client_channel = timeout(DEADLINE, connection.open_session())
        .await
        .expect("other channel opens while first send waits")
        .expect("open other channel");
    let server_channel = opened(&mut opened_channels).await;
    timeout(DEADLINE, server_channel.data_bytes(vec![0x37]))
        .await
        .expect("server sends on independent channel")
        .expect("independent channel remains writable");
    drain_client(&mut client_channel, 1, 0x37).await;

    blocked_send.abort();
    assert!(blocked_send.await.expect_err("blocked send was cancelled").is_cancelled());
    finish(&connection, server).await;
}
