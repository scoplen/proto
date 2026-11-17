// SPDX-License-Identifier: Apache-2.0

use std::{net::SocketAddr, sync::Arc, time::Duration};

use russh::keys::PrivateKey;
use scoplen_ssh::{
    AgentError, AgentForwardingAuthorizer, AgentForwardingPolicy, AgentIdentity, AgentKeyStore,
    AgentServer, ChannelEvent, ClientChannel, ClientConfig, ClientConnection, ClientError,
    ForwardedChannel, ForwardedChannelKind, ForwardedChannelReceiver, HostKey,
};
use ssh_key::Algorithm;
use tokio::{
    io::copy_bidirectional,
    net::{TcpListener, TcpStream},
    sync::oneshot,
    task::JoinHandle,
    time::timeout,
};

const DEADLINE: Duration = Duration::from_secs(5);

#[derive(Default)]
struct Peer {
    relays: Vec<russh::ChannelId>,
}

impl russh::server::Handler for Peer {
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

    async fn channel_open_direct_tcpip(
        &mut self,
        channel: russh::Channel<russh::server::Msg>,
        host: &str,
        port: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: russh::server::ChannelOpenHandle,
        _session: &mut russh::server::Session,
    ) -> Result<(), Self::Error> {
        if host == "relay.test" {
            self.relays.push(channel.id());
            let mut stream = TcpStream::connect(("127.0.0.1", u16::try_from(port).unwrap()))
                .await
                .expect("connect disposable target");
            reply.accept().await;
            tokio::spawn(async move {
                let _ = copy_bidirectional(&mut channel.into_stream(), &mut stream).await;
            });
        } else {
            reply.accept().await;
        }
        Ok(())
    }

    async fn data(
        &mut self,
        channel: russh::ChannelId,
        data: &[u8],
        session: &mut russh::server::Session,
    ) -> Result<(), Self::Error> {
        if !self.relays.contains(&channel) {
            session.data(channel, data.to_vec())?;
        }
        Ok(())
    }

    async fn agent_request(
        &mut self,
        channel: russh::ChannelId,
        session: &mut russh::server::Session,
    ) -> Result<bool, Self::Error> {
        session.channel_success(channel)?;
        Ok(true)
    }
}

async fn start_peer() -> (SocketAddr, oneshot::Receiver<russh::server::Handle>, JoinHandle<()>) {
    let mut config = russh::server::Config::default();
    config.keys.push(
        PrivateKey::random(
            &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
            Algorithm::Ed25519,
        )
        .expect("disposable host key"),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind peer");
    let address = listener.local_addr().expect("peer address");
    let (sender, receiver) = oneshot::channel();
    let task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept client");
        let session = russh::server::run_stream(Arc::new(config), stream, Peer::default())
            .await
            .expect("start peer");
        sender.send(session.handle()).unwrap_or_else(|_| panic!("receive peer handle"));
        let _ = session.await;
    });
    (address, receiver, task)
}

fn config(address: SocketAddr, limit: usize) -> ClientConfig {
    ClientConfig::new("127.0.0.1", address.port(), |_host: &str, _key: &HostKey| Ok(()))
        .expect("client config")
        .with_channel_limit(limit)
        .expect("channel limit")
}

async fn authenticate(connection: &mut ClientConnection) {
    timeout(DEADLINE, connection.authenticate_password("user", b"test-password"))
        .await
        .expect("authentication deadline")
        .expect("authenticate client");
}

async fn connect(limit: usize) -> (ClientConnection, russh::server::Handle, JoinHandle<()>) {
    let (address, handle, task) = start_peer().await;
    let mut connection = timeout(DEADLINE, ClientConnection::connect(config(address, limit)))
        .await
        .expect("connection deadline")
        .expect("connect client");
    authenticate(&mut connection).await;
    (connection, handle.await.expect("peer handle"), task)
}

async fn incoming(handle: &russh::server::Handle, port: u32) -> russh::Channel<russh::server::Msg> {
    timeout(DEADLINE, handle.channel_open_forwarded_tcpip("127.0.0.1", port, "127.0.0.1", 4242))
        .await
        .expect("incoming channel deadline")
        .expect("incoming channel accepted")
}

async fn receive(receiver: &mut ForwardedChannelReceiver, port: u32) -> ForwardedChannel {
    let forwarded = timeout(DEADLINE, receiver.recv())
        .await
        .expect("receive deadline")
        .expect("incoming queue remains open");
    assert!(matches!(
        forwarded.kind(),
        ForwardedChannelKind::Tcp { connected_port, .. } if *connected_port == port
    ));
    forwarded
}

async fn echo(channel: &mut ClientChannel, payload: &[u8]) {
    channel.send_data(payload).await.expect("send channel data");
    assert_eq!(
        timeout(DEADLINE, channel.next_event()).await.expect("echo deadline").expect("echo result"),
        Some(ChannelEvent::Data(payload.to_vec()))
    );
}

async fn ordinary_channels(connection: &ClientConnection) {
    let mut session = connection.open_session().await.expect("ordinary session");
    echo(&mut session, b"session remains usable").await;
    let mut direct = connection
        .open_direct_tcpip("echo.test", 2222, "127.0.0.1", 0)
        .await
        .expect("ordinary direct channel");
    echo(&mut direct, b"direct channel remains usable").await;
}

async fn stopped(task: JoinHandle<()>) {
    timeout(DEADLINE, task).await.expect("peer shutdown deadline").expect("peer task");
}

#[tokio::test(flavor = "current_thread")]
async fn extracted_receive_is_independent_and_ownership_transfers_once() {
    let (mut connection, _peer, task) = connect(4).await;
    let mut receiver = connection.take_forwarded_channels().expect("first extraction");
    assert!(connection.take_forwarded_channels().is_none());
    assert!(
        timeout(Duration::ZERO, connection.next_forwarded_channel())
            .await
            .expect("legacy receive returns immediately after transfer")
            .is_none()
    );
    timeout(DEADLINE, async {
        tokio::select! {
            biased;
            unexpected = receiver.recv() => panic!("empty incoming queue returned: {unexpected:?}"),
            () = ordinary_channels(&connection) => {}
        }
    })
    .await
    .expect("ordinary channels progress while receive is pending");
    connection.disconnect().await.expect("disconnect");
    assert!(timeout(DEADLINE, receiver.recv()).await.expect("queue closes").is_none());
    stopped(task).await;
}

#[tokio::test]
async fn legacy_receive_remains_available_without_extraction() {
    let (mut connection, peer, task) = connect(2).await;
    let _opened = incoming(&peer, 2000).await;
    let forwarded = timeout(DEADLINE, connection.next_forwarded_channel())
        .await
        .expect("legacy receive deadline")
        .expect("legacy incoming channel");
    assert!(matches!(forwarded.kind(), ForwardedChannelKind::Tcp { connected_port: 2000, .. }));
    drop(forwarded);
    connection.disconnect().await.expect("disconnect");
    stopped(task).await;
}

#[tokio::test]
async fn extraction_preserves_queued_fifo_and_shared_channel_bound() {
    let (mut connection, peer, task) = connect(2).await;
    let _first = incoming(&peer, 2001).await;
    let mut receiver = connection.take_forwarded_channels().expect("receiver");
    let _second = incoming(&peer, 2002).await;
    assert!(matches!(
        timeout(DEADLINE, peer.channel_open_forwarded_tcpip("127.0.0.1", 2003, "127.0.0.1", 4242))
            .await
            .expect("full queue rejection deadline"),
        Err(russh::Error::ChannelOpenFailure(russh::ChannelOpenFailure::ResourceShortage))
    ));
    assert!(matches!(
        connection.open_session().await,
        Err(ClientError::ChannelLimitReached { max: 2 })
    ));
    let first = receive(&mut receiver, 2001).await;
    assert!(matches!(
        connection.open_session().await,
        Err(ClientError::ChannelLimitReached { max: 2 })
    ));
    drop(first);
    let mut session = connection.open_session().await.expect("received channel releases slot");
    echo(&mut session, b"slot reused").await;
    drop(receive(&mut receiver, 2002).await);
    connection.disconnect().await.expect("disconnect");
    assert!(timeout(DEADLINE, receiver.recv()).await.expect("queue closes").is_none());
    stopped(task).await;
}

#[tokio::test]
async fn dropping_receiver_discards_queued_channels_without_disconnect() {
    let (mut connection, peer, task) = connect(2).await;
    let receiver = connection.take_forwarded_channels().expect("receiver");
    let _first = incoming(&peer, 2010).await;
    let _second = incoming(&peer, 2011).await;
    drop(receiver);
    assert!(matches!(
        timeout(DEADLINE, peer.channel_open_forwarded_tcpip("127.0.0.1", 2012, "127.0.0.1", 4242))
            .await
            .expect("dropped queue rejection deadline"),
        Err(russh::Error::ChannelOpenFailure(russh::ChannelOpenFailure::ResourceShortage))
    ));
    ordinary_channels(&connection).await;
    connection.disconnect().await.expect("disconnect");
    stopped(task).await;
}

#[tokio::test]
async fn parent_teardown_drains_queued_channels_before_closure() {
    for teardown in 0..3 {
        let (mut connection, peer, task) = connect(2).await;
        let mut receiver = connection.take_forwarded_channels().expect("receiver");
        let _first = incoming(&peer, 2020).await;
        let _second = incoming(&peer, 2021).await;
        match teardown {
            0 => connection.disconnect().await.expect("explicit disconnect"),
            1 => drop(connection),
            2 => peer
                .disconnect(russh::Disconnect::ByApplication, String::new(), "en".to_owned())
                .await
                .expect("peer disconnect"),
            _ => unreachable!(),
        }
        drop(receive(&mut receiver, 2020).await);
        drop(receive(&mut receiver, 2021).await);
        assert!(timeout(DEADLINE, receiver.recv()).await.expect("queue closes").is_none());
        stopped(task).await;
    }
}

#[tokio::test]
async fn composed_parent_drop_closes_extracted_target_queue() {
    let (jump, _jump_peer, jump_task) = connect(2).await;
    let (address, peer, target_task) = start_peer().await;
    let target_config =
        ClientConfig::new("relay.test", address.port(), |_host: &str, _key: &HostKey| Ok(()))
            .expect("target config");
    let mut target = timeout(
        DEADLINE,
        ClientConnection::connect_via_direct_tcpip(target_config, &jump, "127.0.0.1", 0),
    )
    .await
    .expect("target handshake deadline")
    .expect("target through jump");
    authenticate(&mut target).await;
    let peer = peer.await.expect("target peer handle");
    let mut receiver = target.take_forwarded_channels().expect("target receiver");
    let _queued = incoming(&peer, 2030).await;
    drop(jump);
    drop(receive(&mut receiver, 2030).await);
    assert!(timeout(DEADLINE, receiver.recv()).await.expect("composed queue closes").is_none());
    stopped(jump_task).await;
    stopped(target_task).await;
}

struct UnusedAgent;

impl AgentKeyStore for UnusedAgent {
    fn identities(&self) -> Result<Vec<AgentIdentity>, AgentError> {
        panic!("expired opt-in must not reach the agent store");
    }

    fn sign(&self, _key_blob: &[u8], _data: &[u8], _flags: u32) -> Result<Vec<u8>, AgentError> {
        panic!("expired opt-in must not reach the agent store");
    }
}

impl AgentForwardingAuthorizer for UnusedAgent {
    fn authorize_signature(
        &self,
        _key_blob: &[u8],
        _data: &[u8],
        _flags: u32,
    ) -> Result<(), AgentError> {
        panic!("expired opt-in must not reach the authorizer");
    }
}

#[tokio::test]
async fn queued_agent_rechecks_live_opt_in_after_extraction() {
    let (mut connection, peer, task) = connect(4).await;
    let mut receiver = connection.take_forwarded_channels().expect("receiver");
    let mut session = connection.open_session().await.expect("session");
    session.request_agent_forward(true).await.expect("enable agent forwarding");
    assert_eq!(
        session.next_event().await.expect("agent request reply"),
        Some(ChannelEvent::Success)
    );
    let _agent = timeout(DEADLINE, peer.channel_open_agent())
        .await
        .expect("agent channel deadline")
        .expect("authorized incoming agent");
    session.close().await.expect("revoke live opt-in");
    let forwarded = timeout(DEADLINE, receiver.recv())
        .await
        .expect("queued agent receive deadline")
        .expect("queued agent channel");
    assert_eq!(forwarded.kind(), &ForwardedChannelKind::Agent);
    assert!(matches!(
        forwarded
            .serve_agent(AgentServer::new(UnusedAgent), AgentForwardingPolicy::enabled(UnusedAgent))
            .await,
        Err(ClientError::InvalidInput("agent forwarding is no longer authorized"))
    ));
    ordinary_channels(&connection).await;
    connection.disconnect().await.expect("disconnect");
    stopped(task).await;
}
