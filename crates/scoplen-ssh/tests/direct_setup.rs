// SPDX-License-Identifier: Apache-2.0

use std::{net::SocketAddr, sync::Arc, time::Duration};

use russh::keys::PrivateKey;
use scoplen_ssh::{
    ChannelEvent, ClientConfig, ClientConnection, ClientError, HostKey, MAX_TCP_HOST,
    TransportError,
};
use ssh_key::Algorithm;
use tokio::{
    io::AsyncReadExt,
    net::{TcpListener, TcpStream},
    time::timeout,
};

const DEADLINE: Duration = Duration::from_secs(5);

struct CommandServer;

impl russh::server::Handler for CommandServer {
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

    async fn exec_request(
        &mut self,
        channel: russh::ChannelId,
        command: &[u8],
        session: &mut russh::server::Session,
    ) -> Result<(), Self::Error> {
        assert_eq!(command, b"printf connected");
        session.channel_success(channel)?;
        session.data(channel, b"connected".to_vec())?;
        session.exit_status_request(channel, 0)?;
        session.eof(channel)?;
        session.close(channel)?;
        Ok(())
    }
}

fn config(host: impl Into<String>, port: u16) -> ClientConfig {
    ClientConfig::new(host, port, |_host: &str, _key: &HostKey| Ok(()))
        .expect("valid client config")
}

async fn peer_closes(mut stream: TcpStream) {
    timeout(DEADLINE, async {
        let mut buffer = [0_u8; 512];
        loop {
            if stream.read(&mut buffer).await.expect("read accepted socket") == 0 {
                break;
            }
        }
    })
    .await
    .expect("peer closes after handshake ends");
}

#[tokio::test]
async fn direct_setup_preserves_typed_input_and_timeout_errors() {
    let error = ClientConnection::connect(config("a".repeat(MAX_TCP_HOST + 1), 22))
        .await
        .expect_err("direct transport enforces its host bound");
    assert!(matches!(
        error,
        ClientError::DirectTcp(TransportError::HostTooLong { max: MAX_TCP_HOST })
    ));
    for invalid in [Duration::ZERO, Duration::MAX] {
        let error = ClientConnection::connect_with_timeout(config("127.0.0.1", 22), invalid)
            .await
            .expect_err("invalid deadline is rejected locally");
        assert!(matches!(error, ClientError::DirectTcp(TransportError::InvalidTimeout)));
    }
}

#[tokio::test]
async fn direct_setup_authenticates_and_runs_a_command_over_loopback() {
    let mut server_config = russh::server::Config::default();
    server_config.keys.push(
        PrivateKey::random(
            &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
            Algorithm::Ed25519,
        )
        .expect("disposable host key"),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind SSH server");
    let address: SocketAddr = listener.local_addr().expect("server address");
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept SSH client");
        let session = russh::server::run_stream(Arc::new(server_config), stream, CommandServer)
            .await
            .expect("start SSH session");
        let _ = session.await;
    });
    let mut client = timeout(
        DEADLINE,
        ClientConnection::connect_with_timeout(
            config("localhost", address.port()),
            Duration::from_secs(2),
        ),
    )
    .await
    .expect("direct setup deadline")
    .expect("connect through local resolution");
    client.authenticate_password("user", b"test-password").await.expect("authenticate");
    let mut channel = client.open_session().await.expect("session channel");
    channel.exec(true, b"printf connected").await.expect("execute command");
    let (mut output, mut status, mut closed) = (Vec::new(), None, false);
    timeout(DEADLINE, async {
        while let Some(event) = channel.next_event().await.expect("command event") {
            match event {
                ChannelEvent::Data(data) => output.extend_from_slice(&data),
                ChannelEvent::ExitStatus(code) => status = Some(code),
                ChannelEvent::Close => closed = true,
                _ => {}
            }
        }
    })
    .await
    .expect("command completes");
    assert_eq!(output, b"connected");
    assert_eq!(status, Some(0));
    assert!(closed, "peer closed the completed command channel");
    client.disconnect().await.expect("disconnect");
    timeout(DEADLINE, server).await.expect("server ends").expect("server task");
}

#[tokio::test]
async fn stalled_handshake_timeout_closes_the_accepted_socket() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind stalled peer");
    let port = listener.local_addr().expect("listener address").port();
    let connecting = tokio::spawn(ClientConnection::connect_with_timeout(
        config("127.0.0.1", port),
        Duration::from_millis(200),
    ));
    let (socket, _) =
        timeout(DEADLINE, listener.accept()).await.expect("client dials").expect("accept");
    let error = timeout(DEADLINE, connecting)
        .await
        .expect("bounded handshake")
        .expect("connect task")
        .expect_err("silent peer times out");
    assert!(matches!(
        error,
        ClientError::DirectSshHandshakeTimeout { timeout } if timeout == Duration::from_millis(200)
    ));
    peer_closes(socket).await;
}

#[tokio::test]
async fn canceling_handshake_closes_the_accepted_socket() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind stalled peer");
    let port = listener.local_addr().expect("listener address").port();
    let connecting =
        tokio::spawn(ClientConnection::connect_with_timeout(config("127.0.0.1", port), DEADLINE));
    let (socket, _) =
        timeout(DEADLINE, listener.accept()).await.expect("client dials").expect("accept");
    connecting.abort();
    assert!(connecting.await.expect_err("connect task aborted").is_cancelled());
    peer_closes(socket).await;
}
