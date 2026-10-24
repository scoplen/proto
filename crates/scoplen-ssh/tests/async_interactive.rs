// SPDX-License-Identifier: Apache-2.0

use std::{
    borrow::Cow,
    collections::VecDeque,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use russh::keys::PrivateKey;
use scoplen_crypto::Ed25519SigningKey;
use scoplen_ssh::{
    ChannelEvent, ClientConfig, ClientConnection, ClientError, Ed25519SshSigner, HostKey,
    KeyboardInteractiveResponse,
};
use tokio::{
    net::TcpListener,
    sync::{mpsc, oneshot},
    task::JoinHandle,
    time::timeout,
};

const DEADLINE: Duration = Duration::from_secs(5);

struct InteractivePeer {
    replies: Arc<AtomicUsize>,
}

impl russh::server::Handler for InteractivePeer {
    type Error = russh::Error;

    async fn auth_keyboard_interactive<'a>(
        &'a mut self,
        _user: &str,
        _submethods: &str,
        response: Option<russh::server::Response<'a>>,
    ) -> Result<russh::server::Auth, Self::Error> {
        if let Some(response) = response {
            let round = self.replies.fetch_add(1, Ordering::SeqCst);
            let responses = response.map(|answer| answer.as_ref().to_vec()).collect::<Vec<_>>();
            if round == 0 && responses == [b"123456".to_vec(), b"alice".to_vec()] {
                return Ok(russh::server::Auth::Partial {
                    name: Cow::Borrowed("Confirmation"),
                    instructions: Cow::Borrowed("Confirm the account"),
                    prompts: Cow::Borrowed(&[(Cow::Borrowed("Continue? "), true)]),
                });
            }
            return Ok(if round == 1 && responses == [b"yes".to_vec()] {
                russh::server::Auth::Accept
            } else {
                russh::server::Auth::reject()
            });
        }
        Ok(russh::server::Auth::Partial {
            name: Cow::Borrowed("Two prompts"),
            instructions: Cow::Borrowed("Enter code and account"),
            prompts: Cow::Borrowed(&[
                (Cow::Borrowed("Code: "), false),
                (Cow::Borrowed("Account: "), true),
            ]),
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
        assert_eq!(command, b"printf async-interactive-ok");
        session.channel_success(channel)?;
        session.data(channel, b"async-interactive-ok".to_vec())?;
        session.exit_status_request(channel, 0)?;
        session.eof(channel)?;
        session.close(channel)
    }
}

async fn connect() -> (ClientConnection, Arc<AtomicUsize>, russh::server::Handle, JoinHandle<()>) {
    let mut config = russh::server::Config {
        auth_rejection_time: Duration::ZERO,
        ..russh::server::Config::default()
    };
    config.keys.push(
        PrivateKey::random(
            &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
            ssh_key::Algorithm::Ed25519,
        )
        .expect("host key"),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind peer");
    let port = listener.local_addr().expect("peer address").port();
    let replies = Arc::new(AtomicUsize::new(0));
    let peer_replies = Arc::clone(&replies);
    let (handle_tx, handle_rx) = oneshot::channel();
    let task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept client");
        let peer = russh::server::run_stream(
            Arc::new(config),
            stream,
            InteractivePeer { replies: peer_replies },
        )
        .await
        .expect("start peer");
        handle_tx.send(peer.handle()).unwrap_or_else(|_| panic!("receive peer handle"));
        let _ = peer.await;
    });
    let config = ClientConfig::new("127.0.0.1", port, |_host: &str, _key: &HostKey| Ok(()))
        .expect("client config");
    let client = timeout(DEADLINE, ClientConnection::connect(config))
        .await
        .expect("handshake deadline")
        .expect("connect client");
    (client, replies, handle_rx.await.expect("peer handle"), task)
}

fn answers(values: &[&str]) -> KeyboardInteractiveResponse {
    KeyboardInteractiveResponse::new(values.iter().map(|value| value.as_bytes().to_vec()).collect())
        .expect("bounded responses")
}

async fn authenticate(connection: &mut ClientConnection) {
    timeout(
        DEADLINE,
        connection.authenticate_keyboard_interactive("user", None, |info| async move {
            Ok(if info.prompts().len() == 2 {
                answers(&["123456", "alice"])
            } else {
                answers(&["yes"])
            })
        }),
    )
    .await
    .expect("authentication deadline")
    .expect("authenticate");
}

async fn command(connection: &ClientConnection) {
    let mut channel = connection.open_session().await.expect("authenticated session");
    channel.exec(true, b"printf async-interactive-ok").await.expect("exec command");
    let mut output = Vec::new();
    let mut status = None;
    while let Some(event) = timeout(DEADLINE, channel.next_event())
        .await
        .expect("command deadline")
        .expect("command event")
    {
        match event {
            ChannelEvent::Data(data) => output.extend(data),
            ChannelEvent::ExitStatus(value) => status = Some(value),
            ChannelEvent::Close => break,
            ChannelEvent::Success | ChannelEvent::Eof => {}
            other => panic!("unexpected command event: {other:?}"),
        }
    }
    assert_eq!(output, b"async-interactive-ok");
    assert_eq!(status, Some(0));
}

#[tokio::test(flavor = "current_thread")]
async fn pending_response_preserves_prompt_order_and_unrelated_executor_progress() {
    let (mut connection, replies, _peer, task) = connect().await;
    assert!(matches!(connection.open_session().await, Err(ClientError::NotAuthenticated)));
    let (first_tx, first_rx) = oneshot::channel();
    let (second_tx, second_rx) = oneshot::channel();
    let mut responses = VecDeque::from([first_rx, second_rx]);
    let (request_tx, mut requests) = mpsc::unbounded_channel();
    let authentication = connection.authenticate_keyboard_interactive("user", None, move |info| {
        request_tx.send(info).expect("observe request");
        let response = responses.pop_front().expect("one response per round");
        async move { response.await.map_err(|_| ClientError::InvalidInput("reply canceled")) }
    });
    let control = async {
        let first = requests.recv().await.expect("first request");
        assert_eq!(first.name(), b"Two prompts");
        assert_eq!(first.instruction(), b"Enter code and account");
        assert_eq!(first.language_tag(), b"");
        assert_eq!(first.prompts()[0].text(), b"Code: ");
        assert!(!first.prompts()[0].echo());
        assert_eq!(first.prompts()[1].text(), b"Account: ");
        assert!(first.prompts()[1].echo());
        tokio::time::sleep(Duration::from_millis(25)).await;
        let (mut independent, _, _peer, independent_task) = connect().await;
        authenticate(&mut independent).await;
        command(&independent).await;
        independent.disconnect().await.expect("disconnect independent connection");
        independent_task.await.expect("independent peer");
        assert_eq!(replies.load(Ordering::SeqCst), 0, "no answer before user reply");
        assert!(requests.try_recv().is_err(), "no next round before matching reply");
        first_tx.send(answers(&["123456", "alice"])).expect("release first reply");
        let second = requests.recv().await.expect("second request");
        assert_eq!(second.prompts()[0].text(), b"Continue? ");
        assert!(second.prompts()[0].echo());
        assert_eq!(replies.load(Ordering::SeqCst), 1);
        second_tx.send(answers(&["yes"])).expect("release second reply");
    };
    let (result, ()) = Box::pin(timeout(DEADLINE, async { tokio::join!(authentication, control) }))
        .await
        .expect("single-thread executor progress deadline");
    result.expect("authenticate after asynchronous replies");
    command(&connection).await;
    connection.disconnect().await.expect("disconnect");
    timeout(DEADLINE, task).await.expect("peer stopped").expect("peer task");
}

async fn assert_closed(connection: &mut ClientConnection) {
    timeout(DEADLINE, async {
        assert!(matches!(
            connection.authenticate_password("user", b"password").await,
            Err(ClientError::ConnectionClosed)
        ));
        assert!(matches!(
            connection.probe_authentication("user").await,
            Err(ClientError::ConnectionClosed)
        ));
        let signer =
            Ed25519SshSigner::new(Ed25519SigningKey::from_bytes(&[9; 32]).expect("signer"));
        assert!(matches!(
            connection.authenticate_publickey("user", &signer).await,
            Err(ClientError::ConnectionClosed)
        ));
        assert!(matches!(
            connection
                .authenticate_keyboard_interactive("user", None, |_| async {
                    panic!("closed connection cannot request a reply")
                })
                .await,
            Err(ClientError::ConnectionClosed)
        ));
        assert!(matches!(
            connection.server_rsa_sha2_selection().await,
            Err(ClientError::ConnectionClosed)
        ));
        assert!(matches!(connection.open_session().await, Err(ClientError::ConnectionClosed)));
        assert!(matches!(
            connection.open_direct_tcpip("127.0.0.1", 22, "127.0.0.1", 0).await,
            Err(ClientError::ConnectionClosed)
        ));
        assert!(matches!(
            connection.open_direct_streamlocal("/tmp/closed").await,
            Err(ClientError::ConnectionClosed)
        ));
        assert!(matches!(
            connection.request_tcpip_forward("127.0.0.1", 0).await,
            Err(ClientError::ConnectionClosed)
        ));
        assert!(matches!(
            connection.cancel_tcpip_forward("127.0.0.1", 22).await,
            Err(ClientError::ConnectionClosed)
        ));
        assert!(matches!(
            connection.request_streamlocal_forward("/tmp/closed").await,
            Err(ClientError::ConnectionClosed)
        ));
        assert!(matches!(
            connection.cancel_streamlocal_forward("/tmp/closed").await,
            Err(ClientError::ConnectionClosed)
        ));
        assert!(connection.next_forwarded_channel().await.is_none());
        connection.disconnect().await.expect("idempotent disconnect");
    })
    .await
    .expect("closed operations return locally");
}

#[tokio::test(flavor = "current_thread")]
async fn canceled_response_closes_engine_and_discards_late_reply() {
    let (mut connection, replies, _peer, task) = connect().await;
    let (reply_tx, reply_rx) = oneshot::channel();
    let mut reply_rx = Some(reply_rx);
    let (request_tx, request_rx) = oneshot::channel();
    let mut request_tx = Some(request_tx);
    {
        let authentication = connection.authenticate_keyboard_interactive("user", None, |_| {
            request_tx.take().expect("first request").send(()).expect("observe challenge");
            let reply = reply_rx.take().expect("first reply");
            async move { reply.await.map_err(|_| ClientError::InvalidInput("reply canceled")) }
        });
        tokio::pin!(authentication);
        tokio::select! {
            () = async { request_rx.await.expect("pending challenge"); } => {},
            result = &mut authentication => panic!("authentication completed before reply: {result:?}"),
            () = tokio::time::sleep(DEADLINE) => panic!("challenge deadline"),
        }
    }
    assert_closed(&mut connection).await;
    timeout(DEADLINE, task)
        .await
        .expect("dropped engine wakes pending authentication")
        .expect("peer task");
    assert_eq!(replies.load(Ordering::SeqCst), 0);
    let (mut fresh, _, _peer, task) = connect().await;
    assert!(reply_tx.send(answers(&["123456", "alice"])).is_err(), "late reply has no receiver");
    authenticate(&mut fresh).await;
    command(&fresh).await;
    fresh.disconnect().await.expect("disconnect fresh connection");
    timeout(DEADLINE, task).await.expect("fresh peer stopped").expect("fresh peer task");
}

#[tokio::test]
async fn responder_and_response_failures_terminate_dispatched_connection() {
    for case in 0..4 {
        let (mut connection, replies, _peer, task) = connect().await;
        let result = timeout(
            DEADLINE,
            connection.authenticate_keyboard_interactive("user", None, |_| async move {
                match case {
                    0 => Err(ClientError::InvalidInput("responder failed")),
                    1 => Ok(answers(&["one answer"])),
                    2 => KeyboardInteractiveResponse::new(vec![vec![b'x'; 65_537]])
                        .map_err(|_| ClientError::InvalidInput("oversized answer")),
                    _ => Ok(KeyboardInteractiveResponse::new(vec![vec![0xff], vec![]])
                        .expect("bounded bytes")),
                }
            }),
        )
        .await
        .expect("invalid response deadline");
        assert!(matches!(result, Err(ClientError::InvalidInput(_))), "case {case}: {result:?}");
        assert_closed(&mut connection).await;
        timeout(DEADLINE, task).await.expect("peer closes after invalid reply").expect("peer task");
        assert_eq!(replies.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn pre_dispatch_validation_preserves_connection_and_peer_disconnect_fences_it() {
    let (mut connection, _, _peer, task) = connect().await;
    assert!(
        connection
            .authenticate_keyboard_interactive("", None, |_| async {
                panic!("invalid username cannot dispatch")
            })
            .await
            .is_err()
    );
    assert!(
        connection
            .authenticate_keyboard_interactive("user", Some("bad\0submethod"), |_| async {
                panic!("invalid submethods cannot dispatch")
            })
            .await
            .is_err()
    );
    authenticate(&mut connection).await;
    command(&connection).await;
    connection.disconnect().await.expect("disconnect after local validation");
    timeout(DEADLINE, task).await.expect("peer stopped").expect("peer task");
    let (mut connection, _, peer, task) = connect().await;
    let result = timeout(
        DEADLINE,
        connection.authenticate_keyboard_interactive("user", None, |_| {
            let peer = peer.clone();
            async move {
                peer.disconnect(
                    russh::Disconnect::ByApplication,
                    "peer stopped".to_owned(),
                    "en".to_owned(),
                )
                .await
                .expect("disconnect peer");
                tokio::time::sleep(Duration::from_millis(25)).await;
                Ok(answers(&["123456", "alice"]))
            }
        }),
    )
    .await
    .expect("disconnected exchange deadline");
    assert!(result.is_err());
    assert_closed(&mut connection).await;
    timeout(DEADLINE, task).await.expect("disconnected peer stops").expect("peer task");
}
