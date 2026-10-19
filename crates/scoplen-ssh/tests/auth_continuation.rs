// SPDX-License-Identifier: Apache-2.0

use std::{
    borrow::Cow,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use russh::keys::PrivateKey;
use scoplen_crypto::Ed25519SigningKey;
use scoplen_ssh::{
    CertificateValidationPolicy, ChannelEvent, ClientConfig, ClientConnection, ClientError,
    Ed25519SshSigner, HostKey, Signer, UserCertificate,
};
use ssh_key::Algorithm;
use tokio::{net::TcpListener, task::JoinHandle, time::timeout};

const DEADLINE: Duration = Duration::from_secs(5);

struct TwoFactorServer {
    otp_verified: bool,
    opened_sessions: Arc<AtomicUsize>,
}

impl russh::server::Handler for TwoFactorServer {
    type Error = russh::Error;

    async fn auth_none(&mut self, _user: &str) -> Result<russh::server::Auth, Self::Error> {
        Ok(russh::server::Auth::Reject {
            proceed_with_methods: Some((&[russh::MethodKind::KeyboardInteractive][..]).into()),
            partial_success: false,
        })
    }

    async fn auth_keyboard_interactive<'a>(
        &'a mut self,
        user: &str,
        submethods: &str,
        response: Option<russh::server::Response<'a>>,
    ) -> Result<russh::server::Auth, Self::Error> {
        if user != "user" || submethods != "otp" {
            return Ok(russh::server::Auth::reject());
        }
        let Some(mut response) = response else {
            return Ok(russh::server::Auth::Partial {
                name: Cow::Borrowed("Two-factor test"),
                instructions: Cow::Borrowed("Enter the one-time code"),
                prompts: Cow::Borrowed(&[(Cow::Borrowed("Code: "), false)]),
            });
        };
        if response.next().is_some_and(|answer| answer.as_ref() == b"123456")
            && response.next().is_none()
        {
            self.otp_verified = true;
            Ok(russh::server::Auth::Reject {
                proceed_with_methods: Some((&[russh::MethodKind::Password][..]).into()),
                partial_success: true,
            })
        } else {
            Ok(russh::server::Auth::Reject {
                proceed_with_methods: Some((&[russh::MethodKind::KeyboardInteractive][..]).into()),
                partial_success: false,
            })
        }
    }

    async fn auth_password(
        &mut self,
        user: &str,
        password: &str,
    ) -> Result<russh::server::Auth, Self::Error> {
        if self.otp_verified && user == "user" && password == "test-password" {
            Ok(russh::server::Auth::Accept)
        } else {
            Ok(russh::server::Auth::Reject {
                proceed_with_methods: Some(
                    (&[if self.otp_verified {
                        russh::MethodKind::Password
                    } else {
                        russh::MethodKind::KeyboardInteractive
                    }][..])
                        .into(),
                ),
                partial_success: false,
            })
        }
    }

    async fn channel_open_session(
        &mut self,
        _channel: russh::Channel<russh::server::Msg>,
        reply: russh::server::ChannelOpenHandle,
        _session: &mut russh::server::Session,
    ) -> Result<(), Self::Error> {
        self.opened_sessions.fetch_add(1, Ordering::SeqCst);
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

async fn connect() -> (ClientConnection, Arc<AtomicUsize>, JoinHandle<()>) {
    let mut server_config = russh::server::Config::default();
    server_config.keys.push(
        PrivateKey::random(
            &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
            Algorithm::Ed25519,
        )
        .expect("generate disposable host key"),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind SSH server");
    let address: SocketAddr = listener.local_addr().expect("SSH server address");
    let opened_sessions = Arc::new(AtomicUsize::new(0));
    let server_sessions = Arc::clone(&opened_sessions);
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept SSH client");
        let session = russh::server::run_stream(
            Arc::new(server_config),
            stream,
            TwoFactorServer { otp_verified: false, opened_sessions: server_sessions },
        )
        .await
        .expect("start SSH server session");
        let _ = session.await;
    });
    let config =
        ClientConfig::new("127.0.0.1", address.port(), |_host: &str, _key: &HostKey| Ok(()))
            .expect("client config");
    let client = timeout(DEADLINE, ClientConnection::connect(config))
        .await
        .expect("SSH handshake deadline")
        .expect("connect SSH client");
    (client, opened_sessions, server)
}

async fn one_time_code(connection: &mut ClientConnection, answer: &str) -> ClientError {
    timeout(
        DEADLINE,
        connection.authenticate_keyboard_interactive("user", Some("otp"), |info| {
            assert_eq!(info.prompts().len(), 1);
            assert_eq!(info.prompts()[0].text(), b"Code: ");
            assert!(!info.prompts()[0].echo());
            Ok(vec![answer.to_owned()])
        }),
    )
    .await
    .expect("keyboard-interactive deadline")
    .expect_err("server requires a second factor")
}

#[tokio::test]
async fn keyboard_interactive_partial_success_continues_with_password() {
    let (mut connection, opened_sessions, server) = connect().await;
    let error = one_time_code(&mut connection, "123456").await;
    assert_eq!(error.to_string(), "SSH authentication was rejected");
    assert!(matches!(
        error,
        ClientError::AuthenticationRejected { partial_success: true, remaining_methods }
            if remaining_methods == ["password"]
    ));
    assert!(matches!(
        timeout(DEADLINE, connection.open_session())
            .await
            .expect("pre-authentication channel deadline"),
        Err(ClientError::NotAuthenticated)
    ));
    assert_eq!(opened_sessions.load(Ordering::SeqCst), 0);

    timeout(DEADLINE, connection.authenticate_password("user", b"test-password"))
        .await
        .expect("password deadline")
        .expect("second factor authenticates the connection");
    let mut channel = timeout(DEADLINE, connection.open_session())
        .await
        .expect("session deadline")
        .expect("open authenticated session");
    assert_eq!(opened_sessions.load(Ordering::SeqCst), 1);
    channel.send_data(b"two factors accepted").await.expect("send session data");
    let event = timeout(DEADLINE, channel.next_event())
        .await
        .expect("echo deadline")
        .expect("read session event")
        .expect("session remains open");
    assert_eq!(event, ChannelEvent::Data(b"two factors accepted".to_vec()));
    connection.disconnect().await.expect("disconnect");
    timeout(DEADLINE, server).await.expect("server shutdown deadline").expect("server task");
}

#[tokio::test]
async fn unauthenticated_channel_and_forward_requests_leave_the_connection_usable() {
    let (mut connection, opened_sessions, server) = connect().await;
    assert!(matches!(connection.open_session().await, Err(ClientError::NotAuthenticated)));
    assert!(matches!(
        connection.open_direct_tcpip("127.0.0.1", 22, "127.0.0.1", 12345).await,
        Err(ClientError::NotAuthenticated)
    ));
    assert!(matches!(
        connection.open_direct_streamlocal("/tmp/test.sock").await,
        Err(ClientError::NotAuthenticated)
    ));
    assert!(matches!(
        connection.request_tcpip_forward("127.0.0.1", 0).await,
        Err(ClientError::NotAuthenticated)
    ));
    assert!(matches!(
        connection.cancel_tcpip_forward("127.0.0.1", 2222).await,
        Err(ClientError::NotAuthenticated)
    ));
    assert!(matches!(
        connection.request_streamlocal_forward("/tmp/test.sock").await,
        Err(ClientError::NotAuthenticated)
    ));
    assert!(matches!(
        connection.cancel_streamlocal_forward("/tmp/test.sock").await,
        Err(ClientError::NotAuthenticated)
    ));
    let error = one_time_code(&mut connection, "123456").await;
    assert!(matches!(
        error,
        ClientError::AuthenticationRejected { partial_success: true, remaining_methods }
            if remaining_methods == ["password"]
    ));
    assert_eq!(opened_sessions.load(Ordering::SeqCst), 0);
    connection.authenticate_password("user", b"test-password").await.expect("complete MFA");
    let channel = connection.open_session().await.expect("connection remains usable");
    assert_eq!(opened_sessions.load(Ordering::SeqCst), 1);
    drop(channel);
    connection.disconnect().await.expect("disconnect");
    timeout(DEADLINE, server).await.expect("server shutdown deadline").expect("server task");
}

#[tokio::test]
async fn rejected_first_and_second_factors_do_not_open_a_session() {
    let (mut connection, opened_sessions, server) = connect().await;
    let error = one_time_code(&mut connection, "wrong-code").await;
    assert!(matches!(
        error,
        ClientError::AuthenticationRejected { partial_success: false, remaining_methods }
            if remaining_methods == ["keyboard-interactive"]
    ));
    assert_eq!(opened_sessions.load(Ordering::SeqCst), 0);

    let error = one_time_code(&mut connection, "123456").await;
    assert!(matches!(
        error,
        ClientError::AuthenticationRejected { partial_success: true, remaining_methods }
            if remaining_methods == ["password"]
    ));
    let error = timeout(DEADLINE, connection.authenticate_password("user", b"wrong-password"))
        .await
        .expect("rejected password deadline")
        .expect_err("wrong second factor is rejected");
    assert!(matches!(
        error,
        ClientError::AuthenticationRejected { partial_success: false, remaining_methods }
            if remaining_methods == ["password"]
    ));
    assert!(matches!(
        timeout(DEADLINE, connection.open_session()).await.expect("rejected channel deadline"),
        Err(ClientError::NotAuthenticated)
    ));
    assert_eq!(opened_sessions.load(Ordering::SeqCst), 0);
    connection.disconnect().await.expect("disconnect");
    timeout(DEADLINE, server).await.expect("server shutdown deadline").expect("server task");
}

#[tokio::test]
async fn completed_authentication_rejects_all_further_authentication_without_blocking_channels() {
    let (mut connection, opened_sessions, server) = connect().await;
    let error = one_time_code(&mut connection, "123456").await;
    assert!(matches!(error, ClientError::AuthenticationRejected { partial_success: true, .. }));
    timeout(DEADLINE, connection.authenticate_password("user", b"test-password"))
        .await
        .expect("second factor deadline")
        .expect("complete authentication");

    let signer =
        Ed25519SshSigner::new(Ed25519SigningKey::from_bytes(&[9; 32]).expect("signer key"));
    let subject = ssh_key::PublicKey::from_bytes(&signer.public_key_blob().expect("subject blob"))
        .expect("subject key");
    let mut builder = ssh_key::certificate::Builder::new(vec![8; 16], subject, 1, 1000)
        .expect("certificate builder");
    builder.cert_type(ssh_key::certificate::CertType::User).expect("user certificate");
    builder.valid_principal("user").expect("certificate principal");
    let ca = PrivateKey::random(
        &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
        Algorithm::Ed25519,
    )
    .expect("certificate CA");
    let certificate = UserCertificate::parse_and_validate(
        &builder.sign(&ca).expect("signed certificate").to_bytes().expect("certificate bytes"),
        &CertificateValidationPolicy::user("user", 100),
    )
    .expect("validated certificate");

    assert!(matches!(
        timeout(DEADLINE, connection.authenticate_password("", &[0xff]))
            .await
            .expect("repeated password deadline"),
        Err(ClientError::AlreadyAuthenticated)
    ));
    assert!(matches!(
        timeout(DEADLINE, connection.authenticate_publickey("", &signer))
            .await
            .expect("repeated public-key deadline"),
        Err(ClientError::AlreadyAuthenticated)
    ));
    assert!(matches!(
        timeout(DEADLINE, connection.authenticate_certificate("", &certificate, &signer))
            .await
            .expect("repeated certificate deadline"),
        Err(ClientError::AlreadyAuthenticated)
    ));
    assert!(matches!(
        timeout(DEADLINE, connection.probe_authentication(""))
            .await
            .expect("repeated none probe deadline"),
        Err(ClientError::AlreadyAuthenticated)
    ));
    assert!(matches!(
        timeout(
            DEADLINE,
            connection.authenticate_keyboard_interactive("", None, |_| {
                panic!("completed authentication must not call the responder")
            })
        )
        .await
        .expect("repeated keyboard-interactive deadline"),
        Err(ClientError::AlreadyAuthenticated)
    ));

    let mut channel = timeout(DEADLINE, connection.open_session())
        .await
        .expect("post-guard session deadline")
        .expect("connection remains authenticated");
    assert_eq!(opened_sessions.load(Ordering::SeqCst), 1);
    channel.send_data(b"authentication guard kept the session open").await.expect("send echo");
    assert_eq!(
        timeout(DEADLINE, channel.next_event())
            .await
            .expect("post-guard echo deadline")
            .expect("read echoed data")
            .expect("session remains open"),
        ChannelEvent::Data(b"authentication guard kept the session open".to_vec())
    );
    connection.disconnect().await.expect("disconnect");
    timeout(DEADLINE, server).await.expect("server shutdown deadline").expect("server task");
}
