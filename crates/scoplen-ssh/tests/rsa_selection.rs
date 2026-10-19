// SPDX-License-Identifier: Apache-2.0

use std::{
    borrow::Cow,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use russh::keys::{Algorithm, HashAlg, PrivateKey};
use scoplen_crypto::Ed25519SigningKey;
use scoplen_ssh::{
    ClientConfig, ClientConnection, ClientError, Ed25519SshSigner, HostKey, ServerRsaSha2Selection,
    Signer,
};
use tokio::{net::TcpListener, time::timeout};

const DEADLINE: Duration = Duration::from_secs(5);

struct PasswordServer {
    auth_requests: Arc<AtomicUsize>,
    expected_public_key: Option<Vec<u8>>,
    publickey_verified: bool,
}

impl russh::server::Handler for PasswordServer {
    type Error = russh::Error;

    async fn auth_none(&mut self, _user: &str) -> Result<russh::server::Auth, Self::Error> {
        self.auth_requests.fetch_add(1, Ordering::SeqCst);
        Ok(russh::server::Auth::reject())
    }

    async fn auth_publickey(
        &mut self,
        user: &str,
        key: &ssh_key::PublicKey,
    ) -> Result<russh::server::Auth, Self::Error> {
        self.auth_requests.fetch_add(1, Ordering::SeqCst);
        if user != "alice" || key.to_bytes().ok().as_ref() != self.expected_public_key.as_ref() {
            return Ok(russh::server::Auth::reject());
        }
        self.publickey_verified = true;
        Ok(russh::server::Auth::Reject {
            proceed_with_methods: Some((&[russh::MethodKind::Password][..]).into()),
            partial_success: true,
        })
    }

    async fn auth_password(
        &mut self,
        user: &str,
        password: &str,
    ) -> Result<russh::server::Auth, Self::Error> {
        self.auth_requests.fetch_add(1, Ordering::SeqCst);
        if user == "alice"
            && password == "test-password"
            && (self.expected_public_key.is_none() || self.publickey_verified)
        {
            Ok(russh::server::Auth::Accept)
        } else {
            Ok(russh::server::Auth::reject())
        }
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
}

async fn connect(
    algorithms: Vec<Algorithm>,
    expected_public_key: Option<Vec<u8>>,
) -> (ClientConnection, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
    let mut server_config = russh::server::Config::default();
    server_config.keys.push(
        PrivateKey::random(
            &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
            Algorithm::Ed25519,
        )
        .expect("host key"),
    );
    server_config.preferred.key = Cow::Owned(algorithms);
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind server");
    let port = listener.local_addr().expect("server port").port();
    let auth_requests = Arc::new(AtomicUsize::new(0));
    let requests = Arc::clone(&auth_requests);
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept client");
        let session = russh::server::run_stream(
            Arc::new(server_config),
            stream,
            PasswordServer {
                auth_requests: requests,
                expected_public_key,
                publickey_verified: false,
            },
        )
        .await
        .expect("start session");
        let _ = session.await;
    });
    let config = ClientConfig::new("127.0.0.1", port, |_host: &str, _key: &HostKey| Ok(()))
        .expect("client config");
    let connection = timeout(DEADLINE, ClientConnection::connect(config))
        .await
        .expect("connect deadline")
        .expect("connect client");
    (connection, auth_requests, server)
}

#[tokio::test]
async fn rsa_advertisement_is_cached_without_auth_probe_and_password_auth_still_works() {
    let cases = [
        (
            vec![
                Algorithm::Ed25519,
                Algorithm::Rsa { hash: Some(HashAlg::Sha512) },
                Algorithm::Rsa { hash: Some(HashAlg::Sha256) },
            ],
            ServerRsaSha2Selection::Sha512,
        ),
        (
            vec![Algorithm::Ed25519, Algorithm::Rsa { hash: Some(HashAlg::Sha256) }],
            ServerRsaSha2Selection::Sha256,
        ),
        (
            vec![Algorithm::Ed25519, Algorithm::Rsa { hash: None }],
            ServerRsaSha2Selection::Sha1OnlyAdvertised,
        ),
        (vec![Algorithm::Ed25519], ServerRsaSha2Selection::Undetermined),
    ];
    for (algorithms, expected) in cases {
        let (mut connection, auth_requests, server) = connect(algorithms, None).await;
        assert_eq!(
            timeout(DEADLINE, connection.server_rsa_sha2_selection())
                .await
                .expect("discovery deadline")
                .expect("discovery"),
            expected,
        );
        assert_eq!(
            connection.server_rsa_sha2_selection().await.expect("cached discovery"),
            expected
        );
        assert_eq!(auth_requests.load(Ordering::SeqCst), 0);
        connection.authenticate_password("alice", b"test-password").await.expect("password auth");
        assert_eq!(auth_requests.load(Ordering::SeqCst), 1);
        connection.open_session().await.expect("session after discovery");
        connection.disconnect().await.expect("disconnect");
        timeout(DEADLINE, server).await.expect("server deadline").expect("server task");
    }
}

#[tokio::test]
async fn discovery_between_publickey_and_password_factors_preserves_mfa() {
    let signer = Ed25519SshSigner::new(Ed25519SigningKey::from_bytes(&[7; 32]).expect("signer"));
    let (mut connection, auth_requests, server) = connect(
        vec![Algorithm::Ed25519, Algorithm::Rsa { hash: Some(HashAlg::Sha256) }],
        Some(signer.public_key_blob().expect("public key")),
    )
    .await;
    assert!(matches!(
        connection.authenticate_publickey("alice", &signer).await,
        Err(ClientError::AuthenticationRejected {
            partial_success: true,
            remaining_methods,
        }) if remaining_methods == ["password"]
    ));
    assert_eq!(auth_requests.load(Ordering::SeqCst), 1);
    assert_eq!(
        connection.server_rsa_sha2_selection().await.expect("discovery between factors"),
        ServerRsaSha2Selection::Sha256
    );
    assert_eq!(
        connection.server_rsa_sha2_selection().await.expect("cached discovery"),
        ServerRsaSha2Selection::Sha256
    );
    assert_eq!(auth_requests.load(Ordering::SeqCst), 1);
    connection.authenticate_password("alice", b"test-password").await.expect("second factor");
    assert_eq!(auth_requests.load(Ordering::SeqCst), 2);
    connection.open_session().await.expect("session after MFA");
    connection.disconnect().await.expect("disconnect");
    timeout(DEADLINE, server).await.expect("server deadline").expect("server task");
}
