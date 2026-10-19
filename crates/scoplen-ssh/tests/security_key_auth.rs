// SPDX-License-Identifier: Apache-2.0

use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use russh::keys::PrivateKey;
use scoplen_crypto::{Ed25519SigningKey, P256SigningKey};
use scoplen_ssh::{
    ClientConfig, ClientConnection, ClientError, HostKey, HostKeyVerificationError,
    SecurityKeyAlgorithm, SecurityKeyError, SecurityKeyProvider, SecurityKeyPublicKey,
    SecurityKeySignOptions, SecurityKeySignature, SecurityKeySshSigner,
};
use ssh_key::{
    Algorithm,
    sha2::{Digest, Sha256},
};
use tokio::{net::TcpListener, task::JoinHandle, time::timeout};

const DEADLINE: Duration = Duration::from_secs(5);
const APPLICATION: &str = "ssh:scoplen-test";

#[derive(Clone, Copy)]
enum Fault {
    None,
    WrongKey,
    WrongApplication,
    WrongPayload,
    ChangeIdentity,
}

enum TestKey {
    Ed25519(Ed25519SigningKey),
    P256(P256SigningKey),
}

struct SoftwareProvider {
    key: TestKey,
    fault: Fault,
    public_key_calls: AtomicUsize,
    sign_calls: AtomicUsize,
}

impl SoftwareProvider {
    fn new(algorithm: SecurityKeyAlgorithm, fault: Fault) -> Self {
        let key = match algorithm {
            SecurityKeyAlgorithm::Ed25519 => {
                TestKey::Ed25519(Ed25519SigningKey::from_bytes(&[9; 32]).expect("Ed25519 key"))
            }
            SecurityKeyAlgorithm::EcdsaSha2Nistp256 => {
                TestKey::P256(P256SigningKey::from_bytes(&[1; 32]).expect("P-256 key"))
            }
        };
        Self { key, fault, public_key_calls: AtomicUsize::new(0), sign_calls: AtomicUsize::new(0) }
    }

    fn identity(&self) -> SecurityKeyPublicKey {
        let key = match &self.key {
            TestKey::Ed25519(key) => key.public_key().to_vec(),
            TestKey::P256(key) => key.public_key_sec1().clone(),
        };
        SecurityKeyPublicKey::new(self.algorithm(), key, APPLICATION).expect("test identity")
    }
}

impl SecurityKeyProvider for SoftwareProvider {
    fn algorithm(&self) -> SecurityKeyAlgorithm {
        match self.key {
            TestKey::Ed25519(_) => SecurityKeyAlgorithm::Ed25519,
            TestKey::P256(_) => SecurityKeyAlgorithm::EcdsaSha2Nistp256,
        }
    }

    fn public_key(&self) -> Result<SecurityKeyPublicKey, SecurityKeyError> {
        let mut identity = self.identity();
        if matches!(self.fault, Fault::ChangeIdentity)
            && self.public_key_calls.fetch_add(1, Ordering::SeqCst) > 0
        {
            identity = SecurityKeyPublicKey::new(
                identity.algorithm(),
                identity.key(),
                "ssh:changed-application",
            )?;
        }
        Ok(identity)
    }

    fn discover(&self, application: &str) -> Result<Vec<SecurityKeyPublicKey>, SecurityKeyError> {
        Ok(if application == APPLICATION { vec![self.identity()] } else { Vec::new() })
    }

    fn sign(
        &self,
        application: &str,
        message: &[u8],
        _options: SecurityKeySignOptions,
    ) -> Result<SecurityKeySignature, SecurityKeyError> {
        self.sign_calls.fetch_add(1, Ordering::SeqCst);
        let application = if matches!(self.fault, Fault::WrongApplication) {
            "ssh:other-application"
        } else {
            application
        };
        let mut message = message.to_vec();
        if matches!(self.fault, Fault::WrongPayload) {
            message[0] ^= 1;
        }
        let flags = 0x05;
        let counter = 7_u32;
        let mut signed_data = Vec::with_capacity(69);
        signed_data.extend_from_slice(&Sha256::digest(application.as_bytes()));
        signed_data.push(flags);
        signed_data.extend_from_slice(&counter.to_be_bytes());
        signed_data.extend_from_slice(&Sha256::digest(&message));
        let signature = match &self.key {
            TestKey::Ed25519(key) => {
                if matches!(self.fault, Fault::WrongKey) {
                    Ed25519SigningKey::from_bytes(&[8; 32])
                        .expect("wrong Ed25519 key")
                        .sign(&signed_data)
                        .to_vec()
                } else {
                    key.sign(&signed_data).to_vec()
                }
            }
            TestKey::P256(key) => {
                let raw = if matches!(self.fault, Fault::WrongKey) {
                    P256SigningKey::from_bytes(&[2; 32])
                        .expect("wrong P-256 key")
                        .sign(&signed_data)
                } else {
                    key.sign(&signed_data)
                };
                let mut encoded = Vec::new();
                for part in [&raw[..32], &raw[32..]] {
                    let part = part.iter().position(|byte| *byte != 0).map_or(part, |i| &part[i..]);
                    let mut part = part.to_vec();
                    if part.first().is_some_and(|byte| byte & 0x80 != 0) {
                        part.insert(0, 0);
                    }
                    encoded.extend_from_slice(
                        &u32::try_from(part.len())
                            .expect("signature component length")
                            .to_be_bytes(),
                    );
                    encoded.extend_from_slice(&part);
                }
                encoded
            }
        };
        SecurityKeySignature::new(self.algorithm(), signature, flags, counter)
    }
}

struct Server {
    expected_key: Vec<u8>,
    authenticated: Arc<AtomicUsize>,
}

impl russh::server::Handler for Server {
    type Error = russh::Error;

    async fn auth_publickey(
        &mut self,
        user: &str,
        key: &ssh_key::PublicKey,
    ) -> Result<russh::server::Auth, Self::Error> {
        if user == "scoplen" && key.to_bytes().is_ok_and(|blob| blob == self.expected_key) {
            self.authenticated.fetch_add(1, Ordering::SeqCst);
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

async fn connect(expected_key: Vec<u8>) -> (ClientConnection, Arc<AtomicUsize>, JoinHandle<()>) {
    let mut server_config = russh::server::Config::default();
    server_config.keys.push(
        PrivateKey::random(
            &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
            Algorithm::Ed25519,
        )
        .expect("disposable host key"),
    );
    let host_key = server_config.keys[0].public_key().to_bytes().expect("host key bytes");
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind server");
    let address: SocketAddr = listener.local_addr().expect("server address");
    let authenticated = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&authenticated);
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept client");
        let session = russh::server::run_stream(
            Arc::new(server_config),
            stream,
            Server { expected_key, authenticated: count },
        )
        .await
        .expect("start server session");
        let _ = session.await;
    });
    let config =
        ClientConfig::new("127.0.0.1", address.port(), move |_: &str, key: &HostKey| match key {
            HostKey::Raw { key_blob, .. } if *key_blob == host_key => Ok(()),
            _ => Err(HostKeyVerificationError::Rejected("unexpected host key".into())),
        })
        .expect("client config");
    let connection = timeout(DEADLINE, ClientConnection::connect(config))
        .await
        .expect("handshake deadline")
        .expect("connect client");
    (connection, authenticated, server)
}

#[tokio::test]
async fn both_security_key_algorithms_authenticate_through_the_public_client() {
    for algorithm in [SecurityKeyAlgorithm::Ed25519, SecurityKeyAlgorithm::EcdsaSha2Nistp256] {
        let provider = SoftwareProvider::new(algorithm, Fault::None);
        let identity = provider.identity();
        let signer = SecurityKeySshSigner::new(
            &provider,
            identity.clone(),
            SecurityKeySignOptions::user_presence_and_verification(),
        )
        .expect("provider signer");
        let (mut connection, authenticated, server) =
            connect(identity.to_blob().expect("key blob")).await;
        timeout(DEADLINE, connection.authenticate_publickey("scoplen", &signer))
            .await
            .expect("auth deadline")
            .expect("security-key authentication");
        connection.open_session().await.expect("authenticated session");
        assert_eq!(authenticated.load(Ordering::SeqCst), 1);
        connection.disconnect().await.expect("disconnect");
        drop(connection);
        timeout(DEADLINE, server).await.expect("server shutdown").expect("server task");
    }
}

#[tokio::test]
async fn wrong_key_application_and_session_payload_fail_real_signature_verification() {
    for algorithm in [SecurityKeyAlgorithm::Ed25519, SecurityKeyAlgorithm::EcdsaSha2Nistp256] {
        for fault in [Fault::WrongKey, Fault::WrongApplication, Fault::WrongPayload] {
            let provider = SoftwareProvider::new(algorithm, fault);
            let identity = provider.identity();
            let signer = SecurityKeySshSigner::new(
                &provider,
                identity.clone(),
                SecurityKeySignOptions::user_presence(),
            )
            .expect("provider signer");
            let (mut connection, authenticated, server) =
                connect(identity.to_blob().expect("key blob")).await;
            let error = timeout(DEADLINE, connection.authenticate_publickey("scoplen", &signer))
                .await
                .expect("auth deadline")
                .expect_err("invalid signature must fail");
            assert!(matches!(error, ClientError::AuthenticationRejected { .. }), "{error:?}");
            assert_eq!(authenticated.load(Ordering::SeqCst), 0);
            connection.disconnect().await.expect("disconnect");
            drop(connection);
            timeout(DEADLINE, server).await.expect("server shutdown").expect("server task");
        }
    }
}

#[tokio::test]
async fn changed_provider_identity_is_rejected_before_signing() {
    let provider = SoftwareProvider::new(SecurityKeyAlgorithm::Ed25519, Fault::ChangeIdentity);
    let identity = provider.identity();
    let signer = SecurityKeySshSigner::new(
        &provider,
        identity.clone(),
        SecurityKeySignOptions::user_presence(),
    )
    .expect("provider signer");
    let (mut connection, authenticated, server) =
        connect(identity.to_blob().expect("key blob")).await;
    let error = timeout(DEADLINE, connection.authenticate_publickey("scoplen", &signer))
        .await
        .expect("auth deadline")
        .expect_err("changed application must fail");
    assert!(matches!(error, ClientError::PublicKey(_)), "{error:?}");
    assert_eq!(authenticated.load(Ordering::SeqCst), 0);
    assert_eq!(provider.sign_calls.load(Ordering::SeqCst), 0);
    connection.disconnect().await.expect("disconnect");
    drop(connection);
    timeout(DEADLINE, server).await.expect("server shutdown").expect("server task");
}
