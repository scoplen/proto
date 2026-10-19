// SPDX-License-Identifier: Apache-2.0

use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use russh::keys::PrivateKey;
use scoplen_ssh::{
    CertificateValidationError, ClientConfig, ClientConnection, ClientError, HostKey,
    HostKeyPolicy, HostKeyVerificationError,
};
use ssh_key::{Algorithm, certificate};
use tokio::{net::TcpListener, time::timeout};

const DEADLINE: Duration = Duration::from_secs(5);

struct PasswordServer {
    auth_requests: Arc<AtomicUsize>,
}

impl russh::server::Handler for PasswordServer {
    type Error = russh::Error;

    async fn auth_password(
        &mut self,
        user: &str,
        password: &str,
    ) -> Result<russh::server::Auth, Self::Error> {
        self.auth_requests.fetch_add(1, Ordering::SeqCst);
        Ok(if user == "alice" && password == "test-password" {
            russh::server::Auth::Accept
        } else {
            russh::server::Auth::reject()
        })
    }
}

fn unix_now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).expect("system clock").as_secs()
}

#[tokio::test]
async fn delayed_default_rejects_expired_host_certificate_but_fixed_policy_keeps_its_time() {
    let mut rng = ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng);
    let host_key = PrivateKey::random(&mut rng, Algorithm::Ed25519).expect("host key");
    let ca = PrivateKey::random(&mut rng, Algorithm::Ed25519).expect("CA key");
    let created_at = unix_now();
    let expires_at = created_at + 2;
    let mut builder = certificate::Builder::new(
        vec![8; 16],
        host_key.public_key().clone(),
        created_at - 60,
        expires_at,
    )
    .expect("certificate builder");
    builder.cert_type(certificate::CertType::Host).expect("host certificate");
    builder.valid_principal("127.0.0.1").expect("host principal");
    let certificate = builder.sign(&ca).expect("signed host certificate");
    let ca_blob = ca.public_key().to_bytes().expect("CA blob");

    let mut server_config = russh::server::Config::default();
    server_config.keys.push(host_key);
    server_config.certificates.push(certificate);
    let server_config = Arc::new(server_config);
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind server");
    let port = listener.local_addr().expect("server port").port();
    let auth_requests = Arc::new(AtomicUsize::new(0));
    let requests = Arc::clone(&auth_requests);
    let server = tokio::spawn(async move {
        for _ in 0..2 {
            let (stream, _) = listener.accept().await.expect("accept client");
            let config = Arc::clone(&server_config);
            let requests = Arc::clone(&requests);
            tokio::spawn(async move {
                if let Ok(session) = russh::server::run_stream(
                    config,
                    stream,
                    PasswordServer { auth_requests: requests },
                )
                .await
                {
                    let _ = session.await;
                }
            });
        }
    });

    let callback_calls = Arc::new(AtomicUsize::new(0));
    let calls = Arc::clone(&callback_calls);
    let expected_ca = ca_blob.clone();
    let default = ClientConfig::new("127.0.0.1", port, move |_host: &str, key: &HostKey| {
        calls.fetch_add(1, Ordering::SeqCst);
        match key {
            HostKey::Certificate(cert) if cert.ca_public_key_blob() == expected_ca => Ok(()),
            _ => Err(HostKeyVerificationError::Rejected("unexpected host CA".to_owned())),
        }
    })
    .expect("default config");
    let delayed = default.clone();
    drop(default);
    while unix_now() < expires_at {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(matches!(
        timeout(DEADLINE, ClientConnection::connect(delayed)).await.expect("handshake deadline"),
        Err(ClientError::HostKey(HostKeyVerificationError::Certificate(
            CertificateValidationError::Expired
        )))
    ));
    assert_eq!(callback_calls.load(Ordering::SeqCst), 0);
    assert_eq!(auth_requests.load(Ordering::SeqCst), 0);

    let calls = Arc::clone(&callback_calls);
    let explicit = ClientConfig::new("127.0.0.1", port, move |_host: &str, key: &HostKey| {
        calls.fetch_add(1, Ordering::SeqCst);
        match key {
            HostKey::Certificate(cert) if cert.ca_public_key_blob() == ca_blob => Ok(()),
            _ => Err(HostKeyVerificationError::Rejected("unexpected host CA".to_owned())),
        }
    })
    .expect("fixed config")
    .with_host_key_policy(HostKeyPolicy::new("127.0.0.1", created_at).expect("fixed policy"));
    let mut connection = timeout(DEADLINE, ClientConnection::connect(explicit))
        .await
        .expect("fixed handshake deadline")
        .expect("fixed time accepts certificate");
    assert_eq!(callback_calls.load(Ordering::SeqCst), 1);
    connection.authenticate_password("alice", b"test-password").await.expect("password auth");
    assert_eq!(auth_requests.load(Ordering::SeqCst), 1);
    connection.disconnect().await.expect("disconnect");
    timeout(DEADLINE, server).await.expect("server deadline").expect("server task");
}
