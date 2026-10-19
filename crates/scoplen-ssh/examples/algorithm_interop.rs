// SPDX-License-Identifier: Apache-2.0
//! Exercise constrained modern and per-Host legacy SSH negotiation against disposable OpenSSH.

use std::{
    env,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use scoplen_ssh::{
    AlgorithmCategory, ChannelEvent, ClientConfig, ClientConnection, ClientError,
    HostAlgorithmPolicy, HostKey, HostKeyVerificationError,
};
use ssh_key::PublicKey;
use tokio::{net::TcpStream, time::timeout};

const DEADLINE: Duration = Duration::from_secs(10);
const COMMAND_OUTPUT: &[u8] = b"scoplen-algorithm-ok";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let modern_port = env::var("SCOPLEN_ALGORITHM_MODERN_PORT")?.parse()?;
    let legacy_port = env::var("SCOPLEN_ALGORITHM_LEGACY_PORT")?.parse()?;
    let legacy_cipher =
        env::var("SCOPLEN_ALGORITHM_LEGACY_CIPHER").unwrap_or_else(|_| "aes256-cbc".to_owned());
    if !matches!(legacy_cipher.as_str(), "aes256-cbc" | "3des-cbc") {
        return Err("SCOPLEN_ALGORITHM_LEGACY_CIPHER must be aes256-cbc or 3des-cbc".into());
    }
    let expected_key =
        PublicKey::from_openssh(&env::var("SCOPLEN_ALGORITHM_HOST_KEY")?)?.to_bytes()?;
    let username = env::var("SCOPLEN_ALGORITHM_USER")?;
    let password = env::var("SCOPLEN_ALGORITHM_PASSWORD")?;

    let (modern, modern_checks) = pinned_config("modern.example.test", modern_port, &expected_key)?;
    let connection = connect(modern, modern_port).await?;
    verify_command(connection, &username, &password).await?;
    require_checks(&modern_checks, 1, "modern Host")?;

    let (legacy_default, default_checks) =
        pinned_config("legacy-default.example.test", legacy_port, &expected_key)?;
    reject_unshared_algorithms(legacy_default, legacy_port).await?;
    require_checks(&default_checks, 0, "default legacy attempt")?;

    let legacy_policy = HostAlgorithmPolicy::with_legacy(&[
        (AlgorithmCategory::KeyExchange, "diffie-hellman-group14-sha256"),
        (AlgorithmCategory::Cipher, legacy_cipher.as_str()),
        (AlgorithmCategory::Mac, "hmac-sha1"),
    ])?;
    let (legacy, legacy_checks) = pinned_config("legacy.example.test", legacy_port, &expected_key)?;
    let connection = connect(legacy.with_algorithm_policy(legacy_policy), legacy_port).await?;
    verify_command(connection, &username, &password).await?;
    require_checks(&legacy_checks, 1, "opted-in legacy Host")?;

    let (other, other_checks) = pinned_config("other.example.test", legacy_port, &expected_key)?;
    reject_unshared_algorithms(other, legacy_port).await?;
    require_checks(&other_checks, 0, "other default Host")?;

    println!("OpenSSH constrained modern, legacy opt-in, and Host isolation passed");
    Ok(())
}

fn pinned_config(
    host: &str,
    port: u16,
    expected_key: &[u8],
) -> Result<(ClientConfig, Arc<AtomicUsize>), Box<dyn std::error::Error>> {
    let expected_host = host.to_owned();
    let expected_key = expected_key.to_vec();
    let checks = Arc::new(AtomicUsize::new(0));
    let callback_checks = Arc::clone(&checks);
    let verifier = move |presented_host: &str, key: &HostKey| {
        if presented_host != expected_host {
            return Err(HostKeyVerificationError::Rejected("unexpected Host".to_owned()));
        }
        match key {
            HostKey::Raw { key_blob, .. } if key_blob.as_slice() == expected_key.as_slice() => {
                callback_checks.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
            _ => Err(HostKeyVerificationError::Rejected("unexpected server key".to_owned())),
        }
    };
    Ok((ClientConfig::new(host, port, verifier)?, checks))
}

async fn connect(
    config: ClientConfig,
    port: u16,
) -> Result<ClientConnection, Box<dyn std::error::Error>> {
    let stream = timeout(DEADLINE, TcpStream::connect(("127.0.0.1", port)))
        .await
        .map_err(|_| "TCP connection timed out")??;
    Ok(timeout(DEADLINE, ClientConnection::connect_stream(config, stream))
        .await
        .map_err(|_| "SSH handshake timed out")??)
}

async fn reject_unshared_algorithms(
    config: ClientConfig,
    port: u16,
) -> Result<(), Box<dyn std::error::Error>> {
    match connect(config, port).await {
        Err(error)
            if matches!(error.downcast_ref::<ClientError>(), Some(ClientError::Protocol)) =>
        {
            Ok(())
        }
        Err(error) => Err(format!("expected algorithm negotiation rejection, got {error}").into()),
        Ok(connection) => {
            connection.disconnect().await?;
            Err("default policy connected to a legacy-only Host".into())
        }
    }
}

fn require_checks(
    checks: &AtomicUsize,
    expected: usize,
    scenario: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    if checks.load(Ordering::SeqCst) != expected {
        return Err(format!("{scenario}: unexpected host-key callback count").into());
    }
    Ok(())
}

async fn verify_command(
    mut connection: ClientConnection,
    username: &str,
    password: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    timeout(DEADLINE, connection.authenticate_password(username, password.as_bytes())).await??;
    let mut channel = timeout(DEADLINE, connection.open_session()).await??;
    timeout(DEADLINE, channel.exec(true, b"printf scoplen-algorithm-ok")).await??;
    let (output, exit_status) = timeout(DEADLINE, async {
        let mut output = Vec::new();
        let mut exit_status = None;
        loop {
            match channel.next_event().await? {
                Some(ChannelEvent::Data(data)) => output.extend_from_slice(&data),
                Some(ChannelEvent::ExitStatus(status)) => exit_status = Some(status),
                Some(ChannelEvent::Close) | None => break,
                Some(ChannelEvent::Eof | ChannelEvent::Success) => {}
                Some(other) => return Err(format!("unexpected command event: {other:?}").into()),
            }
        }
        Ok::<_, Box<dyn std::error::Error>>((output, exit_status))
    })
    .await??;
    if output != COMMAND_OUTPUT || exit_status != Some(0) {
        return Err(format!(
            "unexpected command result: status {exit_status:?}, output {output:?}"
        )
        .into());
    }
    timeout(DEADLINE, connection.disconnect()).await??;
    Ok(())
}
