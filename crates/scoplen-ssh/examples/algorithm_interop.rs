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
const MATRIX_OUTPUT_LEN: usize = 64 * 1024;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    if let Ok(cases) = env::var("SCOPLEN_ALGORITHM_MATRIX") {
        return verify_modern_matrix(&cases).await;
    }
    let modern_port = env::var("SCOPLEN_ALGORITHM_MODERN_PORT")?.parse()?;
    let mlkem_port = env::var("SCOPLEN_ALGORITHM_MLKEM_PORT")?.parse()?;
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

    let (mlkem, mlkem_checks) = pinned_config("mlkem.example.test", mlkem_port, &expected_key)?;
    let connection = connect(mlkem, mlkem_port).await?;
    verify_command(connection, &username, &password).await?;
    require_checks(&mlkem_checks, 1, "ML-KEM Host")?;

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

    println!(
        "OpenSSH constrained Curve25519/AES-CTR, ML-KEM/ChaCha20, legacy opt-in, and Host isolation passed"
    );
    Ok(())
}

async fn verify_modern_matrix(cases: &str) -> Result<(), Box<dyn std::error::Error>> {
    let expected_key =
        PublicKey::from_openssh(&env::var("SCOPLEN_ALGORITHM_HOST_KEY")?)?.to_bytes()?;
    let username = env::var("SCOPLEN_ALGORITHM_USER")?;
    let password = env::var("SCOPLEN_ALGORITHM_PASSWORD")?;
    let expected_output = vec![0; MATRIX_OUTPUT_LEN];
    let mut count = 0;
    for case in cases.split(';') {
        let fields: Vec<_> = case.split('|').collect();
        let [name, port, expected_compression, preference] = fields.as_slice() else {
            return Err(format!("invalid modern algorithm case: {case}").into());
        };
        let port = port.parse::<u16>()?;
        if !matches!(*expected_compression, "none" | "zlib@openssh.com") {
            return Err(format!("invalid compression expectation for {name}").into());
        }
        if !matches!(*preference, "default" | "zlib") {
            return Err(format!("invalid policy selection for {name}").into());
        }
        let host = format!("{name}.example.test");
        if count == 0 {
            let wrong_key = vec![0; expected_key.len()];
            let (wrong_config, wrong_checks) = pinned_config(&host, port, &wrong_key)?;
            match connect(wrong_config, port).await {
                Err(error)
                    if matches!(
                        error.downcast_ref::<ClientError>(),
                        Some(ClientError::HostKey(_))
                    ) => {}
                Err(error) => {
                    return Err(format!("{name}: expected wrong-pin rejection, got {error}").into());
                }
                Ok(connection) => {
                    connection.disconnect().await?;
                    return Err(format!("{name}: accepted a wrong host key").into());
                }
            }
            require_checks(&wrong_checks, 0, "wrong host-key pin")?;
        }
        let (mut config, checks) = pinned_config(&host, port, &expected_key)?;
        if *preference == "zlib" {
            config = config.with_algorithm_policy(
                HostAlgorithmPolicy::default()
                    .prefer_default(AlgorithmCategory::Compression, "zlib@openssh.com")?,
            );
        }
        let connection = connect(config, port).await?;
        verify_command_output(
            connection,
            &username,
            &password,
            b"head -c 65536 /dev/zero",
            &expected_output,
        )
        .await?;
        require_checks(&checks, 1, name)?;
        println!(
            "modern algorithm case {name}: command, exact data, exit status, and host pin passed ({expected_compression})"
        );
        count += 1;
    }
    if count == 0 {
        return Err("modern algorithm matrix is empty".into());
    }
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
    connection: ClientConnection,
    username: &str,
    password: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    verify_command_output(
        connection,
        username,
        password,
        b"printf scoplen-algorithm-ok",
        COMMAND_OUTPUT,
    )
    .await
}

async fn verify_command_output(
    mut connection: ClientConnection,
    username: &str,
    password: &str,
    command: &[u8],
    expected_output: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    timeout(DEADLINE, connection.authenticate_password(username, password.as_bytes())).await??;
    let mut channel = timeout(DEADLINE, connection.open_session()).await??;
    timeout(DEADLINE, channel.exec(true, command)).await??;
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
    if output != expected_output || exit_status != Some(0) {
        let first_difference =
            output.iter().zip(expected_output).position(|(actual, expected)| actual != expected);
        return Err(format!(
            "unexpected command result: status {exit_status:?}, output length {}, expected length {}, first differing byte {first_difference:?}",
            output.len(),
            expected_output.len(),
        )
        .into());
    }
    timeout(DEADLINE, connection.disconnect()).await??;
    Ok(())
}
