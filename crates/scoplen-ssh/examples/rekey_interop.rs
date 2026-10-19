// SPDX-License-Identifier: Apache-2.0
//! Verify exact authenticated session data across client- and server-initiated OpenSSH rekey.

use std::{env, error::Error, time::Duration};

use scoplen_ssh::{
    ChannelEvent, ClientChannel, ClientConfig, ClientConnection, HostKey, HostKeyVerificationError,
};
use ssh_key::PublicKey;
use tokio::{net::TcpStream, time::timeout};

const STEP_DEADLINE: Duration = Duration::from_secs(10);
const TRANSFER_DEADLINE: Duration = Duration::from_secs(45);
const CHUNK_BYTES: usize = 4096;
const CHUNKS: usize = 32;

#[derive(Clone, Copy)]
enum RekeyMode {
    Client,
    Server,
    Control,
}

impl RekeyMode {
    fn name(self) -> &'static str {
        match self {
            Self::Client => "client-initiated",
            Self::Server => "server-initiated",
            Self::Control => "no-rekey control",
        }
    }

    fn port_variable(self) -> &'static str {
        match self {
            Self::Client => "SCOPLEN_REKEY_CLIENT_PORT",
            Self::Server => "SCOPLEN_REKEY_SERVER_PORT",
            Self::Control => "SCOPLEN_REKEY_CONTROL_PORT",
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let expected_key =
        PublicKey::from_openssh(&env::var("SCOPLEN_ALGORITHM_HOST_KEY")?)?.to_bytes()?;
    let username = env::var("SCOPLEN_ALGORITHM_USER")?;
    let password = env::var("SCOPLEN_ALGORITHM_PASSWORD")?;

    for mode in [RekeyMode::Client, RekeyMode::Server, RekeyMode::Control] {
        let port = env::var(mode.port_variable())?.parse::<u16>()?;
        exercise(mode, port, &expected_key, &username, &password).await?;
        println!(
            "OpenSSH {}: {} exact echo bytes and exit status zero",
            mode.name(),
            CHUNK_BYTES * CHUNKS
        );
    }
    Ok(())
}

async fn exercise(
    mode: RekeyMode,
    port: u16,
    expected_key: &[u8],
    username: &str,
    password: &str,
) -> Result<(), Box<dyn Error>> {
    let expected_key = expected_key.to_vec();
    let verifier = move |_host: &str, presented: &HostKey| match presented {
        HostKey::Raw { key_blob, .. } if key_blob == &expected_key => Ok(()),
        _ => Err(HostKeyVerificationError::Rejected("unexpected server key".to_owned())),
    };
    let mut config = ClientConfig::new("rekey.example.test", port, verifier)?;
    if matches!(mode, RekeyMode::Client) {
        config = config.with_rekey_limits(32 * 1024, Duration::from_secs(3600))?;
    }
    let stream = timeout(STEP_DEADLINE, TcpStream::connect(("127.0.0.1", port))).await??;
    let mut connection =
        timeout(STEP_DEADLINE, ClientConnection::connect_stream(config, stream)).await??;
    timeout(STEP_DEADLINE, connection.authenticate_password(username, password.as_bytes()))
        .await??;
    let mut channel = timeout(STEP_DEADLINE, connection.open_session()).await??;
    timeout(STEP_DEADLINE, channel.exec(true, b"cat")).await??;

    timeout(TRANSFER_DEADLINE, async {
        for sequence in 0..CHUNKS {
            let mut next = u8::try_from(sequence)?;
            let payload = (0..CHUNK_BYTES)
                .map(|_| {
                    let byte = next;
                    next = next.wrapping_add(31);
                    byte
                })
                .collect::<Vec<_>>();
            channel.send_data(&payload).await?;
            let echo = read_echo(&mut channel, payload.len()).await?;
            if echo != payload {
                return Err(format!("{} echo differs at chunk {sequence}", mode.name()).into());
            }
        }
        channel.send_eof().await?;
        read_exit(&mut channel).await
    })
    .await??;
    timeout(STEP_DEADLINE, connection.disconnect()).await??;
    Ok(())
}

async fn read_echo(
    channel: &mut ClientChannel,
    expected: usize,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut echo = Vec::with_capacity(expected);
    while echo.len() < expected {
        match channel.next_event().await? {
            Some(ChannelEvent::Data(data)) if echo.len() + data.len() <= expected => {
                echo.extend_from_slice(&data);
            }
            Some(ChannelEvent::Success) => {}
            other => return Err(format!("unexpected echo event: {other:?}").into()),
        }
    }
    Ok(echo)
}

async fn read_exit(channel: &mut ClientChannel) -> Result<(), Box<dyn Error>> {
    let mut exit_status = None;
    loop {
        match channel.next_event().await? {
            Some(ChannelEvent::ExitStatus(status)) => exit_status = Some(status),
            Some(ChannelEvent::Eof | ChannelEvent::Success) => {}
            Some(ChannelEvent::Close) | None => break,
            other => return Err(format!("unexpected event after echo: {other:?}").into()),
        }
    }
    if exit_status != Some(0) {
        return Err(format!("remote cat exit status was {exit_status:?}").into());
    }
    Ok(())
}
