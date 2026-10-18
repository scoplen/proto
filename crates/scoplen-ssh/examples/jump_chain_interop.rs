// SPDX-License-Identifier: Apache-2.0
//! Exercise nested SSH handshakes through a disposable OpenSSH server with TCP forwarding.

use std::{env, time::Duration};

use scoplen_ssh::{
    ChannelEvent, ClientConfig, ClientConnection, ClientError, HostKey, HostKeyVerificationError,
};
use ssh_key::PublicKey;
use tokio::time::timeout;

const DEADLINE: Duration = Duration::from_secs(10);

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let host = env::var("SCOPLEN_OPENSSH_HOST").unwrap_or_else(|_| "127.0.0.1".to_owned());
    let port =
        env::var("SCOPLEN_OPENSSH_PORT").unwrap_or_else(|_| "22223".to_owned()).parse::<u16>()?;
    let target_port = env::var("SCOPLEN_OPENSSH_JUMP_TARGET_PORT")?.parse::<u16>()?;
    let username = env::var("SCOPLEN_OPENSSH_USER").unwrap_or_else(|_| "scoplen".to_owned());
    let password = env::var("SCOPLEN_OPENSSH_PASSWORD")?;
    let expected_key =
        PublicKey::from_openssh(&env::var("SCOPLEN_OPENSSH_HOST_KEY")?)?.to_bytes()?;

    let mut first =
        timeout(DEADLINE, ClientConnection::connect(pinned_config(&host, port, &expected_key)?))
            .await??;
    authenticate(&mut first, &username, &password).await?;
    let mut second = timeout(
        DEADLINE,
        ClientConnection::connect_via_direct_tcpip(
            pinned_config("127.0.0.1", target_port, &expected_key)?,
            &first,
            "127.0.0.1",
            5000,
        ),
    )
    .await??;
    authenticate(&mut second, &username, &password).await?;
    let mut target = timeout(
        DEADLINE,
        ClientConnection::connect_via_direct_tcpip(
            pinned_config("127.0.0.1", target_port, &expected_key)?,
            &second,
            "127.0.0.1",
            5001,
        ),
    )
    .await??;
    authenticate(&mut target, &username, &password).await?;

    verify_session(&target).await?;
    verify_session(&second).await?;
    verify_session(&first).await?;

    let wrong_pin = timeout(
        DEADLINE,
        ClientConnection::connect_via_direct_tcpip(
            pinned_config("127.0.0.1", target_port, &[])?,
            &second,
            "127.0.0.1",
            5002,
        ),
    )
    .await?
    .expect_err("nested connection accepted an untrusted host key");
    if !matches!(wrong_pin, ClientError::HostKey(HostKeyVerificationError::Rejected(_))) {
        return Err(format!("wrong host key produced {wrong_pin}").into());
    }

    let closed = timeout(
        DEADLINE,
        ClientConnection::connect_via_direct_tcpip(
            pinned_config("127.0.0.1", 65534, &expected_key)?,
            &second,
            "127.0.0.1",
            5003,
        ),
    )
    .await?
    .expect_err("nested connection reached a closed target port");
    if !matches!(closed, ClientError::ChannelOpen { .. }) {
        return Err(format!("closed target produced {closed}").into());
    }
    verify_session(&second).await?;

    timeout(DEADLINE, target.disconnect()).await??;
    timeout(DEADLINE, second.disconnect()).await??;
    timeout(DEADLINE, first.disconnect()).await??;
    println!("openssh nested jump interop ok");
    Ok(())
}

fn pinned_config(host: &str, port: u16, expected_key: &[u8]) -> Result<ClientConfig, ClientError> {
    let expected_key = expected_key.to_vec();
    Ok(ClientConfig::new(host, port, move |_host: &str, key: &HostKey| match key {
        HostKey::Raw { key_blob, .. } if *key_blob == expected_key => Ok(()),
        _ => Err(HostKeyVerificationError::Rejected("unexpected server key".to_owned())),
    })?)
}

async fn authenticate(
    connection: &mut ClientConnection,
    username: &str,
    password: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    timeout(DEADLINE, connection.authenticate_password(username, password.as_bytes())).await??;
    Ok(())
}

async fn verify_session(connection: &ClientConnection) -> Result<(), Box<dyn std::error::Error>> {
    timeout(DEADLINE, async {
        let mut channel = connection.open_session().await?;
        channel.exec(true, b"printf scoplen-jump-ok").await?;
        let mut output = Vec::new();
        let mut exited = false;
        loop {
            match channel.next_event().await? {
                Some(ChannelEvent::Data(data)) if output.len() + data.len() <= 256 => {
                    output.extend_from_slice(&data);
                }
                Some(ChannelEvent::ExitStatus(0)) => exited = true,
                Some(ChannelEvent::Success | ChannelEvent::Eof) => {}
                Some(ChannelEvent::Close) | None => break,
                _ => return Err(ClientError::Protocol),
            }
        }
        if !exited || output != b"scoplen-jump-ok" {
            return Err(ClientError::Protocol);
        }
        Ok(())
    })
    .await??;
    Ok(())
}
