// SPDX-License-Identifier: Apache-2.0
//! Verify independent OpenSSH/Dropbear jump identities, rejection, and teardown.

use std::{env, fs::File, io::Read, path::Path, time::Duration};

use scoplen_crypto::SecretVec;
use scoplen_ssh::{
    ChannelEvent, ClientConfig, ClientConnection, ClientError, HostKey, HostKeyVerificationError,
};
use ssh_key::PublicKey;
use tokio::time::timeout;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
const DEADLINE: Duration = Duration::from_secs(15);
const TRAILER: &[u8] = b"\0scoplen-mixed-jump-eof\xff";
const CLOSED_PORT: u16 = 2299;
const STALLED_PORT: u16 = 2240;

struct Profile {
    index: usize,
    kind: String,
    hostname: String,
    port: u16,
    ingress_port: u16,
    username: String,
    password: SecretVec,
    host_key: Vec<u8>,
}

#[tokio::main]
async fn main() -> Result<()> {
    Box::pin(run()).await
}

async fn run() -> Result<()> {
    let path = env::args_os().nth(1).ok_or("expected the private fixture descriptor")?;
    let profiles = read_profiles(Path::new(&path))?;
    for start in 0..2 {
        for depth in 1..=3 {
            Box::pin(exercise(&profiles, start, depth)).await?;
            println!("mixed Jump ingress={} depth={depth} verified", profiles[start].kind);
        }
    }
    println!("mixed OpenSSH/Dropbear Jump depths 1/2/3 acceptance passed");
    Ok(())
}

fn read_profiles(path: &Path) -> Result<Vec<Profile>> {
    let mut bytes = Vec::new();
    File::open(path)?.take(8193).read_to_end(&mut bytes)?;
    let descriptor = SecretVec::new(bytes);
    if descriptor.as_bytes().len() > 8192 {
        return Err("fixture descriptor exceeds its bound".into());
    }
    let mut profiles = Vec::<Profile>::new();
    for line in std::str::from_utf8(descriptor.as_bytes())?.lines() {
        let fields: Vec<_> = line.split('|').collect();
        if fields.len() != 8 || profiles.len() >= 4 {
            return Err("invalid fixture descriptor row".into());
        }
        let index = fields[0].parse::<usize>()?;
        let port = fields[3].parse::<u16>()?;
        let ingress_port = fields[4].parse::<u16>()?;
        let kind = if index.is_multiple_of(2) { "openssh" } else { "dropbear" };
        if index != profiles.len()
            || fields[1] != kind
            || fields[2] != format!("scoplen-jump-hop{index}.invalid")
            || port != 2230 + u16::try_from(index)?
            || (index < 2) != (ingress_port != 0)
            || fields[5] != format!("hop{index}")
            || fields[6].is_empty()
        {
            return Err("fixture endpoint identity differs from the fixed profile".into());
        }
        let host_key = PublicKey::from_openssh(fields[7])?.to_bytes()?;
        if profiles.iter().any(|profile| {
            profile.host_key == host_key || profile.password.as_bytes() == fields[6].as_bytes()
        }) {
            return Err("fixture hops must have independent host keys and passwords".into());
        }
        profiles.push(Profile {
            index,
            kind: kind.into(),
            hostname: fields[2].into(),
            port,
            ingress_port,
            username: fields[5].into(),
            password: SecretVec::new(fields[6].as_bytes().to_vec()),
            host_key,
        });
    }
    if profiles.len() != 4 {
        return Err("fixture must contain four independent SSH endpoints".into());
    }
    Ok(profiles)
}

fn pinned_config(
    profile: &Profile,
    parent: Option<&ClientConnection>,
    key: &[u8],
) -> std::result::Result<ClientConfig, ClientError> {
    let key = key.to_vec();
    let (host, port) = if parent.is_some() {
        (profile.hostname.as_str(), profile.port)
    } else {
        ("127.0.0.1", profile.ingress_port)
    };
    // One retained child plus one probe makes leaked failed/canceled channel slots observable.
    Ok(ClientConfig::new(host, port, move |_host: &str, presented: &HostKey| match presented {
        HostKey::Raw { key_blob, .. } if *key_blob == key => Ok(()),
        _ => Err(HostKeyVerificationError::Rejected("unexpected mixed Jump hop key".into())),
    })?
    .with_channel_limit(2)?)
}

async fn connect(
    profile: &Profile,
    parent: Option<&ClientConnection>,
    key: &[u8],
) -> std::result::Result<Box<ClientConnection>, ClientError> {
    let config = pinned_config(profile, parent, key)?;
    let result = if let Some(parent) = parent {
        timeout(
            DEADLINE,
            Box::pin(ClientConnection::connect_via_direct_tcpip(config, parent, "127.0.0.1", 0)),
        )
        .await
    } else {
        timeout(DEADLINE, Box::pin(ClientConnection::connect(config))).await
    };
    result.map_err(|_| ClientError::InvalidInput("mixed Jump connection deadline"))?.map(Box::new)
}

async fn authenticate(connection: &mut ClientConnection, profile: &Profile) -> Result<()> {
    timeout(
        DEADLINE,
        connection.authenticate_password(&profile.username, profile.password.as_bytes()),
    )
    .await??;
    Ok(())
}

async fn exercise(profiles: &[Profile], start: usize, depth: usize) -> Result<()> {
    let mut chain = Vec::<Box<ClientConnection>>::new();
    for position in 0..=depth {
        let profile = &profiles[(start + position) % profiles.len()];
        let parent = chain.last().map(Box::as_ref);
        let other_key = &profiles[(profile.index + 1) % profiles.len()].host_key;
        let wrong_pin = connect(profile, parent, other_key)
            .await
            .expect_err("mixed Jump accepted another hop's key");
        if !matches!(wrong_pin, ClientError::HostKey(HostKeyVerificationError::Rejected(_))) {
            return Err(format!("wrong mixed Jump pin produced {wrong_pin}").into());
        }
        let mut trusted_control = connect(profile, parent, &profile.host_key).await?;
        authenticate(&mut trusted_control, profile).await?;
        verify_session(&trusted_control, profile).await?;
        timeout(DEADLINE, trusted_control.disconnect()).await??;
        drop(trusted_control);
        if let Some(parent) = parent {
            verify_session(parent, &profiles[(start + position - 1) % profiles.len()]).await?;
            refused_open(parent).await?;
            verify_session(parent, &profiles[(start + position - 1) % profiles.len()]).await?;
        }

        let mut connection = connect(profile, parent, &profile.host_key).await?;
        let rejected = timeout(
            DEADLINE,
            connection.authenticate_password(&profile.username, b"incorrect-disposable-password"),
        )
        .await?
        .expect_err("mixed Jump accepted an incorrect password");
        if !matches!(rejected, ClientError::AuthenticationRejected { partial_success: false, .. }) {
            return Err(format!("incorrect mixed Jump password produced {rejected}").into());
        }
        if !matches!(connection.open_session().await, Err(ClientError::NotAuthenticated)) {
            return Err("a rejected mixed Jump factor allowed a session".into());
        }
        authenticate(&mut connection, profile).await?;
        verify_session(&connection, profile).await?;
        chain.push(connection);
    }

    verify_binary(chain.last().ok_or("missing mixed Jump target")?).await?;
    for (position, connection) in chain.iter().enumerate().take(depth) {
        cancel_pending_handshake(connection).await?;
        verify_session(connection, &profiles[(start + position) % profiles.len()]).await?;
        verify_session(
            chain.last().ok_or("missing mixed Jump target")?,
            &profiles[(start + depth) % profiles.len()],
        )
        .await?;
    }
    while let Some(connection) = chain.pop() {
        timeout(DEADLINE, connection.disconnect()).await??;
        drop(connection);
        if let Some(parent) = chain.last() {
            let position = chain.len() - 1;
            verify_session(parent, &profiles[(start + position) % profiles.len()]).await?;
        }
    }
    Ok(())
}

async fn refused_open(parent: &ClientConnection) -> Result<()> {
    let config = ClientConfig::new(
        "scoplen-jump-closed.invalid",
        CLOSED_PORT,
        |_host: &str, _key: &HostKey| {
            Err(HostKeyVerificationError::Rejected("closed target presented a key".into()))
        },
    )?;
    let error = timeout(
        DEADLINE,
        Box::pin(ClientConnection::connect_via_direct_tcpip(config, parent, "127.0.0.1", 0)),
    )
    .await?
    .expect_err("mixed Jump reached a closed remote target");
    if !matches!(error, ClientError::ChannelOpen { .. }) {
        return Err(format!("closed mixed Jump target produced {error}").into());
    }
    Ok(())
}

async fn cancel_pending_handshake(parent: &ClientConnection) -> Result<()> {
    let config = ClientConfig::new(
        "scoplen-jump-stall.invalid",
        STALLED_PORT,
        |_host: &str, _key: &HostKey| {
            Err(HostKeyVerificationError::Rejected("stalled target completed key exchange".into()))
        },
    )?;
    if timeout(
        Duration::from_secs(1),
        Box::pin(ClientConnection::connect_via_direct_tcpip(config, parent, "127.0.0.1", 0)),
    )
    .await
    .is_ok()
    {
        return Err("mixed Jump stalled handshake did not remain pending".into());
    }
    Ok(())
}

async fn verify_session(connection: &ClientConnection, profile: &Profile) -> Result<()> {
    let command = format!("printf 'SCOPLEN-MIXED-HOP-{}\\n'; id -un", profile.index);
    let expected = format!("SCOPLEN-MIXED-HOP-{}\n{}\n", profile.index, profile.username);
    timeout(DEADLINE, command_output(connection, command.as_bytes(), &[], expected.as_bytes()))
        .await??;
    Ok(())
}

async fn verify_binary(connection: &ClientConnection) -> Result<()> {
    let payload: Vec<u8> = (0_u8..=255).cycle().take(131_087).collect();
    let mut expected = payload.clone();
    expected.extend_from_slice(TRAILER);
    timeout(
        DEADLINE,
        command_output(
            connection,
            b"cat; printf '\\000scoplen-mixed-jump-eof\\377'",
            &payload,
            &expected,
        ),
    )
    .await??;
    Ok(())
}

async fn command_output(
    connection: &ClientConnection,
    command: &[u8],
    input: &[u8],
    expected: &[u8],
) -> Result<()> {
    let mut channel = connection.open_session().await?;
    channel.exec(true, command).await?;
    channel.send_data(input).await?;
    channel.send_eof().await?;
    let mut received = Vec::new();
    let mut exited = false;
    loop {
        match channel.next_event().await? {
            Some(ChannelEvent::Data(data)) if received.len() + data.len() <= expected.len() => {
                received.extend_from_slice(&data);
            }
            Some(ChannelEvent::ExitStatus(0)) => exited = true,
            Some(ChannelEvent::Success | ChannelEvent::Eof) => {}
            Some(ChannelEvent::Close) | None => break,
            _ => return Err("mixed Jump command returned unexpected output or status".into()),
        }
    }
    if !exited || received != expected {
        return Err("mixed Jump command bytes or exit status differed".into());
    }
    Ok(())
}
