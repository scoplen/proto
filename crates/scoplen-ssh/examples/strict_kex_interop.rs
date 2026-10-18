// SPDX-License-Identifier: Apache-2.0
//! Exercise concrete strict KEX packet admission against disposable OpenSSH.

use std::{
    borrow::Cow,
    env,
    error::Error,
    io::{self, ErrorKind},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use russh::{kex, server};
use scoplen_ssh::{
    ChannelEvent, ClientConfig, ClientConnection, ClientError, HostKey, HostKeyVerificationError,
};
use ssh_key::{Algorithm, PrivateKey, PublicKey};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt, copy},
    net::{TcpListener, TcpStream},
    time::timeout,
};

const DEADLINE: Duration = Duration::from_secs(10);
const IGNORE_PACKET: [u8; 16] = [0, 0, 0, 12, 6, 2, 0, 0, 0, 0, 0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6];
const STRICT_SERVER_MARKER: &[u8] = b"kex-strict-s-v00@openssh.com";
const COMMAND_OUTPUT: &[u8] = b"scoplen-strict-kex-ok";

#[derive(Clone, Copy, Debug)]
enum InjectionPoint {
    BeforeKexInit,
    AfterKexInit,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let openssh_port = env::var("SCOPLEN_ALGORITHM_MODERN_PORT")?.parse::<u16>()?;
    let expected_key =
        PublicKey::from_openssh(&env::var("SCOPLEN_ALGORITHM_HOST_KEY")?)?.to_bytes()?;
    let username = env::var("SCOPLEN_ALGORITHM_USER")?;
    let password = env::var("SCOPLEN_ALGORITHM_PASSWORD")?;

    let (control_config, control_checks) =
        pinned_config("strict-control.example.test", openssh_port, &expected_key)?;
    let control_stream =
        timeout(DEADLINE, TcpStream::connect(("127.0.0.1", openssh_port))).await??;
    let connection =
        timeout(DEADLINE, ClientConnection::connect_stream(control_config, control_stream))
            .await??;
    verify_command(connection, &username, &password).await?;
    require_checks(&control_checks, 1, "OpenSSH control")?;

    for point in [InjectionPoint::BeforeKexInit, InjectionPoint::AfterKexInit] {
        let (strict_config, strict_checks) =
            pinned_config("strict-injected.example.test", openssh_port, &expected_key)?;
        let result = connect_with_ignore(strict_config, openssh_port, true, point).await?;
        if !matches!(result, Err(ClientError::Protocol)) {
            return Err(format!(
                "strict OpenSSH connection did not reject IGNORE at {point:?}: {result:?}"
            )
            .into());
        }
        require_checks(&strict_checks, 0, "strict OpenSSH rejection")?;
    }

    let server_key = PrivateKey::random(
        &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
        Algorithm::Ed25519,
    )?;
    let no_strict_key = server_key.public_key().to_bytes()?;
    let mut server_config = server::Config::default();
    server_config.keys.push(server_key);
    server_config.preferred.kex = Cow::Borrowed(&[kex::CURVE25519]);
    let server_config = Arc::new(server_config);
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let no_strict_port = listener.local_addr()?.port();
    let server_task = tokio::spawn(async move {
        let mut sessions = Vec::new();
        for _ in 0..2 {
            let (stream, _) = listener.accept().await?;
            let session = server::run_stream(Arc::clone(&server_config), stream, NoStrictServer)
                .await
                .map_err(io::Error::other)?;
            sessions.push(session);
        }
        for session in sessions {
            let _ = session.await;
        }
        Ok::<(), io::Error>(())
    });

    for point in [InjectionPoint::BeforeKexInit, InjectionPoint::AfterKexInit] {
        let (no_strict_config, no_strict_checks) =
            pinned_config("no-strict.example.test", no_strict_port, &no_strict_key)?;
        connect_with_ignore(no_strict_config, no_strict_port, false, point).await??;
        require_checks(&no_strict_checks, 1, "non-strict control")?;
    }
    timeout(DEADLINE, server_task).await???;

    println!(
        "OpenSSH strict KEX accepted the control, rejected IGNORE before and after KEXINIT, and non-strict KEX accepted both packets"
    );
    Ok(())
}

struct NoStrictServer;

impl server::Handler for NoStrictServer {
    type Error = russh::Error;
}

fn pinned_config(
    host: &str,
    port: u16,
    expected_key: &[u8],
) -> Result<(ClientConfig, Arc<AtomicUsize>), Box<dyn Error>> {
    let expected_key = expected_key.to_vec();
    let checks = Arc::new(AtomicUsize::new(0));
    let callback_checks = Arc::clone(&checks);
    let verifier = move |_host: &str, key: &HostKey| match key {
        HostKey::Raw { key_blob, .. } if key_blob.as_slice() == expected_key.as_slice() => {
            callback_checks.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
        _ => Err(HostKeyVerificationError::Rejected("unexpected server key".to_owned())),
    };
    Ok((ClientConfig::new(host, port, verifier)?, checks))
}

async fn connect_with_ignore(
    config: ClientConfig,
    upstream_port: u16,
    server_advertises_strict: bool,
    point: InjectionPoint,
) -> Result<Result<(), ClientError>, Box<dyn Error>> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let relay_port = listener.local_addr()?.port();
    let stream = timeout(DEADLINE, TcpStream::connect(("127.0.0.1", relay_port))).await??;
    let mut relay = tokio::spawn(async move {
        relay_ignore_at_kexinit(listener, upstream_port, server_advertises_strict, point).await
    });
    let connection = match timeout(DEADLINE, ClientConnection::connect_stream(config, stream)).await
    {
        Ok(connection) => connection,
        Err(error) => {
            relay.abort();
            let _ = relay.await;
            return Err(error.into());
        }
    };
    let outcome = match connection {
        Ok(connection) => match timeout(DEADLINE, connection.disconnect()).await {
            Ok(outcome) => outcome,
            Err(error) => {
                relay.abort();
                let _ = relay.await;
                return Err(error.into());
            }
        },
        Err(error) => Err(error),
    };
    match timeout(DEADLINE, &mut relay).await {
        Ok(result) => result??,
        Err(error) => {
            relay.abort();
            let _ = relay.await;
            return Err(error.into());
        }
    }
    Ok(outcome)
}

async fn relay_ignore_at_kexinit(
    listener: TcpListener,
    upstream_port: u16,
    server_advertises_strict: bool,
    point: InjectionPoint,
) -> io::Result<()> {
    let (client, _) = listener.accept().await?;
    let server = TcpStream::connect(("127.0.0.1", upstream_port)).await?;
    let (mut client_reader, mut client_writer) = client.into_split();
    let (mut server_reader, mut server_writer) = server.into_split();
    let client_to_server = async {
        peer_close(copy(&mut client_reader, &mut server_writer).await)?;
        peer_close(server_writer.shutdown().await)
    };
    let server_to_client = async {
        let banner = read_banner(&mut server_reader).await?;
        client_writer.write_all(&banner).await?;
        let packet = read_first_kexinit(&mut server_reader, server_advertises_strict).await?;
        if matches!(point, InjectionPoint::BeforeKexInit) {
            client_writer.write_all(&IGNORE_PACKET).await?;
        }
        client_writer.write_all(&packet).await?;
        if matches!(point, InjectionPoint::AfterKexInit) {
            client_writer.write_all(&IGNORE_PACKET).await?;
        }
        peer_close(copy(&mut server_reader, &mut client_writer).await)
    };
    tokio::pin!(client_to_server, server_to_client);
    tokio::select! {
        result = &mut server_to_client => result,
        result = &mut client_to_server => {
            result?;
            server_to_client.await
        }
    }
}

fn peer_close<T>(result: io::Result<T>) -> io::Result<()> {
    match result {
        Ok(_) => Ok(()),
        Err(error)
            if matches!(
                error.kind(),
                ErrorKind::UnexpectedEof | ErrorKind::ConnectionReset | ErrorKind::BrokenPipe
            ) =>
        {
            Ok(())
        }
        Err(error) => Err(error),
    }
}

async fn read_banner<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<Vec<u8>> {
    let mut banner = Vec::new();
    loop {
        if banner.len() == 255 {
            return Err(io::Error::new(ErrorKind::InvalidData, "SSH banner is too long"));
        }
        let mut byte = [0];
        reader.read_exact(&mut byte).await?;
        banner.push(byte[0]);
        if byte[0] == b'\n' {
            break;
        }
    }
    if !banner.starts_with(b"SSH-2.0-") {
        return Err(io::Error::new(ErrorKind::InvalidData, "missing SSH server banner"));
    }
    Ok(banner)
}

async fn read_first_kexinit<R: AsyncRead + Unpin>(
    reader: &mut R,
    server_advertises_strict: bool,
) -> io::Result<Vec<u8>> {
    let mut length = [0; 4];
    reader.read_exact(&mut length).await?;
    let packet_length = u32::from_be_bytes(length) as usize;
    if !(6..=35_000).contains(&packet_length) {
        return Err(io::Error::new(ErrorKind::InvalidData, "invalid SSH KEXINIT length"));
    }
    let mut packet = vec![0; packet_length + 4];
    packet[..4].copy_from_slice(&length);
    reader.read_exact(&mut packet[4..]).await?;
    let padding_length = usize::from(packet[4]);
    if packet_length < padding_length + 2 || packet[5] != 20 {
        return Err(io::Error::new(ErrorKind::InvalidData, "first SSH packet is not KEXINIT"));
    }
    let payload_end = packet.len() - padding_length;
    let marker_present = kexinit_offers_strict(&packet[5..payload_end])?;
    if marker_present != server_advertises_strict {
        return Err(io::Error::new(ErrorKind::InvalidData, "unexpected server strict KEX offer"));
    }
    Ok(packet)
}

fn kexinit_offers_strict(payload: &[u8]) -> io::Result<bool> {
    let names_length = payload
        .get(17..21)
        .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
        .map(u32::from_be_bytes)
        .ok_or_else(|| io::Error::new(ErrorKind::InvalidData, "missing KEX algorithm length"))?;
    let names_end = 21usize
        .checked_add(names_length as usize)
        .ok_or_else(|| io::Error::new(ErrorKind::InvalidData, "invalid KEX algorithm length"))?;
    let names = payload
        .get(21..names_end)
        .ok_or_else(|| io::Error::new(ErrorKind::InvalidData, "truncated KEX algorithms"))?;
    Ok(names.split(|byte| *byte == b',').any(|name| name == STRICT_SERVER_MARKER))
}

fn require_checks(
    checks: &AtomicUsize,
    expected: usize,
    scenario: &str,
) -> Result<(), Box<dyn Error>> {
    if checks.load(Ordering::SeqCst) != expected {
        return Err(format!("{scenario}: unexpected host-key callback count").into());
    }
    Ok(())
}

async fn verify_command(
    mut connection: ClientConnection,
    username: &str,
    password: &str,
) -> Result<(), Box<dyn Error>> {
    timeout(DEADLINE, connection.authenticate_password(username, password.as_bytes())).await??;
    let mut channel = timeout(DEADLINE, connection.open_session()).await??;
    timeout(DEADLINE, channel.exec(true, b"printf scoplen-strict-kex-ok")).await??;
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
        Ok::<_, Box<dyn Error>>((output, exit_status))
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

#[cfg(test)]
mod tests {
    use super::{STRICT_SERVER_MARKER, kexinit_offers_strict};

    fn kexinit_payload(names: &[u8], extra: &[u8]) -> Vec<u8> {
        let mut payload = vec![20];
        payload.extend_from_slice(&[0; 16]);
        payload.extend_from_slice(&(names.len() as u32).to_be_bytes());
        payload.extend_from_slice(names);
        payload.extend_from_slice(extra);
        payload
    }

    #[test]
    fn strict_marker_must_be_a_complete_kex_algorithm_name() {
        let mut names = b"curve25519-sha256,".to_vec();
        names.extend_from_slice(STRICT_SERVER_MARKER);
        assert!(kexinit_offers_strict(&kexinit_payload(&names, &[])).unwrap());
        assert!(
            !kexinit_offers_strict(&kexinit_payload(b"curve25519-sha256", STRICT_SERVER_MARKER,))
                .unwrap()
        );
        names.push(b'x');
        assert!(!kexinit_offers_strict(&kexinit_payload(&names, &[])).unwrap());
    }

    #[test]
    fn truncated_kex_algorithm_list_is_rejected() {
        let mut payload = kexinit_payload(b"curve25519-sha256", &[]);
        payload[17..21].copy_from_slice(&100u32.to_be_bytes());
        assert!(kexinit_offers_strict(&payload).is_err());
    }
}
