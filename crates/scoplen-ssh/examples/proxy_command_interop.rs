// SPDX-License-Identifier: Apache-2.0
//! Run with a disposable OpenSSH server, `SCOPLEN_OPENSSH_HOST_KEY` set to its public-key line,
//! and `SCOPLEN_OPENSSH_PASSWORD` set to the test account's password. Optional host, port, and
//! username variables have the same names as the direct OpenSSH interoperability example.

use std::{
    env,
    ffi::OsString,
    fs,
    io::{self, Read, Write},
    net::{Shutdown, TcpListener, TcpStream},
    path::Path,
    process,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use scoplen_ssh::{
    ChannelEvent, ClientConfig, ClientConnection, ClientError, HostKey, HostKeyVerificationError,
    ProxyCommandError,
};
use ssh_key::PublicKey;
use tokio::time::{sleep, timeout};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args_os();
    let _program = args.next();
    match args.next().as_deref() {
        Some(mode) if mode == "--relay" => {
            let host = args.next().ok_or("relay host is missing")?;
            let port = args.next().ok_or("relay port is missing")?;
            return relay(&host.to_string_lossy(), port.to_string_lossy().parse()?);
        }
        Some(mode) if mode == "--stall" => {
            let marker = args.next().ok_or("stall marker is missing")?;
            return stall(Path::new(&marker));
        }
        Some(mode) if mode == "--fail" => return Err("relay failed before connecting".into()),
        Some(_) => return Err("unknown proxy mode".into()),
        None => {}
    }

    let host = env::var("SCOPLEN_OPENSSH_HOST").unwrap_or_else(|_| "127.0.0.1".to_owned());
    let port =
        env::var("SCOPLEN_OPENSSH_PORT").unwrap_or_else(|_| "22223".to_owned()).parse::<u16>()?;
    let username = env::var("SCOPLEN_OPENSSH_USER").unwrap_or_else(|_| "scoplen".to_owned());
    let password = env::var("SCOPLEN_OPENSSH_PASSWORD")?;
    let expected_key =
        PublicKey::from_openssh(&env::var("SCOPLEN_OPENSSH_HOST_KEY")?)?.to_bytes()?;
    let program = env::current_exe()?;
    let relay_args =
        [OsString::from("--relay"), OsString::from(&host), OsString::from(port.to_string())];

    let config = pinned_config(&host, port, expected_key)?;
    let mut connection = timeout(
        Duration::from_secs(10),
        ClientConnection::connect_via_proxy_command(
            config,
            &program,
            &relay_args,
            HANDSHAKE_TIMEOUT,
        ),
    )
    .await
    .map_err(|_| "initial ProxyCommand route exceeded its outer deadline")??;
    timeout(
        Duration::from_secs(10),
        connection.authenticate_password(&username, password.as_bytes()),
    )
    .await
    .map_err(|_| "ProxyCommand authentication timed out")??;
    timeout(Duration::from_secs(10), verify_session(&connection))
        .await
        .map_err(|_| "ProxyCommand session timed out")??;
    timeout(Duration::from_secs(10), connection.disconnect())
        .await
        .map_err(|_| "ProxyCommand disconnect timed out")??;
    drop(connection);

    verify_failures(&host, port, &program, &relay_args).await?;
    println!("openssh ProxyCommand interop ok");
    Ok(())
}

async fn verify_failures(
    host: &str,
    port: u16,
    program: &Path,
    relay_args: &[OsString],
) -> Result<(), Box<dyn std::error::Error>> {
    let wrong_pin = pinned_config(host, port, Vec::new())?;
    let error = timeout(
        Duration::from_secs(10),
        ClientConnection::connect_via_proxy_command(
            wrong_pin,
            program,
            relay_args,
            HANDSHAKE_TIMEOUT,
        ),
    )
    .await
    .map_err(|_| "wrong-pin ProxyCommand route timed out")?
    .expect_err("an untrusted host key was accepted");
    if !matches!(error, ClientError::HostKey(HostKeyVerificationError::Rejected(_))) {
        return Err(format!("wrong host key produced {error}").into());
    }

    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let missing_program =
        env::temp_dir().join(format!("scoplen-no-proxy-{}-{nonce}", process::id()));
    let error = ClientConnection::connect_via_proxy_command(
        pinned_config(host, port, Vec::new())?,
        missing_program,
        &[],
        HANDSHAKE_TIMEOUT,
    )
    .await
    .expect_err("a missing ProxyCommand executable was accepted");
    if !matches!(error, ClientError::ProxyCommand(ProxyCommandError::Spawn { .. })) {
        return Err(format!("missing ProxyCommand produced {error}").into());
    }

    let error = timeout(
        Duration::from_secs(10),
        ClientConnection::connect_via_proxy_command(
            pinned_config(host, port, Vec::new())?,
            program,
            &[OsString::from("--fail")],
            HANDSHAKE_TIMEOUT,
        ),
    )
    .await
    .map_err(|_| "failed ProxyCommand route timed out")?
    .expect_err("a failed ProxyCommand child unexpectedly connected");
    if !matches!(
        error,
        ClientError::ConnectionClosed | ClientError::Transport(_) | ClientError::Protocol
    ) {
        return Err(format!("failed ProxyCommand produced {error}").into());
    }

    verify_timeout_and_reaping(host, port, program).await?;
    Ok(())
}

fn pinned_config(
    host: &str,
    port: u16,
    expected_key: Vec<u8>,
) -> Result<ClientConfig, ClientError> {
    Ok(ClientConfig::new(host, port, move |_host: &str, key: &HostKey| match key {
        HostKey::Raw { key_blob, .. } if *key_blob == expected_key => Ok(()),
        _ => Err(HostKeyVerificationError::Rejected("unexpected server key".to_owned())),
    })?)
}

async fn verify_session(connection: &ClientConnection) -> Result<(), ClientError> {
    let mut channel = connection.open_session().await?;
    channel.exec(true, b"printf scoplen-proxy-command-ok").await?;
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
    if !exited || output != b"scoplen-proxy-command-ok" {
        return Err(ClientError::Protocol);
    }
    Ok(())
}

async fn verify_timeout_and_reaping(
    host: &str,
    port: u16,
    program: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let marker = env::temp_dir().join(format!("scoplen-proxy-stall-{}-{nonce}", process::id()));
    let result = verify_stalled_child(host, port, program, &marker).await;
    let _ = fs::remove_file(marker);
    result
}

async fn verify_stalled_child(
    host: &str,
    port: u16,
    program: &Path,
    marker: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let stall_args = [OsString::from("--stall"), marker.as_os_str().to_os_string()];
    let handshake_timeout = Duration::from_secs(1);
    let error = timeout(
        Duration::from_secs(10),
        ClientConnection::connect_via_proxy_command(
            pinned_config(host, port, Vec::new())?,
            program,
            &stall_args,
            handshake_timeout,
        ),
    )
    .await
    .map_err(|_| "stalled ProxyCommand route exceeded its outer deadline")?
    .expect_err("stalled ProxyCommand unexpectedly connected");
    if !matches!(error, ClientError::ProxyCommandHandshakeTimeout { timeout } if timeout == handshake_timeout)
    {
        return Err(format!("stalled ProxyCommand produced {error}").into());
    }
    let listener_port = fs::read_to_string(marker)?.parse::<u16>()?;
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match TcpListener::bind(("127.0.0.1", listener_port)) {
            Ok(listener) => {
                drop(listener);
                return Ok(());
            }
            Err(_) if Instant::now() < deadline => {
                sleep(Duration::from_millis(50)).await;
            }
            Err(error) => return Err(format!("stalled child kept its listener: {error}").into()),
        }
    }
}

fn relay(host: &str, port: u16) -> Result<(), Box<dyn std::error::Error>> {
    let mut remote = TcpStream::connect((host, port))?;
    let mut upload = remote.try_clone()?;
    let stdin_to_remote = std::thread::spawn(move || -> io::Result<()> {
        io::copy(&mut io::stdin(), &mut upload)?;
        upload.shutdown(Shutdown::Write)
    });
    let mut stdout = io::stdout();
    let mut buffer = [0u8; 16 * 1024];
    loop {
        let length = remote.read(&mut buffer)?;
        if length == 0 {
            break;
        }
        stdout.write_all(&buffer[..length])?;
        stdout.flush()?;
    }
    stdin_to_remote.join().map_err(|_| "relay input worker panicked")??;
    Ok(())
}

fn stall(marker: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind(("127.0.0.1", 0))?;
    fs::write(marker, listener.local_addr()?.port().to_string())?;
    std::thread::sleep(Duration::from_secs(30));
    drop(listener);
    Ok(())
}
