// SPDX-License-Identifier: Apache-2.0
//! Public client forwarding checks against the disposable OpenSSH fixture.

use std::{env, time::Duration};

use scoplen_ssh::{
    ChannelEvent, ClientChannel, ClientConfig, ClientConnection, ClientError, ForwardedChannelKind,
    HostKey, HostKeyVerificationError,
};
use ssh_key::PublicKey;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    time::timeout,
};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
const STEP: Duration = Duration::from_secs(10);
const ECHO_SOCKET: &str = "/tmp/scoplen-forward-fixture/echo.sock";
const REMOTE_SOCKET: &str = "/tmp/scoplen-forward-fixture/remote.sock";
const PAYLOAD: &[u8] = b"scoplen-forward\0\xff\x80\r\n";
const EXPECTED_HEX: &[u8] = b"73636f706c656e2d666f727761726400ff800d0a";

#[tokio::main]
async fn main() -> Result<()> {
    timeout(Duration::from_secs(90), verify()).await??;
    println!("openssh remote forwarding interop ok");
    Ok(())
}

async fn connect(port: u16) -> Result<ClientConnection> {
    let host_key = PublicKey::from_openssh(&env::var("SCOPLEN_FORWARD_HOST_KEY")?)?.to_bytes()?;
    let config = ClientConfig::new("127.0.0.1", port, move |_: &str, key: &HostKey| match key {
        HostKey::Raw { key_blob, .. } if key_blob == &host_key => Ok(()),
        _ => Err(HostKeyVerificationError::Rejected("unexpected fixture host key".into())),
    })?
    .with_channel_limit(4)?;
    let mut connection = timeout(STEP, ClientConnection::connect(config)).await??;
    timeout(STEP, connection.authenticate_password("scoplen", b"fixture-forward-password"))
        .await??;
    Ok(connection)
}

async fn verify() -> Result<()> {
    let port = env::var("SCOPLEN_FORWARD_PORT")?.parse()?;
    let denied_port = env::var("SCOPLEN_FORWARD_DENIED_PORT")?.parse()?;
    let mut connection = connect(port).await?;

    let direct = timeout(STEP, connection.open_direct_streamlocal(ECHO_SOCKET)).await??;
    let mut stream = direct.into_stream();
    timeout(STEP, stream.write_all(PAYLOAD)).await??;
    timeout(STEP, stream.shutdown()).await??;
    let mut echoed = Vec::new();
    timeout(STEP, (&mut stream).take(256).read_to_end(&mut echoed)).await??;
    if echoed != PAYLOAD {
        return Err("direct streamlocal changed binary bytes".into());
    }
    drop(stream);
    if !matches!(
        timeout(
            STEP,
            connection.open_direct_streamlocal("/tmp/scoplen-forward-fixture/missing.sock")
        )
        .await?,
        Err(ClientError::ChannelOpen { .. })
    ) {
        return Err("missing Unix socket did not reject the channel open".into());
    }

    let allocated = timeout(STEP, connection.request_tcpip_forward("127.0.0.1", 0)).await??;
    if allocated == 0 || allocated > u32::from(u16::MAX) {
        return Err("OpenSSH did not allocate a valid remote TCP port".into());
    }
    let tcp_target = format!("(\"127.0.0.1\", {allocated})");
    verify_remote(&mut connection, "AF_INET", &tcp_target, Some(allocated)).await?;
    timeout(STEP, connection.cancel_tcpip_forward("127.0.0.1", allocated)).await??;
    verify_cancelled(&connection, "AF_INET", &tcp_target).await?;

    timeout(STEP, connection.request_streamlocal_forward(REMOTE_SOCKET)).await??;
    let unix_target = format!("\"{REMOTE_SOCKET}\"");
    verify_remote(&mut connection, "AF_UNIX", &unix_target, None).await?;
    timeout(STEP, connection.cancel_streamlocal_forward(REMOTE_SOCKET)).await??;
    verify_cancelled(&connection, "AF_UNIX", &unix_target).await?;
    timeout(STEP, connection.request_streamlocal_forward(REMOTE_SOCKET)).await??;
    verify_remote(&mut connection, "AF_UNIX", &unix_target, None).await?;
    timeout(STEP, connection.cancel_streamlocal_forward(REMOTE_SOCKET)).await??;
    verify_session(&connection).await?;
    timeout(STEP, connection.disconnect()).await??;

    let denied = connect(denied_port).await?;
    if !matches!(
        timeout(STEP, denied.request_tcpip_forward("127.0.0.1", 0)).await?,
        Err(ClientError::Channel)
    ) {
        return Err("disabled remote TCP forwarding was not refused".into());
    }
    if !matches!(
        timeout(STEP, denied.request_streamlocal_forward(REMOTE_SOCKET)).await?,
        Err(ClientError::Channel)
    ) {
        return Err("disabled remote Unix forwarding was not refused".into());
    }
    if !matches!(
        timeout(STEP, denied.open_direct_streamlocal(ECHO_SOCKET)).await?,
        Err(ClientError::ChannelOpen { .. })
    ) {
        return Err("disabled direct Unix forwarding was not refused".into());
    }
    verify_session(&denied).await?;
    timeout(STEP, denied.disconnect()).await??;
    Ok(())
}

async fn command(connection: &ClientConnection, source: &str) -> Result<ClientChannel> {
    let channel = timeout(STEP, connection.open_session()).await??;
    timeout(STEP, channel.exec(true, source.as_bytes())).await??;
    Ok(channel)
}

async fn command_output(mut channel: ClientChannel, expected: &[u8]) -> Result<()> {
    let mut output = Vec::new();
    let mut exited = false;
    loop {
        match timeout(STEP, channel.next_event()).await?? {
            Some(ChannelEvent::Data(bytes)) => {
                if output.len() + bytes.len() > 256 {
                    return Err("unexpected command output size".into());
                }
                output.extend(bytes);
            }
            Some(ChannelEvent::ExitStatus(0)) => exited = true,
            Some(ChannelEvent::Eof | ChannelEvent::Success) => {}
            Some(ChannelEvent::Close) | None => break,
            Some(other) => return Err(format!("unexpected remote command event: {other:?}").into()),
        }
    }
    if !exited || output != expected {
        return Err("remote command bytes or exit status mismatched".into());
    }
    Ok(())
}

async fn verify_remote(
    connection: &mut ClientConnection,
    family: &str,
    target: &str,
    port: Option<u32>,
) -> Result<()> {
    let source = format!(
        "python3 -c 'import socket,sys; s=socket.socket(socket.{family}); s.settimeout(5); s.connect({target}); s.sendall(bytes.fromhex(\"{}\")); s.shutdown(socket.SHUT_WR); b=s.makefile(\"rb\").read(256); sys.stdout.write(b.hex())'",
        std::str::from_utf8(EXPECTED_HEX)?
    );
    let request = command(connection, &source).await?;
    let forwarded = timeout(STEP, connection.next_forwarded_channel())
        .await?
        .ok_or("SSH connection closed before forwarded channel")?;
    match (forwarded.kind(), port) {
        (
            ForwardedChannelKind::Tcp {
                connected_address,
                connected_port,
                originator_address,
                originator_port,
            },
            Some(port),
        ) if connected_address == "127.0.0.1"
            && *connected_port == port
            && originator_address == "127.0.0.1"
            && (1..=65535).contains(originator_port) => {}
        (ForwardedChannelKind::Streamlocal { socket_path }, None)
            if socket_path == REMOTE_SOCKET => {}
        _ => return Err("forwarded channel metadata mismatched".into()),
    }
    let mut stream = forwarded.into_channel().into_stream();
    let mut received = Vec::new();
    timeout(STEP, (&mut stream).take(256).read_to_end(&mut received)).await??;
    if received != PAYLOAD {
        return Err("forwarded channel changed binary bytes".into());
    }
    timeout(STEP, stream.write_all(&received)).await??;
    timeout(STEP, stream.shutdown()).await??;
    command_output(request, EXPECTED_HEX).await
}

async fn verify_cancelled(connection: &ClientConnection, family: &str, target: &str) -> Result<()> {
    let source = format!(
        "python3 -c 'import socket,sys; s=socket.socket(socket.{family}); s.settimeout(5)\ntry: s.connect({target})\nexcept (ConnectionRefusedError,FileNotFoundError): sys.stdout.write(\"refused\")\nelse: sys.exit(1)'"
    );
    command_output(command(connection, &source).await?, b"refused").await
}

async fn verify_session(connection: &ClientConnection) -> Result<()> {
    command_output(command(connection, "printf connection-reusable").await?, b"connection-reusable")
        .await
}
