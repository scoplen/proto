use std::{
    env,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use scoplen_crypto::Ed25519SigningKey;
use scoplen_ssh::{
    ChannelEvent, ClientConfig, ClientConnection, ClientError, Ed25519SshSigner, HostKey,
    HostKeyVerificationError, RsaSshSigner, SftpAttributes, SftpPacket, SftpSession,
    SignatureAlgorithm,
};
use ssh_key::{PrivateKey, PublicKey};
use tokio::time::timeout;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let host = env::var("SCOPLEN_OPENSSH_HOST").unwrap_or_else(|_| "127.0.0.1".to_owned());
    let port =
        env::var("SCOPLEN_OPENSSH_PORT").unwrap_or_else(|_| "22223".to_owned()).parse::<u16>()?;
    let username = env::var("SCOPLEN_OPENSSH_USER").unwrap_or_else(|_| "scoplen".to_owned());
    let expected_key = env::var("SCOPLEN_OPENSSH_HOST_KEY")
        .map_err(|_| "SCOPLEN_OPENSSH_HOST_KEY must be set to the server's public key")?;
    let expected_key = PublicKey::from_openssh(&expected_key)?.to_bytes()?;
    let verifier = move |_host: &str, key: &HostKey| match key {
        HostKey::Raw { key_blob, .. } if key_blob == &expected_key => Ok(()),
        _ => Err(HostKeyVerificationError::Rejected("unexpected server key".to_owned())),
    };
    let config = ClientConfig::new(host, port, verifier)?;
    let mut connection = ClientConnection::connect(config).await?;
    let rsa_key = env::var("SCOPLEN_OPENSSH_RSA_KEY").ok();
    let ed25519_key = env::var("SCOPLEN_OPENSSH_ED25519_KEY").ok();
    if rsa_key.is_some() && ed25519_key.is_some() {
        return Err("set only one OpenSSH private-key path".into());
    }
    if let Some(path) = rsa_key {
        let key = PrivateKey::read_openssh_file(path)?;
        let algorithm = match env::var("SCOPLEN_OPENSSH_RSA_HASH").as_deref() {
            Ok("256") => SignatureAlgorithm::RsaSha2_256,
            Ok("512") | Err(_) => SignatureAlgorithm::RsaSha2_512,
            _ => return Err("SCOPLEN_OPENSSH_RSA_HASH must be 256 or 512".into()),
        };
        let signer = RsaSshSigner::new(key, algorithm)?;
        connection.authenticate_publickey(&username, &signer).await?;
    } else if let Some(path) = ed25519_key {
        let key = PrivateKey::read_openssh_file(path)?;
        let keypair = key.key_data().ed25519().ok_or("expected an Ed25519 private key")?;
        let signer =
            Ed25519SshSigner::new(Ed25519SigningKey::from_bytes(keypair.private.as_ref())?);
        connection.authenticate_publickey(&username, &signer).await?;
    } else {
        let password = env::var("SCOPLEN_OPENSSH_PASSWORD")
            .map_err(|_| "password or an OpenSSH private-key path is required")?;
        connection.authenticate_password(&username, password.as_bytes()).await?;
    }
    let channel = connection.open_session().await?;
    channel.exec(true, b"printf scoplen-openssh-ok").await?;
    let mut channel = channel;
    let mut output = Vec::new();
    loop {
        let event = timeout(Duration::from_secs(5), channel.next_event()).await??;
        match event {
            Some(ChannelEvent::Data(data)) => output.extend_from_slice(&data),
            Some(ChannelEvent::Eof | ChannelEvent::Close) | None => break,
            Some(ChannelEvent::Success | ChannelEvent::ExitStatus(0)) => {}
            Some(ChannelEvent::ExitStatus(status)) => {
                return Err(format!("remote command exited with {status}").into());
            }
            Some(other) => return Err(format!("unexpected SSH event: {other:?}").into()),
        }
    }
    if output != b"scoplen-openssh-ok" {
        return Err(format!("unexpected output: {output:?}").into());
    }
    if env::var("SCOPLEN_OPENSSH_SFTP").as_deref() == Ok("1") {
        timeout(Duration::from_secs(30), verify_sftp(&connection)).await??;
    }
    if env::var("SCOPLEN_OPENSSH_FORWARD").as_deref() == Ok("1") {
        timeout(Duration::from_secs(10), verify_forwarding(&connection)).await??;
    }
    connection.disconnect().await?;
    println!("openssh interop ok");
    Ok(())
}

async fn verify_forwarding(
    connection: &ClientConnection,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut channel = connection.open_direct_tcpip("127.0.0.1", 2222, "127.0.0.1", 0).await?;
    let mut banner = Vec::new();
    while !banner.contains(&b'\n') && banner.len() < 256 {
        match channel.next_event().await? {
            Some(ChannelEvent::Data(data)) => {
                if banner.len().saturating_add(data.len()) > 256 {
                    return Err("forwarded OpenSSH banner exceeded 256 bytes".into());
                }
                banner.extend_from_slice(&data);
            }
            other => return Err(format!("unexpected forwarding event: {other:?}").into()),
        }
    }
    if !banner.starts_with(b"SSH-2.0-OpenSSH_") || !banner.contains(&b'\n') {
        return Err("forwarded OpenSSH banner was missing or invalid".into());
    }
    channel.close().await?;
    drop(channel);

    match connection.open_direct_tcpip("127.0.0.1", 1, "127.0.0.1", 0).await {
        Err(ClientError::ChannelOpen { .. }) => {}
        Ok(_) => return Err("forwarding to a closed port unexpectedly succeeded".into()),
        Err(error) => return Err(format!("unexpected forwarding failure: {error}").into()),
    }
    let channel = connection.open_session().await?;
    channel.close().await?;
    println!("openssh forwarding interop ok");
    Ok(())
}

async fn sftp_response(
    session: &mut SftpSession,
    request: SftpPacket,
) -> Result<SftpPacket, Box<dyn std::error::Error>> {
    session.send_request(&request).await?;
    Ok(session.read_response().await?)
}

async fn verify_sftp(connection: &ClientConnection) -> Result<(), Box<dyn std::error::Error>> {
    let mut session = SftpSession::open(connection, 4).await?;
    if session.limits().is_none() {
        return Err("OpenSSH did not advertise SFTP transfer limits".into());
    }
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let path = format!(".scoplen-interop-{}-{nonce}", std::process::id()).into_bytes();
    let missing_path = [path.as_slice(), b"-missing"].concat();
    let missing = session.client_mut().open(missing_path, 1, SftpAttributes::default())?;
    if !matches!(sftp_response(&mut session, missing).await?, SftpPacket::Status { code: 2, .. })
        || session.pending_requests() != 0
    {
        return Err("missing SFTP file was not rejected cleanly".into());
    }

    let create = session.client_mut().open(path.clone(), 0x1a, SftpAttributes::default())?;
    let write_handle = match sftp_response(&mut session, create).await? {
        SftpPacket::Handle { handle, .. } => handle,
        other => return Err(format!("unexpected SFTP create response: {other:?}").into()),
    };
    let data: Vec<u8> = b"scoplen-sftp-v3".iter().copied().cycle().take(100_000).collect();
    let mut upload_progress = Vec::new();
    let first = session
        .upload(&write_handle, 0, &data[..40_000], 4096, 4, |event| {
            upload_progress.push(event);
        })
        .await?;
    let second = session
        .upload(&write_handle, first, &data[40_000..], 4096, 4, |event| {
            upload_progress.push(event);
        })
        .await?;
    if first != 40_000
        || second != 60_000
        || upload_progress.last().is_none_or(|event| {
            event.offset != data.len() as u64
                || event.transferred != second
                || event.total != Some(data.len() as u64)
        })
        || session.pending_requests() != 0
    {
        return Err("SFTP upload or progress mismatch".into());
    }
    let close = session.client_mut().close(write_handle)?;
    if !matches!(sftp_response(&mut session, close).await?, SftpPacket::Status { code: 0, .. }) {
        return Err("SFTP write handle close failed".into());
    }

    let read = session.client_mut().open(path.clone(), 1, SftpAttributes::default())?;
    let read_handle = match sftp_response(&mut session, read).await? {
        SftpPacket::Handle { handle, .. } => handle,
        other => return Err(format!("unexpected SFTP read response: {other:?}").into()),
    };
    let mut downloaded = Vec::new();
    let mut download_progress = Vec::new();
    let count = session
        .download_to(
            &read_handle,
            1000,
            Some(data.len() as u64),
            4096,
            4,
            &mut downloaded,
            |event| download_progress.push(event),
        )
        .await?;
    if count != (data.len() - 1000) as u64
        || downloaded != data[1000..]
        || download_progress.last().is_none_or(|event| {
            event.offset != data.len() as u64
                || event.transferred != count
                || event.total != Some(data.len() as u64)
        })
        || session.pending_requests() != 0
    {
        return Err("SFTP resumed download or progress mismatch".into());
    }
    let close = session.client_mut().close(read_handle)?;
    if !matches!(sftp_response(&mut session, close).await?, SftpPacket::Status { code: 0, .. }) {
        return Err("SFTP read handle close failed".into());
    }
    let remove = session.client_mut().remove(path)?;
    if !matches!(sftp_response(&mut session, remove).await?, SftpPacket::Status { code: 0, .. })
        || session.pending_requests() != 0
    {
        return Err("SFTP cleanup or request release failed".into());
    }
    println!("openssh sftp interop ok");
    Ok(())
}
