use std::{
    env,
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use scoplen_crypto::{Ed25519SigningKey, P256SigningKey};
use scoplen_ssh::{
    CertificateValidationPolicy, ChannelEvent, ClientConfig, ClientConnection, ClientError,
    EcdsaSshSigner, Ed25519SshSigner, HostKey, HostKeyVerificationError, P256SshSigner,
    RsaSshSigner, SftpAttributes, SftpPacket, SftpSession, SignatureAlgorithm, Signer,
    UserCertificate,
};
use ssh_key::{Certificate, PrivateKey, PublicKey};
use tokio::time::timeout;

const SSH_STEP_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, thiserror::Error)]
#[error("user certificate CA is not trusted")]
struct UntrustedUserCa;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let host = env::var("SCOPLEN_OPENSSH_HOST").unwrap_or_else(|_| "127.0.0.1".to_owned());
    let port =
        env::var("SCOPLEN_OPENSSH_PORT").unwrap_or_else(|_| "22223".to_owned()).parse::<u16>()?;
    let username = env::var("SCOPLEN_OPENSSH_USER").unwrap_or_else(|_| "scoplen".to_owned());
    let config = client_config(host, port)?;
    let mut connection = timeout(SSH_STEP_TIMEOUT, ClientConnection::connect(config)).await??;
    timeout(SSH_STEP_TIMEOUT, authenticate(&mut connection, &username)).await??;
    let channel = timeout(SSH_STEP_TIMEOUT, connection.open_session()).await??;
    timeout(SSH_STEP_TIMEOUT, channel.exec(true, b"printf scoplen-openssh-ok")).await??;
    let mut channel = channel;
    let mut output = Vec::new();
    let mut exited_successfully = false;
    loop {
        let event = timeout(Duration::from_secs(5), channel.next_event()).await??;
        match event {
            Some(ChannelEvent::Data(data)) => output.extend_from_slice(&data),
            Some(ChannelEvent::Eof | ChannelEvent::Success) => {}
            Some(ChannelEvent::Close) | None => break,
            Some(ChannelEvent::ExitStatus(0)) => exited_successfully = true,
            Some(ChannelEvent::ExitStatus(status)) => {
                return Err(format!("remote command exited with {status}").into());
            }
            Some(other) => return Err(format!("unexpected SSH event: {other:?}").into()),
        }
    }
    if output != b"scoplen-openssh-ok" {
        return Err(format!("unexpected output: {output:?}").into());
    }
    if !exited_successfully {
        return Err("remote command did not report a successful exit status".into());
    }
    if env::var("SCOPLEN_OPENSSH_SFTP").as_deref() == Ok("1") {
        timeout(Duration::from_secs(30), verify_sftp(&connection)).await??;
    }
    if env::var("SCOPLEN_OPENSSH_FORWARD").as_deref() == Ok("1") {
        timeout(Duration::from_secs(10), verify_forwarding(&connection)).await??;
    }
    timeout(SSH_STEP_TIMEOUT, connection.disconnect()).await??;
    println!("openssh interop ok");
    Ok(())
}

fn client_config(host: String, port: u16) -> Result<ClientConfig, Box<dyn std::error::Error>> {
    let expected_key = env::var("SCOPLEN_OPENSSH_HOST_KEY").ok();
    let host_ca = env::var("SCOPLEN_OPENSSH_HOST_CA_KEY").ok();
    if expected_key.is_some() == host_ca.is_some() {
        return Err("set exactly one host key or host CA pin".into());
    }
    let expected_key = expected_key
        .map(|line| PublicKey::from_openssh(&line).and_then(|key| key.to_bytes()))
        .transpose()?;
    let expected_ca = host_ca
        .map(|path| PublicKey::read_openssh_file(path).and_then(|key| key.to_bytes()))
        .transpose()?;
    let verifier = move |_host: &str, key: &HostKey| match key {
        HostKey::Raw { key_blob, .. } if expected_key.as_ref() == Some(key_blob) => Ok(()),
        HostKey::Certificate(cert) if expected_ca.as_deref() == Some(cert.ca_public_key_blob()) => {
            Ok(())
        }
        _ => Err(HostKeyVerificationError::Rejected("unexpected server key".to_owned())),
    };
    Ok(ClientConfig::new(host, port, verifier)?)
}

async fn authenticate(
    connection: &mut ClientConnection,
    username: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let rsa_key = env::var("SCOPLEN_OPENSSH_RSA_KEY").ok();
    let ed25519_key = env::var("SCOPLEN_OPENSSH_ED25519_KEY").ok();
    let p256_key = env::var("SCOPLEN_OPENSSH_P256_KEY").ok();
    let ecdsa_key = env::var("SCOPLEN_OPENSSH_ECDSA_KEY").ok();
    let user_certificate = env::var("SCOPLEN_OPENSSH_USER_CERT").ok();
    let key_count = [rsa_key.as_ref(), ed25519_key.as_ref(), p256_key.as_ref(), ecdsa_key.as_ref()]
        .iter()
        .filter(|key| key.is_some())
        .count();
    if key_count > 1 {
        return Err("set only one OpenSSH private-key path".into());
    }
    if user_certificate.is_some() && key_count == 0 {
        return Err("user certificate requires an OpenSSH private-key path".into());
    }
    if let Some(path) = rsa_key {
        let key = PrivateKey::read_openssh_file(path)?;
        let algorithm = match env::var("SCOPLEN_OPENSSH_RSA_HASH").as_deref() {
            Ok("256") => SignatureAlgorithm::RsaSha2_256,
            Ok("512") | Err(_) => SignatureAlgorithm::RsaSha2_512,
            _ => return Err("SCOPLEN_OPENSSH_RSA_HASH must be 256 or 512".into()),
        };
        let signer = RsaSshSigner::new(key, algorithm)?;
        authenticate_with_signer(connection, username, &signer, user_certificate.as_deref())
            .await?;
    } else if let Some(path) = ed25519_key {
        let key = PrivateKey::read_openssh_file(path)?;
        let keypair = key.key_data().ed25519().ok_or("expected an Ed25519 private key")?;
        let signer =
            Ed25519SshSigner::new(Ed25519SigningKey::from_bytes(keypair.private.as_ref())?);
        authenticate_with_signer(connection, username, &signer, user_certificate.as_deref())
            .await?;
    } else if let Some(path) = p256_key {
        let key = PrivateKey::read_openssh_file(path)?;
        let keypair = key.key_data().ecdsa().ok_or("expected a P-256 private key")?;
        if keypair.curve() != ssh_key::EcdsaCurve::NistP256 {
            return Err("expected a P-256 private key".into());
        }
        let signer = P256SshSigner::new(P256SigningKey::from_bytes(keypair.private_key_bytes())?);
        authenticate_with_signer(connection, username, &signer, user_certificate.as_deref())
            .await?;
    } else if let Some(path) = ecdsa_key {
        let signer = EcdsaSshSigner::new(PrivateKey::read_openssh_file(path)?)?;
        authenticate_with_signer(connection, username, &signer, user_certificate.as_deref())
            .await?;
    } else {
        let password = env::var("SCOPLEN_OPENSSH_PASSWORD")
            .map_err(|_| "password or an OpenSSH private-key path is required")?;
        connection.authenticate_password(username, password.as_bytes()).await?;
    }
    Ok(())
}

async fn authenticate_with_signer<S: Signer + Sync>(
    connection: &mut ClientConnection,
    username: &str,
    signer: &S,
    certificate_path: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(certificate_path) = certificate_path {
        let ca_path = env::var("SCOPLEN_OPENSSH_USER_CA_KEY")
            .map_err(|_| "user certificate requires a pinned CA public-key path")?;
        let certificate = Certificate::read_file(Path::new(certificate_path))?;
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let certificate = UserCertificate::parse_and_validate(
            &certificate.to_bytes()?,
            &CertificateValidationPolicy::user(username, now),
        )?;
        let pinned_ca = PublicKey::read_openssh_file(ca_path)?.to_bytes()?;
        if certificate.certificate().ca_public_key_blob() != pinned_ca {
            return Err(UntrustedUserCa.into());
        }
        timeout(
            SSH_STEP_TIMEOUT,
            connection.authenticate_certificate(username, &certificate, signer),
        )
        .await??;
    } else {
        timeout(SSH_STEP_TIMEOUT, connection.authenticate_publickey(username, signer)).await??;
    }
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

async fn verify_statvfs(
    session: &mut SftpSession,
    missing_path: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    if !session.extensions().iter().any(|extension| extension.name == b"statvfs@openssh.com") {
        return Err("OpenSSH did not advertise statvfs@openssh.com".into());
    }
    let statvfs = session.client_mut().statvfs(b".")?;
    let stats = sftp_response(session, statvfs).await?.statvfs_response()?;
    if stats.block_size == 0
        || stats.fragment_size == 0
        || stats.blocks == 0
        || stats.name_max == 0
        || session.pending_requests() != 0
    {
        return Err("SFTP statvfs returned invalid filesystem statistics".into());
    }
    let missing_statvfs = session.client_mut().statvfs(missing_path.to_vec())?;
    if !matches!(sftp_response(session, missing_statvfs).await?, SftpPacket::Status { code: 2, .. })
        || session.pending_requests() != 0
    {
        return Err("missing SFTP statvfs path was not rejected cleanly".into());
    }
    Ok(())
}

async fn verify_fsync(
    session: &mut SftpSession,
    handle: &[u8],
    expect_success: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let request = session.client_mut().fsync(handle.to_vec())?;
    let response = sftp_response(session, request).await?;
    let valid_status = match response {
        SftpPacket::Status { code: 0, .. } => expect_success,
        SftpPacket::Status { code: 1.., .. } => !expect_success,
        _ => false,
    };
    if !valid_status || session.pending_requests() != 0 {
        return Err(if expect_success {
            "SFTP fsync failed or retained a request slot"
        } else {
            "SFTP fsync accepted a closed handle or retained a request slot"
        }
        .into());
    }
    Ok(())
}

async fn verify_fstatvfs(
    session: &mut SftpSession,
    handle: &[u8],
    expect_success: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let request = session.client_mut().fstatvfs(handle.to_vec())?;
    let response = sftp_response(session, request).await?;
    if expect_success {
        let stats = response.statvfs_response()?;
        if stats.block_size == 0
            || stats.fragment_size == 0
            || stats.blocks == 0
            || stats.name_max == 0
            || session.pending_requests() != 0
        {
            return Err("SFTP fstatvfs returned invalid filesystem statistics".into());
        }
    } else if !matches!(response, SftpPacket::Status { code: 1.., .. })
        || session.pending_requests() != 0
    {
        return Err("SFTP fstatvfs accepted a closed handle or retained a request slot".into());
    }
    Ok(())
}

async fn verify_fstat(
    session: &mut SftpSession,
    handle: &[u8],
    expected_size: Option<u64>,
) -> Result<(), Box<dyn std::error::Error>> {
    let request = session.client_mut().fstat(handle.to_vec())?;
    let response = sftp_response(session, request).await?;
    if let Some(size) = expected_size {
        if !matches!(response, SftpPacket::Attrs { attrs: SftpAttributes { size: Some(actual), .. }, .. } if actual == size)
            || session.pending_requests() != 0
        {
            return Err("SFTP fstat returned the wrong file size or retained a request slot".into());
        }
    } else if !matches!(response, SftpPacket::Status { code: 1.., .. })
        || session.pending_requests() != 0
    {
        return Err("SFTP fstat accepted a closed handle or retained a request slot".into());
    }
    Ok(())
}

async fn verify_fsetstat(
    session: &mut SftpSession,
    handle: &[u8],
    size: u64,
    open: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let request = session.client_mut().fsetstat(
        handle.to_vec(),
        SftpAttributes { size: Some(size), ..SftpAttributes::default() },
    )?;
    let response = sftp_response(session, request).await?;
    if !matches!(response, SftpPacket::Status { code, .. } if (code == 0) == open)
        || session.pending_requests() != 0
    {
        return Err("SFTP fsetstat returned the wrong status or retained a request slot".into());
    }
    Ok(())
}

async fn verify_fsetstat_open_round_trip(
    session: &mut SftpSession,
    handle: &[u8],
    original_size: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    verify_fsetstat(session, handle, original_size + 1, true).await?;
    verify_fstat(session, handle, Some(original_size + 1)).await?;
    verify_fsetstat(session, handle, original_size, true).await?;
    verify_fstat(session, handle, Some(original_size)).await
}

async fn verify_fsetstat_closed(
    session: &mut SftpSession,
    handle: &[u8],
    path: &[u8],
    original_size: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    verify_fsetstat(session, handle, original_size + 1, false).await?;
    let stat = session.client_mut().stat(path.to_vec())?;
    if !matches!(sftp_response(session, stat).await?, SftpPacket::Attrs { attrs: SftpAttributes { size: Some(actual), .. }, .. } if actual == original_size)
        || session.pending_requests() != 0
    {
        return Err(
            "SFTP closed-handle fsetstat changed the file or retained a request slot".into()
        );
    }
    Ok(())
}

async fn verify_hardlink(
    session: &mut SftpSession,
    path: &[u8],
    linked_path: &[u8],
    missing_path: &[u8],
    data: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    let missing_link_path = [path, b"-missing-link"].concat();
    let missing = session.client_mut().hardlink(missing_path.to_vec(), missing_link_path)?;
    if !matches!(sftp_response(session, missing).await?, SftpPacket::Status { code: 2, .. })
        || session.pending_requests() != 0
    {
        return Err("SFTP hardlink did not reject a missing source cleanly".into());
    }
    let link = session.client_mut().hardlink(path.to_vec(), linked_path.to_vec())?;
    if !matches!(sftp_response(session, link).await?, SftpPacket::Status { code: 0, .. })
        || session.pending_requests() != 0
    {
        return Err("SFTP hardlink failed or retained a request slot".into());
    }
    let existing = session.client_mut().hardlink(path.to_vec(), linked_path.to_vec())?;
    if !matches!(sftp_response(session, existing).await?, SftpPacket::Status { code: 1.., .. })
        || session.pending_requests() != 0
    {
        return Err(
            "SFTP hardlink accepted an existing destination or retained a request slot".into()
        );
    }

    let open = session.client_mut().open(linked_path.to_vec(), 1, SftpAttributes::default())?;
    let handle = match sftp_response(session, open).await? {
        SftpPacket::Handle { handle, .. } => handle,
        other => return Err(format!("unexpected SFTP linked-file open response: {other:?}").into()),
    };
    let mut linked_data = Vec::new();
    let count = session
        .download_to(&handle, 0, Some(data.len() as u64), 4096, 4, &mut linked_data, |_| {})
        .await?;
    if count != data.len() as u64 || linked_data != data || session.pending_requests() != 0 {
        return Err("SFTP hardlink contents did not match the uploaded file".into());
    }
    let close = session.client_mut().close(handle)?;
    if !matches!(sftp_response(session, close).await?, SftpPacket::Status { code: 0, .. }) {
        return Err("SFTP linked-file handle close failed".into());
    }
    let remove = session.client_mut().remove(linked_path.to_vec())?;
    if !matches!(sftp_response(session, remove).await?, SftpPacket::Status { code: 0, .. })
        || session.pending_requests() != 0
    {
        return Err("SFTP hardlink cleanup or request release failed".into());
    }
    Ok(())
}

async fn verify_sftp_bytes(
    session: &mut SftpSession,
    path: &[u8],
    expected: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    let open = session.client_mut().open(path.to_vec(), 1, SftpAttributes::default())?;
    let handle = match sftp_response(session, open).await? {
        SftpPacket::Handle { handle, .. } => handle,
        other => return Err(format!("unexpected SFTP file open response: {other:?}").into()),
    };
    let mut downloaded = Vec::new();
    let count = session
        .download_to(&handle, 0, Some(expected.len() as u64), 4096, 4, &mut downloaded, |_| {})
        .await?;
    if count != expected.len() as u64 || downloaded != expected || session.pending_requests() != 0 {
        return Err("SFTP file contents or request release mismatch".into());
    }
    let close = session.client_mut().close(handle)?;
    if !matches!(sftp_response(session, close).await?, SftpPacket::Status { code: 0, .. })
        || session.pending_requests() != 0
    {
        return Err("SFTP file handle close or request release failed".into());
    }
    Ok(())
}

async fn verify_copy_data(
    session: &mut SftpSession,
    source_handle: &[u8],
    path: &[u8],
    data: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    let target_path = [path, b"-copy"].concat();
    let create = session.client_mut().open(target_path.clone(), 0x1a, SftpAttributes::default())?;
    let target_handle = match sftp_response(session, create).await? {
        SftpPacket::Handle { handle, .. } => handle,
        other => return Err(format!("unexpected SFTP copy target response: {other:?}").into()),
    };
    let initial = b"0123456789";
    if session.upload(&target_handle, 0, initial, 4096, 4, |_| {}).await? != initial.len() as u64
        || session.pending_requests() != 0
    {
        return Err("SFTP copy target setup failed or retained a request slot".into());
    }

    let copy =
        session.client_mut().copy_data(source_handle.to_vec(), 9, 8, target_handle.clone(), 1)?;
    if !matches!(sftp_response(session, copy).await?, SftpPacket::Status { code: 0, .. })
        || session.pending_requests() != 0
    {
        return Err("SFTP copy-data failed or retained a request slot".into());
    }
    let invalid =
        session.client_mut().copy_data(b"invalid-copy-handle", 9, 8, target_handle.clone(), 1)?;
    if !matches!(sftp_response(session, invalid).await?, SftpPacket::Status { code: 1.., .. })
        || session.pending_requests() != 0
    {
        return Err(
            "SFTP copy-data accepted an invalid source handle or retained a request slot".into()
        );
    }

    let close = session.client_mut().close(target_handle.clone())?;
    if !matches!(sftp_response(session, close).await?, SftpPacket::Status { code: 0, .. })
        || session.pending_requests() != 0
    {
        return Err("SFTP copy target close failed or retained a request slot".into());
    }
    let closed = session.client_mut().copy_data(source_handle.to_vec(), 9, 8, target_handle, 1)?;
    if !matches!(sftp_response(session, closed).await?, SftpPacket::Status { code: 1.., .. })
        || session.pending_requests() != 0
    {
        return Err(
            "SFTP copy-data accepted a closed target handle or retained a request slot".into()
        );
    }
    let expected = [b"0".as_slice(), &data[9..17], b"9"].concat();
    verify_sftp_bytes(session, &target_path, &expected).await?;
    let remove = session.client_mut().remove(target_path.clone())?;
    if !matches!(sftp_response(session, remove).await?, SftpPacket::Status { code: 0, .. })
        || session.pending_requests() != 0
    {
        return Err("SFTP copy target cleanup failed or retained a request slot".into());
    }
    let gone = session.client_mut().open(target_path, 1, SftpAttributes::default())?;
    if !matches!(sftp_response(session, gone).await?, SftpPacket::Status { code: 2, .. })
        || session.pending_requests() != 0
    {
        return Err("SFTP copy target cleanup left a path behind".into());
    }
    Ok(())
}

async fn verify_lsetstat(
    session: &mut SftpSession,
    path: &[u8],
    missing_path: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    let attrs = SftpAttributes {
        access_time: Some(1_600_000_000),
        modify_time: Some(1_600_000_000),
        ..SftpAttributes::default()
    };
    let missing = session.client_mut().lsetstat(missing_path.to_vec(), &attrs)?;
    if !matches!(sftp_response(session, missing).await?, SftpPacket::Status { code: 2, .. })
        || session.pending_requests() != 0
    {
        return Err("SFTP lsetstat did not reject a missing path cleanly".into());
    }
    let set = session.client_mut().lsetstat(path.to_vec(), &attrs)?;
    if !matches!(sftp_response(session, set).await?, SftpPacket::Status { code: 0, .. })
        || session.pending_requests() != 0
    {
        return Err("SFTP lsetstat failed or retained a request slot".into());
    }
    let stat = session.client_mut().lstat(path.to_vec())?;
    if !matches!(
        sftp_response(session, stat).await?,
        SftpPacket::Attrs { attrs, .. } if attrs.modify_time == Some(1_600_000_000)
    ) || session.pending_requests() != 0
    {
        return Err("SFTP lsetstat timestamp was not visible through lstat".into());
    }

    let missing_link = session.client_mut().readlink(missing_path.to_vec())?;
    if !matches!(sftp_response(session, missing_link).await?, SftpPacket::Status { code: 2, .. })
        || session.pending_requests() != 0
    {
        return Err("SFTP readlink did not reject a missing link cleanly".into());
    }

    let link_path = [path, b"-symlink"].concat();
    // OpenSSH reverses the SFTP v3 draft's linkpath/targetpath wire order.
    let link = session.client_mut().symlink(path.to_vec(), link_path.clone())?;
    if !matches!(sftp_response(session, link).await?, SftpPacket::Status { code: 0, .. })
        || session.pending_requests() != 0
    {
        return Err("SFTP symlink setup failed or retained a request slot".into());
    }
    let read_link = session.client_mut().readlink(link_path.clone())?;
    if !matches!(
        sftp_response(session, read_link).await?,
        SftpPacket::Name { entries, .. }
            if entries.len() == 1 && entries[0].filename == path
    ) || session.pending_requests() != 0
    {
        return Err("SFTP readlink target mismatch or retained a request slot".into());
    }
    let link_attrs = SftpAttributes {
        access_time: Some(1_500_000_000),
        modify_time: Some(1_500_000_000),
        ..SftpAttributes::default()
    };
    let set_link = session.client_mut().lsetstat(link_path.clone(), &link_attrs)?;
    if !matches!(sftp_response(session, set_link).await?, SftpPacket::Status { code: 0, .. })
        || session.pending_requests() != 0
    {
        return Err("SFTP lsetstat did not update the symlink".into());
    }
    let link = session.client_mut().lstat(link_path.clone())?;
    if !matches!(
        sftp_response(session, link).await?,
        SftpPacket::Attrs { attrs, .. } if attrs.modify_time == Some(1_500_000_000)
    ) || session.pending_requests() != 0
    {
        return Err("SFTP lsetstat did not change the symlink timestamp".into());
    }
    let target = session.client_mut().stat(link_path.clone())?;
    if !matches!(
        sftp_response(session, target).await?,
        SftpPacket::Attrs { attrs, .. } if attrs.modify_time == Some(1_600_000_000)
    ) || session.pending_requests() != 0
    {
        return Err("SFTP lsetstat changed the symlink target timestamp".into());
    }
    let remove = session.client_mut().remove(link_path.clone())?;
    if !matches!(sftp_response(session, remove).await?, SftpPacket::Status { code: 0, .. })
        || session.pending_requests() != 0
    {
        return Err("SFTP symlink cleanup failed or retained a request slot".into());
    }
    let after_cleanup = session.client_mut().readlink(link_path)?;
    if !matches!(sftp_response(session, after_cleanup).await?, SftpPacket::Status { code: 2, .. })
        || session.pending_requests() != 0
    {
        return Err("SFTP removed link was still readable or retained a request slot".into());
    }
    Ok(())
}

async fn verify_realpath(
    session: &mut SftpSession,
    path: &[u8],
    missing_path: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    let cwd = session.client_mut().realpath(b".")?;
    let cwd = match sftp_response(session, cwd).await? {
        SftpPacket::Name { entries, .. }
            if entries.len() == 1 && entries[0].filename.starts_with(b"/") =>
        {
            entries[0].filename.clone()
        }
        _ => return Err("SFTP realpath did not resolve the current directory".into()),
    };
    if session.pending_requests() != 0 {
        return Err("SFTP realpath retained a current-directory request slot".into());
    }
    let mut expected = cwd.clone();
    if !expected.ends_with(b"/") {
        expected.push(b'/');
    }
    expected.extend_from_slice(path);

    let relative = [b"./".as_slice(), path].concat();
    let resolved = session.client_mut().realpath(relative)?;
    if !matches!(
        sftp_response(session, resolved).await?,
        SftpPacket::Name { entries, .. }
            if entries.len() == 1 && entries[0].filename == expected
    ) || session.pending_requests() != 0
    {
        return Err("SFTP realpath did not canonicalize the existing file cleanly".into());
    }

    let mut expected_missing = cwd;
    if !expected_missing.ends_with(b"/") {
        expected_missing.push(b'/');
    }
    expected_missing.extend_from_slice(missing_path);
    let missing = session.client_mut().realpath(missing_path.to_vec())?;
    if !matches!(
        sftp_response(session, missing).await?,
        SftpPacket::Name { entries, .. }
            if entries.len() == 1 && entries[0].filename == expected_missing
    ) || session.pending_requests() != 0
    {
        return Err("SFTP realpath did not normalize a missing final component".into());
    }

    let invalid = [path, b"/child"].concat();
    let request = session.client_mut().realpath(invalid)?;
    if !matches!(sftp_response(session, request).await?, SftpPacket::Status { code: 1.., .. })
        || session.pending_requests() != 0
    {
        return Err(
            "SFTP realpath accepted a file as a directory or retained a request slot".into()
        );
    }
    Ok(())
}

async fn verify_directory(
    session: &mut SftpSession,
    path: &[u8],
    missing_path: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    let missing = session.client_mut().opendir(missing_path.to_vec())?;
    if !matches!(sftp_response(session, missing).await?, SftpPacket::Status { code: 2, .. })
        || session.pending_requests() != 0
    {
        return Err("SFTP opendir did not reject a missing directory cleanly".into());
    }

    let directory = [path, b"-dir"].concat();
    let entry = [directory.as_slice(), b"/entry"].concat();
    let mkdir = session.client_mut().mkdir(directory.clone(), SftpAttributes::default())?;
    if !matches!(sftp_response(session, mkdir).await?, SftpPacket::Status { code: 0, .. }) {
        return Err("SFTP mkdir failed".into());
    }
    let create = session.client_mut().open(entry.clone(), 0x1a, SftpAttributes::default())?;
    let file_handle = match sftp_response(session, create).await? {
        SftpPacket::Handle { handle, .. } => handle,
        other => {
            return Err(
                format!("unexpected SFTP directory entry create response: {other:?}").into()
            );
        }
    };
    let close = session.client_mut().close(file_handle)?;
    if !matches!(sftp_response(session, close).await?, SftpPacket::Status { code: 0, .. }) {
        return Err("SFTP directory entry close failed".into());
    }

    let open = session.client_mut().opendir(directory.clone())?;
    let directory_handle = match sftp_response(session, open).await? {
        SftpPacket::Handle { handle, .. } => handle,
        other => return Err(format!("unexpected SFTP opendir response: {other:?}").into()),
    };
    let mut saw_entry = false;
    let mut saw_eof = false;
    for _ in 0..16 {
        let read = session.client_mut().readdir(directory_handle.clone())?;
        match sftp_response(session, read).await? {
            SftpPacket::Name { entries, .. } => {
                saw_entry |= entries.iter().any(|entry| entry.filename == b"entry");
            }
            SftpPacket::Status { code: 1, .. } => {
                saw_eof = true;
                break;
            }
            other => return Err(format!("unexpected SFTP readdir response: {other:?}").into()),
        }
    }
    if !saw_entry || !saw_eof || session.pending_requests() != 0 {
        return Err("SFTP directory listing omitted the entry, EOF, or request release".into());
    }

    let nonempty = session.client_mut().rmdir(directory.clone())?;
    if !matches!(sftp_response(session, nonempty).await?, SftpPacket::Status { code: 1.., .. })
        || session.pending_requests() != 0
    {
        return Err("SFTP rmdir accepted a nonempty directory or retained a request slot".into());
    }
    let close = session.client_mut().close(directory_handle.clone())?;
    if !matches!(sftp_response(session, close).await?, SftpPacket::Status { code: 0, .. }) {
        return Err("SFTP directory handle close failed".into());
    }
    let closed = session.client_mut().readdir(directory_handle)?;
    if !matches!(sftp_response(session, closed).await?, SftpPacket::Status { code: 1.., .. })
        || session.pending_requests() != 0
    {
        return Err("SFTP readdir accepted a closed handle or retained a request slot".into());
    }
    let remove = session.client_mut().remove(entry)?;
    if !matches!(sftp_response(session, remove).await?, SftpPacket::Status { code: 0, .. }) {
        return Err("SFTP directory entry cleanup failed".into());
    }
    let rmdir = session.client_mut().rmdir(directory.clone())?;
    if !matches!(sftp_response(session, rmdir).await?, SftpPacket::Status { code: 0, .. }) {
        return Err("SFTP rmdir cleanup failed".into());
    }
    let removed = session.client_mut().opendir(directory)?;
    if !matches!(sftp_response(session, removed).await?, SftpPacket::Status { code: 2, .. })
        || session.pending_requests() != 0
    {
        return Err("SFTP removed directory was still openable or retained a request slot".into());
    }
    Ok(())
}

async fn expand_sftp_path(
    session: &mut SftpSession,
    path: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let request = session.client_mut().expand_path(path.to_vec())?;
    let expanded = match sftp_response(session, request).await? {
        SftpPacket::Name { entries, .. } if entries.len() == 1 => entries[0].filename.clone(),
        other => return Err(format!("unexpected SFTP expand-path response: {other:?}").into()),
    };
    if !expanded.starts_with(b"/") || !expanded.ends_with(path) || session.pending_requests() != 0 {
        return Err("SFTP expand-path returned an invalid path or retained a request slot".into());
    }
    Ok(expanded)
}

async fn verify_expand_path(
    session: &mut SftpSession,
    path: &[u8],
    missing_path: &[u8],
    data: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    let expanded = expand_sftp_path(session, path).await?;
    verify_sftp_bytes(session, &expanded, data).await?;

    let missing = expand_sftp_path(session, missing_path).await?;
    let open = session.client_mut().open(missing, 1, SftpAttributes::default())?;
    if !matches!(sftp_response(session, open).await?, SftpPacket::Status { code: 2, .. })
        || session.pending_requests() != 0
    {
        return Err("SFTP expanded missing path opened or retained a request slot".into());
    }
    Ok(())
}

async fn verify_posix_rename(
    session: &mut SftpSession,
    path: &[u8],
    missing_path: &[u8],
    data: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    let renamed_path = [path, b"-renamed"].concat();
    let replacement_path = [path, b"-replacement"].concat();
    let missing_destination = [path, b"-missing-rename"].concat();
    let missing = session.client_mut().posix_rename(missing_path.to_vec(), missing_destination)?;
    if !matches!(sftp_response(session, missing).await?, SftpPacket::Status { code: 2, .. })
        || session.pending_requests() != 0
    {
        return Err("SFTP posix-rename did not reject a missing source cleanly".into());
    }

    let previous = b"previous destination contents";
    let create =
        session.client_mut().open(replacement_path.clone(), 0x1a, SftpAttributes::default())?;
    let handle = match sftp_response(session, create).await? {
        SftpPacket::Handle { handle, .. } => handle,
        other => {
            return Err(format!("unexpected SFTP replacement create response: {other:?}").into());
        }
    };
    if session.upload(&handle, 0, previous, 4096, 4, |_| {}).await? != previous.len() as u64
        || session.pending_requests() != 0
    {
        return Err("SFTP replacement setup failed or retained a request slot".into());
    }
    let close = session.client_mut().close(handle)?;
    if !matches!(sftp_response(session, close).await?, SftpPacket::Status { code: 0, .. })
        || session.pending_requests() != 0
    {
        return Err("SFTP replacement setup handle close failed".into());
    }
    verify_sftp_bytes(session, &replacement_path, previous).await?;

    let rename = session.client_mut().posix_rename(path.to_vec(), renamed_path.clone())?;
    if !matches!(sftp_response(session, rename).await?, SftpPacket::Status { code: 0, .. })
        || session.pending_requests() != 0
    {
        return Err("SFTP posix-rename failed or retained a request slot".into());
    }
    let old = session.client_mut().open(path.to_vec(), 1, SftpAttributes::default())?;
    if !matches!(sftp_response(session, old).await?, SftpPacket::Status { code: 2, .. })
        || session.pending_requests() != 0
    {
        return Err("SFTP posix-rename left the source path behind".into());
    }
    verify_sftp_bytes(session, &renamed_path, data).await?;

    let replace =
        session.client_mut().posix_rename(renamed_path.clone(), replacement_path.clone())?;
    if !matches!(sftp_response(session, replace).await?, SftpPacket::Status { code: 0, .. })
        || session.pending_requests() != 0
    {
        return Err("SFTP posix-rename did not replace an existing destination cleanly".into());
    }
    let old = session.client_mut().open(renamed_path, 1, SftpAttributes::default())?;
    if !matches!(sftp_response(session, old).await?, SftpPacket::Status { code: 2, .. })
        || session.pending_requests() != 0
    {
        return Err("SFTP posix-rename left the replaced source path behind".into());
    }
    verify_sftp_bytes(session, &replacement_path, data).await?;
    let remove = session.client_mut().remove(replacement_path)?;
    if !matches!(sftp_response(session, remove).await?, SftpPacket::Status { code: 0, .. })
        || session.pending_requests() != 0
    {
        return Err("SFTP posix-rename cleanup or request release failed".into());
    }
    let gone = session.client_mut().open(
        [path, b"-replacement"].concat(),
        1,
        SftpAttributes::default(),
    )?;
    if !matches!(sftp_response(session, gone).await?, SftpPacket::Status { code: 2, .. })
        || session.pending_requests() != 0
    {
        return Err("SFTP posix-rename cleanup left a destination path behind".into());
    }
    Ok(())
}

async fn verify_standard_rename(
    session: &mut SftpSession,
    path: &[u8],
    missing_path: &[u8],
    data: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    let renamed_path = [path, b"-standard-renamed"].concat();
    let existing_path = [path, b"-standard-existing"].concat();
    let missing_destination = [path, b"-standard-missing"].concat();
    let missing =
        session.client_mut().rename(missing_path.to_vec(), missing_destination.clone())?;
    if !matches!(sftp_response(session, missing).await?, SftpPacket::Status { code: 2, .. })
        || session.pending_requests() != 0
    {
        return Err("SFTP standard rename did not reject a missing source cleanly".into());
    }
    let absent = session.client_mut().open(missing_destination, 1, SftpAttributes::default())?;
    if !matches!(sftp_response(session, absent).await?, SftpPacket::Status { code: 2, .. })
        || session.pending_requests() != 0
    {
        return Err("SFTP standard rename created a destination for a missing source".into());
    }

    let previous = b"previous standard destination contents";
    let create =
        session.client_mut().open(existing_path.clone(), 0x1a, SftpAttributes::default())?;
    let handle = match sftp_response(session, create).await? {
        SftpPacket::Handle { handle, .. } => handle,
        other => return Err(format!("unexpected standard rename setup: {other:?}").into()),
    };
    if session.upload(&handle, 0, previous, 4096, 4, |_| {}).await? != previous.len() as u64
        || session.pending_requests() != 0
    {
        return Err("SFTP standard rename destination setup failed".into());
    }
    let close = session.client_mut().close(handle)?;
    if !matches!(sftp_response(session, close).await?, SftpPacket::Status { code: 0, .. })
        || session.pending_requests() != 0
    {
        return Err("SFTP standard rename destination close failed".into());
    }
    let no_replace = session.client_mut().rename(path.to_vec(), existing_path.clone())?;
    if !matches!(sftp_response(session, no_replace).await?, SftpPacket::Status { code: 1.., .. })
        || session.pending_requests() != 0
    {
        return Err("SFTP standard rename replaced an existing destination".into());
    }
    verify_sftp_bytes(session, path, data).await?;
    verify_sftp_bytes(session, &existing_path, previous).await?;
    let remove = session.client_mut().remove(existing_path.clone())?;
    if !matches!(sftp_response(session, remove).await?, SftpPacket::Status { code: 0, .. })
        || session.pending_requests() != 0
    {
        return Err("SFTP standard rename destination cleanup failed".into());
    }
    let gone = session.client_mut().open(existing_path, 1, SftpAttributes::default())?;
    if !matches!(sftp_response(session, gone).await?, SftpPacket::Status { code: 2, .. })
        || session.pending_requests() != 0
    {
        return Err("SFTP standard rename destination remained after cleanup".into());
    }

    let rename = session.client_mut().rename(path.to_vec(), renamed_path.clone())?;
    if !matches!(sftp_response(session, rename).await?, SftpPacket::Status { code: 0, .. })
        || session.pending_requests() != 0
    {
        return Err("SFTP standard rename failed or retained a request slot".into());
    }
    let old = session.client_mut().open(path.to_vec(), 1, SftpAttributes::default())?;
    if !matches!(sftp_response(session, old).await?, SftpPacket::Status { code: 2, .. })
        || session.pending_requests() != 0
    {
        return Err("SFTP standard rename left the source path behind".into());
    }
    verify_sftp_bytes(session, &renamed_path, data).await?;
    let restore = session.client_mut().rename(renamed_path.clone(), path.to_vec())?;
    if !matches!(sftp_response(session, restore).await?, SftpPacket::Status { code: 0, .. })
        || session.pending_requests() != 0
    {
        return Err("SFTP standard rename could not restore the source path".into());
    }
    let gone = session.client_mut().open(renamed_path, 1, SftpAttributes::default())?;
    if !matches!(sftp_response(session, gone).await?, SftpPacket::Status { code: 2, .. })
        || session.pending_requests() != 0
    {
        return Err("SFTP standard rename left a temporary path behind".into());
    }
    verify_sftp_bytes(session, path, data).await?;
    Ok(())
}

fn verify_sftp_capabilities(session: &SftpSession) -> Result<(), Box<dyn std::error::Error>> {
    if session.limits().is_none() {
        return Err("OpenSSH did not advertise SFTP transfer limits".into());
    }
    if !session.extensions().iter().any(|extension| extension.name == b"fsync@openssh.com") {
        return Err("OpenSSH did not advertise fsync@openssh.com".into());
    }
    if !session.extensions().iter().any(|extension| extension.name == b"fstatvfs@openssh.com") {
        return Err("OpenSSH did not advertise fstatvfs@openssh.com".into());
    }
    if !session.extensions().iter().any(|extension| extension.name == b"hardlink@openssh.com") {
        return Err("OpenSSH did not advertise hardlink@openssh.com".into());
    }
    if !session.extensions().iter().any(|extension| extension.name == b"posix-rename@openssh.com") {
        return Err("OpenSSH did not advertise posix-rename@openssh.com".into());
    }
    if !session.extensions().iter().any(|extension| extension.name == b"expand-path@openssh.com") {
        return Err("OpenSSH did not advertise expand-path@openssh.com".into());
    }
    if !session.extensions().iter().any(|extension| extension.name == b"copy-data") {
        return Err("OpenSSH did not advertise copy-data".into());
    }
    if !session.extensions().iter().any(|extension| extension.name == b"lsetstat@openssh.com") {
        return Err("OpenSSH did not advertise lsetstat@openssh.com".into());
    }
    Ok(())
}

async fn verify_sftp(connection: &ClientConnection) -> Result<(), Box<dyn std::error::Error>> {
    let mut session = SftpSession::open(connection, 4).await?;
    verify_sftp_capabilities(&session)?;
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let path = format!(".scoplen-interop-{}-{nonce}", std::process::id()).into_bytes();
    let linked_path = [path.as_slice(), b"-link"].concat();
    let missing_path = [path.as_slice(), b"-missing"].concat();
    let missing = session.client_mut().open(missing_path.clone(), 1, SftpAttributes::default())?;
    if !matches!(sftp_response(&mut session, missing).await?, SftpPacket::Status { code: 2, .. })
        || session.pending_requests() != 0
    {
        return Err("missing SFTP file was not rejected cleanly".into());
    }

    verify_statvfs(&mut session, &missing_path).await?;
    verify_directory(&mut session, &path, &missing_path).await?;

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
    verify_fsync(&mut session, &write_handle, true).await?;
    verify_fstatvfs(&mut session, &write_handle, true).await?;
    verify_fstat(&mut session, &write_handle, Some(data.len() as u64)).await?;
    verify_fsetstat_open_round_trip(&mut session, &write_handle, data.len() as u64).await?;
    let close = session.client_mut().close(write_handle.clone())?;
    if !matches!(sftp_response(&mut session, close).await?, SftpPacket::Status { code: 0, .. }) {
        return Err("SFTP write handle close failed".into());
    }
    verify_fsync(&mut session, &write_handle, false).await?;
    verify_fstatvfs(&mut session, &write_handle, false).await?;
    verify_fstat(&mut session, &write_handle, None).await?;
    verify_fsetstat_closed(&mut session, &write_handle, &path, data.len() as u64).await?;
    verify_realpath(&mut session, &path, &missing_path).await?;
    verify_lsetstat(&mut session, &path, &missing_path).await?;

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
    verify_copy_data(&mut session, &read_handle, &path, &data).await?;
    let close = session.client_mut().close(read_handle)?;
    if !matches!(sftp_response(&mut session, close).await?, SftpPacket::Status { code: 0, .. }) {
        return Err("SFTP read handle close failed".into());
    }
    verify_hardlink(&mut session, &path, &linked_path, &missing_path, &data).await?;
    verify_expand_path(&mut session, &path, &missing_path, &data).await?;
    verify_standard_rename(&mut session, &path, &missing_path, &data).await?;
    verify_posix_rename(&mut session, &path, &missing_path, &data).await?;
    println!("openssh sftp interop ok");
    Ok(())
}
