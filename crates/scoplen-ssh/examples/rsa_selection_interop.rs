// SPDX-License-Identifier: Apache-2.0
//! Verify RSA signature discovery and authentication against constrained OpenSSH listeners.

use std::{env, time::Duration};

use scoplen_ssh::{
    ChannelEvent, ClientConfig, ClientConnection, HostKey, HostKeyVerificationError, RsaSshSigner,
    ServerRsaSha2Selection, SignatureAlgorithm,
};
use ssh_key::{PrivateKey, PublicKey};
use tokio::{net::TcpStream, time::timeout};

const DEADLINE: Duration = Duration::from_secs(10);

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let host_key =
        PublicKey::from_openssh(&env::var("SCOPLEN_RSA_SELECTION_HOST_KEY")?)?.to_bytes()?;
    let key = PrivateKey::read_openssh_file(env::var("SCOPLEN_RSA_SELECTION_USER_KEY")?)?;
    let user = env::var("SCOPLEN_RSA_SELECTION_USER")?;
    for (port_variable, expected) in [
        ("SCOPLEN_RSA_SELECTION_SHA256_PORT", ServerRsaSha2Selection::Sha256),
        ("SCOPLEN_RSA_SELECTION_DUAL_PORT", ServerRsaSha2Selection::Sha512),
        ("SCOPLEN_RSA_SELECTION_SHA1_PORT", ServerRsaSha2Selection::Sha1OnlyAdvertised),
    ] {
        let port = env::var(port_variable)?.parse()?;
        let expected_key = host_key.clone();
        let config =
            ClientConfig::new("127.0.0.1", port, move |_host: &str, key: &HostKey| match key {
                HostKey::Raw { key_blob, .. } if *key_blob == expected_key => Ok(()),
                _ => Err(HostKeyVerificationError::Rejected("unexpected server key".to_owned())),
            })?;
        let stream = timeout(DEADLINE, TcpStream::connect(("127.0.0.1", port))).await??;
        let mut connection =
            timeout(DEADLINE, ClientConnection::connect_stream(config, stream)).await??;
        let actual = connection.server_rsa_sha2_selection().await?;
        if actual != expected || connection.server_rsa_sha2_selection().await? != expected {
            return Err(format!("{port_variable}: expected {expected:?}, got {actual:?}").into());
        }
        if let Some(algorithm) = match actual {
            ServerRsaSha2Selection::Sha256 => Some(SignatureAlgorithm::RsaSha2_256),
            ServerRsaSha2Selection::Sha512 => Some(SignatureAlgorithm::RsaSha2_512),
            ServerRsaSha2Selection::Sha1OnlyAdvertised | ServerRsaSha2Selection::Undetermined => {
                None
            }
        } {
            let signer = RsaSshSigner::new(key.clone(), algorithm)?;
            timeout(DEADLINE, connection.authenticate_publickey(&user, &signer)).await??;
            let mut channel = timeout(DEADLINE, connection.open_session()).await??;
            timeout(DEADLINE, channel.exec(true, b"printf scoplen-rsa-selection-ok")).await??;
            let mut output = Vec::new();
            let mut status = None;
            loop {
                match timeout(DEADLINE, channel.next_event()).await?? {
                    Some(ChannelEvent::Data(data)) => output.extend_from_slice(&data),
                    Some(ChannelEvent::ExitStatus(code)) => status = Some(code),
                    Some(ChannelEvent::Close) | None => break,
                    Some(ChannelEvent::Eof | ChannelEvent::Success) => {}
                    other => return Err(format!("unexpected command event: {other:?}").into()),
                }
            }
            if output != b"scoplen-rsa-selection-ok" || status != Some(0) {
                return Err(
                    format!("{port_variable}: command failed: {status:?}, {output:?}").into()
                );
            }
        }
        timeout(DEADLINE, connection.disconnect()).await??;
        println!("{port_variable}: {actual:?} passed");
    }
    Ok(())
}
