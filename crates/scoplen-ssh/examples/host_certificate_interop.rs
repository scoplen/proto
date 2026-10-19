// SPDX-License-Identifier: Apache-2.0
//! Exercise P-384/P-521 host identities against disposable OpenSSH listeners.

use std::{env, time::Duration};

use scoplen_ssh::{
    CertificateValidationError, ChannelEvent, ClientConfig, ClientConnection, ClientError, HostKey,
    HostKeyVerificationError,
};
use ssh_key::PublicKey;
use tokio::time::timeout;

const DEADLINE: Duration = Duration::from_secs(10);

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args().skip(1);
    let identity = args.next().ok_or("expected raw or certificate identity")?;
    let outcome = args.next().ok_or("expected valid, wrong-ca, wrong-principal, or expired")?;
    if !matches!(identity.as_str(), "raw" | "certificate")
        || !matches!(outcome.as_str(), "valid" | "wrong-ca" | "wrong-principal" | "expired")
        || (identity == "raw" && outcome != "valid")
        || args.next().is_some()
    {
        return Err("invalid host-certificate interop case".into());
    }
    let port = env::var("SCOPLEN_HOST_CERT_PORT")?.parse()?;
    let expected_raw =
        PublicKey::from_openssh(&env::var("SCOPLEN_HOST_CERT_RAW_KEY")?)?.to_bytes()?;
    let trusted_ca = PublicKey::from_openssh(&env::var("SCOPLEN_HOST_CERT_CA_KEY")?)?.to_bytes()?;
    let expected_identity = identity.clone();
    let config = ClientConfig::new("127.0.0.1", port, move |_host: &str, key: &HostKey| {
        match (&*expected_identity, key) {
            ("raw", HostKey::Raw { key_blob, .. }) if *key_blob == expected_raw => Ok(()),
            ("certificate", HostKey::Certificate(cert))
                if cert.ca_public_key_blob() == trusted_ca =>
            {
                Ok(())
            }
            _ => {
                Err(HostKeyVerificationError::Rejected("unexpected host identity or CA".to_owned()))
            }
        }
    })?;

    let connection = timeout(DEADLINE, ClientConnection::connect(config)).await?;
    match outcome.as_str() {
        "wrong-ca" => {
            if !matches!(
                connection,
                Err(ClientError::HostKey(HostKeyVerificationError::Rejected(_)))
            ) {
                return Err(format!("expected wrong-CA rejection, got {connection:?}").into());
            }
            println!("host certificate wrong-ca rejected");
        }
        "wrong-principal" => {
            if !matches!(
                connection,
                Err(ClientError::HostKey(HostKeyVerificationError::Certificate(
                    CertificateValidationError::PrincipalMismatch
                )))
            ) {
                return Err(
                    format!("expected wrong-principal rejection, got {connection:?}").into()
                );
            }
            println!("host certificate wrong-principal rejected");
        }
        "expired" => {
            if !matches!(
                connection,
                Err(ClientError::HostKey(HostKeyVerificationError::Certificate(
                    CertificateValidationError::Expired
                )))
            ) {
                return Err(
                    format!("expected expired-certificate rejection, got {connection:?}").into()
                );
            }
            println!("host certificate expired rejected");
        }
        "valid" => {
            let mut connection = connection?;
            timeout(
                DEADLINE,
                connection.authenticate_password("scoplen", b"scoplen-test-password"),
            )
            .await??;
            let mut channel = timeout(DEADLINE, connection.open_session()).await??;
            timeout(DEADLINE, channel.exec(true, b"printf scoplen-host-cert-ok")).await??;
            let mut output = Vec::new();
            let mut status = None;
            loop {
                match timeout(DEADLINE, channel.next_event()).await?? {
                    Some(ChannelEvent::Data(data)) => output.extend_from_slice(&data),
                    Some(ChannelEvent::ExitStatus(code)) => status = Some(code),
                    Some(ChannelEvent::Close) | None => break,
                    Some(ChannelEvent::Eof | ChannelEvent::Success) => {}
                    other => return Err(format!("unexpected SSH command event: {other:?}").into()),
                }
            }
            if output != b"scoplen-host-cert-ok" || status != Some(0) {
                return Err(format!("unexpected command result: {status:?}, {output:?}").into());
            }
            timeout(DEADLINE, connection.disconnect()).await??;
            let label = if identity == "raw" { "raw" } else { "valid" };
            println!("host certificate {label} command ok");
        }
        _ => unreachable!("validated interop outcome"),
    }
    Ok(())
}
