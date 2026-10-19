// SPDX-License-Identifier: Apache-2.0
//! Exercise a real OpenSSH agent and server through the public SSH client API.

use std::{
    env,
    net::{SocketAddr, TcpStream},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use scoplen_ssh::{
    AgentClient, AgentSshSigner, CertificateValidationPolicy, ChannelEvent, ClientConfig,
    ClientConnection, FramedAgentChannel, HostKey, HostKeyVerificationError, SignatureAlgorithm,
    UserCertificate,
};
use ssh_key::{Certificate, PublicKey};
use tokio::time::timeout;

const DEADLINE: Duration = Duration::from_secs(10);

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mode = env::args().nth(1).ok_or("expected raw or certificate mode")?;
    if !matches!(mode.as_str(), "raw" | "certificate") || env::args().nth(2).is_some() {
        return Err("expected exactly one raw or certificate mode".into());
    }

    let host_key = PublicKey::from_openssh(&env::var("SCOPLEN_AGENT_HOST_KEY")?)?.to_bytes()?;
    let user_key = PublicKey::from_openssh(&env::var("SCOPLEN_AGENT_USER_KEY")?)?.to_bytes()?;
    let agent_port = env::var("SCOPLEN_AGENT_PORT")?.parse::<u16>()?;
    let server_port = env::var("SCOPLEN_AGENT_SSH_PORT")?.parse::<u16>()?;

    let address = SocketAddr::from(([127, 0, 0, 1], agent_port));
    let stream = TcpStream::connect_timeout(&address, DEADLINE)?;
    stream.set_read_timeout(Some(DEADLINE))?;
    stream.set_write_timeout(Some(DEADLINE))?;
    let mut agent = AgentClient::new(FramedAgentChannel::new(stream));
    if !agent.identities()?.iter().any(|identity| identity.key_blob() == user_key) {
        return Err("requested identity is absent from OpenSSH agent".into());
    }
    let signer = AgentSshSigner::new(agent, SignatureAlgorithm::Ed25519, user_key)?;

    let config =
        ClientConfig::new("127.0.0.1", server_port, move |_host: &str, key: &HostKey| match key {
            HostKey::Raw { key_blob, .. } if *key_blob == host_key => Ok(()),
            _ => Err(HostKeyVerificationError::Rejected("unexpected OpenSSH host key".to_owned())),
        })?;
    let mut connection = timeout(DEADLINE, ClientConnection::connect(config)).await??;
    if mode == "certificate" {
        let certificate = Certificate::from_openssh(&env::var("SCOPLEN_AGENT_USER_CERT")?)?;
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let certificate = UserCertificate::parse_and_validate(
            &certificate.to_bytes()?,
            &CertificateValidationPolicy::user("scoplen", now),
        )?;
        let pinned_ca =
            PublicKey::from_openssh(&env::var("SCOPLEN_AGENT_USER_CA_KEY")?)?.to_bytes()?;
        if certificate.certificate().ca_public_key_blob() != pinned_ca {
            return Err("user certificate CA is not trusted".into());
        }
        timeout(DEADLINE, connection.authenticate_certificate("scoplen", &certificate, &signer))
            .await??;
    } else {
        timeout(DEADLINE, connection.authenticate_publickey("scoplen", &signer)).await??;
    }

    let mut channel = timeout(DEADLINE, connection.open_session()).await??;
    timeout(DEADLINE, channel.exec(true, b"printf scoplen-agent-ok")).await??;
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
    if output != b"scoplen-agent-ok" || status != Some(0) {
        return Err(format!("unexpected SSH command result: {status:?}, {output:?}").into());
    }
    timeout(DEADLINE, connection.disconnect()).await??;
    println!("openssh agent {mode} command ok");
    Ok(())
}
