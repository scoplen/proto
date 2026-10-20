// SPDX-License-Identifier: Apache-2.0
//! Exercise the native Windows OpenSSH agent against a disposable SSH server.

#[cfg(not(windows))]
fn main() {
    eprintln!("the native Windows agent example requires Windows");
    std::process::exit(1);
}

#[cfg(windows)]
mod windows {
    use std::{env, io, sync::Arc, time::Duration};

    use russh::keys::PrivateKey;
    use scoplen_ssh::{
        AgentSshSigner, ChannelEvent, ClientConfig, ClientConnection, HostKey,
        HostKeyVerificationError, SignatureAlgorithm, connect_windows_agent,
    };
    use ssh_key::{Algorithm, PublicKey};
    use tokio::{net::TcpListener, time::timeout};

    const DEADLINE: Duration = Duration::from_secs(10);

    struct CommandServer {
        expected_key: Vec<u8>,
    }

    impl russh::server::Handler for CommandServer {
        type Error = russh::Error;

        async fn auth_publickey(
            &mut self,
            user: &str,
            key: &PublicKey,
        ) -> Result<russh::server::Auth, Self::Error> {
            Ok(if user == "scoplen" && key.to_bytes().is_ok_and(|blob| blob == self.expected_key) {
                russh::server::Auth::Accept
            } else {
                russh::server::Auth::reject()
            })
        }

        async fn channel_open_session(
            &mut self,
            _channel: russh::Channel<russh::server::Msg>,
            reply: russh::server::ChannelOpenHandle,
            _session: &mut russh::server::Session,
        ) -> Result<(), Self::Error> {
            reply.accept().await;
            Ok(())
        }

        async fn exec_request(
            &mut self,
            channel: russh::ChannelId,
            command: &[u8],
            session: &mut russh::server::Session,
        ) -> Result<(), Self::Error> {
            if command == b"printf scoplen-agent-ok" {
                session.channel_success(channel)?;
                session.data(channel, b"scoplen-agent-ok".to_vec())?;
                session.exit_status_request(channel, 0)?;
            } else {
                session.channel_failure(channel)?;
                session.exit_status_request(channel, 1)?;
            }
            session.eof(channel)?;
            session.close(channel)?;
            Ok(())
        }
    }

    #[tokio::main]
    pub async fn main() -> Result<(), Box<dyn std::error::Error>> {
        let mode = env::args().nth(1).ok_or("expected raw or wrong-host mode")?;
        if !matches!(mode.as_str(), "raw" | "wrong-host") || env::args().nth(2).is_some() {
            return Err("expected exactly one raw or wrong-host mode".into());
        }
        let user_key = PublicKey::from_openssh(&env::var("SCOPLEN_AGENT_USER_KEY")?)?.to_bytes()?;
        let agent = connect_windows_agent(env::var("SCOPLEN_AGENT_PIPE")?).map_err(|error| {
            if error.kind() == io::ErrorKind::NotFound {
                io::Error::new(error.kind(), "Windows agent pipe not found")
            } else {
                error
            }
        })?;
        let mut agent = agent;
        if !agent.identities()?.iter().any(|identity| identity.key_blob() == user_key) {
            return Err("requested identity is absent from Windows OpenSSH agent".into());
        }
        let signer = AgentSshSigner::new(agent, SignatureAlgorithm::Ed25519, user_key.clone())?;

        let mut server_config = russh::server::Config::default();
        server_config.keys.push(PrivateKey::random(
            &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
            Algorithm::Ed25519,
        )?);
        let host_key = server_config.keys[0].public_key().to_bytes()?;
        let expected_host_key = if mode == "wrong-host" { user_key.clone() } else { host_key };
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await?;
            let session = russh::server::run_stream(
                Arc::new(server_config),
                stream,
                CommandServer { expected_key: user_key },
            )
            .await?;
            let _ = session.await;
            Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
        });

        let config =
            ClientConfig::new("127.0.0.1", port, move |_host: &str, key: &HostKey| match key {
                HostKey::Raw { key_blob, .. } if *key_blob == expected_host_key => Ok(()),
                _ => Err(HostKeyVerificationError::Rejected("unexpected test host key".to_owned())),
            })?;
        let mut connection = timeout(DEADLINE, ClientConnection::connect(config)).await??;
        timeout(DEADLINE, connection.authenticate_publickey("scoplen", &signer)).await??;
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
        timeout(DEADLINE, server).await??.map_err(|error| error.to_string())?;
        println!("windows agent SSH command ok");
        Ok(())
    }
}

#[cfg(windows)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    windows::main()
}
