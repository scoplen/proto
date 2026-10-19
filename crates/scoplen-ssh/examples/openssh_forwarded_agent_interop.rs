// SPDX-License-Identifier: Apache-2.0
//! Exercise OpenSSH's second-hop public-key authentication through a forwarded agent.

#[cfg(not(unix))]
fn main() {
    eprintln!("the forwarded-agent interoperability fixture requires Unix sockets");
    std::process::exit(2);
}

#[cfg(unix)]
mod unix {
    use std::{
        env,
        os::unix::net::UnixStream,
        sync::{
            Arc, Mutex,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };

    use scoplen_ssh::{
        AgentClient, AgentError, AgentForwardingAuthorizer, AgentForwardingPolicy, AgentIdentity,
        AgentKeyStore, AgentServer, ChannelEvent, ClientChannel, ClientConfig, ClientConnection,
        FramedAgentChannel, HostKey, HostKeyVerificationError,
    };
    use ssh_key::PublicKey;
    use tokio::time::timeout;

    const STEP_TIMEOUT: Duration = Duration::from_secs(10);
    const SECOND_HOP: &[u8] = b"ssh -p 2223 -o BatchMode=yes -o PasswordAuthentication=no -o PreferredAuthentications=publickey -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=/home/scoplen/.ssh/known_hosts -i /home/scoplen/.ssh/second.pub scoplen@127.0.0.1 'printf second-hop-ok'";
    const REMOVE_ALL: &[u8] = br#"python3 - <<'PY'
import os
import socket
import struct

with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as agent:
    agent.settimeout(5)
    agent.connect(os.environ["SSH_AUTH_SOCK"])
    reader = agent.makefile("rb")

    def exchange(message):
        agent.sendall(struct.pack(">I", len(message)) + message)
        length_bytes = reader.read(4)
        if len(length_bytes) != 4:
            raise RuntimeError("agent response header was truncated")
        length = struct.unpack(">I", length_bytes)[0]
        if length > 65536:
            raise RuntimeError("agent response was too large")
        response = reader.read(length)
        if len(response) != length:
            raise RuntimeError("agent response was truncated")
        return response

    if exchange(b"\x13") != b"\x05":
        raise RuntimeError("forwarded agent accepted remove-all")
    identities = exchange(b"\x0b")
    if len(identities) < 5 or identities[0] != 12 or struct.unpack(">I", identities[1:5])[0] != 1:
        raise RuntimeError("forwarded agent lost its identity after refusal")

print("remove-all-denied", end="")
PY"#;

    type NativeAgent = AgentClient<FramedAgentChannel<UnixStream>>;

    struct SourceAgent {
        client: Mutex<NativeAgent>,
        signs: Arc<AtomicUsize>,
        removals: Arc<AtomicUsize>,
    }

    impl AgentKeyStore for SourceAgent {
        fn identities(&self) -> Result<Vec<AgentIdentity>, AgentError> {
            self.client.lock().map_err(|_| AgentError::AgentFailure)?.identities()
        }

        fn sign(&self, key_blob: &[u8], data: &[u8], flags: u32) -> Result<Vec<u8>, AgentError> {
            self.signs.fetch_add(1, Ordering::SeqCst);
            self.client.lock().map_err(|_| AgentError::AgentFailure)?.sign(key_blob, data, flags)
        }

        fn remove_all_identities(&self) -> Result<(), AgentError> {
            self.removals.fetch_add(1, Ordering::SeqCst);
            self.client.lock().map_err(|_| AgentError::AgentFailure)?.remove_all_identities()
        }
    }

    struct Authorizer {
        allowed: bool,
        expected_key: Vec<u8>,
        calls: Arc<AtomicUsize>,
    }

    impl AgentForwardingAuthorizer for Authorizer {
        fn authorize_signature(
            &self,
            key_blob: &[u8],
            data: &[u8],
            flags: u32,
        ) -> Result<(), AgentError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.allowed && key_blob == self.expected_key && !data.is_empty() && flags == 0 {
                Ok(())
            } else {
                Err(AgentError::AgentFailure)
            }
        }
    }

    #[derive(Clone, Copy, Eq, PartialEq)]
    enum Case {
        Allow,
        Disabled,
        Denied,
        RemoveAll,
    }

    struct Observed<'a> {
        output: &'a [u8],
        stderr: &'a [u8],
        status: Option<u32>,
        channels: usize,
        signed: usize,
        removed: usize,
        authorized: usize,
    }

    impl Case {
        fn parse(value: &str) -> Result<Self, &'static str> {
            match value {
                "allow" => Ok(Self::Allow),
                "disabled" => Ok(Self::Disabled),
                "denied" => Ok(Self::Denied),
                "remove-all" => Ok(Self::RemoveAll),
                _ => Err("expected allow, disabled, denied, or remove-all"),
            }
        }

        fn name(self) -> &'static str {
            match self {
                Self::Allow => "allow",
                Self::Disabled => "disabled",
                Self::Denied => "denied",
                Self::RemoveAll => "remove-all",
            }
        }
    }

    fn case_arg() -> Result<Case, Box<dyn std::error::Error>> {
        let mut args = env::args().skip(1);
        let case = Case::parse(&args.next().ok_or("missing case")?)?;
        if args.next().is_some() {
            return Err("expected exactly one case".into());
        }
        Ok(case)
    }

    fn source_agent(
        path: &str,
        signs: Arc<AtomicUsize>,
        removals: Arc<AtomicUsize>,
    ) -> Result<SourceAgent, Box<dyn std::error::Error>> {
        let stream = UnixStream::connect(path)?;
        stream.set_read_timeout(Some(STEP_TIMEOUT))?;
        stream.set_write_timeout(Some(STEP_TIMEOUT))?;
        Ok(SourceAgent {
            client: Mutex::new(AgentClient::new(FramedAgentChannel::new(stream))),
            signs,
            removals,
        })
    }

    fn require_source_key(socket: &str, key: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
        let agent =
            source_agent(socket, Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)))?;
        if !agent.identities()?.iter().any(|identity| identity.key_blob() == key) {
            return Err("second-hop identity is absent from the source agent".into());
        }
        Ok(())
    }

    async fn first_hop(
        port: u16,
        host_key: Vec<u8>,
    ) -> Result<(ClientConnection, ClientChannel), Box<dyn std::error::Error>> {
        let config =
            ClientConfig::new("127.0.0.1", port, move |_host: &str, key: &HostKey| match key {
                HostKey::Raw { key_blob, .. } if *key_blob == host_key => Ok(()),
                _ => {
                    Err(HostKeyVerificationError::Rejected("unexpected first-hop host key".into()))
                }
            })?;
        let mut connection = timeout(STEP_TIMEOUT, ClientConnection::connect(config))
            .await
            .map_err(|_| "first-hop connect timed out")??;
        timeout(STEP_TIMEOUT, connection.authenticate_password("scoplen", b"fixture-first-hop"))
            .await
            .map_err(|_| "first-hop password authentication timed out")??;
        let session = timeout(STEP_TIMEOUT, connection.open_session())
            .await
            .map_err(|_| "first-hop session open timed out")??;
        timeout(STEP_TIMEOUT, session.request_agent_forward(false))
            .await
            .map_err(|_| "agent-forward request timed out")??;
        Ok((connection, session))
    }

    pub async fn run() -> Result<(), Box<dyn std::error::Error>> {
        let case = case_arg()?;
        let socket = env::var("SCOPLEN_FORWARD_AGENT_SOCKET")?;
        let host_key =
            PublicKey::from_openssh(&env::var("SCOPLEN_FORWARD_HOST_KEY")?)?.to_bytes()?;
        let user_key =
            PublicKey::from_openssh(&env::var("SCOPLEN_FORWARD_USER_KEY")?)?.to_bytes()?;
        let port = env::var("SCOPLEN_FORWARD_SSH_PORT")?.parse::<u16>()?;
        let signs = Arc::new(AtomicUsize::new(0));
        let removals = Arc::new(AtomicUsize::new(0));
        let approvals = Arc::new(AtomicUsize::new(0));
        require_source_key(&socket, &user_key)?;

        let (mut connection, mut session) = first_hop(port, host_key).await?;
        let command = if case == Case::RemoveAll { REMOVE_ALL } else { SECOND_HOP };
        timeout(STEP_TIMEOUT, session.exec(true, command))
            .await
            .map_err(|_| "first-hop exec request timed out")??;
        let mut output = Vec::new();
        let mut stderr = Vec::new();
        let mut status = None;
        let mut forwarded_tasks = tokio::task::JoinSet::new();
        let mut channels = 0;
        loop {
            tokio::select! {
                forwarded = connection.next_forwarded_channel() => {
                    let forwarded = forwarded.ok_or("forwarded channel queue closed")?;
                    channels += 1;
                    let store = source_agent(&socket, Arc::clone(&signs), Arc::clone(&removals))?;
                    let authorizer = Authorizer {
                        allowed: case != Case::Denied,
                        expected_key: user_key.clone(),
                        calls: Arc::clone(&approvals),
                    };
                    let policy = if case == Case::Disabled {
                        AgentForwardingPolicy::disabled(authorizer)
                    } else {
                        AgentForwardingPolicy::enabled(authorizer)
                    };
                    forwarded_tasks.spawn(async move {
                        forwarded.serve_agent(AgentServer::new(store), policy).await
                    });
                }
                event = timeout(STEP_TIMEOUT, session.next_event()) => {
                    let event = event.map_err(|_| format!(
                        "first-hop command event timed out: channels={channels}, signs={}, authorizer_calls={}, stderr={stderr:?}",
                        signs.load(Ordering::SeqCst), approvals.load(Ordering::SeqCst),
                    ))??;
                    match event {
                        Some(ChannelEvent::Data(data)) => output.extend_from_slice(&data),
                        Some(ChannelEvent::ExitStatus(code)) => status = Some(code),
                        Some(ChannelEvent::Close) | None => break,
                        Some(ChannelEvent::Eof | ChannelEvent::Success) => {},
                        Some(ChannelEvent::ExtendedData { data, .. }) => stderr.extend_from_slice(&data),
                        other => return Err(format!("unexpected first-hop event: {other:?}").into()),
                    }
                }
                result = forwarded_tasks.join_next(), if !forwarded_tasks.is_empty() => {
                    result.ok_or("forwarded-agent task set ended unexpectedly")???;
                }
            }
        }
        timeout(STEP_TIMEOUT, connection.disconnect())
            .await
            .map_err(|_| "first-hop disconnect timed out")??;
        while let Some(task) = timeout(STEP_TIMEOUT, forwarded_tasks.join_next())
            .await
            .map_err(|_| "forwarded-agent channel did not close")?
        {
            task??;
        }
        let signed = signs.load(Ordering::SeqCst);
        let removed = removals.load(Ordering::SeqCst);
        let authorized = approvals.load(Ordering::SeqCst);
        verify_result(
            case,
            &Observed {
                output: &output,
                stderr: &stderr,
                status,
                channels,
                signed,
                removed,
                authorized,
            },
        )?;
        require_source_key(&socket, &user_key)?;
        println!(
            "forwarded-agent {} ok: channels={channels}, signs={signed}, removals={removed}, authorizer_calls={authorized}",
            case.name()
        );
        Ok(())
    }

    fn verify_result(
        case: Case,
        observed: &Observed<'_>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let &Observed { output, stderr, status, channels, signed, removed, authorized } = observed;
        if removed != 0 {
            return Err(format!(
                "forwarded agent reached source remove-all operation {removed} times"
            )
            .into());
        }
        match case {
            Case::Allow
                if output == b"second-hop-ok"
                    && status == Some(0)
                    && signed > 0
                    && signed == authorized => {}
            Case::Disabled
                if status == Some(255) && channels > 0 && signed == 0 && authorized == 0 => {}
            Case::Denied if status == Some(255) && signed == 0 && authorized > 0 => {}
            Case::RemoveAll
                if output == b"remove-all-denied"
                    && status == Some(0)
                    && signed == 0
                    && authorized == 0 => {}
            _ => return Err(format!("unexpected {} result: status={status:?}, output={output:?}, stderr={stderr:?}, channels={channels}, signs={signed}, removals={removed}, authorizer_calls={authorized}", case.name()).into()),
        }
        Ok(())
    }
}

#[cfg(unix)]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    unix::run().await
}
