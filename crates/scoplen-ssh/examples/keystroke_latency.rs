// SPDX-License-Identifier: Apache-2.0

use std::{
    borrow::Cow,
    env,
    error::Error,
    net::SocketAddr,
    process::Stdio,
    sync::Arc,
    time::{Duration, Instant},
};

use russh::{
    ChannelId, ChannelMsg,
    keys::{PrivateKey, PublicKeyOrCertificate},
};
use scoplen_crypto::Ed25519SigningKey;
use scoplen_ssh::{
    ChannelEvent, ClientConfig, ClientConnection, Ed25519SshSigner, HostKey,
    HostKeyVerificationError,
};
use ssh_key::{Algorithm, PrivateKey as SshPrivateKey, PublicKey};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    process::{ChildStdin, ChildStdout, Command},
    task::JoinHandle,
    time::timeout,
};

const WARMUP: usize = 100;
const SAMPLES: usize = 1_000;
const DEADLINE: Duration = Duration::from_secs(5);

#[derive(Clone)]
struct EchoServer;

impl russh::server::Handler for EchoServer {
    type Error = russh::Error;

    async fn auth_password(
        &mut self,
        user: &str,
        password: &str,
    ) -> Result<russh::server::Auth, Self::Error> {
        Ok(if user == "bench" && password == "disposable" {
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

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut russh::server::Session,
    ) -> Result<(), Self::Error> {
        session.data(channel, data.to_vec())
    }
}

async fn start_server() -> Result<(SocketAddr, Vec<u8>, JoinHandle<()>), Box<dyn Error>> {
    let host_key = PrivateKey::random(
        &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
        Algorithm::Ed25519,
    )?;
    let pinned_key = host_key.public_key().to_bytes()?;
    let mut config = russh::server::Config::default();
    config.keys.push(host_key);
    config.preferred.cipher = Cow::Borrowed(&[russh::cipher::CHACHA20_POLY1305]);
    let config = Arc::new(config);
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let task = tokio::spawn(async move {
        for _ in 0..2 {
            let Ok((stream, _)) = listener.accept().await else { return };
            stream.set_nodelay(true).expect("enable TCP_NODELAY on echo socket");
            let config = Arc::clone(&config);
            tokio::spawn(async move {
                let _ = russh::server::run_stream(config, stream, EchoServer).await;
            });
        }
    });
    Ok((address, pinned_key, task))
}

struct PinnedKey(Vec<u8>);

impl russh::client::Handler for PinnedKey {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        Ok(matches!(key, PublicKeyOrCertificate::PublicKey { key, .. }
            if key.to_bytes().ok().as_deref() == Some(self.0.as_slice())))
    }
}

fn summary(label: &str, values: &[Duration]) {
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    let at = |percent: usize| sorted[(sorted.len() * percent).div_ceil(100) - 1];
    println!(
        "summary client={label} n={} p50_us={:.3} p95_us={:.3} p99_us={:.3} min_us={:.3} max_us={:.3}",
        sorted.len(),
        micros(at(50)),
        micros(at(95)),
        micros(at(99)),
        micros(sorted[0]),
        micros(sorted[sorted.len() - 1]),
    );
}

fn micros(value: Duration) -> f64 {
    value.as_secs_f64() * 1_000_000.0
}

async fn scoplen_echo(
    channel: &mut scoplen_ssh::ClientChannel,
    byte: u8,
) -> Result<Duration, Box<dyn Error>> {
    let started = Instant::now();
    let event = timeout(DEADLINE, async {
        channel.send_data(&[byte]).await?;
        channel.next_event().await
    })
    .await??;
    match event {
        Some(ChannelEvent::Data(data)) if data == [byte] => Ok(started.elapsed()),
        other => Err(format!("unexpected Scoplen echo: {other:?}").into()),
    }
}

async fn russh_echo(
    channel: &mut russh::Channel<russh::client::Msg>,
    byte: u8,
) -> Result<Duration, Box<dyn Error>> {
    let started = Instant::now();
    let event = timeout(DEADLINE, async {
        channel.data_bytes(vec![byte]).await?;
        Ok::<_, russh::Error>(channel.wait().await)
    })
    .await??;
    match event {
        Some(ChannelMsg::Data { data }) if data.as_ref() == [byte] => Ok(started.elapsed()),
        other => Err(format!("unexpected russh echo: {other:?}").into()),
    }
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> Result<(), Box<dyn Error>> {
    match env::args().skip(1).collect::<Vec<_>>().as_slice() {
        [] => compare_in_process().await,
        [mode] if mode == "--openssh" => compare_openssh().await,
        _ => Err("usage: keystroke_latency [--openssh]".into()),
    }
}

async fn compare_in_process() -> Result<(), Box<dyn Error>> {
    let (address, pinned_key, server) = start_server().await?;
    let scoplen_pin = pinned_key.clone();
    let verifier = move |_host: &str, key: &HostKey| match key {
        HostKey::Raw { key_blob, .. } if *key_blob == scoplen_pin => Ok(()),
        _ => Err(HostKeyVerificationError::Rejected("unexpected disposable host key".into())),
    };
    let config = ClientConfig::new("127.0.0.1", address.port(), verifier)?;
    let mut scoplen = ClientConnection::connect(config).await?;
    scoplen.authenticate_password("bench", b"disposable").await?;
    let mut scoplen_channel = scoplen.open_session().await?;

    let russh_config = Arc::new(russh::client::Config { nodelay: true, ..Default::default() });
    let mut russh = russh::client::connect(russh_config, address, PinnedKey(pinned_key)).await?;
    if !matches!(
        russh.authenticate_password("bench", "disposable").await?,
        russh::client::AuthResult::Success
    ) {
        return Err("direct russh authentication failed".into());
    }
    let mut russh_channel = russh.channel_open_session().await?;

    let mut scoplen_samples = Vec::with_capacity(SAMPLES);
    let mut russh_samples = Vec::with_capacity(SAMPLES);
    println!(
        "fixture=loopback-ssh server=russh-0.65.0 cipher=chacha20-poly1305@openssh.com warmup={WARMUP} samples={SAMPLES} payload_bytes=1 nodelay=true"
    );
    for trial in 0..WARMUP + SAMPLES {
        let byte = u8::try_from(trial % 251)?;
        let (scoplen_time, russh_time) = if trial % 2 == 0 {
            (
                scoplen_echo(&mut scoplen_channel, byte).await?,
                russh_echo(&mut russh_channel, byte).await?,
            )
        } else {
            let russh_time = russh_echo(&mut russh_channel, byte).await?;
            (scoplen_echo(&mut scoplen_channel, byte).await?, russh_time)
        };
        if trial >= WARMUP {
            let sample = trial - WARMUP + 1;
            println!(
                "sample={sample} scoplen_us={:.3} russh_us={:.3}",
                micros(scoplen_time),
                micros(russh_time)
            );
            scoplen_samples.push(scoplen_time);
            russh_samples.push(russh_time);
        }
    }
    summary("scoplen", &scoplen_samples);
    summary("russh", &russh_samples);
    scoplen.disconnect().await?;
    russh.disconnect(russh::Disconnect::ByApplication, "", "en").await?;
    server.await?;
    Ok(())
}

struct ExternalSettings {
    host: String,
    port: u16,
    user: String,
    key_path: String,
    host_key: String,
    known_hosts_path: String,
    ssh_config_path: String,
    ssh_executable: String,
    cipher: String,
}

impl ExternalSettings {
    fn from_environment() -> Result<Self, Box<dyn Error>> {
        let required = |name: &str| -> Result<String, Box<dyn Error>> {
            let value = env::var(name)?;
            if value.is_empty() {
                return Err(format!("{name} must be nonempty").into());
            }
            Ok(value)
        };
        let cipher = required("SCOPLEN_BENCH_CIPHER")?;
        if !matches!(cipher.as_str(), "chacha20-poly1305@openssh.com" | "aes256-gcm@openssh.com") {
            return Err("SCOPLEN_BENCH_CIPHER must name one required S4 cipher".into());
        }
        let port = required("SCOPLEN_BENCH_PORT")?.parse::<u16>()?;
        if port == 0 {
            return Err("SCOPLEN_BENCH_PORT must be nonzero".into());
        }
        Ok(Self {
            host: required("SCOPLEN_BENCH_HOST")?,
            port,
            user: required("SCOPLEN_BENCH_USER")?,
            key_path: required("SCOPLEN_BENCH_KEY")?,
            host_key: required("SCOPLEN_BENCH_HOST_KEY")?,
            known_hosts_path: required("SCOPLEN_BENCH_KNOWN_HOSTS")?,
            ssh_config_path: required("SCOPLEN_BENCH_SSH_CONFIG")?,
            ssh_executable: required("SCOPLEN_BENCH_SSH")?,
            cipher,
        })
    }
}

async fn openssh_echo(
    stdin: &mut ChildStdin,
    stdout: &mut ChildStdout,
    byte: u8,
) -> Result<Duration, Box<dyn Error>> {
    let started = Instant::now();
    let mut echoed = [0];
    timeout(DEADLINE, async {
        stdin.write_all(&[byte]).await?;
        stdin.flush().await?;
        stdout.read_exact(&mut echoed).await
    })
    .await??;
    if echoed != [byte] {
        return Err(format!("unexpected OpenSSH echo: {echoed:?}, expected {byte}").into());
    }
    Ok(started.elapsed())
}

async fn measure_external(
    channel: &mut scoplen_ssh::ClientChannel,
    stdin: &mut ChildStdin,
    stdout: &mut ChildStdout,
) -> Result<(Vec<Duration>, Vec<Duration>), Box<dyn Error>> {
    let mut scoplen_samples = Vec::with_capacity(SAMPLES);
    let mut openssh_samples = Vec::with_capacity(SAMPLES);
    for trial in 0..WARMUP + SAMPLES {
        let byte = u8::try_from(trial % 251)?;
        let (scoplen_time, openssh_time) = if trial % 2 == 0 {
            (scoplen_echo(channel, byte).await?, openssh_echo(stdin, stdout, byte).await?)
        } else {
            let openssh_time = openssh_echo(stdin, stdout, byte).await?;
            (scoplen_echo(channel, byte).await?, openssh_time)
        };
        if trial >= WARMUP {
            let sample = trial - WARMUP + 1;
            println!(
                "sample={sample} scoplen_us={:.3} openssh_us={:.3}",
                micros(scoplen_time),
                micros(openssh_time)
            );
            scoplen_samples.push(scoplen_time);
            openssh_samples.push(openssh_time);
        }
    }
    Ok((scoplen_samples, openssh_samples))
}

async fn compare_openssh() -> Result<(), Box<dyn Error>> {
    let settings = ExternalSettings::from_environment()?;
    let expected = PublicKey::from_openssh(&settings.host_key)?.to_bytes()?;
    let verifier = move |_host: &str, key: &HostKey| match key {
        HostKey::Raw { key_blob, .. } if *key_blob == expected => Ok(()),
        _ => Err(HostKeyVerificationError::Rejected("benchmark host key changed".into())),
    };
    let config = ClientConfig::new(settings.host.as_str(), settings.port, verifier)?;
    let mut scoplen = ClientConnection::connect(config).await?;
    let key = SshPrivateKey::read_openssh_file(&settings.key_path)?;
    let keypair = key.key_data().ed25519().ok_or("benchmark key must be Ed25519")?;
    let signer = Ed25519SshSigner::new(Ed25519SigningKey::from_bytes(keypair.private.as_ref())?);
    scoplen.authenticate_publickey(&settings.user, &signer).await?;
    let mut channel = scoplen.open_session().await?;
    channel.exec(true, b"cat").await?;
    match timeout(DEADLINE, channel.next_event()).await?? {
        Some(ChannelEvent::Success) => {}
        other => return Err(format!("OpenSSH server rejected cat: {other:?}").into()),
    }

    let mut command = Command::new(&settings.ssh_executable);
    command.args([
        "-T",
        "-F",
        &settings.ssh_config_path,
        "-p",
        &settings.port.to_string(),
        "-c",
        &settings.cipher,
        "-i",
        &settings.key_path,
        "-o",
        "BatchMode=yes",
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "PreferredAuthentications=publickey",
        "-o",
        "Compression=no",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        &format!("UserKnownHostsFile={}", settings.known_hosts_path),
        &format!("{}@{}", settings.user, settings.host),
        "cat",
    ]);
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(true);
    let mut child = command.spawn()?;
    let mut stdin = child.stdin.take().ok_or("OpenSSH stdin not piped")?;
    let mut stdout = child.stdout.take().ok_or("OpenSSH stdout not piped")?;

    println!(
        "fixture=external-openssh cipher={} warmup={WARMUP} samples={SAMPLES} payload_bytes=1",
        settings.cipher
    );
    let (scoplen_samples, openssh_samples) =
        match measure_external(&mut channel, &mut stdin, &mut stdout).await {
            Ok(samples) => samples,
            Err(error) => {
                let _ = child.start_kill();
                let _ = timeout(DEADLINE, child.wait()).await;
                return Err(error);
            }
        };
    summary("scoplen", &scoplen_samples);
    summary("openssh", &openssh_samples);
    drop(stdin);
    let status = match timeout(DEADLINE, child.wait()).await {
        Ok(result) => result?,
        Err(error) => {
            let _ = child.start_kill();
            let _ = timeout(DEADLINE, child.wait()).await;
            return Err(error.into());
        }
    };
    if !status.success() {
        return Err(format!("OpenSSH exited with {status}").into());
    }
    channel.send_eof().await?;
    scoplen.disconnect().await?;
    Ok(())
}
