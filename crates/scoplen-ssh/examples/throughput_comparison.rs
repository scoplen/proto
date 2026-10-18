// SPDX-License-Identifier: Apache-2.0

use std::{
    env,
    error::Error,
    io::{self, Write},
    process::Stdio,
    time::{Duration, Instant},
};

use scoplen_crypto::Ed25519SigningKey;
use scoplen_ssh::{
    ChannelEvent, ClientConfig, ClientConnection, Ed25519SshSigner, HostKey,
    HostKeyVerificationError,
};
use ssh_key::{PrivateKey, PublicKey};
use tokio::{io::AsyncReadExt, process::Command, time::timeout};

const MIB: u64 = 1024 * 1024;
const BLOCK_SIZE: u64 = 64 * 1024;
const BUFFER_SIZE: usize = 64 * 1024;
const TRIAL_TIMEOUT: Duration = Duration::from_secs(120);

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    match env::args().skip(1).collect::<Vec<_>>().as_slice() {
        [] => compare().await,
        [mode] if mode == "--scoplen-child" => scoplen_child().await,
        _ => Err("usage: throughput_comparison [--scoplen-child]".into()),
    }
}

struct Settings {
    host: String,
    port: u16,
    username: String,
    key_path: String,
    host_key: String,
    known_hosts_path: String,
    ssh_config_path: String,
    cipher: String,
    bytes: u64,
    samples: usize,
    ssh_executable: String,
}

impl Settings {
    fn from_environment() -> Result<Self, Box<dyn Error>> {
        let cipher = required("SCOPLEN_BENCH_CIPHER")?;
        if !matches!(cipher.as_str(), "chacha20-poly1305@openssh.com" | "aes256-gcm@openssh.com") {
            return Err("SCOPLEN_BENCH_CIPHER must name one required S4 cipher".into());
        }
        let bytes = required("SCOPLEN_BENCH_BYTES")?.parse::<u64>()?;
        if !(16 * MIB..=1024 * MIB).contains(&bytes) || bytes % BLOCK_SIZE != 0 {
            return Err("SCOPLEN_BENCH_BYTES must be 16 MiB to 1 GiB in 64 KiB blocks".into());
        }
        let samples = required("SCOPLEN_BENCH_SAMPLES")?.parse::<usize>()?;
        if !(3..=20).contains(&samples) {
            return Err("SCOPLEN_BENCH_SAMPLES must be between 3 and 20".into());
        }
        Ok(Self {
            host: required("SCOPLEN_BENCH_HOST")?,
            port: required("SCOPLEN_BENCH_PORT")?.parse()?,
            username: required("SCOPLEN_BENCH_USER")?,
            key_path: required("SCOPLEN_BENCH_KEY")?,
            host_key: required("SCOPLEN_BENCH_HOST_KEY")?,
            known_hosts_path: required("SCOPLEN_BENCH_KNOWN_HOSTS")?,
            ssh_config_path: required("SCOPLEN_BENCH_SSH_CONFIG")?,
            cipher,
            bytes,
            samples,
            ssh_executable: required("SCOPLEN_BENCH_SSH")?,
        })
    }

    fn remote_command(&self) -> String {
        format!("dd if=/dev/zero bs={BLOCK_SIZE} count={} 2>/dev/null", self.bytes / BLOCK_SIZE)
    }
}

fn required(name: &str) -> Result<String, Box<dyn Error>> {
    let value = env::var(name)?;
    if value.is_empty() {
        return Err(format!("{name} must be nonempty").into());
    }
    Ok(value)
}

#[derive(Clone, Copy)]
enum Client {
    OpenSsh,
    Scoplen,
}

impl Client {
    fn label(self) -> &'static str {
        match self {
            Self::OpenSsh => "openssh",
            Self::Scoplen => "scoplen",
        }
    }
}

async fn compare() -> Result<(), Box<dyn Error>> {
    let settings = Settings::from_environment()?;
    let executable = env::current_exe()?;
    let mut openssh_rates = Vec::with_capacity(settings.samples);
    let mut scoplen_rates = Vec::with_capacity(settings.samples);
    println!(
        "cipher={} bytes={} warmups=1 samples={}",
        settings.cipher, settings.bytes, settings.samples
    );
    for trial in 0..=settings.samples {
        let order = if trial % 2 == 0 {
            [Client::OpenSsh, Client::Scoplen]
        } else {
            [Client::Scoplen, Client::OpenSsh]
        };
        for client in order {
            let command = match client {
                Client::OpenSsh => openssh_command(&settings),
                Client::Scoplen => {
                    let mut command = Command::new(&executable);
                    command.arg("--scoplen-child");
                    command
                }
            };
            let elapsed = measure(command, settings.bytes).await?;
            let blocks = u32::try_from(settings.bytes / BLOCK_SIZE)?;
            let mib_per_second = f64::from(blocks) / 16.0 / elapsed.as_secs_f64();
            if trial == 0 {
                println!("warmup client={} mib_per_second={mib_per_second:.2}", client.label());
            } else {
                println!(
                    "sample={} client={} seconds={:.6} mib_per_second={mib_per_second:.2}",
                    trial,
                    client.label(),
                    elapsed.as_secs_f64()
                );
                match client {
                    Client::OpenSsh => openssh_rates.push(mib_per_second),
                    Client::Scoplen => scoplen_rates.push(mib_per_second),
                }
            }
        }
    }
    let openssh = median(&mut openssh_rates);
    let scoplen = median(&mut scoplen_rates);
    let ratio = 100.0 * scoplen / openssh;
    println!(
        "median cipher={} openssh_mib_per_second={openssh:.2} scoplen_mib_per_second={scoplen:.2} ratio_percent={ratio:.2} meets_80_percent={}",
        settings.cipher,
        ratio >= 80.0
    );
    Ok(())
}

fn openssh_command(settings: &Settings) -> Command {
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
        &format!("{}@{}", settings.username, settings.host),
        &settings.remote_command(),
    ]);
    command
}

async fn measure(mut command: Command, expected: u64) -> Result<Duration, Box<dyn Error>> {
    command.stdout(Stdio::piped()).stderr(Stdio::inherit()).kill_on_drop(true);
    let mut child = command.spawn()?;
    let mut stdout = child.stdout.take().ok_or("child stdout was not piped")?;
    let measured = timeout(TRIAL_TIMEOUT, async {
        let mut buffer = vec![0u8; BUFFER_SIZE];
        let mut received = 0u64;
        let mut started = None;
        let mut finished = None;
        loop {
            let count = stdout.read(&mut buffer).await?;
            if count == 0 {
                break;
            }
            if started.is_none() {
                started = Some(Instant::now());
            }
            if buffer[..count].iter().any(|&byte| byte != 0) {
                return Err("remote output was not the expected zero stream".into());
            }
            received = received.checked_add(count as u64).ok_or("output byte count overflow")?;
            if received > expected {
                return Err("remote output exceeded the requested byte count".into());
            }
            if received == expected && finished.is_none() {
                finished = Some(Instant::now());
            }
        }
        let status = child.wait().await?;
        if !status.success() {
            return Err(format!("child exited with {status}").into());
        }
        if received != expected {
            return Err(format!("expected {expected} bytes, received {received}").into());
        }
        Ok::<_, Box<dyn Error>>(
            finished.ok_or("no terminal data was received")?.duration_since(started.unwrap()),
        )
    })
    .await
    .map_err(|_| format!("trial exceeded {} seconds", TRIAL_TIMEOUT.as_secs()))??;
    Ok(measured)
}

fn median(values: &mut [f64]) -> f64 {
    values.sort_by(f64::total_cmp);
    let middle = values.len() / 2;
    if values.len().is_multiple_of(2) {
        f64::midpoint(values[middle - 1], values[middle])
    } else {
        values[middle]
    }
}

async fn scoplen_child() -> Result<(), Box<dyn Error>> {
    let settings = Settings::from_environment()?;
    let expected = PublicKey::from_openssh(&settings.host_key)?.to_bytes()?;
    let verifier = move |_host: &str, key: &HostKey| match key {
        HostKey::Raw { key_blob, .. } if *key_blob == expected => Ok(()),
        _ => Err(HostKeyVerificationError::Rejected("benchmark host key changed".to_owned())),
    };
    let config = ClientConfig::new(settings.host.as_str(), settings.port, verifier)?;
    let mut connection = ClientConnection::connect(config).await?;
    let key = PrivateKey::read_openssh_file(&settings.key_path)?;
    let keypair = key.key_data().ed25519().ok_or("benchmark key must be Ed25519")?;
    let signer = Ed25519SshSigner::new(Ed25519SigningKey::from_bytes(keypair.private.as_ref())?);
    connection.authenticate_publickey(&settings.username, &signer).await?;
    let mut channel = connection.open_session().await?;
    channel.exec(true, settings.remote_command().as_bytes()).await?;
    let mut stdout = io::stdout().lock();
    let mut received = 0u64;
    let mut exit_status = None;
    loop {
        match channel.next_event().await? {
            Some(ChannelEvent::Data(data)) => {
                received = received.checked_add(data.len() as u64).ok_or("byte count overflow")?;
                if received > settings.bytes {
                    return Err("server sent more bytes than requested".into());
                }
                stdout.write_all(&data)?;
            }
            Some(ChannelEvent::Success | ChannelEvent::Eof) => {}
            Some(ChannelEvent::ExitStatus(status)) => exit_status = Some(status),
            Some(ChannelEvent::Close) | None => break,
            Some(other) => return Err(format!("unexpected SSH event: {other:?}").into()),
        }
    }
    stdout.flush()?;
    if received != settings.bytes || exit_status != Some(0) {
        return Err(format!(
            "server sent {received} of {} bytes with exit status {exit_status:?}",
            settings.bytes
        )
        .into());
    }
    connection.disconnect().await?;
    Ok(())
}
