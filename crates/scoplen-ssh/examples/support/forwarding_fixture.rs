// SPDX-License-Identifier: Apache-2.0
//! Shared assertions for the disposable SSH forwarding fixtures.

use std::{env, time::Duration};

use scoplen_ssh::{ChannelEvent, ClientConnection};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    time::timeout,
};

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
pub const ECHO_PORT: u16 = 2444;
const ECHO_TRAILER: &[u8] = b"\0scoplen-forward-eof\xff";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Peer {
    OpenSsh,
    Dropbear,
}

impl Peer {
    pub fn from_env() -> Result<Self> {
        let profile = match env::var("SCOPLEN_OPENSSH_SFTP_PROFILE") {
            Ok(value) => Some(value),
            Err(env::VarError::NotPresent) => None,
            Err(error) => return Err(error.into()),
        };
        Self::from_profile(profile.as_deref())
    }

    fn from_profile(profile: Option<&str>) -> Result<Self> {
        match profile {
            None | Some("8.8p1") => Ok(Self::OpenSsh),
            Some("dropbear-2024.86") => Ok(Self::Dropbear),
            Some(_) => Err("unknown SSH interoperability fixture profile".into()),
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::OpenSsh => "openssh",
            Self::Dropbear => "dropbear",
        }
    }

    pub fn matches_banner(self, banner: &[u8]) -> bool {
        match self {
            Self::OpenSsh => banner.starts_with(b"SSH-2.0-OpenSSH_") && banner.ends_with(b"\r\n"),
            Self::Dropbear => banner == b"SSH-2.0-dropbear_2024.86\r\n",
        }
    }

    pub fn denied_port(self) -> Result<Option<u16>> {
        if self == Self::OpenSsh {
            return Ok(None);
        }
        let port = env::var("SCOPLEN_DROPBEAR_FORWARD_DENIED_PORT")?.parse::<u16>()?;
        if port == 0 {
            return Err("Dropbear forwarding-denied fixture port must be nonzero".into());
        }
        Ok(Some(port))
    }
}

pub async fn verify_binary_pair<S>(first: S, second: S) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // The target waits for payload from both peers before echoing; a serialized copy fails.
    timeout(Duration::from_secs(20), async {
        tokio::try_join!(
            binary_roundtrip(first, 131_087, 0),
            binary_roundtrip(second, 196_613, 73)
        )?;
        Ok::<_, Box<dyn std::error::Error>>(())
    })
    .await
    .map_err(|_| "concurrent forwarding or half-close did not finish")??;
    Ok(())
}

async fn binary_roundtrip<S>(stream: S, length: usize, seed: u8) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let payload: Vec<u8> =
        (0_u8..=u8::MAX).cycle().take(length).map(|byte| byte.wrapping_add(seed)).collect();
    let mut expected = payload.clone();
    expected.extend_from_slice(ECHO_TRAILER);
    let (mut reader, mut writer) = tokio::io::split(stream);
    let upload = async {
        writer.write_all(&payload).await?;
        writer.shutdown().await?;
        Ok::<_, Box<dyn std::error::Error>>(())
    };
    let download = async {
        let mut received = vec![0; expected.len()];
        reader.read_exact(&mut received).await?;
        if received != expected || reader.read(&mut [0]).await? != 0 {
            return Err("forwarded bytes, EOF trailer or final EOF differed".into());
        }
        Ok::<_, Box<dyn std::error::Error>>(())
    };
    tokio::try_join!(upload, download)?;
    Ok(())
}

pub async fn verify_session(connection: &ClientConnection) -> Result<()> {
    timeout(Duration::from_secs(10), async {
        let mut channel = connection.open_session().await?;
        channel.exec(true, b"printf scoplen-socks-ok").await?;
        let mut output = Vec::new();
        let mut exited = false;
        loop {
            match channel.next_event().await? {
                Some(ChannelEvent::Data(data)) if output.len() + data.len() <= 256 => {
                    output.extend_from_slice(&data);
                }
                Some(ChannelEvent::ExitStatus(0)) => exited = true,
                Some(ChannelEvent::Success | ChannelEvent::Eof) => {}
                Some(ChannelEvent::Close) | None => break,
                _ => return Err("unexpected session event after forwarding".into()),
            }
        }
        if !exited || output != b"scoplen-socks-ok" {
            return Err("session command failed after forwarding".into());
        }
        Ok::<_, Box<dyn std::error::Error>>(())
    })
    .await
    .map_err(|_| "session command timed out after forwarding")??;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::Peer;

    #[test]
    fn fixture_profiles_are_explicit_and_unknown_profiles_fail() {
        assert_eq!(Peer::from_profile(None).unwrap(), Peer::OpenSsh);
        assert_eq!(Peer::from_profile(Some("8.8p1")).unwrap(), Peer::OpenSsh);
        assert_eq!(Peer::from_profile(Some("dropbear-2024.86")).unwrap(), Peer::Dropbear);
        assert!(Peer::from_profile(Some("dropbear")).is_err());
        assert!(Peer::from_profile(Some("")).is_err());
    }

    #[test]
    fn banners_cannot_substitute_another_peer_version_or_incomplete_line() {
        let openssh = b"SSH-2.0-OpenSSH_9.9\r\n";
        let dropbear = b"SSH-2.0-dropbear_2024.86\r\n";
        assert!(Peer::OpenSsh.matches_banner(openssh));
        assert!(Peer::Dropbear.matches_banner(dropbear));
        assert!(!Peer::OpenSsh.matches_banner(dropbear));
        assert!(!Peer::Dropbear.matches_banner(openssh));
        assert!(!Peer::Dropbear.matches_banner(b"SSH-2.0-dropbear_2025.88\r\n"));
        assert!(!Peer::Dropbear.matches_banner(b"SSH-2.0-dropbear_2024.86\r\nextra"));
        assert!(!Peer::OpenSsh.matches_banner(b"SSH-2.0-OpenSSH_9.9\n"));
    }
}
