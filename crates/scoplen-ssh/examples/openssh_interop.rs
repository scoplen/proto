use std::{env, time::Duration};

use scoplen_ssh::{
    ChannelEvent, ClientConfig, ClientConnection, HostKey, HostKeyVerificationError,
};
use ssh_key::PublicKey;
use tokio::time::timeout;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let host = env::var("SCOPLEN_OPENSSH_HOST").unwrap_or_else(|_| "127.0.0.1".to_owned());
    let port =
        env::var("SCOPLEN_OPENSSH_PORT").unwrap_or_else(|_| "22223".to_owned()).parse::<u16>()?;
    let username = env::var("SCOPLEN_OPENSSH_USER").unwrap_or_else(|_| "scoplen".to_owned());
    let password = env::var("SCOPLEN_OPENSSH_PASSWORD")
        .map_err(|_| "SCOPLEN_OPENSSH_PASSWORD must be set for the disposable test server")?;
    let expected_key = env::var("SCOPLEN_OPENSSH_HOST_KEY")
        .map_err(|_| "SCOPLEN_OPENSSH_HOST_KEY must be set to the server's public key")?;
    let expected_key = PublicKey::from_openssh(&expected_key)?.to_bytes()?;
    let verifier = move |_host: &str, key: &HostKey| match key {
        HostKey::Raw { key_blob, .. } if key_blob == &expected_key => Ok(()),
        _ => Err(HostKeyVerificationError::Rejected("unexpected server key".to_owned())),
    };
    let config = ClientConfig::new(host, port, verifier)?;
    let mut connection = ClientConnection::connect(config).await?;
    connection.authenticate_password(&username, password.as_bytes()).await?;
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
    connection.disconnect().await?;
    println!("openssh interop ok");
    Ok(())
}
