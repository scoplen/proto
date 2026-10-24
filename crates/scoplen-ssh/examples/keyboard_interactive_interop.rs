// SPDX-License-Identifier: Apache-2.0

use std::{env, time::Duration};

use scoplen_crypto::SecretVec;
use scoplen_ssh::{
    ChannelEvent, ClientConfig, ClientConnection, ClientError, HostKey, HostKeyVerificationError,
    KeyboardInteractiveResponse,
};
use tokio::time::timeout;

const DEADLINE: Duration = Duration::from_secs(15);

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let port = env::var("SCOPLEN_INTERACTIVE_PORT")?.parse::<u16>()?;
    let host_key =
        ssh_key::PublicKey::from_openssh(&env::var("SCOPLEN_INTERACTIVE_HOST_KEY")?)?.to_bytes()?;
    let password = SecretVec::new(env::var("SCOPLEN_INTERACTIVE_PASSWORD")?.into_bytes());
    for accepted in [true, false, true] {
        let expected_key = host_key.clone();
        let config =
            ClientConfig::new("127.0.0.1", port, move |_host: &str, key: &HostKey| match key {
                HostKey::Raw { key_blob, .. } if key_blob == &expected_key => Ok(()),
                _ => Err(HostKeyVerificationError::Rejected("unexpected fixture key".to_owned())),
            })?;
        let mut connection = timeout(DEADLINE, ClientConnection::connect(config)).await??;
        let answer =
            if accepted { password.clone() } else { SecretVec::new(b"wrong-answer".to_vec()) };
        let mut prompts_seen = 0;
        let result = timeout(
            DEADLINE,
            connection.authenticate_keyboard_interactive("scoplen", None, |info| {
                let informational = info.prompts().is_empty();
                let valid = info.prompts().len() == 1 && !info.prompts()[0].echo();
                prompts_seen += usize::from(valid);
                let answer = answer.clone();
                async move {
                    if !informational && !valid {
                        return Err(ClientError::InvalidInput("expected one non-echo PAM prompt"));
                    }
                    tokio::time::sleep(Duration::from_millis(25)).await;
                    KeyboardInteractiveResponse::new(if informational {
                        Vec::new()
                    } else {
                        vec![answer.as_bytes().to_vec()]
                    })
                    .map_err(|_| ClientError::InvalidInput("invalid fixture answer"))
                }
            }),
        )
        .await?;
        if prompts_seen == 0 {
            return Err("PAM did not request a non-echo answer".into());
        }
        if accepted {
            result?;
            timeout(DEADLINE, verify_command(&connection)).await??;
        } else {
            if !matches!(
                result,
                Err(ClientError::AuthenticationRejected { partial_success: false, .. })
            ) {
                return Err("wrong PAM answer was not rejected".into());
            }
            if !matches!(connection.open_session().await, Err(ClientError::NotAuthenticated)) {
                return Err("rejected PAM answer permitted a session".into());
            }
        }
        timeout(DEADLINE, connection.disconnect()).await??;
    }
    println!("keyboard-interactive PAM interop ok");
    Ok(())
}

async fn verify_command(connection: &ClientConnection) -> Result<(), Box<dyn std::error::Error>> {
    let mut channel = connection.open_session().await?;
    channel.exec(true, b"printf scoplen-pam-ok").await?;
    let mut output = Vec::new();
    let mut status = None;
    while let Some(event) = channel.next_event().await? {
        match event {
            ChannelEvent::Data(data) => output.extend(data),
            ChannelEvent::ExitStatus(value) => status = Some(value),
            ChannelEvent::Eof | ChannelEvent::Success => {}
            ChannelEvent::Close => break,
            _ => return Err("unexpected PAM command event".into()),
        }
    }
    if output != b"scoplen-pam-ok" || status != Some(0) {
        return Err("PAM command output or exit status did not match".into());
    }
    Ok(())
}
