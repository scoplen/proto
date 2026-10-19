// SPDX-License-Identifier: Apache-2.0
//! Disposable OpenSSH interoperability fixture using software-generated FIDO2 signatures.
//! It does not exercise a physical token or platform provider.

use std::{
    env,
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use scoplen_crypto::{Ed25519SigningKey, P256SigningKey};
use scoplen_ssh::{
    CertificateValidationPolicy, ChannelEvent, ClientConfig, ClientConnection, HostKey,
    HostKeyVerificationError, SecurityKeyAlgorithm, SecurityKeyError, SecurityKeyProvider,
    SecurityKeyPublicKey, SecurityKeySignOptions, SecurityKeySignature, SecurityKeySshSigner,
    UserCertificate,
};
use ssh_key::{
    Certificate, PublicKey,
    sha2::{Digest, Sha256},
};
use tokio::time::timeout;

const DEADLINE: Duration = Duration::from_secs(10);
const APPLICATION: &str = "ssh:scoplen-test";

#[derive(Clone, Copy)]
enum Fault {
    None,
    WrongKey,
    WrongApplication,
    WrongPayload,
}

enum TestKey {
    Ed25519(Ed25519SigningKey),
    P256(P256SigningKey),
}

struct SoftwareProvider {
    key: TestKey,
    fault: Fault,
}

impl SoftwareProvider {
    fn new(algorithm: &str, fault: Fault) -> Result<Self, Box<dyn std::error::Error>> {
        let key = match algorithm {
            "ed25519" => TestKey::Ed25519(Ed25519SigningKey::from_bytes(&[9; 32])?),
            "p256" => TestKey::P256(P256SigningKey::from_bytes(&[1; 32])?),
            _ => return Err("algorithm must be ed25519 or p256".into()),
        };
        Ok(Self { key, fault })
    }
}

impl SecurityKeyProvider for SoftwareProvider {
    fn algorithm(&self) -> SecurityKeyAlgorithm {
        match self.key {
            TestKey::Ed25519(_) => SecurityKeyAlgorithm::Ed25519,
            TestKey::P256(_) => SecurityKeyAlgorithm::EcdsaSha2Nistp256,
        }
    }

    fn public_key(&self) -> Result<SecurityKeyPublicKey, SecurityKeyError> {
        let key = match &self.key {
            TestKey::Ed25519(key) => key.public_key().to_vec(),
            TestKey::P256(key) => key.public_key_sec1().clone(),
        };
        SecurityKeyPublicKey::new(self.algorithm(), key, APPLICATION)
    }

    fn discover(&self, application: &str) -> Result<Vec<SecurityKeyPublicKey>, SecurityKeyError> {
        Ok(if application == APPLICATION { vec![self.public_key()?] } else { Vec::new() })
    }

    fn sign(
        &self,
        application: &str,
        message: &[u8],
        _options: SecurityKeySignOptions,
    ) -> Result<SecurityKeySignature, SecurityKeyError> {
        let application = if matches!(self.fault, Fault::WrongApplication) {
            "ssh:other-application"
        } else {
            application
        };
        let mut message = message.to_vec();
        if matches!(self.fault, Fault::WrongPayload) {
            message[0] ^= 1;
        }
        let flags = 0x05;
        let counter = 7_u32;
        let mut signed_data = Vec::with_capacity(69);
        signed_data.extend_from_slice(&Sha256::digest(application.as_bytes()));
        signed_data.push(flags);
        signed_data.extend_from_slice(&counter.to_be_bytes());
        signed_data.extend_from_slice(&Sha256::digest(&message));
        let signature = match &self.key {
            TestKey::Ed25519(key) => {
                if matches!(self.fault, Fault::WrongKey) {
                    Ed25519SigningKey::from_bytes(&[8; 32])
                        .map_err(|error| SecurityKeyError::Provider(error.to_string()))?
                        .sign(&signed_data)
                        .to_vec()
                } else {
                    key.sign(&signed_data).to_vec()
                }
            }
            TestKey::P256(key) => {
                let raw = if matches!(self.fault, Fault::WrongKey) {
                    P256SigningKey::from_bytes(&[2; 32])
                        .map_err(|error| SecurityKeyError::Provider(error.to_string()))?
                        .sign(&signed_data)
                } else {
                    key.sign(&signed_data)
                };
                let mut encoded = Vec::new();
                for part in [&raw[..32], &raw[32..]] {
                    let first = part.iter().position(|byte| *byte != 0).unwrap_or(part.len());
                    let mut part = part[first..].to_vec();
                    if part.first().is_some_and(|byte| byte & 0x80 != 0) {
                        part.insert(0, 0);
                    }
                    encoded.extend_from_slice(
                        &u32::try_from(part.len())
                            .expect("signature component length")
                            .to_be_bytes(),
                    );
                    encoded.extend_from_slice(&part);
                }
                encoded
            }
        };
        SecurityKeySignature::new(self.algorithm(), signature, flags, counter)
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args().skip(1);
    let mode = args.next().ok_or("expected public or auth")?;
    let algorithm = args.next().ok_or("expected ed25519 or p256")?;
    let fault = match args.next().as_deref() {
        None | Some("valid") => Fault::None,
        Some("wrong-key") => Fault::WrongKey,
        Some("wrong-application") => Fault::WrongApplication,
        Some("wrong-payload") => Fault::WrongPayload,
        Some(_) => return Err("unknown signature fault".into()),
    };
    if args.next().is_some() {
        return Err("too many arguments".into());
    }
    let provider = SoftwareProvider::new(&algorithm, fault)?;
    let identity = provider.public_key()?;
    if mode == "public" {
        let identity = match fault {
            Fault::None => identity,
            Fault::WrongKey => {
                let key = match algorithm.as_str() {
                    "ed25519" => Ed25519SigningKey::from_bytes(&[8; 32])?.public_key().to_vec(),
                    "p256" => P256SigningKey::from_bytes(&[2; 32])?.public_key_sec1().clone(),
                    _ => unreachable!("validated algorithm"),
                };
                SecurityKeyPublicKey::new(identity.algorithm(), key, APPLICATION)?
            }
            Fault::WrongApplication => SecurityKeyPublicKey::new(
                identity.algorithm(),
                identity.key(),
                "ssh:other-application",
            )?,
            Fault::WrongPayload => return Err("public mode does not accept wrong-payload".into()),
        };
        println!("{}", PublicKey::from_bytes(&identity.to_blob()?)?.to_openssh()?);
        return Ok(());
    }
    if mode != "auth" {
        return Err("mode must be public or auth".into());
    }
    let signer =
        SecurityKeySshSigner::new(&provider, identity, SecurityKeySignOptions::user_presence())?;
    let expected_key =
        PublicKey::from_openssh(&env::var("SCOPLEN_OPENSSH_HOST_KEY")?)?.to_bytes()?;
    let host = env::var("SCOPLEN_OPENSSH_HOST").unwrap_or_else(|_| "127.0.0.1".into());
    let port = env::var("SCOPLEN_OPENSSH_PORT")?.parse()?;
    let user = env::var("SCOPLEN_OPENSSH_USER")?;
    let config = ClientConfig::new(host, port, move |_: &str, key: &HostKey| match key {
        HostKey::Raw { key_blob, .. } if *key_blob == expected_key => Ok(()),
        _ => Err(HostKeyVerificationError::Rejected("unexpected server key".into())),
    })?;
    let mut connection = timeout(DEADLINE, ClientConnection::connect(config)).await??;
    if let Ok(path) = env::var("SCOPLEN_OPENSSH_USER_CERT") {
        let ca_path = env::var("SCOPLEN_OPENSSH_USER_CA_KEY")
            .map_err(|_| "security-key certificate requires a pinned CA public key")?;
        let encoded = Certificate::read_file(Path::new(&path))?.to_bytes()?;
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let certificate = UserCertificate::parse_and_validate(
            &encoded,
            &CertificateValidationPolicy::user(&user, now),
        )?;
        let pinned_ca = PublicKey::read_openssh_file(ca_path)?.to_bytes()?;
        if certificate.certificate().ca_public_key_blob() != pinned_ca {
            return Err("UntrustedUserCa".into());
        }
        timeout(DEADLINE, connection.authenticate_certificate(&user, &certificate, &signer))
            .await??;
    } else {
        timeout(DEADLINE, connection.authenticate_publickey(&user, &signer)).await??;
    }
    let mut channel = timeout(DEADLINE, connection.open_session()).await??;
    timeout(DEADLINE, channel.exec(true, b"printf scoplen-security-key-ok")).await??;
    let mut output = Vec::new();
    let mut exit_ok = false;
    loop {
        match timeout(DEADLINE, channel.next_event()).await?? {
            Some(ChannelEvent::Data(data)) => output.extend_from_slice(&data),
            Some(ChannelEvent::ExitStatus(0)) => exit_ok = true,
            Some(ChannelEvent::Eof | ChannelEvent::Success) => {}
            Some(ChannelEvent::Close) | None => break,
            Some(other) => return Err(format!("unexpected channel event: {other:?}").into()),
        }
    }
    if !exit_ok || output != b"scoplen-security-key-ok" {
        return Err("security-key command output or exit status differed".into());
    }
    timeout(DEADLINE, connection.disconnect()).await??;
    println!("security-key interop ok");
    Ok(())
}
