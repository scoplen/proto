// SPDX-License-Identifier: Apache-2.0
#![no_main]

use libfuzzer_sys::fuzz_target;
use scoplen_ssh::{
    CertificateValidationPolicy, ChannelClose, ChannelData, ChannelEof, ChannelExtendedData,
    ChannelFailure, ChannelOpen, ChannelOpenConfirmation, ChannelOpenFailure, ChannelRequest,
    ChannelSuccess, ChannelWindowAdjust, GlobalRequest, GlobalRequestFailure, GlobalRequestSuccess,
    HostKey, HostKeyVerificationError, KeyExchangeFamily, KeyboardInteractiveInfoRequest,
    KeyboardInteractiveResponse, SecurityKeyAlgorithm, SecurityKeyPublicKey, SecurityKeySignature,
    SftpLimits, SftpPacket, SftpStatvfs, SocksHandshake, SshCertificate, StrictKexPacket,
    StrictKeyExchange, UserCertificate, verify_host_key,
};

fuzz_target!(|bytes: &[u8]| {
    let _ = ChannelOpen::decode(bytes);
    let _ = ChannelOpenConfirmation::decode(bytes);
    let _ = ChannelOpenFailure::decode(bytes);
    let _ = ChannelData::decode(bytes);
    let _ = ChannelExtendedData::decode(bytes);
    let _ = ChannelWindowAdjust::decode(bytes);
    let _ = ChannelEof::decode(bytes);
    let _ = ChannelClose::decode(bytes);
    let _ = ChannelSuccess::decode(bytes);
    let _ = ChannelFailure::decode(bytes);
    let _ = ChannelRequest::decode(bytes);
    let _ = GlobalRequest::decode(bytes);
    let _ = GlobalRequestSuccess::decode(bytes);
    let _ = GlobalRequestFailure::decode(bytes);
    let _ = KeyboardInteractiveInfoRequest::decode(bytes);
    let _ = KeyboardInteractiveResponse::decode(bytes);
    let _ = SftpPacket::decode(bytes);
    let _ = SftpLimits::decode(bytes);
    let _ = SftpStatvfs::decode(bytes);

    if let Ok(key) = SecurityKeyPublicKey::from_blob(bytes) {
        let encoded = key.to_blob().expect("validated security key encodes");
        assert_eq!(SecurityKeyPublicKey::from_blob(&encoded), Ok(key));
    }
    for algorithm in [SecurityKeyAlgorithm::Ed25519, SecurityKeyAlgorithm::EcdsaSha2Nistp256] {
        if let Ok(signature) = SecurityKeySignature::from_ssh_blob(algorithm, bytes) {
            let encoded =
                signature.to_ssh_blob().expect("validated security-key signature encodes");
            assert_eq!(SecurityKeySignature::from_ssh_blob(algorithm, &encoded), Ok(signature));
        }
    }

    let user_policy = CertificateValidationPolicy::user("scoplen-fuzz", 1_790_000_000);
    let host_policy = CertificateValidationPolicy::host("scoplen-fuzz", 1_790_000_000);
    if let Ok(certificate) = SshCertificate::from_bytes(bytes) {
        assert_eq!(SshCertificate::from_bytes(certificate.as_bytes()), Ok(certificate.clone()));
        let _ = certificate.validate(&user_policy);
        let _ = certificate.validate(&host_policy);
    }
    if let Ok(certificate) = UserCertificate::parse_and_validate(bytes, &user_policy) {
        assert_eq!(certificate.identity().key_blob(), certificate.certificate().as_bytes());
    }
    let verifier = |_: &str, _: &HostKey| Ok::<(), HostKeyVerificationError>(());
    let _ = verify_host_key("scoplen-fuzz", bytes, &host_policy, &verifier);

    let mut socks = SocksHandshake::new();
    let _ = socks.feed(bytes);
    let _ = socks.finish();

    let mut strict = StrictKeyExchange::new(true, KeyExchangeFamily::Ecdh);
    let mut rekey = StrictKeyExchange::new(true, KeyExchangeFamily::Ecdh);
    rekey.on_send(StrictKexPacket::KexInit).unwrap();
    rekey.on_receive(StrictKexPacket::KexInit).unwrap();
    rekey.on_send(StrictKexPacket::NewKeys).unwrap();
    rekey.on_receive(StrictKexPacket::NewKeys).unwrap();
    rekey.begin_rekey().unwrap();
    for byte in bytes.iter().take(128) {
        let packet = match byte % 15 {
            0 => StrictKexPacket::KexInit,
            1 => StrictKexPacket::NewKeys,
            2 => StrictKexPacket::KexDhInit,
            3 => StrictKexPacket::KexDhReply,
            4 => StrictKexPacket::KexDhGexRequestOld,
            5 => StrictKexPacket::KexDhGexRequest,
            6 => StrictKexPacket::KexDhGexGroup,
            7 => StrictKexPacket::KexDhGexInit,
            8 => StrictKexPacket::KexDhGexReply,
            9 => StrictKexPacket::KexEcdhInit,
            10 => StrictKexPacket::KexEcdhReply,
            11 => StrictKexPacket::KexHybridInit,
            12 => StrictKexPacket::KexHybridReply,
            13 => StrictKexPacket::ExtInfo,
            _ => StrictKexPacket::Other(2),
        };
        let _ = strict.on_receive(packet);
        if rekey.phase() == scoplen_ssh::StrictKexPhase::Established {
            rekey.begin_rekey().unwrap();
        }
        let _ = rekey.on_send(packet);
        let _ = rekey.on_receive(packet);
    }
});
