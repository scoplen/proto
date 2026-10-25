// SPDX-License-Identifier: Apache-2.0
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|bytes: &[u8]| {
    if let Ok(wrap) = scoplen_crypto::PasswordArkWrap::decode(bytes) {
        assert_eq!(wrap.encode().as_slice(), bytes);
    }
    // These entry points normalize/validate bounded inputs only; fuzzing never runs Argon2.
    if bytes.len() <= 2049 {
        let _ = scoplen_crypto::normalize_account_password(scoplen_crypto::SecretVec::new(
            bytes.to_vec(),
        ));
    }
    if bytes.len() >= 17
        && let Ok(username) = std::str::from_utf8(&bytes[17..])
    {
        let _ = scoplen_crypto::PasswordKdfContext::new(
            "https://control.example.com",
            username,
            bytes[0],
            &bytes[1..17],
        );
    }
    if bytes.len() == 161
        && let (Ok(kdf), Ok(account), Ok(vault)) = (
            scoplen_crypto::PasswordKdfContext::new(
                "https://control.example.com",
                "alice",
                bytes[0],
                &bytes[1..17],
            ),
            std::str::from_utf8(&bytes[17..53]),
            std::str::from_utf8(&bytes[53..89]),
        )
        && let (Ok(account), Ok(vault)) = (account.parse(), vault.parse())
    {
        let generation =
            u64::from_be_bytes(bytes[153..].try_into().expect("fixed generation width"));
        let _ = scoplen_crypto::PasswordBootstrapContext::new(
            kdf,
            account,
            vault,
            &bytes[89..121],
            &bytes[121..153],
            generation,
        );
    }
    if let Ok(value) = scoplen_crypto::PairingNewDevice::decode(bytes) {
        assert_eq!(value.encode().expect("validated pairing device").as_bytes(), bytes);
    }
    if let Ok(value) = scoplen_crypto::PairingHandoff::decode(bytes) {
        assert_eq!(value.encode().expect("validated pairing handoff").as_bytes(), bytes);
    }
    if let Ok(wrap) = scoplen_crypto::DeviceArkWrap::decode(bytes) {
        assert_eq!(wrap.encode().as_slice(), bytes);
    }
    if let Ok(wrap) = scoplen_crypto::AccountSigningKeyWrap::decode(bytes) {
        assert_eq!(wrap.encode().as_slice(), bytes);
    }
    if let Ok(wrap) = scoplen_crypto::AccountKemKeyWrap::decode(bytes) {
        assert_eq!(wrap.encode().as_slice(), bytes);
    }
    if let Ok(wrap) = scoplen_crypto::PersonalVaultKeyWrap::decode(bytes) {
        assert_eq!(wrap.encode().as_slice(), bytes);
    }
    let _ = scoplen_crypto::DeviceCertificate::decode(bytes);
    let _ = scoplen_crypto::LocalDatabaseKeyEnvelope::decode(bytes);
    let _ = scoplen_crypto::ObjectEnvelope::decode(bytes);
    let _ = scoplen_crypto::RecoveryBlob::decode(bytes);
    let _ = scoplen_crypto::RevocationStatement::decode(bytes);
    let _ = scoplen_crypto::ShamirShare::from_bytes(bytes);

    let text = String::from_utf8_lossy(bytes);
    let _ = scoplen_crypto::RecoveryKey::parse_display(&text);

    if let Ok(proof_text) = std::str::from_utf8(bytes) {
        if let Some((origin, username)) = proof_text.split_once('\n') {
            let _ = scoplen_crypto::PasswordKdfContext::new(origin, username, 1, &[0; 16]);
        }
        if let Ok(link) = scoplen_crypto::PairingLink::decode(proof_text) {
            assert_eq!(link.encode(), proof_text);
        }
        if let Ok(qr) = scoplen_crypto::PairingQrPayload::decode(proof_text) {
            assert_eq!(qr.encode().as_bytes(), bytes);
        }
        let _ = scoplen_crypto::GatewayProof::parse(proof_text);
        if let Ok(proof) = scoplen_crypto::DpopProof::parse(proof_text) {
            let target = scoplen_crypto::DpopTarget::new(
                "GET",
                "https://resource.example.org",
                "/protectedresource",
            )
            .expect("fixed canonical DPoP target");
            let _ = proof.verify(
                &target,
                scoplen_crypto::DpopToken::Protected("Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU"),
                "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I",
                1_562_262_618,
                None,
            );
            let _ = proof.verify_presented_key(
                &target,
                scoplen_crypto::DpopToken::Refresh,
                1_562_262_618,
                None,
            );
        }
        if let Ok(ticket) = scoplen_crypto::GatewayTicket::parse(proof_text) {
            let signer = scoplen_crypto::Ed25519SigningKey::from_bytes(&[0x42; 32])
                .expect("fixed synthetic ticket key");
            let mut trusted =
                scoplen_crypto::TrustedGatewayTicketKeys::new("https://control.example.com")
                    .expect("fixed canonical issuer");
            trusted.insert("ticket-1", &signer.public_key()).expect("fixed ticket key");
            let _ = ticket.verify(&trusted, 1_700_000_000);
        }
        if let Ok(token) = scoplen_crypto::DeviceAccessToken::parse(proof_text) {
            let signer = scoplen_crypto::Ed25519SigningKey::from_bytes(&[0x42; 32])
                .expect("fixed synthetic access-token key");
            let mut trusted =
                scoplen_crypto::TrustedDeviceAccessTokenKeys::new("https://control.example.com")
                    .expect("fixed canonical issuer");
            trusted.insert("access-1", &signer.public_key()).expect("fixed access-token key");
            let _ = token.verify(&trusted, 1_700_000_000);
        }
        if let Ok(token) = scoplen_crypto::OperatorAccessToken::parse(proof_text) {
            let signer = scoplen_crypto::Ed25519SigningKey::from_bytes(&[0x62; 32])
                .expect("fixed synthetic Operator key");
            let mut trusted =
                scoplen_crypto::TrustedOperatorAccessTokenKeys::new("https://control.example.com")
                    .expect("fixed canonical issuer");
            trusted.insert("operator-1", &signer.public_key()).expect("fixed Operator key");
            let _ = token.verify(&trusted, 1_700_000_000);
        }
        if let Some((ticket_text, gateway_proof_text)) = proof_text.split_once('\n')
            && let (Ok(ticket), Ok(gateway_proof)) = (
                scoplen_crypto::GatewayTicket::parse(
                    ticket_text.strip_suffix('\r').unwrap_or(ticket_text),
                ),
                scoplen_crypto::GatewayProof::parse(
                    gateway_proof_text
                        .strip_suffix("\r\n")
                        .or_else(|| gateway_proof_text.strip_suffix('\n'))
                        .unwrap_or(gateway_proof_text),
                ),
            )
        {
            let signer = scoplen_crypto::Ed25519SigningKey::from_bytes(&[0x42; 32])
                .expect("fixed synthetic ticket key");
            let mut trusted =
                scoplen_crypto::TrustedGatewayTicketKeys::new("https://control.example.com")
                    .expect("fixed canonical issuer");
            trusted.insert("ticket-1", &signer.public_key()).expect("fixed ticket key");
            let _ = gateway_proof.verify(&ticket, &trusted, 1_700_000_000);
        }
    }
});
