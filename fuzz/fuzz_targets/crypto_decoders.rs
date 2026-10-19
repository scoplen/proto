// SPDX-License-Identifier: Apache-2.0
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|bytes: &[u8]| {
    let _ = scoplen_crypto::DeviceCertificate::decode(bytes);
    let _ = scoplen_crypto::LocalDatabaseKeyEnvelope::decode(bytes);
    let _ = scoplen_crypto::ObjectEnvelope::decode(bytes);
    let _ = scoplen_crypto::RecoveryBlob::decode(bytes);
    let _ = scoplen_crypto::RevocationStatement::decode(bytes);
    let _ = scoplen_crypto::ShamirShare::from_bytes(bytes);

    let text = String::from_utf8_lossy(bytes);
    let _ = scoplen_crypto::RecoveryKey::parse_display(&text);

    if let Ok(proof_text) = std::str::from_utf8(bytes) {
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
        }
    }
});
