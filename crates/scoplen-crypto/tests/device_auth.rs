// SPDX-License-Identifier: Apache-2.0
//! Exercise K-3 device authentication through the public K-2 API.

use scoplen_crypto::{
    DeviceAuthContext, DeviceAuthError, DeviceSigner, P256SigningKey, p256_verify,
    validate_server_origin,
};
use scoplen_test_vectors::VectorDocument;
use std::fmt::Write;
use uuid::Uuid;

const NONCE: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const DEVICE_ID: &str = "00000000-0000-7000-8000-000000000001";

fn device_id() -> Uuid {
    Uuid::parse_str(DEVICE_ID).expect("valid UUIDv7")
}

fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut output, "{byte:02x}").expect("write to string");
    }
    output
}

#[test]
fn published_signature_input_is_exact_and_signs_with_device_boundary() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../vectors/api-auth.json");
    let document = VectorDocument::from_path(path).expect("auth vectors");
    let vector = document
        .vectors
        .iter()
        .find(|vector| vector.kind == "auth.device.signature-input")
        .expect("signature-input vector");
    let fields: Vec<_> = vector.input.split('|').collect();
    assert_eq!(fields.len(), 3);
    let context = DeviceAuthContext::new(
        fields[0],
        fields[1],
        Uuid::parse_str(fields[2]).expect("fixture UUID"),
    )
    .expect("valid context");
    assert_eq!(hex(&context.signature_input()), vector.expected);

    let signer = P256SigningKey::from_bytes(&[1; 32]).expect("synthetic test key");
    let signature = DeviceSigner::sign(&signer, &context.signature_input()).expect("sign");
    p256_verify(&signer.public_key_sec1(), &context.signature_input(), &signature)
        .expect("verify exact context");
    for altered in [
        DeviceAuthContext::new("https://example.org:8443", NONCE, device_id())
            .expect("alternate origin"),
        DeviceAuthContext::new("https://example.com:8443", &"11".repeat(32), device_id())
            .expect("alternate nonce"),
        DeviceAuthContext::new(
            "https://example.com:8443",
            NONCE,
            Uuid::parse_str("00000000-0000-7000-8000-000000000002").expect("UUIDv7"),
        )
        .expect("alternate device"),
    ] {
        assert!(
            p256_verify(&signer.public_key_sec1(), &altered.signature_input(), &signature).is_err()
        );
    }
}

#[test]
fn bare_hexadecimal_host_marker_cannot_change_signed_origin() {
    for origin in ["https://0x", "https://edge.0x", "https://0x:8443", "https://edge.0x:8443"] {
        assert_eq!(
            DeviceAuthContext::new(origin, NONCE, device_id()),
            Err(DeviceAuthError::InvalidOrigin),
            "{origin}"
        );
    }
    for origin in ["https://0.0.0.0", "https://0.0.0.0:8443", "https://0x.example.com"] {
        assert!(DeviceAuthContext::new(origin, NONCE, device_id()).is_ok(), "{origin}");
    }
}

#[test]
fn public_context_rejects_noncanonical_origin_nonce_and_device() {
    for origin in [
        "http://example.com",
        "HTTPS://example.com",
        "https://EXAMPLE.com",
        "https://example.com:443",
        "https://example.com:0",
        "https://example.com:08443",
        "https://example.com/",
        "https://example.com/path",
        "https://example.com?x=1",
        "https://example.com#fragment",
        "https://user@example.com",
        "https://example..com",
        "https://-example.com",
        "https://example.com.",
        "https://éxample.com",
        "https://[2001:0db8::1]",
        "https://127.000.000.001",
        "https://0x7f.0.0.1",
        "https://0x7f000001",
        "https://192.0x0.2.1",
        "https://example.0x1",
    ] {
        assert_eq!(validate_server_origin(origin), Err(DeviceAuthError::InvalidOrigin), "{origin}");
        assert_eq!(
            DeviceAuthContext::new(origin, NONCE, device_id()),
            Err(DeviceAuthError::InvalidOrigin),
            "{origin}"
        );
    }
    assert_eq!(
        DeviceAuthContext::new(&format!("https://{}.com", "a".repeat(2_050)), NONCE, device_id()),
        Err(DeviceAuthError::InvalidOrigin)
    );
    for origin in [
        "https://example.com",
        "https://example.com:8443",
        "https://127.0.0.1",
        "https://[2001:db8::1]",
        "https://0xabc.example.com",
    ] {
        assert_eq!(validate_server_origin(origin), Ok(()), "{origin}");
        assert!(DeviceAuthContext::new(origin, NONCE, device_id()).is_ok(), "{origin}");
    }
    for nonce in ["00".repeat(31), "00".repeat(33), "AA".repeat(32), "zz".repeat(32)] {
        assert_eq!(
            DeviceAuthContext::new("https://example.com", &nonce, device_id()),
            Err(DeviceAuthError::InvalidNonce)
        );
    }
    let wrong_version = Uuid::parse_str("00000000-0000-4000-8000-000000000001").expect("UUID");
    assert_eq!(
        DeviceAuthContext::new("https://example.com", NONCE, wrong_version),
        Err(DeviceAuthError::InvalidDeviceId)
    );
}
