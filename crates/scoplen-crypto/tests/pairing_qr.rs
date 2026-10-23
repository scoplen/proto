// SPDX-License-Identifier: Apache-2.0
//! Exercise public locators and secret-bearing `QRv2` through the public API.

use scoplen_crypto::{
    DeviceKemKeyPair, P256SigningKey, PairingCode, PairingLink, PairingQrError, PairingQrPayload,
};
use uuid::Uuid;

fn id() -> Uuid {
    "03000000-0000-7000-8000-000000000000".parse().unwrap()
}
fn payload() -> PairingQrPayload {
    PairingQrPayload::new(
        "https://control.example.com:8443",
        id(),
        DeviceKemKeyPair::from_private_bytes(&[7; 32]).unwrap().public_key(),
        &P256SigningKey::from_bytes(&[2; 32]).unwrap().public_key_sec1(),
        PairingCode::from_ascii(b"01234567").unwrap(),
    )
    .unwrap()
}

#[test]
fn qr_roundtrip_binds_origin_secret_and_keys_without_debug_disclosure() {
    let p = payload();
    let encoded = p.encode();
    let text = std::str::from_utf8(encoded.as_bytes()).unwrap();
    let decoded = PairingQrPayload::decode(text).unwrap();
    assert_eq!(decoded.encode(), encoded);
    assert_eq!(decoded.pairing_id(), id());
    assert_eq!(decoded.link().origin(), "https://control.example.com:8443");
    assert_eq!(decoded.code().as_ascii(), b"01234567");
    assert_eq!(format!("{decoded:?}"), "PairingQrPayload([REDACTED])");
    assert!(!p.link().encode().contains("01234567"));
    let kem = DeviceKemKeyPair::from_private_bytes(&[7; 32]).unwrap();
    let signing = P256SigningKey::from_bytes(&[2; 32]).unwrap();
    decoded.verify_public_keys(kem.public_key(), &signing.public_key_sec1()).unwrap();
    assert_eq!(
        decoded.verify_public_keys(
            kem.public_key(),
            &P256SigningKey::from_bytes(&[3; 32]).unwrap().public_key_sec1()
        ),
        Err(PairingQrError::KeyMismatch)
    );
    assert_eq!(
        decoded.verify_public_keys(&[4; 65], &signing.public_key_sec1()),
        Err(PairingQrError::InvalidPublicKey)
    );
}

#[test]
fn public_links_reject_aliases_queries_secrets_and_invalid_origins() {
    let link = PairingLink::new("https://control.example.com:8443", id()).unwrap();
    assert_eq!(PairingLink::decode(&link.encode()).unwrap(), link);
    for bad in [
        link.encode() + "&password=01234567",
        link.encode() + "/",
        link.encode().replace("/pair#", "/pair/?x=1#"),
        link.encode().replace("https:", "http:"),
        link.encode().replace("control.example", "CONTROL.example"),
        link.encode().replace("03000000", "0300000A"),
        link.encode().replace("-7000-", "-4000-"),
        format!("https://u:p@control.example.com/pair#id={}", id()),
    ] {
        assert!(PairingLink::decode(&bad).is_err(), "accepted malformed public link");
    }
}

#[test]
fn qr_rejects_old_version_noncanonical_fields_and_secret_aliases() {
    let encoded = payload().encode();
    let text = std::str::from_utf8(encoded.as_bytes()).unwrap();
    for bad in [
        text.replace("splpair2:", "splpair1:"),
        text.replace("03000000", "0300000A"),
        text.replace("-7000-", "-4000-"),
        text.replace("e595d", "E595D"),
        text.replace(":01234567", ":0123456I"),
        text.replace(":01234567", ":0123456a"),
        text.to_owned() + ":",
        text[..text.len() - 1].to_owned(),
        text.replace(":03000000", "=:03000000"),
        "x".repeat(4_097),
    ] {
        assert!(PairingQrPayload::decode(&bad).is_err(), "accepted malformed native QR");
    }
}
