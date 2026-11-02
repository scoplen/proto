// SPDX-License-Identifier: Apache-2.0

use scoplen_crypto::P256SigningKey;
use scoplen_ssh::{
    CertificateValidationPolicy, EcdsaSshSigner, PublicKeyAuthContext, PublicKeyAuthRequest,
    PublicKeyIdentity, SignatureAlgorithm, Signer, SignerError, UserCertificate,
};
use ssh_key::{
    Algorithm, EcdsaCurve, PrivateKey, PublicKey, Signature, certificate,
    encoding::base64::{Base64, Encoding},
    getrandom::SysRng,
    rand_core::UnwrapErr,
};

fn key(curve: EcdsaCurve) -> PrivateKey {
    PrivateKey::random(&mut UnwrapErr(SysRng), Algorithm::Ecdsa { curve }).expect("ECDSA key")
}

fn context() -> PublicKeyAuthContext {
    PublicKeyAuthContext::new([3; 32], "alice", "ssh-connection").expect("context")
}

fn signature_body(request: &PublicKeyAuthRequest) -> Vec<u8> {
    let signature = request.signature().expect("signed request");
    let algorithm_len =
        u32::from_be_bytes(signature[..4].try_into().expect("algorithm length")) as usize;
    let algorithm_end = 4 + algorithm_len;
    let body_len = u32::from_be_bytes(
        signature[algorithm_end..algorithm_end + 4].try_into().expect("body length"),
    ) as usize;
    assert_eq!(signature.len(), algorithm_end + 4 + body_len);
    assert_eq!(
        &signature[4..algorithm_end],
        request.identity().algorithm().replace("-cert-v01@openssh.com", "").as_bytes(),
    );
    signature[algorithm_end + 4..].to_vec()
}

fn p256_openssh_fixture(scalar: &[u8], mpint: &[u8]) -> (String, Vec<u8>) {
    let mut fixed = [0u8; 32];
    fixed[32 - scalar.len()..].copy_from_slice(scalar);
    let key = P256SigningKey::from_bytes(&fixed).expect("synthetic P-256 scalar");
    let public = scoplen_ssh::P256SshSigner::new(key).public_key_blob().expect("public key");
    let string = |output: &mut Vec<u8>, value: &[u8]| {
        output
            .extend_from_slice(&u32::try_from(value.len()).expect("fixture length").to_be_bytes());
        output.extend_from_slice(value);
    };
    let mut private = Vec::new();
    private.extend_from_slice(&7u32.to_be_bytes());
    private.extend_from_slice(&7u32.to_be_bytes());
    private.extend_from_slice(&public);
    string(&mut private, mpint);
    string(&mut private, b"synthetic-short-scalar");
    let mut padding = 1;
    while !private.len().is_multiple_of(8) {
        private.push(padding);
        padding += 1;
    }
    let mut encoded = b"openssh-key-v1\0".to_vec();
    string(&mut encoded, b"none");
    string(&mut encoded, b"none");
    string(&mut encoded, b"");
    encoded.extend_from_slice(&1u32.to_be_bytes());
    string(&mut encoded, &public);
    string(&mut encoded, &private);
    let base64 = Base64::encode_string(&encoded);
    let mut pem = String::from("-----BEGIN OPENSSH PRIVATE KEY-----\n");
    for line in base64.as_bytes().chunks(70) {
        pem.push_str(std::str::from_utf8(line).expect("base64 ASCII"));
        pem.push('\n');
    }
    pem.push_str("-----END OPENSSH PRIVATE KEY-----\n");
    (pem, public)
}

#[test]
fn openssh_p256_short_scalars_import_and_sign_session_bound_requests() {
    for (len, high_bit) in [(30, false), (31, false), (32, false), (32, true)] {
        let mut scalar = vec![1; len];
        if high_bit {
            scalar[0] = 0x80;
        }
        let mut mpint = Vec::new();
        if high_bit {
            mpint.push(0);
        }
        mpint.extend_from_slice(&scalar);
        let (pem, expected_public) = p256_openssh_fixture(&scalar, &mpint);
        let imported = PrivateKey::from_openssh(&pem).expect("valid OpenSSH P-256 scalar");
        assert_eq!(imported.public_key().to_bytes().expect("public key"), expected_public);
        let private = imported.key_data().ecdsa().expect("ECDSA key").private_key_bytes();
        assert_eq!(&private[32 - len..], scalar);
        assert!(private[..32 - len].iter().all(|byte| *byte == 0));
        let signer = EcdsaSshSigner::new(imported).expect("signer");
        let identity = PublicKeyIdentity::from_signer(&signer).expect("identity");
        let request = PublicKeyAuthRequest::signed(context(), identity, &signer).expect("request");
        let signature = Signature::new(
            Algorithm::Ecdsa { curve: EcdsaCurve::NistP256 },
            signature_body(&request),
        )
        .expect("signature");
        let public = PublicKey::from_bytes(&expected_public).expect("parsed public key");
        signature::Verifier::verify(&public, &request.signature_payload(), &signature)
            .expect("session-bound request verifies");
    }
}

#[test]
fn openssh_p256_scalar_decoder_retains_length_and_truncation_rejections() {
    for mpint in [Vec::new(), vec![1; 33], vec![0; 34]] {
        let (pem, _) = p256_openssh_fixture(&[1; 31], &mpint);
        assert!(PrivateKey::from_openssh(pem).is_err());
    }
    let (mut pem, _) = p256_openssh_fixture(&[1; 31], &[1; 31]);
    pem.truncate(pem.len() / 2);
    assert!(PrivateKey::from_openssh(pem).is_err());
}

#[test]
fn software_ecdsa_curves_sign_verifiable_raw_and_certificate_requests() {
    let ca = PrivateKey::random(&mut UnwrapErr(SysRng), Algorithm::Ed25519).expect("CA");
    for (curve, algorithm) in [
        (EcdsaCurve::NistP256, SignatureAlgorithm::EcdsaSha2Nistp256),
        (EcdsaCurve::NistP384, SignatureAlgorithm::EcdsaSha2Nistp384),
        (EcdsaCurve::NistP521, SignatureAlgorithm::EcdsaSha2Nistp521),
    ] {
        let signer = EcdsaSshSigner::new(key(curve)).expect("signer");
        assert_eq!(signer.algorithm(), algorithm);
        let public = PublicKey::from_bytes(&signer.public_key_blob().expect("public key"))
            .expect("parsed public key");
        let raw = PublicKeyIdentity::from_signer(&signer).expect("raw identity");
        assert_eq!(raw.algorithm(), algorithm.name());
        let raw_request =
            PublicKeyAuthRequest::signed(context(), raw, &signer).expect("raw request");
        let signature = Signature::new(Algorithm::Ecdsa { curve }, signature_body(&raw_request))
            .expect("SSH ECDSA signature body");
        signature::Verifier::verify(&public, &raw_request.signature_payload(), &signature)
            .expect("raw request verifies");

        let mut builder = certificate::Builder::new(vec![8; 16], public.clone(), 100, 200)
            .expect("certificate builder");
        builder.cert_type(certificate::CertType::User).expect("user certificate");
        builder.valid_principal("alice").expect("principal");
        let certificate = UserCertificate::parse_and_validate(
            &builder.sign(&ca).expect("signed certificate").to_bytes().expect("certificate bytes"),
            &CertificateValidationPolicy::user("alice", 150),
        )
        .expect("valid certificate");
        let identity = certificate.identity();
        assert_eq!(identity.algorithm(), algorithm.certificate_name());
        let request = PublicKeyAuthRequest::signed(context(), identity.clone(), &signer)
            .expect("certificate request");
        let signature = Signature::new(Algorithm::Ecdsa { curve }, signature_body(&request))
            .expect("SSH ECDSA signature body");
        signature::Verifier::verify(&public, &request.signature_payload(), &signature)
            .expect("certificate request verifies");

        let other = EcdsaSshSigner::new(key(curve)).expect("other signer");
        assert_eq!(
            PublicKeyAuthRequest::signed(context(), identity, &other),
            Err(SignerError::InvalidInput("signer key does not match public-key identity")),
        );
    }
}

#[test]
fn software_ecdsa_rejects_non_ecdsa_and_curve_substitution() {
    let ed25519 =
        PrivateKey::random(&mut UnwrapErr(SysRng), Algorithm::Ed25519).expect("Ed25519 key");
    assert!(matches!(
        EcdsaSshSigner::new(ed25519),
        Err(SignerError::InvalidInput("ECDSA signer requires an ECDSA private key"))
    ));
    let p384 = EcdsaSshSigner::new(key(EcdsaCurve::NistP384)).expect("P-384 signer");
    let p521 = EcdsaSshSigner::new(key(EcdsaCurve::NistP521)).expect("P-521 signer");
    let identity = PublicKeyIdentity::from_signer(&p384).expect("identity");
    assert_eq!(
        PublicKeyAuthRequest::signed(context(), identity, &p521),
        Err(SignerError::AlgorithmMismatch {
            signer: "ecdsa-sha2-nistp521".into(),
            identity: "ecdsa-sha2-nistp384".into(),
        }),
    );
}
