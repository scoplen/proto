// SPDX-License-Identifier: Apache-2.0

use scoplen_ssh::{
    CertificateValidationPolicy, EcdsaSshSigner, PublicKeyAuthContext, PublicKeyAuthRequest,
    PublicKeyIdentity, SignatureAlgorithm, Signer, SignerError, UserCertificate,
};
use ssh_key::{
    Algorithm, EcdsaCurve, PrivateKey, PublicKey, Signature, certificate, getrandom::SysRng,
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
