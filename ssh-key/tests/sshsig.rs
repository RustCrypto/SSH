//! `sshsig` signature tests.

#![cfg(feature = "alloc")]

use hex_literal::hex;
use ssh_key::{Algorithm, HashAlg, LineEnding, PublicKey, SshSig};

#[cfg(any(feature = "dsa", feature = "ed25519", feature = "rsa"))]
use ssh_key::PrivateKey;

#[cfg(feature = "ed25519")]
use ssh_key::Error;

/// DSA OpenSSH-formatted private key.
#[cfg(feature = "dsa")]
const DSA_PRIVATE_KEY: &str = include_str!("examples/id_dsa_1024");

/// DSA OpenSSH-formatted public key.
#[cfg(feature = "dsa")]
const DSA_PUBLIC_KEY: &str = include_str!("examples/id_dsa_1024.pub");

/// ECDSA/P-256 OpenSSH-formatted private key.
#[cfg(feature = "p256")]
const ECDSA_P256_PRIVATE_KEY: &str = include_str!("examples/id_ecdsa_p256");

/// ECDSA/P-256 OpenSSH-formatted public key.
#[cfg(feature = "p256")]
const ECDSA_P256_PUBLIC_KEY: &str = include_str!("examples/id_ecdsa_p256.pub");

/// Ed25519 OpenSSH-formatted private key.
#[cfg(feature = "ed25519")]
const ED25519_PRIVATE_KEY: &str = include_str!("examples/id_ed25519");

/// Ed25519 OpenSSH-formatted public key.
const ED25519_PUBLIC_KEY: &str = include_str!("examples/id_ed25519.pub");

/// `sshsig`-encoded signature.
const ED25519_SIGNATURE: &str = include_str!("examples/sshsig_ed25519");

/// Bytes of the raw Ed25519 signature.
const ED25519_SIGNATURE_BYTES: [u8; 64] = hex!(
    "4f11abfeb4c18d9e8c7832eccceeb947c9505a8c29fc074900ca2396c0f2a9ac"
    "db06de2e97fafa33fd60928a4fc5a30630aa18020015094af457dc011154150f"
);

/// SkEd25519 OpenSSH-formatted public key.
const SK_ED25519_PUBLIC_KEY: &str = include_str!("examples/id_sk_ed25519_2.pub");

/// `sshsig`-encoded signature.
const SK_ED25519_SIGNATURE: &str = include_str!("examples/sshsig_sk_ed25519");

/// Bytes of the raw SkEd25519 signature.
const SK_ED25519_SIGNATURE_BYTES: [u8; 69] = hex!(
    "2f5670b6f93465d17423878a74084bf331767031ed240c627c8eb79ab8fa1b93"
    "5a1fd993f52f5a13fec1797f8a434f943a6096246aea8dd5c8aa922cba3d9506"
    "0100000009"
);

/// RSA OpenSSH-formatted private key.
#[cfg(feature = "rsa")]
const RSA_PRIVATE_KEY: &str = include_str!("examples/id_rsa_3072");

/// RSA OpenSSH-formatted public key.
#[cfg(feature = "rsa")]
const RSA_PUBLIC_KEY: &str = include_str!("examples/id_rsa_3072.pub");

/// Example message to be signed/verified.
#[allow(dead_code)]
const MSG_EXAMPLE: &[u8] = b"testing";

/// Example domain/namespace used for the message.
const NAMESPACE_EXAMPLE: &str = "example";

#[test]
fn decode_ed25519() {
    let sshsig = ED25519_SIGNATURE.parse::<SshSig>().unwrap();
    let public_key = ED25519_PUBLIC_KEY.parse::<PublicKey>().unwrap();

    assert_eq!(sshsig.algorithm(), Algorithm::Ed25519);
    assert_eq!(sshsig.version(), 1);
    assert_eq!(sshsig.public_key(), public_key.key_data());
    assert_eq!(sshsig.namespace(), NAMESPACE_EXAMPLE);
    assert_eq!(sshsig.reserved(), &[]);
    assert_eq!(sshsig.hash_alg(), HashAlg::Sha512);
    assert_eq!(sshsig.signature_bytes(), ED25519_SIGNATURE_BYTES);
}

#[test]
fn encode_ed25519() {
    let sshsig = ED25519_SIGNATURE.parse::<SshSig>().unwrap();
    let sshsig_pem = sshsig.to_pem(LineEnding::LF).unwrap();
    assert_eq!(&sshsig_pem, ED25519_SIGNATURE);
}

#[test]
fn decode_sk_ed25519() {
    let sshsig = SK_ED25519_SIGNATURE.parse::<SshSig>().unwrap();
    let public_key = SK_ED25519_PUBLIC_KEY.parse::<PublicKey>().unwrap();

    assert_eq!(sshsig.algorithm(), Algorithm::SkEd25519);
    assert_eq!(sshsig.version(), 1);
    assert_eq!(sshsig.public_key(), public_key.key_data());
    assert_eq!(sshsig.namespace(), NAMESPACE_EXAMPLE);
    assert_eq!(sshsig.reserved(), &[]);
    assert_eq!(sshsig.hash_alg(), HashAlg::Sha512);
    assert_eq!(sshsig.signature_bytes(), SK_ED25519_SIGNATURE_BYTES);
}

#[test]
fn encode_sk_ed25519() {
    let sshsig = SK_ED25519_SIGNATURE.parse::<SshSig>().unwrap();
    let sshsig_pem = sshsig.to_pem(LineEnding::LF).unwrap();
    assert_eq!(&sshsig_pem, SK_ED25519_SIGNATURE);
}

#[test]
#[cfg(feature = "dsa")]
fn sign_dsa() {
    let signing_key = PrivateKey::from_openssh(DSA_PRIVATE_KEY).unwrap();
    let verifying_key = DSA_PUBLIC_KEY.parse::<PublicKey>().unwrap();

    let signature = signing_key
        .sign(NAMESPACE_EXAMPLE, HashAlg::Sha512, MSG_EXAMPLE)
        .unwrap();

    assert_eq!(
        verifying_key.verify(NAMESPACE_EXAMPLE, MSG_EXAMPLE, &signature),
        Ok(())
    );
}

#[test]
#[cfg(feature = "p256")]
fn sign_ecdsa_p256() {
    let signing_key = PrivateKey::from_openssh(ECDSA_P256_PRIVATE_KEY).unwrap();
    let verifying_key = ECDSA_P256_PUBLIC_KEY.parse::<PublicKey>().unwrap();

    let signature = signing_key
        .sign(NAMESPACE_EXAMPLE, HashAlg::Sha512, MSG_EXAMPLE)
        .unwrap();

    assert_eq!(
        verifying_key.verify(NAMESPACE_EXAMPLE, MSG_EXAMPLE, &signature),
        Ok(())
    );
}

#[test]
#[cfg(feature = "ed25519")]
fn sign_ed25519() {
    let signing_key = PrivateKey::from_openssh(ED25519_PRIVATE_KEY).unwrap();
    let signature = signing_key
        .sign(NAMESPACE_EXAMPLE, HashAlg::Sha512, MSG_EXAMPLE)
        .unwrap();

    assert_eq!(signature, ED25519_SIGNATURE.parse::<SshSig>().unwrap());
}

#[test]
#[cfg(feature = "rsa")]
fn sign_rsa() {
    let signing_key = PrivateKey::from_openssh(RSA_PRIVATE_KEY).unwrap();
    let verifying_key = RSA_PUBLIC_KEY.parse::<PublicKey>().unwrap();

    let signature = signing_key
        .sign(NAMESPACE_EXAMPLE, HashAlg::Sha512, MSG_EXAMPLE)
        .unwrap();

    assert_eq!(
        verifying_key.verify(NAMESPACE_EXAMPLE, MSG_EXAMPLE, &signature),
        Ok(())
    );
}

#[test]
#[cfg(feature = "ed25519")]
fn verify_ed25519() {
    let verifying_key = ED25519_PUBLIC_KEY.parse::<PublicKey>().unwrap();
    let signature = ED25519_SIGNATURE.parse::<SshSig>().unwrap();

    // valid
    assert_eq!(
        verifying_key.verify(NAMESPACE_EXAMPLE, MSG_EXAMPLE, &signature),
        Ok(())
    );

    // bad namespace
    assert_eq!(
        verifying_key.verify("bogus namespace", MSG_EXAMPLE, &signature),
        Err(Error::Namespace)
    );

    // invalid message
    assert_eq!(
        verifying_key.verify(NAMESPACE_EXAMPLE, b"bogus!", &signature),
        Err(Error::Crypto)
    );
}

#[test]
#[cfg(feature = "ed25519")]
fn verify_sk_ed25519() {
    let verifying_key = SK_ED25519_PUBLIC_KEY.parse::<PublicKey>().unwrap();
    let signature = SK_ED25519_SIGNATURE.parse::<SshSig>().unwrap();

    // valid
    assert_eq!(
        verifying_key.verify(NAMESPACE_EXAMPLE, MSG_EXAMPLE, &signature),
        Ok(())
    );

    // bad namespace
    assert_eq!(
        verifying_key.verify("bogus namespace", MSG_EXAMPLE, &signature),
        Err(Error::Namespace)
    );

    // invalid message
    assert_eq!(
        verifying_key.verify(NAMESPACE_EXAMPLE, b"bogus!", &signature),
        Err(Error::Crypto)
    );
}
