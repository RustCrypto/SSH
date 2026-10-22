//! MLDSA44-Ed25519 composite key tests.
//!
//! Key, certificate and fingerprint fixtures are taken from OpenSSH's
//! `regress/unittests/sshkey/testdata`.

#![cfg(feature = "mldsa-eddsa")]

use ssh_key::{Algorithm, HashAlg, PrivateKey, PublicKey};

#[cfg(feature = "alloc")]
use ssh_key::Certificate;

/// Unencrypted OpenSSH-format private key.
const OPENSSH_PRIVATE_1: &str = include_str!("examples/mldsa44_ed25519_1");

/// The same key, encrypted under [`PASSWORD`].
#[cfg(feature = "encryption")]
const OPENSSH_PRIVATE_1_PW: &str = include_str!("examples/mldsa44_ed25519_1_pw");

/// Public key matching [`OPENSSH_PRIVATE_1`].
const OPENSSH_PUBLIC_1: &str = include_str!("examples/mldsa44_ed25519_1.pub");

/// Certificate over [`OPENSSH_PUBLIC_1`].
#[cfg(feature = "alloc")]
const OPENSSH_CERT_1: &str = include_str!("examples/mldsa44_ed25519_1-cert.pub");

/// A second, unrelated key.
const OPENSSH_PRIVATE_2: &str = include_str!("examples/mldsa44_ed25519_2");

/// Passphrase protecting [`OPENSSH_PRIVATE_1_PW`], from OpenSSH's `testdata/pw`.
#[cfg(feature = "encryption")]
const PASSWORD: &[u8] = b"mekmitasdigoat";

/// Expected SHA-256 fingerprints, as reported by `ssh-keygen -l`.
const FINGERPRINT_1: &str = "SHA256:MHrtMS/Vf35zxTemIBpFyKqv9rT1bd1XMLqM9CnT8WY";
const FINGERPRINT_2: &str = "SHA256:fkgm6buCjmefUacy+TObQT3vsbO08/z6D8VHKqlMh/4";

#[test]
fn decode_openssh_private_key() {
    let key = PrivateKey::from_openssh(OPENSSH_PRIVATE_1).unwrap();
    assert_eq!(key.algorithm(), Algorithm::MlDsa44Ed25519);

    let keypair = key.key_data().mldsa44_ed25519().unwrap();
    assert_eq!(keypair.public.to_bytes().len(), 1344);
    assert_eq!(keypair.private.to_bytes().len(), 64);
}

#[test]
fn decode_openssh_public_key() {
    let key = PublicKey::from_openssh(OPENSSH_PUBLIC_1).unwrap();
    assert_eq!(key.algorithm(), Algorithm::MlDsa44Ed25519);
    assert!(key.key_data().is_mldsa44_ed25519());
}

#[test]
fn public_key_matches_private_key() {
    let private = PrivateKey::from_openssh(OPENSSH_PRIVATE_1).unwrap();
    let public = PublicKey::from_openssh(OPENSSH_PUBLIC_1).unwrap();
    assert_eq!(private.public_key().key_data(), public.key_data());
}

#[test]
fn encode_openssh_private_key() {
    let key = PrivateKey::from_openssh(OPENSSH_PRIVATE_1).unwrap();
    let encoded = key.to_openssh(ssh_key::LineEnding::LF).unwrap();
    assert_eq!(&*encoded, OPENSSH_PRIVATE_1);
}

#[test]
fn encode_openssh_public_key() {
    let key = PublicKey::from_openssh(OPENSSH_PUBLIC_1).unwrap();
    let encoded = key.to_openssh().unwrap();
    // The fixture carries a trailing newline and a comment; compare trimmed.
    assert_eq!(encoded.trim_end(), OPENSSH_PUBLIC_1.trim_end());
}

#[cfg(feature = "encryption")]
#[test]
fn decrypt_openssh_private_key() {
    let encrypted = PrivateKey::from_openssh(OPENSSH_PRIVATE_1_PW).unwrap();
    assert!(encrypted.is_encrypted());

    let decrypted = encrypted.decrypt(PASSWORD).unwrap();
    let expected = PrivateKey::from_openssh(OPENSSH_PRIVATE_1).unwrap();
    assert_eq!(decrypted.key_data(), expected.key_data());
}

#[cfg(feature = "encryption")]
#[test]
fn decrypt_with_wrong_password_fails() {
    let encrypted = PrivateKey::from_openssh(OPENSSH_PRIVATE_1_PW).unwrap();
    assert!(encrypted.decrypt(b"not the password").is_err());
}

#[test]
fn fingerprints_match_openssh() {
    let key_1 = PrivateKey::from_openssh(OPENSSH_PRIVATE_1).unwrap();
    assert_eq!(
        key_1.fingerprint(HashAlg::Sha256).to_string(),
        FINGERPRINT_1
    );

    let key_2 = PrivateKey::from_openssh(OPENSSH_PRIVATE_2).unwrap();
    assert_eq!(
        key_2.fingerprint(HashAlg::Sha256).to_string(),
        FINGERPRINT_2
    );
}

#[test]
fn sign_and_verify() {
    use signature::{Signer, Verifier};

    let msg = b"MLDSA44-Ed25519 signing test";
    let key = PrivateKey::from_openssh(OPENSSH_PRIVATE_1).unwrap();
    let signature = key.key_data().sign(msg);

    assert_eq!(signature.algorithm(), Algorithm::MlDsa44Ed25519);
    assert_eq!(signature.as_bytes().len(), 2484);

    let public = PublicKey::from_openssh(OPENSSH_PUBLIC_1).unwrap();
    assert!(public.key_data().verify(msg, &signature).is_ok());
    assert!(
        public
            .key_data()
            .verify(b"other message", &signature)
            .is_err()
    );

    // A signature from key 2 must not verify under key 1.
    let other = PrivateKey::from_openssh(OPENSSH_PRIVATE_2).unwrap();
    let other_signature = other.key_data().sign(msg);
    assert!(public.key_data().verify(msg, &other_signature).is_err());
}

#[cfg(feature = "alloc")]
#[test]
fn decode_certificate() {
    let cert = Certificate::from_openssh(OPENSSH_CERT_1).unwrap();
    assert_eq!(cert.algorithm(), Algorithm::MlDsa44Ed25519);
    assert!(cert.public_key().is_mldsa44_ed25519());

    // OpenSSH fingerprints a certificate by its embedded public key, so this
    // matches the plain key's fingerprint.
    assert_eq!(
        cert.public_key().fingerprint(HashAlg::Sha256).to_string(),
        FINGERPRINT_1
    );

    let public = PublicKey::from_openssh(OPENSSH_PUBLIC_1).unwrap();
    assert_eq!(cert.public_key(), public.key_data());
}

#[cfg(feature = "alloc")]
#[test]
fn encode_certificate() {
    let cert = Certificate::from_openssh(OPENSSH_CERT_1).unwrap();
    assert_eq!(
        cert.to_openssh().unwrap().trim_end(),
        OPENSSH_CERT_1.trim_end()
    );
}

/// A composite key can act as a certificate authority: it signs the cert and
/// the cert validates against it.
#[cfg(feature = "alloc")]
#[test]
fn certificate_sign_and_validate() {
    use ssh_key::certificate::Builder;
    use std::time::{SystemTime, UNIX_EPOCH};

    let ca_key = PrivateKey::from_openssh(OPENSSH_PRIVATE_1).unwrap();
    let subject = PrivateKey::from_openssh(OPENSSH_PRIVATE_2).unwrap();

    let valid_after = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let valid_before = valid_after + 3600;

    let mut builder =
        Builder::new([0u8; 32], subject.public_key(), valid_after, valid_before).unwrap();
    builder.valid_principal("example").unwrap();

    let cert = builder.sign(&ca_key).unwrap();

    assert_eq!(cert.algorithm(), Algorithm::MlDsa44Ed25519);
    assert_eq!(cert.signature_key(), ca_key.public_key().key_data());
    cert.validate_at(valid_after + 1, &[ca_key.fingerprint(HashAlg::Sha256)])
        .unwrap();
}
