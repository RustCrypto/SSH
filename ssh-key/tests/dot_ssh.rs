//! Tests for `~/.ssh` support. Uses the `tests/examples` directory instead.

#![cfg(feature = "std")]

use hex_literal::hex;
use ssh_key::{Algorithm, DotSsh, Fingerprint};

/// Number of `mldsa44_ed25519` example keys, which only parse when the
/// algorithm is enabled.
#[cfg(feature = "mldsa-eddsa")]
const MLDSA_EDDSA_PRIVATE_KEYS: usize = 3;
#[cfg(not(feature = "mldsa-eddsa"))]
const MLDSA_EDDSA_PRIVATE_KEYS: usize = 0;

#[cfg(feature = "mldsa-eddsa")]
const MLDSA_EDDSA_PUBLIC_KEYS: usize = 1;
#[cfg(not(feature = "mldsa-eddsa"))]
const MLDSA_EDDSA_PUBLIC_KEYS: usize = 0;

/// Open `.ssh` using the `test/examples`.
fn dot_ssh() -> DotSsh {
    DotSsh::open("tests/examples")
}

#[test]
fn path_round_trip() {
    let dot_ssh = dot_ssh();
    dbg!(dot_ssh.path());
    assert!(dot_ssh.path().ends_with("tests/examples"));
}

#[test]
fn private_keys() {
    let dot_ssh = dot_ssh();
    assert_eq!(
        dot_ssh.private_keys().unwrap().count(),
        22 + MLDSA_EDDSA_PRIVATE_KEYS
    );
}

#[test]
fn private_key_with_fingerprint() {
    let fingerprint = Fingerprint::Sha256(hex!(
        "5025222ebecf8ecf7014524c0c1c8b81cdcdaed754df8e0e814338e7064f7084"
    ));

    let dot_ssh = dot_ssh();
    let key = dot_ssh.private_key_with_fingerprint(fingerprint).unwrap();
    assert_eq!(key.algorithm(), Algorithm::Ed25519);
}

#[test]
fn public_keys() {
    let dot_ssh = dot_ssh();
    assert_eq!(
        dot_ssh.public_keys().unwrap().count(),
        12 + MLDSA_EDDSA_PUBLIC_KEYS
    );
}

#[test]
fn public_key_with_fingerprint() {
    let fingerprint = Fingerprint::Sha256(hex!(
        "5025222ebecf8ecf7014524c0c1c8b81cdcdaed754df8e0e814338e7064f7084"
    ));

    let dot_ssh = dot_ssh();
    let key = dot_ssh.public_key_with_fingerprint(fingerprint).unwrap();
    assert_eq!(key.algorithm(), Algorithm::Ed25519);
}
