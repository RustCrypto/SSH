//! ECDSA scalar parsing and validation tests.

#![cfg(feature = "ecdsa")]
#![allow(clippy::unwrap_used, reason = "tests")]

use encoding::{Base64Reader, Base64Writer, Decode, Encode};
use hex_literal::hex;
use ssh_key::{PrivateKey, private::EcdsaPrivateKey};

// Throwaway OpenSSH key from https://github.com/RustCrypto/SSH/issues/620.
const SHORT_P256_KEY: &str = include_str!("examples/id_ecdsa_p256_short");

#[test]
fn decode_short_p256_openssh() {
    let key = PrivateKey::from_openssh(SHORT_P256_KEY).unwrap();
    let ssh_key::private::EcdsaKeypair::NistP256 { private, .. } = key.key_data().ecdsa().unwrap()
    else {
        panic!("unexpected ECDSA curve");
    };
    assert_eq!(
        private.as_slice(),
        &hex!("0069aaed302f8421543fffa7b5eecb6f17a2bf72ab2df53b548aeab9e42d9106")
    );

    #[cfg(feature = "alloc")]
    {
        let encoded = key.to_openssh(ssh_key::LineEnding::LF).unwrap();
        assert_eq!(PrivateKey::from_openssh(encoded.as_str()).unwrap(), key);
    }
}

#[cfg(feature = "encryption")]
#[test]
fn encrypt_decrypt_short_p256() {
    let key = PrivateKey::from_openssh(SHORT_P256_KEY).unwrap();
    let openssh_encrypted =
        PrivateKey::from_openssh(include_str!("examples/id_ecdsa_p256_short.enc")).unwrap();
    assert_eq!(openssh_encrypted.decrypt(b"password").unwrap(), key);

    let encrypted = key.encrypt(&mut getrandom::SysRng, b"password").unwrap();
    let encoded = encrypted.to_openssh(ssh_key::LineEnding::LF).unwrap();
    let decoded = PrivateKey::from_openssh(encoded.as_str()).unwrap();
    assert_eq!(decoded.decrypt(b"password").unwrap(), key);
}

#[cfg(all(feature = "alloc", feature = "p256"))]
#[test]
fn sign_with_short_p256() {
    let key = PrivateKey::from_openssh(SHORT_P256_KEY).unwrap();
    let signature = key
        .sign("test", ssh_key::HashAlg::Sha256, b"message")
        .unwrap();
    key.public_key()
        .verify("test", b"message", &signature)
        .unwrap();
}

/// Decode a length-prefixed scalar without requiring `ssh-key`'s `alloc` feature.
fn decode_scalar<const SIZE: usize>(bytes: &[u8]) -> ssh_key::Result<EcdsaPrivateKey<SIZE>> {
    let mut encoded = u32::try_from(bytes.len()).unwrap().to_be_bytes().to_vec();
    encoded.extend_from_slice(bytes);
    EcdsaPrivateKey::decode(&mut encoded.as_slice().into())
}

fn encode_positive(bytes: &[u8]) -> Vec<u8> {
    let mut encoded = Vec::new();
    if bytes.first().is_some_and(|byte| *byte >= 0x80) {
        encoded.push(0);
    }
    encoded.extend_from_slice(bytes);
    encoded
}

fn check_scalar_encodings<const SIZE: usize>() {
    // Cover every accepted length, including the 24-byte floor and 31-byte P-256 keys.
    for len in 24..=SIZE {
        let mut bytes = vec![0x42; len];
        bytes[0] = 1;
        let private = decode_scalar::<SIZE>(&bytes).unwrap();
        assert_eq!(&private.as_slice()[SIZE - len..], bytes);
        assert!(
            private.as_slice()[..SIZE - len]
                .iter()
                .all(|byte| *byte == 0)
        );

        // Keep accepting fixed-width encodings, including redundant leading zeros.
        let mut encoded = [0u8; 96];
        let mut writer = Base64Writer::new(&mut encoded).unwrap();
        private.encode(&mut writer).unwrap();
        let encoded = writer.finish().unwrap();
        let mut reader = encoding::Decoder::from(Base64Reader::new(encoded.as_bytes()).unwrap());
        assert_eq!(private.encoded_len().unwrap(), reader.remaining_len());
        let decoded = EcdsaPrivateKey::<SIZE>::decode(&mut reader).unwrap();
        assert_eq!(private, reader.finish(decoded).unwrap());

        // A set high bit requires a leading sign byte, regardless of magnitude length.
        bytes[0] = 0x80;
        assert_eq!(
            decode_scalar::<SIZE>(&bytes),
            Err(ssh_key::Error::FormatEncoding)
        );
        let padded = decode_scalar::<SIZE>(&encode_positive(&bytes)).unwrap();
        assert_eq!(&padded.as_slice()[SIZE - len..], bytes);

        // Additional leading zeros are accepted within the wire-length bound.
        let mut redundant = vec![0; SIZE + 1 - len];
        redundant.extend_from_slice(&bytes);
        assert_eq!(decode_scalar::<SIZE>(&redundant).unwrap(), padded);
        redundant.insert(0, 0);
        assert_eq!(
            decode_scalar::<SIZE>(&redundant),
            Err(encoding::Error::Length.into())
        );
    }

    // Zero and magnitudes below 24 bytes are rejected, even with enough padding
    // to fill the whole scalar or an additional sign byte.
    for len in 0..24 {
        let bytes = vec![0x80; len];
        assert!(decode_scalar::<SIZE>(&encode_positive(&bytes)).is_err());
        let mut padded = vec![0; SIZE + 1 - len];
        padded.extend_from_slice(&bytes);
        assert_eq!(
            decode_scalar::<SIZE>(&padded),
            Err(encoding::Error::Length.into())
        );
    }

    assert_eq!(
        decode_scalar::<SIZE>(&vec![1; SIZE + 1]),
        Err(encoding::Error::Length.into())
    );
}

#[test]
fn p256_scalar_encodings() {
    check_scalar_encodings::<32>();
}

#[test]
fn p384_scalar_encodings() {
    check_scalar_encodings::<48>();
}

#[test]
fn p521_scalar_encodings() {
    check_scalar_encodings::<66>();
}
