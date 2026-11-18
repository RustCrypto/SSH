//! Integration tests for `ssh-cipher`.
// TODO(tarcieri): test vectors for each supported cipher

use ssh_cipher::Cipher;

#[test]
fn round_trip() {
    const MSG: &[u8] = b"Testing 1 2 3...";
    const CIPHERS: &[Cipher] = &[
        #[cfg(feature = "aes")]
        Cipher::Aes128Cbc,
        #[cfg(feature = "aes")]
        Cipher::Aes192Cbc,
        #[cfg(feature = "aes")]
        Cipher::Aes256Cbc,
        #[cfg(feature = "aes")]
        Cipher::Aes128Ctr,
        #[cfg(feature = "aes")]
        Cipher::Aes192Ctr,
        #[cfg(feature = "aes")]
        Cipher::Aes256Ctr,
        #[cfg(feature = "aes")]
        Cipher::Aes128Gcm,
        #[cfg(feature = "aes")]
        Cipher::Aes256Gcm,
        #[cfg(feature = "chacha20poly1305")]
        Cipher::ChaCha20Poly1305,
        #[cfg(feature = "tdes")]
        Cipher::TdesCbc,
    ];

    for &cipher in CIPHERS {
        let (key_len, iv_len) = cipher.key_and_iv_size().unwrap();

        // TODO(tarcieri): randomize keys?
        let key = vec![0; key_len];
        let iv = vec![0; iv_len];
        let mut buffer = Vec::from(MSG);

        let tag = cipher.encrypt(&key, &iv, &mut buffer).unwrap();
        assert_ne!(buffer, MSG);

        cipher.decrypt(&key, &iv, &mut buffer, tag).unwrap();
        assert_eq!(buffer, MSG);
    }
}

#[cfg(feature = "aes")]
#[test]
fn aes_key_and_iv_sizes() {
    use ssh_cipher::{
        Error,
        block_cipher::{AesDecryptor, AesEncryptor},
    };

    let key = [0; 32];
    let iv = [0; 16];

    for (cipher, expected_len) in [
        (Cipher::Aes128Cbc, 16),
        (Cipher::Aes192Cbc, 24),
        (Cipher::Aes256Cbc, 32),
        (Cipher::Aes128Ctr, 16),
        (Cipher::Aes192Ctr, 24),
        (Cipher::Aes256Ctr, 32),
    ] {
        for len in [16, 24, 32] {
            let key = &key[..len];
            let expected = (len != expected_len).then_some(Error::KeySize);
            let enc = AesEncryptor::new(cipher, key, &iv);
            let dec = AesDecryptor::new(cipher, key, &iv);
            assert_eq!(enc.err(), expected, "{cipher}, {len}-byte key");
            assert_eq!(dec.err(), expected, "{cipher}, {len}-byte key");
        }

        let key = &key[..expected_len];
        let enc = AesEncryptor::new(cipher, key, &[]);
        let dec = AesDecryptor::new(cipher, key, &[]);
        assert_eq!(enc.unwrap_err(), Error::IvSize, "{cipher}");
        assert_eq!(dec.unwrap_err(), Error::IvSize, "{cipher}");
    }
}

#[cfg(feature = "aes")]
#[test]
fn decrypt_blocks_b2b() {
    use hex_literal::hex;
    use ssh_cipher::block_cipher::{AesDecryptor, Block, BlockModeDecrypt};

    // First three blocks of NIST SP 800-38A, F.2.2 and F.5.2.
    let key = hex!("2b7e151628aed2a6abf7158809cf4f3c");
    let plaintext = [
        hex!("6bc1bee22e409f96e93d7e117393172a"),
        hex!("ae2d8a571e03ac9c9eb76fac45af8e51"),
        hex!("30c81c46a35ce411e5fbc1191a0a52ef"),
    ]
    .map(Block::<AesDecryptor>::from);

    for (mode, iv, ciphertext) in [
        (
            Cipher::Aes128Cbc,
            hex!("000102030405060708090a0b0c0d0e0f"),
            [
                hex!("7649abac8119b246cee98e9b12e9197d"),
                hex!("5086cb9b507219ee95db113a917678b2"),
                hex!("73bed6b8e3c1743b7116e69e22229516"),
            ],
        ),
        (
            Cipher::Aes128Ctr,
            hex!("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"),
            [
                hex!("874d6191b620e3261bef6864990db6ce"),
                hex!("9806f66b7970fdff8617187bb9fffdff"),
                hex!("5ae4df3edbd5d35e5b4f09020db03eab"),
            ],
        ),
    ] {
        let mut decryptor = AesDecryptor::new(mode, &key, &iv).unwrap();
        let ciphertext = ciphertext.map(Block::<AesDecryptor>::from);
        let mut output = [Block::<AesDecryptor>::default(); 3];
        decryptor.decrypt_block_b2b(&ciphertext[0], &mut output[0]);
        decryptor
            .decrypt_blocks_b2b(&ciphertext[1..], &mut output[1..])
            .unwrap();
        assert_eq!(output, plaintext, "{mode:?}");
    }
}
