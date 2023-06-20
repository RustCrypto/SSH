//! OpenSSH variant of ChaCha20Poly1305: `chacha20-poly1305@openssh.com`
//!
//! Differences from ChaCha20Poly1305 as described in RFC8439:
//!
//! - Construction uses two separately keyed instances of ChaCha20: one for data, one for lengths
//! - The input of Poly1305 is not padded
//! - The lengths of ciphertext and AAD are not authenticated using Poly1305
//!
//! [PROTOCOL.chacha20poly1305]: https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL.chacha20poly1305?annotate=HEAD

use crate::{Error, Nonce, Result, Tag};
use chacha20::{ChaCha20, Key};
use cipher::{KeyInit, KeyIvInit, StreamCipher, StreamCipherSeek};
use poly1305::Poly1305;
use subtle::ConstantTimeEq;

const KEY_SIZE: usize = 32;

pub(crate) struct ChaCha20Poly1305 {
    cipher: ChaCha20,
    mac: Poly1305,
}

impl ChaCha20Poly1305 {
    /// Create a new [`ChaCha20Poly1305`] instance with a 64-byte key.
    /// From [PROTOCOL.chacha20poly1305]:
    ///
    /// > The chacha20-poly1305@openssh.com cipher requires 512 bits of key
    /// > material as output from the SSH key exchange. This forms two 256 bit
    /// > keys (K_1 and K_2), used by two separate instances of chacha20.
    /// > The first 256 bits constitute K_2 and the second 256 bits become
    /// > K_1.
    /// >
    /// > The instance keyed by K_1 is a stream cipher that is used only
    /// > to encrypt the 4 byte packet length field. The second instance,
    /// > keyed by K_2, is used in conjunction with poly1305 to build an AEAD
    /// > (Authenticated Encryption with Associated Data) that is used to encrypt
    /// > and authenticate the entire packet.
    ///
    /// [PROTOCOL.chacha20poly1305]: https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL.chacha20poly1305?annotate=HEAD
    pub fn new(key: &[u8], nonce: &[u8]) -> Result<Self> {
        #[allow(clippy::integer_arithmetic)]
        if key.len() != KEY_SIZE * 2 {
            return Err(Error::KeySize);
        }

        // TODO(tarcieri): support for using both keys
        let (k_2, _k_1) = key.split_at(KEY_SIZE);
        let key = Key::from_slice(k_2);

        let nonce = if nonce.is_empty() {
            // For key encryption
            Nonce::default()
        } else {
            Nonce::try_from(nonce).map_err(|_| Error::IvSize)?
        };

        let mut cipher = ChaCha20::new(key, &nonce.into());
        let mut poly1305_key = poly1305::Key::default();
        cipher.apply_keystream(&mut poly1305_key);

        let mac = Poly1305::new(&poly1305_key);

        // Seek to block 1
        cipher.seek(64);

        Ok(Self { cipher, mac })
    }

    #[inline]
    pub fn encrypt(mut self, buffer: &mut [u8]) -> Tag {
        self.cipher.apply_keystream(buffer);
        self.mac.compute_unpadded(buffer).into()
    }

    #[inline]
    pub fn decrypt(mut self, buffer: &mut [u8], tag: Tag) -> Result<()> {
        let expected_tag = self.mac.compute_unpadded(buffer);

        if expected_tag.ct_eq(&tag).into() {
            self.cipher.apply_keystream(buffer);
            Ok(())
        } else {
            Err(Error::Crypto)
        }
    }
}
