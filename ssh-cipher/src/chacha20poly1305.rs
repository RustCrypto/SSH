//! OpenSSH variant of ChaCha20Poly1305: `chacha20-poly1305@openssh.com`
//!
//! Differences from ChaCha20Poly1305 as described in RFC8439:
//! - The input of Poly1305 is not padded
//! - The lengths of ciphertext and AAD are not authenticated using Poly1305
//!
//! [PROTOCOL.chacha20poly1305]: https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL.chacha20poly1305?annotate=HEAD

use crate::{Error, Nonce, Result, Tag};
use chacha20::{ChaCha20, Key};
use cipher::{KeyInit, KeyIvInit, StreamCipher, StreamCipherSeek};
use poly1305::Poly1305;
use subtle::ConstantTimeEq;

pub(crate) struct ChaCha20Poly1305 {
    cipher: ChaCha20,
    mac: Poly1305,
}

impl ChaCha20Poly1305 {
    /// Create a new [`ChaCha20Poly1305`] instance with a 32-byte key.
    ///
    /// [PROTOCOL.chacha20poly1305]: https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL.chacha20poly1305?annotate=HEAD
    pub fn new(key: &[u8], nonce: &[u8]) -> Result<Self> {
        let key = Key::try_from(key).map_err(|_| Error::KeySize)?;
        let nonce = Nonce::try_from(nonce).map_err(|_| Error::IvSize)?;
        let mut cipher = ChaCha20::new(&key, &nonce.into());
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
