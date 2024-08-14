//! OpenSSH variant of ChaCha20Poly1305.

use crate::Tag;
use aead::{
    array::typenum::{U0, U16, U32, U8},
    AeadCore, AeadInPlace, Error, KeyInit, KeySizeUser, Result,
};
use chacha20::ChaCha20Legacy as ChaCha20;
use cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use poly1305::Poly1305;
use subtle::ConstantTimeEq;

/// Key for `chacha20-poly1305@openssh.com`.
pub type ChaChaKey = chacha20::Key;

/// Nonce for `chacha20-poly1305@openssh.com`.
pub type ChaChaNonce = chacha20::LegacyNonce;

/// OpenSSH variant of ChaCha20Poly1305: `chacha20-poly1305@openssh.com`
/// as described in [PROTOCOL.chacha20poly1305].
///
/// Differences from ChaCha20Poly1305-IETF as described in [RFC8439]:
/// - The input of Poly1305 is not padded.
/// - AAD is unsupported.
/// - The lengths of ciphertext (and AAD) are not authenticated using Poly1305.
///
/// [PROTOCOL.chacha20poly1305]: https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL.chacha20poly1305?annotate=HEAD
/// [RFC8439]: https://datatracker.ietf.org/doc/html/rfc8439
#[derive(Clone)]
pub struct ChaCha20Poly1305 {
    // TODO(tarcieri): zeroize on drop
    key: ChaChaKey,
}

impl KeySizeUser for ChaCha20Poly1305 {
    type KeySize = U32;
}

impl KeyInit for ChaCha20Poly1305 {
    #[inline]
    fn new(key: &ChaChaKey) -> Self {
        Self { key: *key }
    }
}

impl AeadCore for ChaCha20Poly1305 {
    type NonceSize = U8;
    type TagSize = U16;
    type CiphertextOverhead = U0;
}

impl AeadInPlace for ChaCha20Poly1305 {
    fn encrypt_in_place_detached(
        &self,
        nonce: &ChaChaNonce,
        associated_data: &[u8],
        buffer: &mut [u8],
    ) -> Result<Tag> {
        Cipher::new(&self.key, nonce).encrypt(associated_data, buffer)
    }

    fn decrypt_in_place_detached(
        &self,
        nonce: &ChaChaNonce,
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &Tag,
    ) -> Result<()> {
        Cipher::new(&self.key, nonce).decrypt(associated_data, buffer, *tag)
    }
}

/// Internal type representing a cipher instance.
struct Cipher {
    cipher: ChaCha20,
    mac: Poly1305,
}

impl Cipher {
    /// Create a new cipher instance.
    pub fn new(key: &ChaChaKey, nonce: &ChaChaNonce) -> Self {
        let mut cipher = ChaCha20::new(key, nonce);
        let mut poly1305_key = poly1305::Key::default();
        cipher.apply_keystream(&mut poly1305_key);

        let mac = Poly1305::new(&poly1305_key);

        // Seek to block 1
        cipher.seek(64);

        Self { cipher, mac }
    }

    /// Encrypt the provided `buffer` in-place, returning the Poly1305 authentication tag.
    #[inline]
    pub fn encrypt(mut self, associated_data: &[u8], buffer: &mut [u8]) -> Result<Tag> {
        // TODO(tarcieri): support associated data (RustCrypto/SSH#279)
        if !associated_data.is_empty() {
            return Err(Error);
        }

        self.cipher.apply_keystream(buffer);
        Ok(self.mac.compute_unpadded(buffer))
    }

    /// Decrypt the provided `buffer` in-place, verifying it against the provided Poly1305
    /// authentication `tag`.
    ///
    /// In the event tag verification fails, [`Error::Crypto`] is returned, and `buffer` is not
    /// modified.
    ///
    /// Upon success, `Ok(())` is returned and `buffer` is rewritten with the decrypted plaintext.
    #[inline]
    pub fn decrypt(mut self, associated_data: &[u8], buffer: &mut [u8], tag: Tag) -> Result<()> {
        // TODO(tarcieri): support associated data (RustCrypto/SSH#279)
        if !associated_data.is_empty() {
            return Err(Error);
        }

        let expected_tag = self.mac.compute_unpadded(buffer);

        if expected_tag.ct_eq(&tag).into() {
            self.cipher.apply_keystream(buffer);
            Ok(())
        } else {
            Err(Error)
        }
    }
}
