//! OpenSSH variant of ChaCha20Poly1305.

pub use chacha20::ChaCha20Legacy as ChaCha20;

use crate::Tag;
use aead::{
    array::typenum::{U0, U16, U32, U8},
    AeadCore, Error, KeyInit, KeySizeUser, Result,
};
use cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use poly1305::Poly1305;
use subtle::ConstantTimeEq;

#[cfg(feature = "zeroize")]
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Key for `chacha20-poly1305@openssh.com`.
pub type ChaChaKey = chacha20::Key;

/// Nonce for `chacha20-poly1305@openssh.com`.
pub type ChaChaNonce = chacha20::LegacyNonce;

/// OpenSSH variant of ChaCha20Poly1305: `chacha20-poly1305@openssh.com`
/// as described in [PROTOCOL.chacha20poly1305].
///
/// Differences from ChaCha20Poly1305-IETF as described in [RFC8439]:
/// - Nonce is 64-bit instead of 96-bit (i.e. uses legacy "djb" ChaCha20 variant).
/// - The AAD and ciphertext inputs of Poly1305 are not padded.
/// - The lengths of ciphertext and AAD are not authenticated using Poly1305.
///
/// [PROTOCOL.chacha20poly1305]: https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL.chacha20poly1305?annotate=HEAD
/// [RFC8439]: https://datatracker.ietf.org/doc/html/rfc8439
#[derive(Clone)]
pub struct ChaCha20Poly1305 {
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

impl ChaCha20Poly1305 {
    /// Encrypt the provided `buffer` in-place, returning the Poly1305 authentication tag.
    ///
    /// The input `buffer` should contain the concatenation of any additional associated data (AAD)
    /// and the plaintext to be encrypted, where in the context of the SSH packet encryption
    /// protocol the AAD represents an encrypted packet length, which is itself 4-bytes / 64-bits.
    ///
    /// `aad_len` is the length of the AAD in bytes:
    /// - In the context of SSH packet encryption, this should be `4`.
    /// - In the context of SSH key encryption, `aad_len` should be `0`.
    ///
    /// The first `aad_len` bytes of `buffer` will be unmodified after encryption is completed.
    /// Only the data after `aad_len` will be encrypted.
    ///
    /// The resulting `Tag` authenticates both the AAD and the ciphertext in the buffer.
    pub fn encrypt(&self, nonce: &ChaChaNonce, buffer: &mut [u8], aad_len: usize) -> Result<Tag> {
        Cipher::new(&self.key, nonce).encrypt(buffer, aad_len)
    }

    /// Decrypt the provided `buffer` in-place, verifying it against the provided Poly1305
    /// authentication `tag`.
    ///
    /// The input `buffer` should contain the concatenation of any additional associated data (AAD)
    /// and the ciphertext to be authenticated, where in the context of the SSH packet encryption
    /// protocol the AAD represents an encrypted packet length, which is itself 4-bytes / 64-bits.
    ///
    /// `aad_len` is the length of the AAD in bytes:
    /// - In the context of SSH packet encryption, this should be `4`.
    /// - In the context of SSH key encryption, `aad_len` should be `0`.
    ///
    /// The first `aad_len` bytes of `buffer` will be unmodified after decryption completes
    /// successfully. Only data after `aad_len` will be decrypted.
    pub fn decrypt(
        &self,
        nonce: &ChaChaNonce,
        buffer: &mut [u8],
        tag: Tag,
        aad_len: usize,
    ) -> Result<()> {
        Cipher::new(&self.key, nonce).decrypt(buffer, tag, aad_len)
    }
}

impl Drop for ChaCha20Poly1305 {
    fn drop(&mut self) {
        #[cfg(feature = "zeroize")]
        self.key.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl ZeroizeOnDrop for ChaCha20Poly1305 {}

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
    pub fn encrypt(mut self, buffer: &mut [u8], aad_len: usize) -> Result<Tag> {
        if buffer.len() < aad_len {
            return Err(Error);
        }

        self.cipher.apply_keystream(&mut buffer[aad_len..]);
        Ok(self.mac.compute_unpadded(buffer))
    }

    /// Decrypt the provided `buffer` in-place, verifying it against the provided Poly1305
    /// authentication `tag`.
    #[inline]
    pub fn decrypt(mut self, buffer: &mut [u8], tag: Tag, aad_len: usize) -> Result<()> {
        if buffer.len() < aad_len {
            return Err(Error);
        }

        let expected_tag = self.mac.compute_unpadded(buffer);

        if expected_tag.ct_eq(&tag).into() {
            self.cipher.apply_keystream(&mut buffer[aad_len..]);
            Ok(())
        } else {
            Err(Error)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ChaCha20Poly1305, KeyInit};
    use hex_literal::hex;

    #[test]
    fn test_vector() {
        let key = hex!("379a8ca9e7e705763633213511e8d92eb148a46f1dd0045ec8164e5d23e456eb");
        let nonce = hex!("0000000000000003");
        let aad = hex!("5709db2d");
        let plaintext = hex!("06050000000c7373682d7573657261757468de5949ab061f");
        let ciphertext = hex!("6dcfb03be8a55e7f0220465672edd921489ea0171198e8a7");
        let tag = hex!("3e82fe0a2db7128d58ef8d9047963ca3");

        const AAD_LEN: usize = 4;
        const PT_LEN: usize = 24;
        assert_eq!(aad.len(), AAD_LEN);
        assert_eq!(plaintext.len(), PT_LEN);

        let cipher = ChaCha20Poly1305::new(key.as_ref());
        let mut buffer = [0u8; AAD_LEN + PT_LEN];
        let (a, p) = buffer.split_at_mut(AAD_LEN);
        a.copy_from_slice(&aad);
        p.copy_from_slice(&plaintext);

        let actual_tag = cipher
            .encrypt(nonce.as_ref(), &mut buffer, AAD_LEN)
            .unwrap();

        assert_eq!(&buffer[..AAD_LEN], aad);
        assert_eq!(&buffer[AAD_LEN..], ciphertext);
        assert_eq!(actual_tag, tag);

        cipher
            .decrypt(nonce.as_ref(), &mut buffer, actual_tag, AAD_LEN)
            .unwrap();

        assert_eq!(&buffer[..AAD_LEN], aad);
        assert_eq!(&buffer[AAD_LEN..], plaintext);
    }
}
