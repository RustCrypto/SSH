//! OpenSSH variant of ChaCha20Poly1305.

pub use chacha20::ChaCha20Legacy as ChaCha20;

use crate::Tag;
use aead::{
    AeadCore, AeadInOut, Error, KeyInit, KeySizeUser, Result, TagPosition,
    array::typenum::{U8, U16, U32},
    inout::InOutBuf,
};
use cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use poly1305::{Poly1305, universal_hash::UniversalHash};
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
/// - Maximum supported AAD size is 16.
///
/// ## Usage notes
/// - In the context of SSH packet encryption, AAD will be 4 bytes and contain the encrypted length.
/// - In the context of SSH key encryption, AAD will be empty.
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
    const TAG_POSITION: TagPosition = TagPosition::Postfix;
}

impl AeadInOut for ChaCha20Poly1305 {
    // Required methods
    fn encrypt_inout_detached(
        &self,
        nonce: &ChaChaNonce,
        associated_data: &[u8],
        buffer: InOutBuf<'_, '_, u8>,
    ) -> Result<Tag> {
        Cipher::new(&self.key, nonce).encrypt(associated_data, buffer)
    }

    fn decrypt_inout_detached(
        &self,
        nonce: &ChaChaNonce,
        associated_data: &[u8],
        buffer: InOutBuf<'_, '_, u8>,
        tag: &Tag,
    ) -> Result<()> {
        Cipher::new(&self.key, nonce).decrypt(associated_data, buffer, tag)
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
    pub fn encrypt(mut self, aad: &[u8], mut buffer: InOutBuf<'_, '_, u8>) -> Result<Tag> {
        self.cipher.apply_keystream_inout(buffer.reborrow());
        compute_mac(self.mac, aad, buffer.get_out())
    }

    /// Decrypt the provided `buffer` in-place, verifying it against the provided Poly1305
    /// authentication `tag`.
    #[inline]
    pub fn decrypt(mut self, aad: &[u8], buffer: InOutBuf<'_, '_, u8>, tag: &Tag) -> Result<()> {
        let expected_tag = compute_mac(self.mac, aad, buffer.get_in())?;

        if expected_tag.ct_eq(tag).into() {
            self.cipher.apply_keystream_inout(buffer);
            Ok(())
        } else {
            Err(Error)
        }
    }
}

/// Compute the MAC for a given input buffer (containing ciphertext).
fn compute_mac(mut mac: Poly1305, aad: &[u8], buffer: &[u8]) -> Result<Tag> {
    match aad.len() {
        0 => Ok(mac.compute_unpadded(buffer)),
        1..poly1305::BLOCK_SIZE => {
            let mut block = poly1305::Block::default();
            block[..aad.len()].copy_from_slice(aad);

            let block_remaining = poly1305::BLOCK_SIZE.checked_sub(aad.len()).ok_or(Error)?;
            if buffer.len() > block_remaining {
                let (head, tail) = buffer.split_at(block_remaining);
                block[aad.len()..].copy_from_slice(head);
                mac.update(&[block]);
                Ok(mac.compute_unpadded(tail))
            } else {
                let msg_len = aad.len().checked_add(buffer.len()).ok_or(Error)?;
                block[aad.len()..msg_len].copy_from_slice(buffer);
                Ok(mac.compute_unpadded(&block[..msg_len]))
            }
        }
        _ => Err(Error),
    }
}

#[cfg(test)]
mod tests {
    use super::{AeadInOut, ChaCha20Poly1305, KeyInit};
    use hex_literal::hex;

    #[test]
    fn test_vector() {
        let key = hex!("379a8ca9e7e705763633213511e8d92eb148a46f1dd0045ec8164e5d23e456eb");
        let nonce = hex!("0000000000000003");
        let aad = hex!("5709db2d");
        let plaintext = hex!("06050000000c7373682d7573657261757468de5949ab061f");
        let ciphertext = hex!("6dcfb03be8a55e7f0220465672edd921489ea0171198e8a7");
        let tag = hex!("3e82fe0a2db7128d58ef8d9047963ca3");

        let cipher = ChaCha20Poly1305::new(key.as_ref());
        let mut buffer = plaintext.clone();
        let actual_tag = cipher
            .encrypt_inout_detached(nonce.as_ref(), &aad, buffer.as_mut_slice().into())
            .unwrap();

        assert_eq!(buffer, ciphertext);
        assert_eq!(actual_tag, tag);

        cipher
            .decrypt_inout_detached(
                nonce.as_ref(),
                &aad,
                buffer.as_mut_slice().into(),
                &actual_tag,
            )
            .unwrap();

        assert_eq!(buffer, plaintext);
    }
}
