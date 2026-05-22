//! Stateful encryptor object.

use crate::{BlockMode, Cipher, Error, Result, key::Key, state::State};
use core::fmt::{self, Debug};

/// Stateful encryptor object for unauthenticated SSH symmetric ciphers.
///
/// Note that this deliberately does not support AEAD modes such as AES-GCM and ChaCha20Poly1305,
/// which are one-shot by design.
pub struct Encryptor {
    key: Key,
    state: State,
}

impl Encryptor {
    /// Create a new encryptor object with the given [`Cipher`], `key`, and `iv` (i.e.
    /// initialization vector).
    ///
    /// # Errors
    /// - Returns [`Error::Crypto`] if the given `cipher` cannot be used with `Decryptor`.
    /// - Returns [`Error::Length`] if `key` or `iv` are the wrong length for the given `cipher`.
    /// - Returns [`Error::UnsupportedCipher`] if support for the given `cipher` is not enabled
    ///   in the crate features.
    pub fn new(cipher: Cipher, key: &[u8], iv: &[u8]) -> Result<Self> {
        Ok(Self {
            key: Key::new(cipher.block_cipher().ok_or(Error::Crypto)?, key)?,
            state: State::new(cipher, iv)?,
        })
    }

    /// Get the cipher for this encryptor.
    #[must_use]
    pub fn cipher(&self) -> Cipher {
        self.key.cipher_for_mode(self.state.mode())
    }

    /// Encrypt the given buffer in-place.
    ///
    /// # Errors
    /// Returns [`Error::Length`] in the event that `buffer` is not a multiple of the cipher's
    /// block size.
    pub fn encrypt(&mut self, buffer: &mut [u8]) -> Result<()> {
        let block_size = self.key.block_size();

        if buffer.len() % block_size != 0 {
            return Err(Error::Length);
        }

        for block in buffer.chunks_mut(block_size) {
            self.encrypt_block(block);
        }

        Ok(())
    }

    /// Encrypt a single block.
    ///
    /// # Panics
    /// If `block` is not the correct block size for this cipher.
    fn encrypt_block(&mut self, block: &mut [u8]) {
        debug_assert_eq!(block.len(), self.key.block_size());

        match self.state.mode() {
            BlockMode::Cbc => {
                self.state.xor_into(block);
                self.key.encrypt_block(block);
                self.state.update_cbc(block);
            }
            BlockMode::Ctr => {
                let mut pad = self.state.clone();
                self.key.encrypt_block(pad.as_mut());
                pad.xor_into(block);
                self.state.increment_counter();
            }
        }
    }
}

impl Debug for Encryptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Encryptor")
            .field("cipher", &self.cipher())
            .finish_non_exhaustive()
    }
}
