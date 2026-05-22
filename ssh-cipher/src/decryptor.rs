//! Stateful decryptor object.

use crate::{Cipher, Error, Result, key::Key, state::State};
use core::fmt::{self, Debug};

/// Stateful decryptor object for unauthenticated SSH symmetric ciphers.
///
/// Note that this deliberately does not support AEAD modes such as AES-GCM and ChaCha20Poly1305,
/// which are one-shot by design.
pub struct Decryptor {
    key: Key,
    state: State,
}

impl Decryptor {
    /// Create a new decryptor object with the given [`Cipher`], `key`, and `iv` (i.e.
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

    /// Get the cipher for this decryptor.
    #[must_use]
    pub fn cipher(&self) -> Cipher {
        self.key.cipher_for_mode(self.state.mode())
    }

    /// Decrypt the given buffer in place.
    ///
    /// # Errors
    /// Returns [`Error::Length`] in the event that `buffer` is not a multiple of the cipher's
    /// block size.
    pub fn decrypt(&mut self, buffer: &mut [u8]) -> Result<()> {
        let block_size = self.key.block_size();

        if buffer.len() % block_size != 0 {
            return Err(Error::Length);
        }

        for block in buffer.chunks_mut(block_size) {
            self.decrypt_block(block);
        }

        Ok(())
    }

    /// Call the provided function with an ephemeral [`Decryptor`] state which will be reset upon
    /// completion, returning the result of the function.
    pub fn peek<T, F>(&mut self, mut f: F) -> T
    where
        F: FnMut(&mut Self) -> T,
    {
        let state = self.state.clone();
        let ret = f(self);
        self.state = state;
        ret
    }

    /// Decrypt a single block.
    ///
    /// # Panics
    /// If `block` is not the correct block size for this cipher.
    fn decrypt_block(&mut self, block: &mut [u8]) {
        debug_assert_eq!(block.len(), self.key.block_size());

        match self.state.mode() {
            crate::BlockMode::Cbc => {
                let pad = self.state.clone();
                self.state.update_cbc(block);
                self.key.decrypt_block(block);
                pad.xor_into(block);
            }
            crate::BlockMode::Ctr => {
                let mut pad = self.state.clone();
                self.key.encrypt_block(pad.as_mut());
                pad.xor_into(block);
                self.state.increment_counter();
            }
        }
    }
}

impl Debug for Decryptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Decryptor")
            .field("cipher", &self.cipher())
            .finish_non_exhaustive()
    }
}
