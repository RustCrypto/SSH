//! Decryptor for block cipher modes of operation.

use crate::{Cipher, Error, state::State};

#[cfg(feature = "aes")]
use super::{Aes, BlockMode};

/// Stateful decryptor object for unauthenticated SSH symmetric ciphers based on low-level block
/// cipher modes of operation.
///
/// Note that this deliberately does not support AEAD modes such as AES-GCM and ChaCha20Poly1305,
/// which are one-shot by design.
pub struct Decryptor<C> {
    block_cipher: C,
    state: State,
}

#[cfg(feature = "aes")]
impl Decryptor {
    /// Create a new AES decryptor object with the given [`BlockMode`], `key`, and `iv`
    /// (i.e. initialization vector).
    ///
    /// - `key` must be 16-bytes (128-bits), 24-bytes (192-bits), or 32-bytes (256-bits).
    /// - `iv` must be 16-bytes
    ///
    /// # Errors
    /// Returns [`Error::Length`] if `key` or `iv` are the wrong length.
    pub fn new(mode: BlockMode, key: &[u8], iv: &[u8]) -> Result<Self> {
        Ok(Self {
            key: Aes::new(key)?,
            state: State::new(cipher, iv)?,
        })
    }
}
