//! Stateful encryptor object.

use super::{BlockMode, State, sealed::BlockCipher};
use crate::{Cipher, Error, Result};
use ::cipher::{Block, typenum::Unsigned};
use core::fmt::{self, Debug};

/// Stateful encryptor object for unauthenticated symmetric ciphers used in the SSH packet
/// encryption protocol.
pub struct Encryptor<C: BlockCipher> {
    /// Inner block cipher.
    cipher: C,

    /// State of the block cipher's mode of operation.
    state: State<C::BlockSize>,
}

impl<C: BlockCipher> Encryptor<C> {
    /// Create a new encryptor object with the given [`Cipher`], `key`, and `iv` (i.e.
    /// initialization vector).
    ///
    /// # Errors
    /// - Returns [`Error::Crypto`] if the given `cipher` cannot be used with `Encryptor`.
    /// - Returns [`Error::Length`] if `key` or `iv` are the wrong length for the given `cipher`.
    /// - Returns [`Error::UnsupportedCipher`] if support for the given `cipher` is not enabled
    ///   in the crate features.
    pub fn new(cipher: Cipher, key: &[u8], iv: &[u8]) -> Result<Self> {
        if !C::is_supported(cipher) {
            return Err(Error::UnsupportedCipher(cipher));
        }

        let mode = cipher.block_mode().ok_or(Error::Crypto)?;
        let cipher = C::new_from_slice(key)?;
        let state = State::new_from_slice(mode, iv)?;
        Ok(Self { cipher, state })
    }

    /// Encrypt the given buffer in-place.
    ///
    /// # Errors
    /// Returns [`Error::Length`] in the event that `buffer` is not a multiple of the cipher's
    /// block size.
    pub fn encrypt(&mut self, buffer: &mut [u8]) -> Result<()> {
        #[allow(clippy::integer_division_remainder_used, reason = "non-secret length")]
        if buffer.len() % C::BlockSize::USIZE != 0 {
            return Err(Error::Length);
        }

        for block in Block::<C>::slice_as_chunks_mut(buffer).0 {
            self.encrypt_block(block);
        }

        Ok(())
    }

    /// Encrypt a single block.
    ///
    /// # Panics
    /// If `block` is not the correct block size for this cipher.
    fn encrypt_block(&mut self, block: &mut Block<C>) {
        match self.state.mode() {
            BlockMode::Cbc => {
                self.state.xor_into(block);
                self.cipher.encrypt_block(block);
                self.state.as_mut().copy_from_slice(block);
            }
            BlockMode::Ctr => {
                let mut pad = self.state.clone();
                self.cipher.encrypt_block(pad.as_mut());
                pad.xor_into(block);
                self.state.increment_counter();
            }
        }
    }
}

impl<C: BlockCipher> Debug for Encryptor<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Encryptor").finish_non_exhaustive()
    }
}
