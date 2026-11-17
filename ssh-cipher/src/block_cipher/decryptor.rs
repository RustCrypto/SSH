//! Stateful decryptor object.

use super::{BlockMode, State, sealed::BlockCipher};
use crate::{Cipher, Error, Result};
use ::cipher::{
    Block, BlockModeDecBackend, BlockModeDecClosure, BlockModeDecrypt,
    common::{BlockSizeUser, InnerUser, ParBlocksSizeUser, array::sizes::U1},
    inout::InOut,
};
use core::fmt::{self, Debug};

/// Stateful decryptor object for unauthenticated symmetric ciphers used in the SSH packet
/// encryption protocol.
///
/// Note we need encryption support for decryption in order to support AES-CTR, where encryption
/// and decryption are the same operation.
pub struct Decryptor<C: BlockCipher> {
    /// Inner block cipher.
    cipher: C,

    /// State of the block cipher's mode of operation.
    state: State<C::BlockSize>,
}

impl<C: BlockCipher> Decryptor<C> {
    /// Create a new decryptor object with the given [`Cipher`], `key`, and `iv` (i.e.
    /// initialization vector).
    ///
    /// # Errors
    /// - Returns [`Error::Crypto`] if the given `cipher` cannot be used with `Decryptor`.
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
}

impl<C: BlockCipher> BlockModeDecrypt for Decryptor<C> {
    fn decrypt_with_backend(&mut self, f: impl BlockModeDecClosure<BlockSize = Self::BlockSize>) {
        let Self { cipher, state } = self;
        f.call(&mut Backend { cipher, state });
    }
}

impl<C: BlockCipher> BlockSizeUser for Decryptor<C> {
    type BlockSize = C::BlockSize;
}

impl<C: BlockCipher> Debug for Decryptor<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Decryptor").finish_non_exhaustive()
    }
}

impl<C: BlockCipher> InnerUser for Decryptor<C> {
    type Inner = C;
}

struct Backend<'a, C: BlockCipher> {
    cipher: &'a C,
    state: &'a mut State<C::BlockSize>,
}

impl<C: BlockCipher> BlockSizeUser for Backend<'_, C> {
    type BlockSize = C::BlockSize;
}

impl<C: BlockCipher> ParBlocksSizeUser for Backend<'_, C> {
    // TODO(tarcieri): parallel decryption support
    type ParBlocksSize = U1;
}

impl<C: BlockCipher> BlockModeDecBackend for Backend<'_, C> {
    fn decrypt_block(&mut self, mut block: InOut<'_, '_, Block<Self>>) {
        match self.state.mode() {
            BlockMode::Cbc => {
                let ciphertext = block.clone_in();
                self.cipher.decrypt_block_inout(block.reborrow());
                self.state.xor_into(block.get_out());
                *self.state.as_mut() = ciphertext;
            }
            BlockMode::Ctr => {
                let mut pad = self.state.as_ref().clone();
                self.cipher.encrypt_block(&mut pad);
                block.xor_in2out(&pad);
                self.state.increment_counter();
            }
        }
    }
}
