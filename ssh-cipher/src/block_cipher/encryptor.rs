//! Stateful encryptor object.

use super::{BlockMode, State, sealed::BlockCipher};
use crate::{Cipher, Error, Result};
use ::cipher::{
    Block, BlockCipherEncBackend, BlockCipherEncClosure, BlockModeEncBackend, BlockModeEncClosure,
    BlockModeEncrypt,
    common::{
        BlockSizeUser, InnerUser, ParBlocksSizeUser,
        array::{ArraySize, sizes::U1},
    },
    inout::InOut,
};
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
}

impl<C: BlockCipher> BlockModeEncrypt for Encryptor<C> {
    fn encrypt_with_backend(&mut self, f: impl BlockModeEncClosure<BlockSize = Self::BlockSize>) {
        struct Closure<'a, BS, BC>
        where
            BS: ArraySize,
            BC: BlockModeEncClosure<BlockSize = BS>,
        {
            state: &'a mut State<BS>,
            f: BC,
        }

        impl<BS, BC> BlockSizeUser for Closure<'_, BS, BC>
        where
            BS: ArraySize,
            BC: BlockModeEncClosure<BlockSize = BS>,
        {
            type BlockSize = BS;
        }

        impl<BS, BC> BlockCipherEncClosure for Closure<'_, BS, BC>
        where
            BS: ArraySize,
            BC: BlockModeEncClosure<BlockSize = BS>,
        {
            #[inline(always)]
            fn call<B: BlockCipherEncBackend<BlockSize = Self::BlockSize>>(
                self,
                cipher_backend: &B,
            ) {
                let Self { state, f } = self;
                f.call(&mut Backend {
                    state,
                    cipher_backend,
                });
            }
        }

        let Self { cipher, state } = self;
        cipher.encrypt_with_backend(Closure { state, f });
    }
}

impl<C: BlockCipher> BlockSizeUser for Encryptor<C> {
    type BlockSize = C::BlockSize;
}

impl<C: BlockCipher> Debug for Encryptor<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Encryptor").finish_non_exhaustive()
    }
}

impl<C: BlockCipher> InnerUser for Encryptor<C> {
    type Inner = C;
}

struct Backend<'a, BS, BK>
where
    BS: ArraySize,
    BK: BlockCipherEncBackend<BlockSize = BS>,
{
    state: &'a mut State<BS>,
    cipher_backend: &'a BK,
}

impl<BS, BK> BlockSizeUser for Backend<'_, BS, BK>
where
    BS: ArraySize,
    BK: BlockCipherEncBackend<BlockSize = BS>,
{
    type BlockSize = BS;
}

impl<BS, BK> ParBlocksSizeUser for Backend<'_, BS, BK>
where
    BS: ArraySize,
    BK: BlockCipherEncBackend<BlockSize = BS>,
{
    // CBC encryption cannot be performed in parallel
    // TODO(tarcieri): parallel encryption support for CTR mode, serial for CBC
    type ParBlocksSize = U1;
}

impl<BS, BK> BlockModeEncBackend for Backend<'_, BS, BK>
where
    BS: ArraySize,
    BK: BlockCipherEncBackend<BlockSize = BS>,
{
    #[inline(always)]
    fn encrypt_block(&mut self, mut block: InOut<'_, '_, Block<Self>>) {
        let mut t = block.clone_in();

        match self.state.mode() {
            BlockMode::Cbc => {
                self.state.xor_into(&mut t);
                self.cipher_backend.encrypt_block(InOut::from(&mut t));
                self.state.as_mut().copy_from_slice(&t);
            }
            BlockMode::Ctr => {
                let mut pad = self.state.clone();
                self.cipher_backend.encrypt_block(pad.as_mut().into());
                pad.xor_into(&mut t);
                self.state.increment_counter();
            }
        }

        *block.get_out() = t;
    }
}
