//! Block cipher state.

use crate::{BlockMode, Cipher, Error, Result};

/// State of a given block cipher, i.e. for implementing modes of operation.
#[derive(Clone, Debug)]
pub(crate) struct State {
    bytes: [u8; Self::SIZE],
    mode: BlockMode,
}

impl State {
    /// Size of the state in bytes.
    pub(crate) const SIZE: usize = 16;

    /// Create a state for a given block cipher from the provided initialization vector.
    pub(crate) fn new(cipher: Cipher, iv: &[u8]) -> Result<Self> {
        let (iv_len, mode) = match (cipher.key_and_iv_size(), cipher.block_mode()) {
            (Some((_, l)), Some(m)) => (l, m),
            _ => return Err(Error::Crypto),
        };

        if iv.len() != iv_len {
            return Err(Error::Length);
        }

        let mut bytes = [0u8; Self::SIZE];
        bytes[..iv.len()].copy_from_slice(iv);
        Ok(Self { bytes, mode })
    }

    /// Get the block mode the state was initialized with.
    pub(crate) fn mode(&self) -> BlockMode {
        self.mode
    }

    /// Increment the counter for counter mode.
    pub(crate) fn increment_counter(&mut self) {
        debug_assert_eq!(self.mode, BlockMode::Ctr);
        let n = u128::from_be_bytes(self.bytes);
        self.bytes = n.wrapping_add(1).to_be_bytes();
    }

    /// XOR the current state into the given block. This is used to implement CBC mode.
    pub(crate) fn xor_into(&self, block: &mut [u8]) {
        debug_assert!(block.len() <= Self::SIZE);
        for i in 0..block.len() {
            block[i] ^= self.bytes[i];
        }
    }

    /// Update CBC mode state.
    pub(crate) fn update_cbc(&mut self, block: &[u8]) {
        debug_assert_eq!(self.mode, BlockMode::Cbc);
        debug_assert!(block.len() <= Self::SIZE);
        debug_assert!(
            block.len() == Self::SIZE || self.bytes[block.len()..].iter().all(|b| *b == 0)
        );
        self.bytes[..block.len()].copy_from_slice(block);
    }
}

impl AsRef<[u8]> for State {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl AsMut<[u8]> for State {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.bytes
    }
}
