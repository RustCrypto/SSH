//! Block cipher state.

use super::BlockMode;
use crate::Result;
use cipher::common::array::{Array, ArraySize};

/// Block cipher state. Intended for reuse between CBC and CTR modes.
#[derive(Clone, Debug)]
pub(crate) struct State<Size: ArraySize> {
    mode: BlockMode,
    bytes: Array<u8, Size>,
}

impl<Size: ArraySize> State<Size> {
    /// Initialize state for a particular block cipher mode of operation.
    pub(crate) fn new(mode: BlockMode, iv: &Array<u8, Size>) -> Self {
        debug_assert!(
            mode != BlockMode::Ctr || Size::USIZE == 16,
            "we only support CTR for 128-bit block sizes"
        );

        Self {
            bytes: iv.clone(),
            mode,
        }
    }

    /// Initialize state for a particular block cipher mode of operation, with the initialization
    /// vector provided as a slice.
    ///
    /// # Errors
    /// Returns [`Error::Length`] in the event the IV is the wrong size.
    pub(crate) fn new_from_slice(mode: BlockMode, iv: &[u8]) -> Result<Self> {
        Ok(Self::new(mode, iv.try_into()?))
    }

    /// Get the block mode the state was initialized with.
    pub(crate) fn mode(&self) -> BlockMode {
        self.mode
    }

    /// Increment the counter for counter mode.
    pub(crate) fn increment_counter(&mut self) {
        debug_assert_eq!(self.mode, BlockMode::Ctr);
        debug_assert!(self.bytes.len() <= 16);
        let offset = 16 - Size::USIZE;

        // Zero padding is needed to make the generic implementation work,
        let mut bytes = [0u8; 16];
        bytes[offset..].copy_from_slice(&self.bytes);

        let n = u128::from_be_bytes(bytes);
        let bytes = n.wrapping_add(1).to_be_bytes();
        self.bytes.copy_from_slice(&bytes[offset..]);
    }

    /// XOR the current state into the given block. This is used to implement CBC mode.
    pub(crate) fn xor_into(&self, block: &mut Array<u8, Size>) {
        for i in 0..Size::USIZE {
            block[i] ^= self.bytes[i];
        }
    }
}

impl<Size: ArraySize> AsRef<Array<u8, Size>> for State<Size> {
    fn as_ref(&self) -> &Array<u8, Size> {
        &self.bytes
    }
}

impl<Size: ArraySize> AsMut<Array<u8, Size>> for State<Size> {
    fn as_mut(&mut self) -> &mut Array<u8, Size> {
        &mut self.bytes
    }
}
