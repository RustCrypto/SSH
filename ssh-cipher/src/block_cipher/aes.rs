//! AES block cipher.

use ::aes::{Aes128, Aes192, Aes256, Block};
use ::cipher::{
    BlockCipherDecClosure, BlockCipherDecrypt, BlockCipherEncClosure, BlockCipherEncrypt,
    BlockSizeUser, InvalidLength, KeyInit, array::sizes::U16,
};

/// Advanced Encryption Standard (AES) low-level block cipher.
///
/// Supports 128-bit, 192-bit, and 256-bit keys.
pub struct Aes {
    inner: Inner,
}

/// Inner enum over supported key sizes.
enum Inner {
    Aes128(Aes128),
    Aes192(Aes192),
    Aes256(Aes256),
}

impl Aes {
    /// Create a new AES block cipher instance.
    ///
    /// Supports `key` whose length is 16-bytes (128-bit), 24-bytes (192-bits), or 32-bytes
    /// (256-bits).
    ///
    /// # Errors
    /// Returns [`InvalidLength`] if the length of `key` is not any of the above.
    pub fn new(key: &[u8]) -> Result<Self, InvalidLength> {
        if let Ok(cipher) = Aes128::new_from_slice(key) {
            return Ok(Self {
                inner: Inner::Aes128(cipher),
            });
        }

        if let Ok(cipher) = Aes192::new_from_slice(key) {
            return Ok(Self {
                inner: Inner::Aes192(cipher),
            });
        }

        if let Ok(cipher) = Aes256::new_from_slice(key) {
            return Ok(Self {
                inner: Inner::Aes256(cipher),
            });
        }

        Err(InvalidLength)
    }
}

impl BlockCipherDecrypt for Aes {
    fn decrypt_blocks(&self, blocks: &mut [Block]) {
        match &self.inner {
            Inner::Aes128(aes) => aes.decrypt_blocks(blocks),
            Inner::Aes192(aes) => aes.decrypt_blocks(blocks),
            Inner::Aes256(aes) => aes.decrypt_blocks(blocks),
        }
    }

    fn decrypt_with_backend(&self, f: impl BlockCipherDecClosure<BlockSize = Self::BlockSize>) {
        match &self.inner {
            Inner::Aes128(aes) => aes.decrypt_with_backend(f),
            Inner::Aes192(aes) => aes.decrypt_with_backend(f),
            Inner::Aes256(aes) => aes.decrypt_with_backend(f),
        }
    }
}

impl BlockCipherEncrypt for Aes {
    fn encrypt_blocks(&self, blocks: &mut [Block]) {
        match &self.inner {
            Inner::Aes128(aes) => aes.encrypt_blocks(blocks),
            Inner::Aes192(aes) => aes.encrypt_blocks(blocks),
            Inner::Aes256(aes) => aes.encrypt_blocks(blocks),
        }
    }

    fn encrypt_with_backend(&self, f: impl BlockCipherEncClosure<BlockSize = Self::BlockSize>) {
        match &self.inner {
            Inner::Aes128(aes) => aes.encrypt_with_backend(f),
            Inner::Aes192(aes) => aes.encrypt_with_backend(f),
            Inner::Aes256(aes) => aes.encrypt_with_backend(f),
        }
    }
}

impl BlockSizeUser for Aes {
    type BlockSize = U16;
}
