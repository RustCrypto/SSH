//! Block cipher keys.

use crate::{BlockMode, Cipher, Error, Result, block_cipher::Algorithm};
use cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};

#[cfg(feature = "aes")]
use aes::{Aes128, Aes192, Aes256};
#[cfg(feature = "tdes")]
use des::TdesEde3;

/// Block cipher instances.
pub(crate) enum Key {
    #[cfg(feature = "aes")]
    Aes128(Aes128),
    #[cfg(feature = "aes")]
    Aes192(Aes192),
    #[cfg(feature = "aes")]
    Aes256(Aes256),
    #[cfg(feature = "tdes")]
    Tdes(TdesEde3),
}

impl Key {
    /// Create a new block cipher key.
    pub(crate) fn new(block_cipher: Algorithm, bytes: &[u8]) -> Result<Self> {
        match block_cipher {
            #[cfg(feature = "aes")]
            Algorithm::Aes => {
                if let Ok(key) = Aes128::new_from_slice(bytes) {
                    return Ok(Key::Aes128(key));
                }

                if let Ok(key) = Aes192::new_from_slice(bytes) {
                    return Ok(Key::Aes192(key));
                }

                if let Ok(key) = Aes256::new_from_slice(bytes) {
                    return Ok(Key::Aes256(key));
                }

                Err(Error::Length)
            }
            #[cfg(feature = "tdes")]
            Algorithm::Tdes => TdesEde3::new_from_slice(bytes)
                .map(Key::Tdes)
                .map_err(|_| Error::Length),
        }
    }

    /// Get the `BlockCipher` this key is for.
    pub(crate) fn block_cipher(&self) -> Algorithm {
        match self {
            #[cfg(feature = "aes")]
            Self::Aes128(_) | Self::Aes192(_) | Self::Aes256(_) => Algorithm::Aes,
            #[cfg(feature = "tdes")]
            Self::Tdes(_) => Algorithm::Tdes,
        }
    }

    /// Get the block size for this key.
    pub(crate) fn block_size(&self) -> usize {
        self.block_cipher().block_size()
    }

    /// Get the `Cipher` for a particular block mode.
    pub(crate) fn cipher_for_mode(&self, mode: BlockMode) -> Cipher {
        match (self, mode) {
            #[cfg(feature = "aes")]
            (Key::Aes128(_), BlockMode::Cbc) => Cipher::Aes128Cbc,
            #[cfg(feature = "aes")]
            (Key::Aes192(_), BlockMode::Cbc) => Cipher::Aes192Cbc,
            #[cfg(feature = "aes")]
            (Key::Aes256(_), BlockMode::Cbc) => Cipher::Aes256Cbc,
            #[cfg(feature = "aes")]
            (Key::Aes128(_), BlockMode::Ctr) => Cipher::Aes128Ctr,
            #[cfg(feature = "aes")]
            (Key::Aes192(_), BlockMode::Ctr) => Cipher::Aes192Ctr,
            #[cfg(feature = "aes")]
            (Key::Aes256(_), BlockMode::Ctr) => Cipher::Aes256Ctr,
            #[cfg(feature = "tdes")]
            (Key::Tdes(_), BlockMode::Cbc) => Cipher::TdesCbc,
            #[cfg(feature = "tdes")]
            (Key::Tdes(_), BlockMode::Ctr) => unreachable!("TDES-CTR is unconfigurable"),
        }
    }

    /// Encrypt a single block using the raw block cipher interface (a.k.a ECB mode, but as part of
    /// constructing a block cipher mode i.e. CBC or CTR)
    pub(crate) fn encrypt_block(&self, block: &mut [u8]) {
        debug_assert_eq!(block.len(), self.block_size());

        match self {
            Key::Aes128(cipher) => cipher.encrypt_block(block.try_into().unwrap()),
            Key::Aes192(cipher) => cipher.encrypt_block(block.try_into().unwrap()),
            Key::Aes256(cipher) => cipher.encrypt_block(block.try_into().unwrap()),
            Key::Tdes(cipher) => cipher.encrypt_block(block.try_into().unwrap()),
        }
    }

    /// Decrypt a single block using the raw block cipher interface (a.k.a ECB mode, but as part of
    /// constructing a block cipher mode i.e. CBC or CTR)
    pub(crate) fn decrypt_block(&self, block: &mut [u8]) {
        debug_assert_eq!(block.len(), self.block_size());

        match self {
            Key::Aes128(cipher) => cipher.decrypt_block(block.try_into().unwrap()),
            Key::Aes192(cipher) => cipher.decrypt_block(block.try_into().unwrap()),
            Key::Aes256(cipher) => cipher.decrypt_block(block.try_into().unwrap()),
            Key::Tdes(cipher) => cipher.decrypt_block(block.try_into().unwrap()),
        }
    }
}
