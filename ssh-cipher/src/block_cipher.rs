//! Low-level block cipher interface.
//!
//! This module provides APIs which enable streaming and "peeking" when using unauthenticated block
//! cipher modes such as CBC and CTR.

#[cfg(feature = "aes")]
mod aes;
mod decryptor;
mod encryptor;
mod state;

#[cfg(feature = "aes")]
pub use self::aes::Aes;
pub use self::{decryptor::Decryptor, encryptor::Encryptor};
#[cfg(feature = "tdes")]
pub use ::des::TdesEde3 as Tdes;

use self::state::State;

#[cfg(feature = "tdes")]
use {
    crate::Cipher,
    ::cipher::common::{InvalidLength, KeyInit},
};

/// Seal the `BlockCipher` trait so others cannot implement it.
pub(crate) mod sealed {
    use crate::Cipher;
    use ::cipher::{BlockCipherDecrypt, BlockCipherEncrypt, common::InvalidLength};

    /// Trait for block ciphers supported by this crate.
    ///
    /// This trait is deliberately sealed so it cannot be implemented by downstream crates.
    /// Notably new ciphers added to SSH should be authenticated, and we shouldn't support a
    /// proliferation of unauthenticated ciphers.
    pub trait BlockCipher: BlockCipherDecrypt + BlockCipherEncrypt {
        /// Initialize cipher from a byte slice.
        ///
        /// This is defined separate from the [`KeyInit`] trait so it can support variable-sized keys.
        ///
        /// # Errors
        /// Returns [`InvalidLength`] if `slice` is not equal in length to the key size.
        fn new_from_slice(slice: &[u8]) -> Result<Self, InvalidLength>;

        /// Is this the correct block cipher implementation for the given cipher?
        fn is_supported(cipher: Cipher) -> bool;
    }
}

/// Supported block cipher modes of operation.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum BlockMode {
    /// Cipher block chaining.
    Cbc,

    /// Counter mode.
    Ctr,
}

/// Encryptor for the Advanced Encryption Standard (AES).
#[cfg(feature = "aes")]
pub type AesEncryptor = Encryptor<Aes>;
/// Decryptor for the Advanced Encryption Standard (AES).
#[cfg(feature = "aes")]
pub type AesDecryptor = Decryptor<Aes>;

/// Encryptor for 3DES.
#[cfg(feature = "tdes")]
pub type TdesEncryptor = Encryptor<Tdes>;
/// Decryptor for 3DES.
#[cfg(feature = "tdes")]
pub type TdesDecryptor = Decryptor<Tdes>;

#[cfg(feature = "tdes")]
impl sealed::BlockCipher for Tdes {
    fn new_from_slice(slice: &[u8]) -> Result<Self, InvalidLength> {
        KeyInit::new_from_slice(slice)
    }

    fn is_supported(cipher: Cipher) -> bool {
        cipher == Cipher::TdesCbc
    }
}
