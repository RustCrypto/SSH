//! Symmetric encryption ciphers.
//!
//! These are used for encrypting private keys.

use crate::{Error, Result};
use core::{fmt, str};
use encoding::Label;

#[cfg(feature = "encryption")]
use aes::{
    cipher::{InnerIvInit, KeyInit, StreamCipherCore},
    Aes256,
};

#[cfg(feature = "aes-gcm")]
use aes_gcm::{aead::AeadInPlace, Aes256Gcm};

/// AES-256 in counter (CTR) mode
const AES256_CTR: &str = "aes256-ctr";

/// AES-256 in Galois/Counter Mode (GCM).
const AES256_GCM: &str = "aes256-gcm@openssh.com";

/// Nonces for AEAD modes.
#[cfg(feature = "aes-gcm")]
type AeadNonce = [u8; 12];

/// Authentication tag for ciphertext data.
///
/// This is used by e.g. `aes256-gcm@openssh.com`
pub(crate) type Tag = [u8; 16];

/// Counter mode with a 32-bit big endian counter.
#[cfg(feature = "encryption")]
type Ctr128BE<Cipher> = ctr::CtrCore<Cipher, ctr::flavors::Ctr128BE>;

/// Cipher algorithms.
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum Cipher {
    /// No cipher (unencrypted key).
    None,

    /// AES-256 in counter (CTR) mode.
    Aes256Ctr,

    /// AES-256 in Galois/Counter Mode (GCM).
    Aes256Gcm,
}

impl Cipher {
    /// Decode cipher algorithm from the given `ciphername`.
    ///
    /// # Supported cipher names
    /// - `aes256-ctr`
    pub fn new(ciphername: &str) -> Result<Self> {
        match ciphername {
            "none" => Ok(Self::None),
            AES256_CTR => Ok(Self::Aes256Ctr),
            AES256_GCM => Ok(Self::Aes256Gcm),
            _ => Err(Error::Algorithm),
        }
    }

    /// Get the string identifier which corresponds to this algorithm.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Aes256Ctr => AES256_CTR,
            Self::Aes256Gcm => AES256_GCM,
        }
    }

    /// Get the key and IV size for this cipher in bytes.
    pub fn key_and_iv_size(self) -> Option<(usize, usize)> {
        match self {
            Self::None => None,
            Self::Aes256Ctr => Some((32, 16)),
            Self::Aes256Gcm => Some((32, 12)),
        }
    }

    /// Get the block size for this cipher in bytes.
    pub fn block_size(self) -> usize {
        match self {
            Self::None => 8,
            Self::Aes256Ctr | Self::Aes256Gcm => 16,
        }
    }

    /// Compute the length of padding necessary to pad the given input to
    /// the block size.
    #[allow(clippy::integer_arithmetic)]
    pub fn padding_len(self, input_size: usize) -> usize {
        match input_size % self.block_size() {
            0 => 0,
            input_rem => self.block_size() - input_rem,
        }
    }

    /// Does this cipher have an authentication tag? (i.e. is it an AEAD mode?)
    pub fn has_tag(self) -> bool {
        matches!(self, Self::Aes256Gcm)
    }

    /// Is this cipher `none`?
    pub fn is_none(self) -> bool {
        self == Self::None
    }

    /// Is the cipher anything other than `none`?
    pub fn is_some(self) -> bool {
        !self.is_none()
    }

    /// Decrypt the ciphertext in the `buffer` in-place using this cipher.
    #[cfg(feature = "encryption")]
    pub fn decrypt(self, key: &[u8], iv: &[u8], buffer: &mut [u8], tag: Option<Tag>) -> Result<()> {
        match self {
            Self::Aes256Ctr => {
                if tag.is_some() {
                    return Err(Error::Crypto);
                }

                // Counter mode encryption and decryption are the same operation
                self.encrypt(key, iv, buffer)?;
                Ok(())
            }
            #[cfg(feature = "aes-gcm")]
            Self::Aes256Gcm => {
                let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| Error::Crypto)?;
                let nonce = AeadNonce::try_from(iv).map_err(|_| Error::Crypto)?;
                let tag = tag.ok_or(Error::Crypto)?;
                cipher
                    .decrypt_in_place_detached(&nonce.into(), &[], buffer, &tag.into())
                    .map_err(|_| Error::Crypto)?;

                Ok(())
            }
            _ => Err(Error::Crypto),
        }
    }

    /// Encrypt the ciphertext in the `buffer` in-place using this cipher.
    #[cfg(feature = "encryption")]
    pub fn encrypt(self, key: &[u8], iv: &[u8], buffer: &mut [u8]) -> Result<Option<Tag>> {
        match self {
            Self::Aes256Ctr => {
                let cipher = Aes256::new_from_slice(key)
                    .and_then(|aes| Ctr128BE::inner_iv_slice_init(aes, iv))
                    .map_err(|_| Error::Crypto)?;

                cipher
                    .try_apply_keystream_partial(buffer.into())
                    .map_err(|_| Error::Crypto)?;

                Ok(None)
            }
            #[cfg(feature = "aes-gcm")]
            Self::Aes256Gcm => {
                let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| Error::Crypto)?;
                let nonce = AeadNonce::try_from(iv).map_err(|_| Error::Crypto)?;
                let tag = cipher
                    .encrypt_in_place_detached(&nonce.into(), &[], buffer)
                    .map_err(|_| Error::Crypto)?;

                Ok(Some(tag.into()))
            }
            _ => Err(Error::Crypto),
        }
    }
}

impl AsRef<str> for Cipher {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl Label for Cipher {
    type Error = Error;
}

impl Default for Cipher {
    fn default() -> Cipher {
        Cipher::Aes256Ctr
    }
}

impl fmt::Display for Cipher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl str::FromStr for Cipher {
    type Err = Error;

    fn from_str(id: &str) -> Result<Self> {
        Self::new(id)
    }
}
