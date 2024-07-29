#![no_std]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg"
)]
#![forbid(unsafe_code)]
#![warn(
    clippy::alloc_instead_of_core,
    clippy::arithmetic_side_effects,
    clippy::mod_module_files,
    clippy::panic,
    clippy::panic_in_result_fn,
    clippy::std_instead_of_alloc,
    clippy::std_instead_of_core,
    clippy::unwrap_used,
    missing_docs,
    rust_2018_idioms,
    unused_lifetimes,
    unused_qualifications
)]

#[cfg(feature = "std")]
extern crate std;

mod error;

#[cfg(feature = "chacha20poly1305")]
mod chacha20poly1305;
#[cfg(any(feature = "aes-cbc", feature = "aes-ctr", feature = "tdes"))]
mod decryptor;
#[cfg(any(feature = "aes-cbc", feature = "aes-ctr", feature = "tdes"))]
mod encryptor;

pub use crate::error::{Error, Result};

#[cfg(feature = "chacha20poly1305")]
pub use crate::chacha20poly1305::ChaCha20Poly1305;

#[cfg(any(feature = "aes-cbc", feature = "aes-ctr", feature = "tdes"))]
pub use crate::{decryptor::Decryptor, encryptor::Encryptor};

use core::{fmt, str};
use encoding::{Label, LabelError};

#[cfg(feature = "aes-gcm")]
use aes_gcm::{aead::AeadInPlace, Aes128Gcm, Aes256Gcm};

#[cfg(feature = "aes-gcm")]
use cipher::KeyInit;

/// AES-128 in block chaining (CBC) mode
const AES128_CBC: &str = "aes128-cbc";

/// AES-192 in block chaining (CBC) mode
const AES192_CBC: &str = "aes192-cbc";

/// AES-256 in block chaining (CBC) mode
const AES256_CBC: &str = "aes256-cbc";

/// AES-128 in counter (CTR) mode
const AES128_CTR: &str = "aes128-ctr";

/// AES-192 in counter (CTR) mode
const AES192_CTR: &str = "aes192-ctr";

/// AES-256 in counter (CTR) mode
const AES256_CTR: &str = "aes256-ctr";

/// AES-128 in Galois/Counter Mode (GCM).
const AES128_GCM: &str = "aes128-gcm@openssh.com";

/// AES-256 in Galois/Counter Mode (GCM).
const AES256_GCM: &str = "aes256-gcm@openssh.com";

/// ChaCha20-Poly1305
const CHACHA20_POLY1305: &str = "chacha20-poly1305@openssh.com";

/// Triple-DES in block chaining (CBC) mode
const TDES_CBC: &str = "3des-cbc";

/// Nonce for AEAD modes.
///
/// This is used by e.g. `aes128-gcm@openssh.com`/`aes256-gcm@openssh.com` and
/// `chacha20-poly1305@openssh.com`.
pub type Nonce = [u8; 12];

/// Authentication tag for ciphertext data.
///
/// This is used by e.g. `aes128-gcm@openssh.com`/`aes256-gcm@openssh.com` and
/// `chacha20-poly1305@openssh.com`.
pub type Tag = [u8; 16];

/// Counter mode with a 128-bit big endian counter.
#[cfg(feature = "aes-ctr")]
type Ctr128BE<Cipher> = ctr::CtrCore<Cipher, ctr::flavors::Ctr128BE>;

/// Cipher algorithms.
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum Cipher {
    /// No cipher.
    None,

    /// AES-128 in cipher block chaining (CBC) mode.
    Aes128Cbc,

    /// AES-192 in cipher block chaining (CBC) mode.
    Aes192Cbc,

    /// AES-256 in cipher block chaining (CBC) mode.
    Aes256Cbc,

    /// AES-128 in counter (CTR) mode.
    Aes128Ctr,

    /// AES-192 in counter (CTR) mode.
    Aes192Ctr,

    /// AES-256 in counter (CTR) mode.
    Aes256Ctr,

    /// AES-128 in Galois/Counter Mode (GCM).
    Aes128Gcm,

    /// AES-256 in Galois/Counter Mode (GCM).
    Aes256Gcm,

    /// ChaCha20-Poly1305
    ChaCha20Poly1305,

    /// TripleDES in block chaining (CBC) mode
    TDesCbc,
}

impl Cipher {
    /// Decode cipher algorithm from the given `ciphername`.
    ///
    /// # Supported cipher names
    /// - `aes256-ctr`
    pub fn new(ciphername: &str) -> core::result::Result<Self, LabelError> {
        ciphername.parse()
    }

    /// Get the string identifier which corresponds to this algorithm.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Aes128Cbc => AES128_CBC,
            Self::Aes192Cbc => AES192_CBC,
            Self::Aes256Cbc => AES256_CBC,
            Self::Aes128Ctr => AES128_CTR,
            Self::Aes192Ctr => AES192_CTR,
            Self::Aes256Ctr => AES256_CTR,
            Self::Aes128Gcm => AES128_GCM,
            Self::Aes256Gcm => AES256_GCM,
            Self::ChaCha20Poly1305 => CHACHA20_POLY1305,
            Self::TDesCbc => TDES_CBC,
        }
    }

    /// Get the key and IV size for this cipher in bytes.
    pub fn key_and_iv_size(self) -> Option<(usize, usize)> {
        match self {
            Self::None => None,
            Self::Aes128Cbc => Some((16, 16)),
            Self::Aes192Cbc => Some((24, 16)),
            Self::Aes256Cbc => Some((32, 16)),
            Self::Aes128Ctr => Some((16, 16)),
            Self::Aes192Ctr => Some((24, 16)),
            Self::Aes256Ctr => Some((32, 16)),
            Self::Aes128Gcm => Some((16, 12)),
            Self::Aes256Gcm => Some((32, 12)),
            Self::ChaCha20Poly1305 => Some((32, 12)),
            Self::TDesCbc => Some((24, 8)),
        }
    }

    /// Get the block size for this cipher in bytes.
    pub fn block_size(self) -> usize {
        match self {
            Self::None | Self::ChaCha20Poly1305 | Self::TDesCbc => 8,
            Self::Aes128Cbc
            | Self::Aes192Cbc
            | Self::Aes256Cbc
            | Self::Aes128Ctr
            | Self::Aes192Ctr
            | Self::Aes256Ctr
            | Self::Aes128Gcm
            | Self::Aes256Gcm => 16,
        }
    }

    /// Compute the length of padding necessary to pad the given input to
    /// the block size.
    #[allow(clippy::arithmetic_side_effects)]
    pub fn padding_len(self, input_size: usize) -> usize {
        match input_size % self.block_size() {
            0 => 0,
            input_rem => self.block_size() - input_rem,
        }
    }

    /// Does this cipher have an authentication tag? (i.e. is it an AEAD mode?)
    pub fn has_tag(self) -> bool {
        matches!(
            self,
            Self::Aes128Gcm | Self::Aes256Gcm | Self::ChaCha20Poly1305
        )
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
    ///
    /// Returns [`Error::Length`] in the event that `buffer` is not a multiple of the cipher's
    /// block size.
    #[cfg_attr(
        not(any(feature = "aes-cbc", feature = "aes-ctr", feature = "tdes")),
        allow(unused_variables)
    )]
    pub fn decrypt(self, key: &[u8], iv: &[u8], buffer: &mut [u8], tag: Option<Tag>) -> Result<()> {
        match self {
            #[cfg(feature = "aes-gcm")]
            Self::Aes128Gcm => {
                let cipher = Aes128Gcm::new_from_slice(key).map_err(|_| Error::KeySize)?;
                let nonce = Nonce::try_from(iv).map_err(|_| Error::IvSize)?;
                let tag = tag.ok_or(Error::TagSize)?;
                cipher
                    .decrypt_in_place_detached(&nonce.into(), &[], buffer, &tag.into())
                    .map_err(|_| Error::Crypto)?;

                Ok(())
            }
            #[cfg(feature = "aes-gcm")]
            Self::Aes256Gcm => {
                let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| Error::KeySize)?;
                let nonce = Nonce::try_from(iv).map_err(|_| Error::IvSize)?;
                let tag = tag.ok_or(Error::TagSize)?;
                cipher
                    .decrypt_in_place_detached(&nonce.into(), &[], buffer, &tag.into())
                    .map_err(|_| Error::Crypto)?;

                Ok(())
            }
            #[cfg(feature = "chacha20poly1305")]
            Self::ChaCha20Poly1305 => {
                let tag = tag.ok_or(Error::TagSize)?;
                ChaCha20Poly1305::new(key, iv)?.decrypt(buffer, tag)
            }
            // Use `Decryptor` for non-AEAD modes
            #[cfg(any(feature = "aes-cbc", feature = "aes-ctr", feature = "tdes"))]
            _ => {
                // Non-AEAD modes don't take a tag.
                if tag.is_some() {
                    return Err(Error::Crypto);
                }

                self.decryptor(key, iv)?.decrypt(buffer)
            }
            #[cfg(not(any(feature = "aes-cbc", feature = "aes-ctr", feature = "tdes")))]
            _ => return Err(self.unsupported()),
        }
    }

    /// Get a stateful [`Decryptor`] for the given key and IV.
    ///
    /// Only applicable to unauthenticated modes (e.g. AES-CBC, AES-CTR). Not usable with
    /// authenticated modes which are inherently one-shot (AES-GCM, ChaCha20Poly1305).
    #[cfg(any(feature = "aes-cbc", feature = "aes-ctr", feature = "tdes"))]
    pub fn decryptor(self, key: &[u8], iv: &[u8]) -> Result<Decryptor> {
        Decryptor::new(self, key, iv)
    }

    /// Encrypt the ciphertext in the `buffer` in-place using this cipher.
    ///
    /// Returns [`Error::Length`] in the event that `buffer` is not a multiple of the cipher's
    /// block size.
    #[cfg_attr(
        not(any(feature = "aes-cbc", feature = "aes-ctr", feature = "tdes")),
        allow(unused_variables)
    )]
    pub fn encrypt(self, key: &[u8], iv: &[u8], buffer: &mut [u8]) -> Result<Option<Tag>> {
        match self {
            #[cfg(feature = "aes-gcm")]
            Self::Aes128Gcm => {
                let cipher = Aes128Gcm::new_from_slice(key).map_err(|_| Error::KeySize)?;
                let nonce = Nonce::try_from(iv).map_err(|_| Error::IvSize)?;
                let tag = cipher
                    .encrypt_in_place_detached(&nonce.into(), &[], buffer)
                    .map_err(|_| Error::Crypto)?;

                Ok(Some(tag.into()))
            }
            #[cfg(feature = "aes-gcm")]
            Self::Aes256Gcm => {
                let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| Error::KeySize)?;
                let nonce = Nonce::try_from(iv).map_err(|_| Error::IvSize)?;
                let tag = cipher
                    .encrypt_in_place_detached(&nonce.into(), &[], buffer)
                    .map_err(|_| Error::Crypto)?;

                Ok(Some(tag.into()))
            }
            #[cfg(feature = "chacha20poly1305")]
            Self::ChaCha20Poly1305 => {
                let tag = ChaCha20Poly1305::new(key, iv)?.encrypt(buffer);
                Ok(Some(tag))
            }
            // Use `Encryptor` for non-AEAD modes
            #[cfg(any(feature = "aes-cbc", feature = "aes-ctr", feature = "tdes"))]
            _ => {
                self.encryptor(key, iv)?.encrypt(buffer)?;
                Ok(None)
            }
            #[cfg(not(any(feature = "aes-cbc", feature = "aes-ctr", feature = "tdes")))]
            _ => return Err(self.unsupported()),
        }
    }

    /// Get a stateful [`Encryptor`] for the given key and IV.
    ///
    /// Only applicable to unauthenticated modes (e.g. AES-CBC, AES-CTR). Not usable with
    /// authenticated modes which are inherently one-shot (AES-GCM, ChaCha20Poly1305).
    #[cfg(any(feature = "aes-cbc", feature = "aes-ctr", feature = "tdes"))]
    pub fn encryptor(self, key: &[u8], iv: &[u8]) -> Result<Encryptor> {
        Encryptor::new(self, key, iv)
    }

    /// Check that the key and IV are the expected length for this cipher.
    #[cfg(any(feature = "aes-cbc", feature = "aes-ctr", feature = "tdes"))]
    fn check_key_and_iv(self, key: &[u8], iv: &[u8]) -> Result<()> {
        let (key_size, iv_size) = self
            .key_and_iv_size()
            .ok_or(Error::UnsupportedCipher(self))?;

        if key.len() != key_size {
            return Err(Error::KeySize);
        }

        if iv.len() != iv_size {
            return Err(Error::IvSize);
        }

        Ok(())
    }

    /// Create an unsupported cipher error.
    fn unsupported(self) -> Error {
        Error::UnsupportedCipher(self)
    }
}

impl AsRef<str> for Cipher {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl Label for Cipher {}

impl fmt::Display for Cipher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl str::FromStr for Cipher {
    type Err = LabelError;

    fn from_str(ciphername: &str) -> core::result::Result<Self, LabelError> {
        match ciphername {
            "none" => Ok(Self::None),
            AES128_CBC => Ok(Self::Aes128Cbc),
            AES192_CBC => Ok(Self::Aes192Cbc),
            AES256_CBC => Ok(Self::Aes256Cbc),
            AES128_CTR => Ok(Self::Aes128Ctr),
            AES192_CTR => Ok(Self::Aes192Ctr),
            AES256_CTR => Ok(Self::Aes256Ctr),
            AES128_GCM => Ok(Self::Aes128Gcm),
            AES256_GCM => Ok(Self::Aes256Gcm),
            CHACHA20_POLY1305 => Ok(Self::ChaCha20Poly1305),
            TDES_CBC => Ok(Self::TDesCbc),
            _ => Err(LabelError::new(ciphername)),
        }
    }
}
