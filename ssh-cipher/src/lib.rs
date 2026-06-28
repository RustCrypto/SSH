#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg"
)]

#[cfg(any(feature = "aes", feature = "tdes"))]
pub mod block_cipher;

#[cfg(feature = "chacha20poly1305")]
mod chacha20poly1305;
mod error;

pub use crate::error::{Error, Result};
pub use cipher;

#[cfg(feature = "chacha20poly1305")]
pub use crate::chacha20poly1305::{ChaCha20, ChaCha20Poly1305, ChaChaKey, ChaChaNonce};
#[cfg(any(feature = "aes", feature = "chacha20poly1305"))]
pub use aead;

use cipher::array::{Array, typenum::U16};
use core::{fmt, str};
use encoding::{Label, LabelError};

#[cfg(feature = "aes")]
use self::block_cipher::Aes;
#[cfg(feature = "tdes")]
use self::block_cipher::Tdes;
#[cfg(any(feature = "aes", feature = "chacha20poly1305"))]
use ::aead::{AeadInOut, KeyInit};
#[cfg(any(feature = "aes", feature = "tdes"))]
use {
    self::block_cipher::{BlockMode, sealed::BlockCipher},
    ::cipher::{Block, BlockModeDecrypt, BlockModeEncrypt},
};
#[cfg(feature = "aes")]
use {
    aead::array::typenum::U12,
    aes_gcm::{Aes128Gcm, Aes256Gcm},
};

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

/// Nonce for `aes128-gcm@openssh.com`/`aes256-gcm@openssh.com`.
#[cfg(feature = "aes")]
pub type AesGcmNonce = Array<u8, U12>;

/// Authentication tag for ciphertext data.
///
/// This is used by e.g. `aes128-gcm@openssh.com`/`aes256-gcm@openssh.com` and
/// `chacha20-poly1305@openssh.com`.
pub type Tag = Array<u8, U16>;

/// Cipher algorithms.
///
/// A "cipher" within the scope of SSH was originally described in [RFC4253 § 6.3] as a part of
/// of the packet encryption protocol, where it refers to the combination of a symmetric block
/// cipher, such as AES or 3DES, with a particular mode of operation, such as CBC or CTR.
///
/// This has been subsequently expanded by other standards documents, and now includes modern
/// authenticated or "AEAD" modes such as AES-GCM and ChaCha20Poly1305, which we recommend and are
/// marked with a ✅ in the table below.
///
/// Below is a table of the ciphers we support and what standards document defines them, along with
/// which crate feature needs to be enabled to perform encryption with a given algorithm:
///
/// | Cipher name                     | Feature | AEAD | Algorithm   | Standard
/// |---------------------------------|---------|------|-------------|---------
/// | `3des-cbc`                      | `tdes`  | ⛔   | 3DES-CBC    | [RFC4253 § 6.3]
/// | `aes128‑cbc`                    | `aes`   | ⛔   | AES-128-CBC | [RFC4253 § 6.3]
/// | `aes192‑cbc`                    | `aes`   | ⛔   | AES-192-CBC | [RFC4253 § 6.3]
/// | `aes256‑cbc`                    | `aes`   | ⛔   | AES-256-CBC | [RFC4253 § 6.3]
/// | `aes128‑ctr`                    | `aes`   | ⛔   | AES-128-CTR | [RFC4344]
/// | `aes192‑ctr`                    | `aes`   | ⛔   | AES-192-CTR | [RFC4344]
/// | `aes256‑ctr`                    | `aes`   | ⛔   | AES-256-CTR | [RFC4344]
/// | `aes128‑gcm@openssh.com`        | `aes`   | ✅   | AES-128-GCM | [RFC5647]
/// | `aes256‑gcm@openssh.com`        | `aes`   | ✅   | AES-256-GCM | [RFC5647]
/// | `chacha20‑poly1305@openssh.com` | `chacha20poly1305` | ✅ | ChaCha20Poly1305† | [PROTOCOL.chacha20poly1305]
///
/// † The construction called "ChaCha20Poly1305" as used by OpenSSH is different from other
/// constructions with that name including the one defined in RFC8439 and the one found in NaCl
/// variants like libsodium. See [`ChaCha20Poly1305`] for more information.
///
/// [RFC4253 § 6.3]: https://datatracker.ietf.org/doc/html/rfc4253#section-6.3
/// [RFC4344]: https://datatracker.ietf.org/doc/html/rfc4344
/// [RFC5647]: https://datatracker.ietf.org/doc/html/rfc5647
/// [PROTOCOL.chacha20poly1305]: https://web.mit.edu/freebsd/head/crypto/openssh/PROTOCOL.chacha20poly1305
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum Cipher {
    /// `none`: no cipher.
    None,

    /// `aes128-cbc`: AES-128 in cipher block chaining (CBC) mode.
    Aes128Cbc,

    /// `aes192-cbc`: AES-192 in cipher block chaining (CBC) mode.
    Aes192Cbc,

    /// `aes256-cbc`: AES-256 in cipher block chaining (CBC) mode.
    Aes256Cbc,

    /// `aes128-ctr`: AES-128 in counter (CTR) mode.
    Aes128Ctr,

    /// `aes192-ctr`: AES-192 in counter (CTR) mode.
    Aes192Ctr,

    /// `aes256-ctr`: AES-256 in counter (CTR) mode.
    Aes256Ctr,

    /// `aes128-gcm@openssh.com`: AES-128 in Galois/Counter Mode (GCM).
    Aes128Gcm,

    /// `aes256-gcm@openssh.com`: AES-256 in Galois/Counter Mode (GCM).
    Aes256Gcm,

    /// `chacha20-poly1305@openssh.com`: ChaCha20-Poly1305
    ChaCha20Poly1305,

    /// `3des-cbc`: TripleDES in block chaining (CBC) mode
    TdesCbc,
}

impl Cipher {
    /// Decode cipher algorithm from the given `ciphername`.
    ///
    /// # Supported cipher names
    /// - `aes128-cbc`
    /// - `aes192-cbc`
    /// - `aes256-cbc`
    /// - `aes128-ctr`
    /// - `aes192-ctr`
    /// - `aes256-ctr`
    /// - `aes128-gcm@openssh.com`
    /// - `aes256-gcm@openssh.com`
    /// - `chacha20-poly1305@openssh.com`
    /// - `3des-cbc`
    ///
    /// # Errors
    /// Returns [`LabelError`] if the provided `ciphername` is unknown.
    pub fn new(ciphername: &str) -> core::result::Result<Self, LabelError> {
        ciphername.parse()
    }

    /// Get the string identifier which corresponds to this algorithm.
    #[must_use]
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
            Self::TdesCbc => TDES_CBC,
        }
    }

    /// Get the key and IV size for this cipher in bytes.
    #[must_use]
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
            Self::ChaCha20Poly1305 => Some((32, 8)),
            Self::TdesCbc => Some((24, 8)),
        }
    }

    /// Get the block size for this cipher in bytes.
    #[must_use]
    pub fn block_size(self) -> usize {
        match self {
            Self::None | Self::ChaCha20Poly1305 | Self::TdesCbc => 8,
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
    #[must_use]
    pub fn padding_len(self, input_size: usize) -> usize {
        #[allow(
            clippy::integer_division_remainder_used,
            reason = "input_size is non-secret"
        )]
        match input_size % self.block_size() {
            0 => 0,
            input_rem => self.block_size() - input_rem,
        }
    }

    /// Does this cipher have an authentication tag? (i.e. is it an AEAD mode?)
    #[must_use]
    pub fn has_tag(self) -> bool {
        matches!(
            self,
            Self::Aes128Gcm | Self::Aes256Gcm | Self::ChaCha20Poly1305
        )
    }

    /// Is this cipher `none`?
    #[must_use]
    pub fn is_none(self) -> bool {
        self == Self::None
    }

    /// Is the cipher anything other than `none`?
    #[must_use]
    pub fn is_some(self) -> bool {
        !self.is_none()
    }

    /// Decrypt the ciphertext in the `buffer` in-place using this cipher.
    ///
    /// # Errors
    /// Returns [`Error::Length`] in the event that `buffer` is not a multiple of the cipher's
    /// block size.
    #[cfg_attr(not(any(feature = "aes", feature = "tdes")), allow(unused_variables))]
    pub fn decrypt(self, key: &[u8], iv: &[u8], buffer: &mut [u8], tag: Option<Tag>) -> Result<()> {
        match self {
            #[cfg(feature = "aes")]
            Self::Aes128Gcm => {
                let cipher = Aes128Gcm::new_from_slice(key).map_err(|_| Error::KeySize)?;
                let nonce = iv.try_into().map_err(|_| Error::IvSize)?;
                let tag = tag.ok_or(Error::TagSize)?;
                cipher
                    .decrypt_inout_detached(nonce, &[], buffer.into(), &tag)
                    .map_err(|_| Error::Crypto)?;

                Ok(())
            }
            #[cfg(feature = "aes")]
            Self::Aes256Gcm => {
                let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| Error::KeySize)?;
                let nonce = iv.try_into().map_err(|_| Error::IvSize)?;
                let tag = tag.ok_or(Error::TagSize)?;
                cipher
                    .decrypt_inout_detached(nonce, &[], buffer.into(), &tag)
                    .map_err(|_| Error::Crypto)?;

                Ok(())
            }
            #[cfg(feature = "chacha20poly1305")]
            Self::ChaCha20Poly1305 => {
                let key = key.try_into().map_err(|_| Error::KeySize)?;
                let nonce = iv.try_into().map_err(|_| Error::IvSize)?;
                let tag = tag.ok_or(Error::TagSize)?;
                ChaCha20Poly1305::new(key)
                    .decrypt_inout_detached(nonce, &[], buffer.into(), &tag)
                    .map_err(|_| Error::Crypto)
            }
            #[cfg(feature = "aes")]
            Self::Aes128Cbc
            | Self::Aes192Cbc
            | Self::Aes256Cbc
            | Self::Aes128Ctr
            | Self::Aes192Ctr
            | Self::Aes256Ctr => {
                // Non-AEAD modes don't take a tag.
                if tag.is_some() {
                    return Err(Error::Crypto);
                }
                self.decrypt_with_block_cipher::<Aes>(key, iv, buffer)
            }
            #[cfg(feature = "tdes")]
            Self::TdesCbc => {
                // Non-AEAD modes don't take a tag.
                if tag.is_some() {
                    return Err(Error::Crypto);
                }
                self.decrypt_with_block_cipher::<Tdes>(key, iv, buffer)
            }
            _ => Err(Error::UnsupportedCipher(self)),
        }
    }

    /// Perform decryption using a dynamically selected block cipher mode of operation.
    ///
    /// Note that this does not support any form of padding currently.
    ///
    /// # Errors
    /// Returns [`Error::Length`] unless the length of `buffer` is a multiple of the block size.
    #[cfg(any(feature = "aes", feature = "tdes"))]
    fn decrypt_with_block_cipher<C: BlockCipher>(
        self,
        key: &[u8],
        iv: &[u8],
        buffer: &mut [u8],
    ) -> Result<()> {
        let (blocks, remaining) = Block::<C>::slice_as_chunks_mut(buffer);

        if !remaining.is_empty() {
            return Err(Error::Length);
        }

        self.decryptor::<C>(key, iv)?.decrypt_blocks(blocks);
        Ok(())
    }

    /// Get a stateful [`block_cipher::Decryptor`] for the given key and IV.
    ///
    /// Only applicable to unauthenticated modes (e.g. AES-CBC, AES-CTR). Not usable with
    /// authenticated modes which are inherently one-shot (AES-GCM, ChaCha20Poly1305).
    ///
    /// # Errors
    /// Propagates errors from [`block_cipher::Decryptor::new`].
    #[cfg(any(feature = "aes", feature = "tdes"))]
    pub fn decryptor<C>(self, key: &[u8], iv: &[u8]) -> Result<block_cipher::Decryptor<C>>
    where
        C: BlockCipher,
    {
        block_cipher::Decryptor::new(self, key, iv)
    }

    /// Encrypt the ciphertext in the `buffer` in-place using this cipher.
    ///
    /// # Errors
    /// Returns [`Error::Length`] in the event that `buffer` is not a multiple of the cipher's
    /// block size.
    #[cfg_attr(not(any(feature = "aes", feature = "tdes")), allow(unused_variables))]
    pub fn encrypt(self, key: &[u8], iv: &[u8], buffer: &mut [u8]) -> Result<Option<Tag>> {
        match self {
            #[cfg(feature = "aes")]
            Self::Aes128Gcm => {
                let cipher = Aes128Gcm::new_from_slice(key).map_err(|_| Error::KeySize)?;
                let nonce = iv.try_into().map_err(|_| Error::IvSize)?;
                let tag = cipher
                    .encrypt_inout_detached(nonce, &[], buffer.into())
                    .map_err(|_| Error::Crypto)?;

                Ok(Some(tag))
            }
            #[cfg(feature = "aes")]
            Self::Aes256Gcm => {
                let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| Error::KeySize)?;
                let nonce = iv.try_into().map_err(|_| Error::IvSize)?;
                let tag = cipher
                    .encrypt_inout_detached(nonce, &[], buffer.into())
                    .map_err(|_| Error::Crypto)?;

                Ok(Some(tag))
            }
            #[cfg(feature = "chacha20poly1305")]
            Self::ChaCha20Poly1305 => {
                let key = key.try_into().map_err(|_| Error::KeySize)?;
                let nonce = iv.try_into().map_err(|_| Error::IvSize)?;
                let tag = ChaCha20Poly1305::new(key)
                    .encrypt_inout_detached(nonce, &[], buffer.into())
                    .map_err(|_| Error::Crypto)?;
                Ok(Some(tag))
            }
            #[cfg(feature = "aes")]
            Self::Aes128Cbc
            | Self::Aes192Cbc
            | Self::Aes256Cbc
            | Self::Aes128Ctr
            | Self::Aes192Ctr
            | Self::Aes256Ctr => {
                self.encrypt_with_block_cipher::<Aes>(key, iv, buffer)?;
                Ok(None)
            }
            #[cfg(feature = "tdes")]
            Self::TdesCbc => {
                self.encrypt_with_block_cipher::<Tdes>(key, iv, buffer)?;
                Ok(None)
            }
            _ => Err(Error::UnsupportedCipher(self)),
        }
    }

    /// Perform decryption using a dynamically selected block cipher mode of operation.
    ///
    /// Note that this does not support any form of padding currently.
    ///
    /// # Errors
    /// Returns [`Error::Length`] unless the length of `buffer` is a multiple of the block size.
    #[cfg(any(feature = "aes", feature = "tdes"))]
    fn encrypt_with_block_cipher<C: BlockCipher>(
        self,
        key: &[u8],
        iv: &[u8],
        buffer: &mut [u8],
    ) -> Result<()> {
        let (blocks, remaining) = Block::<C>::slice_as_chunks_mut(buffer);

        if !remaining.is_empty() {
            return Err(Error::Length);
        }

        self.encryptor::<C>(key, iv)?.encrypt_blocks(blocks);
        Ok(())
    }

    /// Get a stateful [`block_cipher::Encryptor`] for the given key and IV.
    ///
    /// Only applicable to unauthenticated modes (e.g. AES-CBC, AES-CTR). Not usable with
    /// authenticated modes which are inherently one-shot (AES-GCM, ChaCha20Poly1305).
    ///
    /// # Errors
    /// Propagates errors from [`block_cipher::Encryptor::new`].
    #[cfg(any(feature = "aes", feature = "tdes"))]
    pub fn encryptor<C>(self, key: &[u8], iv: &[u8]) -> Result<block_cipher::Encryptor<C>>
    where
        C: BlockCipher,
    {
        block_cipher::Encryptor::new(self, key, iv)
    }

    /// Get the block cipher mode of operation for this `Cipher`, if applicable.
    #[cfg(any(feature = "aes", feature = "tdes"))]
    pub(crate) fn block_mode(self) -> Option<BlockMode> {
        match self {
            #[cfg(feature = "aes")]
            Self::Aes128Cbc | Self::Aes192Cbc | Self::Aes256Cbc => Some(BlockMode::Cbc),
            #[cfg(feature = "aes")]
            Self::Aes128Ctr | Self::Aes192Ctr | Self::Aes256Ctr => Some(BlockMode::Ctr),
            #[cfg(feature = "tdes")]
            Self::TdesCbc => Some(BlockMode::Cbc),
            _ => None,
        }
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
            TDES_CBC => Ok(Self::TdesCbc),
            _ => Err(LabelError::new(ciphername)),
        }
    }
}
