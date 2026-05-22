//! Stateful encryptor object.

use crate::{Cipher, Error, Result};
use cipher::{Block, BlockCipherEncrypt, BlockModeEncrypt};
use core::fmt::{self, Debug};

#[cfg(feature = "aes")]
use {
    super::Aes,
    cipher::{InnerIvInit, StreamCipher},
    ctr::{Ctr128BE, CtrCore},
};
#[cfg(feature = "tdes")]
use {cipher::KeyIvInit, des::TdesEde3};

/// Stateful encryptor object for unauthenticated SSH symmetric ciphers.
///
/// Note that this deliberately does not support AEAD modes such as AES-GCM and ChaCha20Poly1305,
/// which are one-shot by design.
pub struct Encryptor {
    /// Inner enum over possible encryption ciphers.
    inner: Inner,

    /// Cipher in use by this `Encryptor`.
    cipher: Cipher,
}

/// Inner encryptor enum which is deliberately kept out of the public API.
enum Inner {
    #[cfg(feature = "aes")]
    AesCbc(cbc::Encryptor<Aes>),
    #[cfg(feature = "aes")]
    AesCtr(Ctr128BE<Aes>),
    #[cfg(feature = "tdes")]
    TDesCbc(cbc::Encryptor<TdesEde3>),
}

impl Encryptor {
    /// Create a new encryptor object with the given [`Cipher`], `key`, and `iv` (i.e.
    /// initialization vector).
    ///
    /// # Errors
    /// - Returns [`Error::Length`] if `key` or `iv` are the wrong length for the given `cipher`.
    /// - Returns [`Error::UnsupportedCipher`] if support for the given `cipher` is not enabled
    ///   in the crate features.
    pub fn new(cipher: Cipher, key: &[u8], iv: &[u8]) -> Result<Self> {
        cipher.check_key_and_iv(key, iv)?;

        let inner = match cipher {
            #[cfg(feature = "aes")]
            Cipher::Aes128Cbc | Cipher::Aes192Cbc | Cipher::Aes256Cbc => {
                cbc::Encryptor::inner_iv_slice_init(Aes::new(key)?, iv).map(Inner::AesCbc)
            }
            #[cfg(feature = "aes")]
            Cipher::Aes128Ctr | Cipher::Aes192Ctr | Cipher::Aes256Ctr => {
                let core = CtrCore::inner_iv_slice_init(Aes::new(key)?, iv)?;
                Ok(Inner::AesCtr(Ctr128BE::from_core(core)))
            }
            #[cfg(feature = "tdes")]
            Cipher::TDesCbc => cbc::Encryptor::new_from_slices(key, iv).map(Inner::TDesCbc),
            _ => return Err(cipher.unsupported()),
        }
        .map_err(|_| Error::Length)?;

        Ok(Self { inner, cipher })
    }

    /// Get the cipher for this encryptor.
    #[must_use]
    pub fn cipher(&self) -> Cipher {
        self.cipher
    }

    /// Encrypt the given buffer in place.
    ///
    /// # Errors
    /// Returns [`Error::Length`] in the event that `buffer` is not a multiple of the cipher's
    /// block size.
    pub fn encrypt(&mut self, buffer: &mut [u8]) -> Result<()> {
        match &mut self.inner {
            #[cfg(feature = "aes")]
            Inner::AesCbc(cipher) => cbc_encrypt(cipher, buffer)?,
            #[cfg(feature = "aes")]
            Inner::AesCtr(cipher) => cipher
                .try_apply_keystream(buffer)
                .map_err(|_| Error::Crypto)?,
            #[cfg(feature = "tdes")]
            Inner::TDesCbc(cipher) => cbc_encrypt(cipher, buffer)?,
        }

        Ok(())
    }
}

impl Debug for Encryptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Encryptor")
            .field("cipher", &self.cipher())
            .finish_non_exhaustive()
    }
}

/// CBC mode encryption helper which assumes the input is unpadded and block-aligned.
#[cfg(any(feature = "aes", feature = "tdes"))]
fn cbc_encrypt<C>(encryptor: &mut cbc::Encryptor<C>, buffer: &mut [u8]) -> Result<()>
where
    C: BlockCipherEncrypt,
{
    let (blocks, remaining) = Block::<C>::slice_as_chunks_mut(buffer);

    // Ensure input is block-aligned.
    if !remaining.is_empty() {
        return Err(Error::Length);
    }

    encryptor.encrypt_blocks(blocks);
    Ok(())
}
