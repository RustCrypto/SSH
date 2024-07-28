//! Stateful encryptor object.

use crate::{Cipher, Error, Result};
use cipher::{Block, BlockCipher, BlockCipherEncrypt, KeyIvInit};

#[cfg(feature = "aes-ctr")]
use {
    crate::Ctr128BE,
    cipher::{array::sizes::U16, StreamCipherCore},
};

#[cfg(feature = "tdes")]
use des::TdesEde3;

#[cfg(any(feature = "aes-cbc", feature = "aes-ctr"))]
use aes::{Aes128, Aes192, Aes256};

#[cfg(any(feature = "aes-cbc", feature = "tdes"))]
use cipher::BlockModeEncrypt;

/// Stateful encryptor object for unauthenticated SSH symmetric ciphers.
///
/// Note that this deliberately does not support AEAD modes such as AES-GCM and ChaCha20Poly1305,
/// which are one-shot by design.
pub struct Encryptor {
    /// Inner enum over possible encryption ciphers.
    inner: Inner,
}

/// Inner encryptor enum which is deliberately kept out of the public API.
enum Inner {
    #[cfg(feature = "aes-cbc")]
    Aes128Cbc(cbc::Encryptor<Aes128>),
    #[cfg(feature = "aes-cbc")]
    Aes192Cbc(cbc::Encryptor<Aes192>),
    #[cfg(feature = "aes-cbc")]
    Aes256Cbc(cbc::Encryptor<Aes256>),
    #[cfg(feature = "aes-ctr")]
    Aes128Ctr(Ctr128BE<Aes128>),
    #[cfg(feature = "aes-ctr")]
    Aes192Ctr(Ctr128BE<Aes192>),
    #[cfg(feature = "aes-ctr")]
    Aes256Ctr(Ctr128BE<Aes256>),
    #[cfg(feature = "tdes")]
    TDesCbc(cbc::Encryptor<TdesEde3>),
}

impl Encryptor {
    /// Create a new encryptor object with the given [`Cipher`], key, and IV.
    pub fn new(cipher: Cipher, key: &[u8], iv: &[u8]) -> Result<Self> {
        let inner = match cipher {
            #[cfg(feature = "aes-cbc")]
            Cipher::Aes128Cbc => Inner::Aes128Cbc(
                cbc::Encryptor::new_from_slices(key, iv).map_err(|_| Error::KeySize)?,
            ),
            #[cfg(feature = "aes-cbc")]
            Cipher::Aes192Cbc => Inner::Aes192Cbc(
                cbc::Encryptor::new_from_slices(key, iv).map_err(|_| Error::KeySize)?,
            ),
            #[cfg(feature = "aes-cbc")]
            Cipher::Aes256Cbc => Inner::Aes256Cbc(
                cbc::Encryptor::new_from_slices(key, iv).map_err(|_| Error::KeySize)?,
            ),
            #[cfg(feature = "aes-ctr")]
            Cipher::Aes128Ctr => {
                Inner::Aes128Ctr(Ctr128BE::new_from_slices(key, iv).map_err(|_| Error::KeySize)?)
            }
            #[cfg(feature = "aes-ctr")]
            Cipher::Aes192Ctr => {
                Inner::Aes192Ctr(Ctr128BE::new_from_slices(key, iv).map_err(|_| Error::KeySize)?)
            }
            #[cfg(feature = "aes-ctr")]
            Cipher::Aes256Ctr => {
                Inner::Aes256Ctr(Ctr128BE::new_from_slices(key, iv).map_err(|_| Error::KeySize)?)
            }
            #[cfg(feature = "tdes")]
            Cipher::TDesCbc => Inner::TDesCbc(
                cbc::Encryptor::new_from_slices(key, iv).map_err(|_| Error::KeySize)?,
            ),
            _ => return Err(cipher.unsupported()),
        };

        Ok(Self { inner })
    }

    /// Get the cipher for this encryptor.
    pub fn cipher(&self) -> Cipher {
        match &self.inner {
            #[cfg(feature = "aes-cbc")]
            Inner::Aes128Cbc(_) => Cipher::Aes128Cbc,
            #[cfg(feature = "aes-cbc")]
            Inner::Aes192Cbc(_) => Cipher::Aes192Cbc,
            #[cfg(feature = "aes-cbc")]
            Inner::Aes256Cbc(_) => Cipher::Aes256Cbc,
            #[cfg(feature = "aes-ctr")]
            Inner::Aes128Ctr(_) => Cipher::Aes128Ctr,
            #[cfg(feature = "aes-ctr")]
            Inner::Aes192Ctr(_) => Cipher::Aes192Ctr,
            #[cfg(feature = "aes-ctr")]
            Inner::Aes256Ctr(_) => Cipher::Aes256Ctr,
            #[cfg(feature = "tdes")]
            Inner::TDesCbc(_) => Cipher::TDesCbc,
        }
    }

    /// Encrypt the given buffer in place, returning [`Error::Crypto`] on padding failure.
    pub fn encrypt(&mut self, buffer: &mut [u8]) -> Result<()> {
        match &mut self.inner {
            #[cfg(feature = "aes-cbc")]
            Inner::Aes128Cbc(cipher) => cbc_encrypt(cipher, buffer)?,
            #[cfg(feature = "aes-cbc")]
            Inner::Aes192Cbc(cipher) => cbc_encrypt(cipher, buffer)?,
            #[cfg(feature = "aes-cbc")]
            Inner::Aes256Cbc(cipher) => cbc_encrypt(cipher, buffer)?,
            #[cfg(feature = "aes-ctr")]
            Inner::Aes128Ctr(cipher) => ctr_encrypt(cipher, buffer)?,
            #[cfg(feature = "aes-ctr")]
            Inner::Aes192Ctr(cipher) => ctr_encrypt(cipher, buffer)?,
            #[cfg(feature = "aes-ctr")]
            Inner::Aes256Ctr(cipher) => ctr_encrypt(cipher, buffer)?,
            #[cfg(feature = "tdes")]
            Inner::TDesCbc(cipher) => cbc_encrypt(cipher, buffer)?,
        }

        Ok(())
    }
}

/// CBC mode encryption helper which assumes the input is unpadded and block-aligned.
#[cfg(any(feature = "aes-cbc", feature = "tdes"))]
fn cbc_encrypt<C>(encryptor: &mut cbc::Encryptor<C>, buffer: &mut [u8]) -> Result<()>
where
    C: BlockCipher + BlockCipherEncrypt,
{
    let (blocks, remaining) = Block::<C>::slice_as_chunks_mut(buffer);

    // Ensure input is block-aligned.
    if !remaining.is_empty() {
        return Err(Error::Crypto);
    }

    encryptor.encrypt_blocks(blocks);
    Ok(())
}

/// CTR mode encryption helper which assumes the input is unpadded and block-aligned.
#[cfg(feature = "aes-ctr")]
pub(crate) fn ctr_encrypt<C>(encryptor: &mut Ctr128BE<C>, buffer: &mut [u8]) -> Result<()>
where
    C: BlockCipher<BlockSize = U16> + BlockCipherEncrypt,
{
    let (blocks, remaining) = Block::<C>::slice_as_chunks_mut(buffer);

    // Ensure input is block-aligned.
    if !remaining.is_empty() {
        return Err(Error::Crypto);
    }

    encryptor.apply_keystream_blocks(blocks);
    Ok(())
}
