//! Stateful decryptor object.

use crate::{Cipher, Error, Result};
use cipher::KeyIvInit;
use core::fmt::{self, Debug};

#[cfg(any(feature = "aes-cbc", feature = "aes-ctr"))]
use aes::{Aes128, Aes192, Aes256};
#[cfg(any(feature = "aes-cbc", feature = "tdes"))]
use cipher::SetIvState;
#[cfg(any(feature = "aes-cbc", feature = "tdes"))]
use cipher::{
    Block, IvState,
    block::{BlockCipherDecrypt, BlockModeDecrypt},
};
#[cfg(feature = "tdes")]
use des::TdesEde3;
#[cfg(feature = "aes-ctr")]
use {crate::encryptor::ctr_encrypt as ctr_decrypt, cipher::StreamCipherSeek, ctr::Ctr128BE};

/// Stateful decryptor object for unauthenticated SSH symmetric ciphers.
///
/// Note that this deliberately does not support AEAD modes such as AES-GCM and ChaCha20Poly1305,
/// which are one-shot by design.
pub struct Decryptor {
    /// Inner enum over possible decryption ciphers.
    inner: Inner,
}

/// Inner decryptor enum which is deliberately kept out of the public API.
enum Inner {
    #[cfg(feature = "aes-cbc")]
    Aes128Cbc(cbc::Decryptor<Aes128>),
    #[cfg(feature = "aes-cbc")]
    Aes192Cbc(cbc::Decryptor<Aes192>),
    #[cfg(feature = "aes-cbc")]
    Aes256Cbc(cbc::Decryptor<Aes256>),
    #[cfg(feature = "aes-ctr")]
    Aes128Ctr(Ctr128BE<Aes128>),
    #[cfg(feature = "aes-ctr")]
    Aes192Ctr(Ctr128BE<Aes192>),
    #[cfg(feature = "aes-ctr")]
    Aes256Ctr(Ctr128BE<Aes256>),
    #[cfg(feature = "tdes")]
    TDesCbc(cbc::Decryptor<TdesEde3>),
}

/// Current IV state or position within the cipher.
enum State {
    #[cfg(feature = "aes-cbc")]
    AesCbc(aes::Block),
    #[cfg(feature = "aes-ctr")]
    AesCtr(u64),
    #[cfg(feature = "tdes")]
    TDesCbc(Block<TdesEde3>),
}

impl Decryptor {
    /// Create a new decryptor object with the given [`Cipher`], `key`, and `iv` (i.e.
    /// initialization vector).
    ///
    /// # Errors
    /// - Returns [`Error::Length`] if `key` or `iv` are the wrong length for the given `cipher`.
    /// - Returns [`Error::UnsupportedCipher`] if support for the given `cipher` is not enabled
    ///   in the crate features.
    pub fn new(cipher: Cipher, key: &[u8], iv: &[u8]) -> Result<Self> {
        cipher.check_key_and_iv(key, iv)?;

        let inner = match cipher {
            #[cfg(feature = "aes-cbc")]
            Cipher::Aes128Cbc => cbc::Decryptor::new_from_slices(key, iv).map(Inner::Aes128Cbc),
            #[cfg(feature = "aes-cbc")]
            Cipher::Aes192Cbc => cbc::Decryptor::new_from_slices(key, iv).map(Inner::Aes192Cbc),
            #[cfg(feature = "aes-cbc")]
            Cipher::Aes256Cbc => cbc::Decryptor::new_from_slices(key, iv).map(Inner::Aes256Cbc),
            #[cfg(feature = "aes-ctr")]
            Cipher::Aes128Ctr => Ctr128BE::new_from_slices(key, iv).map(Inner::Aes128Ctr),
            #[cfg(feature = "aes-ctr")]
            Cipher::Aes192Ctr => Ctr128BE::new_from_slices(key, iv).map(Inner::Aes192Ctr),
            #[cfg(feature = "aes-ctr")]
            Cipher::Aes256Ctr => Ctr128BE::new_from_slices(key, iv).map(Inner::Aes256Ctr),
            #[cfg(feature = "tdes")]
            Cipher::TDesCbc => cbc::Decryptor::new_from_slices(key, iv).map(Inner::TDesCbc),
            _ => return Err(cipher.unsupported()),
        }
        .map_err(|_| Error::Length)?;

        Ok(Self { inner })
    }

    /// Get the cipher for this decryptor.
    #[must_use]
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

    /// Decrypt the given buffer in place.
    ///
    /// # Errors
    /// Returns [`Error::Length`] in the event that `buffer` is not a multiple of the cipher's
    /// block size.
    pub fn decrypt(&mut self, buffer: &mut [u8]) -> Result<()> {
        #[cfg(any(feature = "aes-cbc", feature = "aes-ctr", feature = "tdes"))]
        match &mut self.inner {
            #[cfg(feature = "aes-cbc")]
            Inner::Aes128Cbc(cipher) => cbc_decrypt(cipher, buffer),
            #[cfg(feature = "aes-cbc")]
            Inner::Aes192Cbc(cipher) => cbc_decrypt(cipher, buffer),
            #[cfg(feature = "aes-cbc")]
            Inner::Aes256Cbc(cipher) => cbc_decrypt(cipher, buffer),
            #[cfg(feature = "aes-ctr")]
            Inner::Aes128Ctr(cipher) => ctr_decrypt(cipher, buffer),
            #[cfg(feature = "aes-ctr")]
            Inner::Aes192Ctr(cipher) => ctr_decrypt(cipher, buffer),
            #[cfg(feature = "aes-ctr")]
            Inner::Aes256Ctr(cipher) => ctr_decrypt(cipher, buffer),
            #[cfg(feature = "tdes")]
            Inner::TDesCbc(cipher) => cbc_decrypt(cipher, buffer),
        }
        .map_err(|_| Error::Length)?;

        Ok(())
    }

    /// Call the provided function with an ephemeral [`Decryptor`] state which will be reset upon
    /// completion, returning the result of the function.
    ///
    /// # Errors
    /// Returns errors propagated from `F`, or if an internal cryptographic error occurs.
    pub fn peek<T, F>(&mut self, mut f: F) -> Result<T>
    where
        F: FnMut(&mut Self) -> Result<T>,
    {
        let state = self.state();
        let ret = f(self);
        self.set_state(state)?;
        ret
    }

    /// Get the current cipher state, i.e. IV or position within the stream cipher.
    fn state(&self) -> State {
        match &self.inner {
            #[cfg(feature = "aes-cbc")]
            Inner::Aes128Cbc(cipher) => State::AesCbc(cipher.iv_state()),
            #[cfg(feature = "aes-cbc")]
            Inner::Aes192Cbc(cipher) => State::AesCbc(cipher.iv_state()),
            #[cfg(feature = "aes-cbc")]
            Inner::Aes256Cbc(cipher) => State::AesCbc(cipher.iv_state()),
            #[cfg(feature = "aes-ctr")]
            Inner::Aes128Ctr(cipher) => State::AesCtr(cipher.current_pos()),
            #[cfg(feature = "aes-ctr")]
            Inner::Aes192Ctr(cipher) => State::AesCtr(cipher.current_pos()),
            #[cfg(feature = "aes-ctr")]
            Inner::Aes256Ctr(cipher) => State::AesCtr(cipher.current_pos()),
            #[cfg(feature = "tdes")]
            Inner::TDesCbc(cipher) => State::TDesCbc(cipher.iv_state()),
        }
    }

    /// Set the current cipher state.
    fn set_state(&mut self, state: State) -> Result<()> {
        match (&mut self.inner, state) {
            #[cfg(feature = "aes-cbc")]
            (Inner::Aes128Cbc(cipher), State::AesCbc(iv)) => {
                cipher.set_iv(&iv);
                Ok(())
            }
            #[cfg(feature = "aes-cbc")]
            (Inner::Aes192Cbc(cipher), State::AesCbc(iv)) => {
                cipher.set_iv(&iv);
                Ok(())
            }
            #[cfg(feature = "aes-cbc")]
            (Inner::Aes256Cbc(cipher), State::AesCbc(iv)) => {
                cipher.set_iv(&iv);
                Ok(())
            }
            #[cfg(feature = "aes-ctr")]
            (Inner::Aes128Ctr(cipher), State::AesCtr(pos)) => {
                cipher.try_seek(pos).map_err(|_| Error::Crypto)
            }
            #[cfg(feature = "aes-ctr")]
            (Inner::Aes192Ctr(cipher), State::AesCtr(pos)) => {
                cipher.try_seek(pos).map_err(|_| Error::Crypto)
            }
            #[cfg(feature = "aes-ctr")]
            (Inner::Aes256Ctr(cipher), State::AesCtr(pos)) => {
                cipher.try_seek(pos).map_err(|_| Error::Crypto)
            }
            #[cfg(feature = "tdes")]
            (Inner::TDesCbc(cipher), State::TDesCbc(iv)) => {
                cipher.set_iv(&iv);
                Ok(())
            }
            #[allow(unreachable_patterns)]
            _ => Err(Error::Crypto), // should be unreachable
        }
    }
}

impl Debug for Decryptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Decryptor")
            .field("cipher", &self.cipher())
            .finish_non_exhaustive()
    }
}

/// CBC mode decryption helper which assumes the input is unpadded and block-aligned.
#[cfg(any(feature = "aes-cbc", feature = "tdes"))]
fn cbc_decrypt<C>(decryptor: &mut cbc::Decryptor<C>, buffer: &mut [u8]) -> Result<()>
where
    C: BlockCipherDecrypt,
{
    let (blocks, remaining) = Block::<C>::slice_as_chunks_mut(buffer);

    // Ensure input is block-aligned.
    if !remaining.is_empty() {
        return Err(Error::Length);
    }

    decryptor.decrypt_blocks(blocks);
    Ok(())
}
