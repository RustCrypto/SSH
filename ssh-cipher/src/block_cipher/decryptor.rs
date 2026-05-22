//! Stateful decryptor object.

use crate::{Cipher, Error, Result};
use cipher::{
    Block, IvState, SetIvState,
    block::{BlockCipherDecrypt, BlockModeDecrypt},
};
use core::fmt::{self, Debug};
#[cfg(feature = "aes")]
use {
    super::Aes,
    cipher::{InnerIvInit, StreamCipher, StreamCipherSeek},
    ctr::{Ctr128BE, CtrCore},
};
#[cfg(feature = "tdes")]
use {cipher::KeyIvInit, des::TdesEde3};

/// Stateful decryptor object for unauthenticated SSH symmetric ciphers.
///
/// Note that this deliberately does not support AEAD modes such as AES-GCM and ChaCha20Poly1305,
/// which are one-shot by design.
pub struct Decryptor {
    /// Inner enum over possible decryption ciphers.
    inner: Inner,

    /// Cipher in use by this `Encryptor`.
    cipher: Cipher,
}

/// Inner decryptor enum which is deliberately kept out of the public API.
enum Inner {
    #[cfg(feature = "aes")]
    AesCbc(cbc::Decryptor<Aes>),
    #[cfg(feature = "aes")]
    AesCtr(Ctr128BE<Aes>),
    #[cfg(feature = "tdes")]
    TDesCbc(cbc::Decryptor<TdesEde3>),
}

/// Current IV state or position within the cipher.
enum State {
    #[cfg(feature = "aes")]
    AesCbc(aes::Block),
    #[cfg(feature = "aes")]
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
            #[cfg(feature = "aes")]
            Cipher::Aes128Cbc | Cipher::Aes192Cbc | Cipher::Aes256Cbc => {
                cbc::Decryptor::inner_iv_slice_init(Aes::new(key)?, iv).map(Inner::AesCbc)
            }
            #[cfg(feature = "aes")]
            Cipher::Aes128Ctr | Cipher::Aes192Ctr | Cipher::Aes256Ctr => {
                let core = CtrCore::inner_iv_slice_init(Aes::new(key)?, iv)?;
                Ok(Inner::AesCtr(Ctr128BE::from_core(core)))
            }
            #[cfg(feature = "tdes")]
            Cipher::TDesCbc => cbc::Decryptor::new_from_slices(key, iv).map(Inner::TDesCbc),
            _ => return Err(cipher.unsupported()),
        }
        .map_err(|_| Error::Length)?;

        Ok(Self { inner, cipher })
    }

    /// Get the cipher for this decryptor.
    #[must_use]
    pub fn cipher(&self) -> Cipher {
        self.cipher
    }

    /// Decrypt the given buffer in place.
    ///
    /// # Errors
    /// Returns [`Error::Length`] in the event that `buffer` is not a multiple of the cipher's
    /// block size.
    pub fn decrypt(&mut self, buffer: &mut [u8]) -> Result<()> {
        match &mut self.inner {
            #[cfg(feature = "aes")]
            Inner::AesCbc(cipher) => cbc_decrypt(cipher, buffer)?,
            #[cfg(feature = "aes")]
            Inner::AesCtr(cipher) => cipher
                .try_apply_keystream(buffer)
                .map_err(|_| Error::Crypto)?,
            #[cfg(feature = "tdes")]
            Inner::TDesCbc(cipher) => cbc_decrypt(cipher, buffer)?,
        }

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
            #[cfg(feature = "aes")]
            Inner::AesCbc(cipher) => State::AesCbc(cipher.iv_state()),
            #[cfg(feature = "aes")]
            Inner::AesCtr(cipher) => State::AesCtr(cipher.current_pos()),
            #[cfg(feature = "tdes")]
            Inner::TDesCbc(cipher) => State::TDesCbc(cipher.iv_state()),
        }
    }

    /// Set the current cipher state.
    fn set_state(&mut self, state: State) -> Result<()> {
        match (&mut self.inner, state) {
            #[cfg(feature = "aes")]
            (Inner::AesCbc(cipher), State::AesCbc(iv)) => {
                cipher.set_iv(&iv);
                Ok(())
            }
            #[cfg(feature = "aes")]
            (Inner::AesCtr(cipher), State::AesCtr(pos)) => {
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
#[cfg(any(feature = "aes", feature = "tdes"))]
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
