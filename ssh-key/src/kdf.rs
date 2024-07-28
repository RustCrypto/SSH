//! Key Derivation Functions.
//!
//! These are used for deriving an encryption key from a password.

use crate::{Error, KdfAlg, Result};
use encoding::{CheckedSum, Decode, Encode, Reader, Writer};

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

#[cfg(feature = "encryption")]
use {crate::Cipher, bcrypt_pbkdf::bcrypt_pbkdf, rand_core::CryptoRngCore, zeroize::Zeroizing};

/// Default number of rounds to use for bcrypt-pbkdf.
#[cfg(feature = "encryption")]
const DEFAULT_BCRYPT_ROUNDS: u32 = 16;

/// Default salt size. Matches OpenSSH.
#[cfg(feature = "encryption")]
const DEFAULT_SALT_SIZE: usize = 16;

/// Key Derivation Functions (KDF).
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Kdf {
    /// No KDF.
    None,

    /// bcrypt-pbkdf options.
    #[cfg(feature = "alloc")]
    Bcrypt {
        /// Salt
        salt: Vec<u8>,

        /// Rounds
        rounds: u32,
    },
}

impl Kdf {
    /// Initialize KDF configuration for the given algorithm.
    #[cfg(feature = "encryption")]
    pub fn new(algorithm: KdfAlg, rng: &mut impl CryptoRngCore) -> Result<Self> {
        let mut salt = vec![0u8; DEFAULT_SALT_SIZE];
        rng.fill_bytes(&mut salt);

        match algorithm {
            KdfAlg::None => {
                // Disallow explicit initialization with a `none` algorithm
                Err(Error::AlgorithmUnknown)
            }
            KdfAlg::Bcrypt => Ok(Kdf::Bcrypt {
                salt,
                rounds: DEFAULT_BCRYPT_ROUNDS,
            }),
        }
    }

    /// Get the KDF algorithm.
    pub fn algorithm(&self) -> KdfAlg {
        match self {
            Self::None => KdfAlg::None,
            #[cfg(feature = "alloc")]
            Self::Bcrypt { .. } => KdfAlg::Bcrypt,
        }
    }

    /// Derive an encryption key from the given password.
    #[cfg(feature = "encryption")]
    pub fn derive(&self, password: impl AsRef<[u8]>, output: &mut [u8]) -> Result<()> {
        match self {
            Kdf::None => Err(Error::Decrypted),
            Kdf::Bcrypt { salt, rounds } => {
                bcrypt_pbkdf(password, salt, *rounds, output).map_err(|_| Error::Crypto)?;
                Ok(())
            }
        }
    }

    /// Derive key and IV for the given [`Cipher`].
    ///
    /// Returns two byte vectors containing the key and IV respectively.
    #[cfg(feature = "encryption")]
    pub fn derive_key_and_iv(
        &self,
        cipher: Cipher,
        password: impl AsRef<[u8]>,
    ) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>)> {
        let (key_size, iv_size) = match cipher {
            // Derive two ChaCha20Poly1305 keys, but only use the first.
            // In the typical SSH protocol, the second key is used for length encryption.
            //
            // From `PROTOCOL.chacha20poly1305`:
            //
            // > The chacha20-poly1305@openssh.com cipher requires 512 bits of key
            // > material as output from the SSH key exchange. This forms two 256 bit
            // > keys (K_1 and K_2), used by two separate instances of chacha20.
            // > The first 256 bits constitute K_2 and the second 256 bits become
            // > K_1.
            // >
            // > The instance keyed by K_1 is a stream cipher that is used only
            // > to encrypt the 4 byte packet length field. The second instance,
            // > keyed by K_2, is used in conjunction with poly1305 to build an AEAD
            // > (Authenticated Encryption with Associated Data) that is used to encrypt
            // > and authenticate the entire packet.
            Cipher::ChaCha20Poly1305 => (64, 0),
            _ => cipher.key_and_iv_size().ok_or(Error::Decrypted)?,
        };

        let okm_size = key_size
            .checked_add(iv_size)
            .ok_or(encoding::Error::Length)?;

        let mut okm = Zeroizing::new(vec![0u8; okm_size]);
        self.derive(password, &mut okm)?;
        let mut iv = okm.split_off(key_size);

        if cipher == Cipher::ChaCha20Poly1305 {
            // Only use the first ChaCha20 key.
            okm.truncate(32);

            // Use an all-zero nonce (with a key derived from password + salt providing uniqueness)
            iv.extend_from_slice(&cipher::Nonce::default());
        }

        Ok((okm, iv))
    }

    /// Is the KDF configured as `none`?
    pub fn is_none(&self) -> bool {
        self == &Self::None
    }

    /// Is the KDF configured as anything other than `none`?
    pub fn is_some(&self) -> bool {
        !self.is_none()
    }

    /// Is the KDF configured as `bcrypt` (i.e. bcrypt-pbkdf)?
    #[cfg(feature = "alloc")]
    pub fn is_bcrypt(&self) -> bool {
        matches!(self, Self::Bcrypt { .. })
    }
}

impl Default for Kdf {
    fn default() -> Self {
        Self::None
    }
}

impl Decode for Kdf {
    type Error = Error;

    fn decode(reader: &mut impl Reader) -> Result<Self> {
        match KdfAlg::decode(reader)? {
            KdfAlg::None => {
                if usize::decode(reader)? == 0 {
                    Ok(Self::None)
                } else {
                    Err(Error::AlgorithmUnknown)
                }
            }
            KdfAlg::Bcrypt => {
                #[cfg(not(feature = "alloc"))]
                return Err(Error::AlgorithmUnknown);

                #[cfg(feature = "alloc")]
                reader.read_prefixed(|reader| {
                    Ok(Self::Bcrypt {
                        salt: Vec::decode(reader)?,
                        rounds: u32::decode(reader)?,
                    })
                })
            }
        }
    }
}

impl Encode for Kdf {
    fn encoded_len(&self) -> encoding::Result<usize> {
        let kdfopts_prefixed_len = match self {
            Self::None => 4,
            #[cfg(feature = "alloc")]
            Self::Bcrypt { salt, .. } => [12, salt.len()].checked_sum()?,
        };

        [self.algorithm().encoded_len()?, kdfopts_prefixed_len].checked_sum()
    }

    fn encode(&self, writer: &mut impl Writer) -> encoding::Result<()> {
        self.algorithm().encode(writer)?;

        match self {
            Self::None => 0usize.encode(writer)?,
            #[cfg(feature = "alloc")]
            Self::Bcrypt { salt, rounds } => {
                [8, salt.len()].checked_sum()?.encode(writer)?;
                salt.encode(writer)?;
                rounds.encode(writer)?
            }
        }

        Ok(())
    }
}
