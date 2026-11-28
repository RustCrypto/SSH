//! Key Derivation Functions.
//!
//! These are used for deriving an encryption key from a password.

use crate::{Error, KdfAlg, Result};
use encoding::{CheckedSum, Decode, Decoder, Encode, Reader, Writer};

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

#[cfg(feature = "encryption")]
use {crate::Cipher, bcrypt_pbkdf::bcrypt_pbkdf, rand_core::TryCryptoRng, zeroize::Zeroizing};

/// Default number of rounds to use for bcrypt-pbkdf. Matches OpenSSH's `DEFAULT_ROUNDS`.
// https://github.com/openssh/openssh-portable/commit/f938c78d490cb7556aa8ca1625e9b9bd1f963ed3
#[cfg(feature = "encryption")]
const DEFAULT_BCRYPT_ROUNDS: u32 = 32;

/// Maximum number of rounds for bcrypt-pbkdf. Matches OpenSSH's `MAX_KDF_ROUNDS`.
// https://github.com/openssh/openssh-portable/commit/f938c78d490cb7556aa8ca1625e9b9bd1f963ed3
#[cfg(feature = "alloc")]
const MAX_BCRYPT_ROUNDS: u32 = 1 << 20;

/// Default salt size. Matches OpenSSH.
#[cfg(feature = "encryption")]
const DEFAULT_SALT_SIZE: usize = 16;

/// Key Derivation Functions (KDF).
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
#[derive(Default)]
pub enum Kdf {
    /// No KDF.
    #[default]
    None,

    /// bcrypt-pbkdf options.
    #[cfg(feature = "alloc")]
    Bcrypt {
        /// Salt: recommended 16-bytes and random.
        salt: Vec<u8>,

        /// Rounds: must be within `1..=1_048_576`.
        rounds: u32,
    },
}

impl Kdf {
    /// Initialize KDF configuration for the given algorithm.
    ///
    /// # Errors
    /// Returns [`Error::RngFailure`] on RNG errors.
    #[cfg(feature = "encryption")]
    pub fn new<R: TryCryptoRng + ?Sized>(algorithm: KdfAlg, rng: &mut R) -> Result<Self> {
        let mut salt = vec![0u8; DEFAULT_SALT_SIZE];
        rng.try_fill_bytes(&mut salt)
            .map_err(|_| Error::RngFailure)?;

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
    #[must_use]
    pub fn algorithm(&self) -> KdfAlg {
        match self {
            Self::None => KdfAlg::None,
            #[cfg(feature = "alloc")]
            Self::Bcrypt { .. } => KdfAlg::Bcrypt,
        }
    }

    /// Derive an encryption key from the given password.
    ///
    /// # Errors
    /// Returns [`Error::Crypto`] if the bcrypt round count is zero or exceeds 1,048,576, or if the
    /// underlying password hashing primitive returns an error.
    #[cfg(feature = "encryption")]
    pub fn derive(&self, password: impl AsRef<[u8]>, output: &mut [u8]) -> Result<()> {
        match self {
            Kdf::None => Err(Error::Decrypted),
            Kdf::Bcrypt { salt, rounds } => {
                validate_bcrypt_rounds(*rounds)?;
                bcrypt_pbkdf(password, salt, *rounds, output).map_err(|_| Error::Crypto)?;
                Ok(())
            }
        }
    }

    /// Derive key and IV for the given [`Cipher`].
    ///
    /// Returns two byte vectors containing the key and IV respectively.
    ///
    /// # Errors
    /// - Returns [`Error::Decrypted`] if `cipher` is [`Cipher::None`].
    /// - Returns [`Error::Encoding`] in the event of a length error.
    /// - Propagates errors returned from [`Self::derive`].
    #[cfg(feature = "encryption")]
    pub fn derive_key_and_iv(
        &self,
        cipher: Cipher,
        password: impl AsRef<[u8]>,
    ) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>)> {
        let (key_size, iv_size) = cipher.key_and_iv_size().ok_or(Error::Decrypted)?;

        let okm_size = key_size
            .checked_add(iv_size)
            .ok_or(encoding::Error::Length)?;

        let mut okm = Zeroizing::new(vec![0u8; okm_size]);
        self.derive(password, &mut okm)?;
        let mut iv = okm.split_off(key_size);

        // For whatever reason `chacha20-poly1305@openssh.com` uses a nonce of all zeros for private
        // key encryption, relying on a unique salt used in the password-based encryption key
        // derivation to ensure that each encryption key is only used once.
        if cipher == Cipher::ChaCha20Poly1305 {
            iv.copy_from_slice(&cipher::ChaChaNonce::default());
        }

        Ok((okm, iv))
    }

    /// Is the KDF configured as `none`?
    #[must_use]
    pub fn is_none(&self) -> bool {
        self == &Self::None
    }

    /// Is the KDF configured as anything other than `none`?
    #[must_use]
    pub fn is_some(&self) -> bool {
        !self.is_none()
    }

    /// Is the KDF configured as `bcrypt` (i.e. bcrypt-pbkdf)?
    #[cfg(feature = "alloc")]
    #[must_use]
    pub fn is_bcrypt(&self) -> bool {
        matches!(self, Self::Bcrypt { .. })
    }
}

impl Decode for Kdf {
    type Error = Error;

    fn decode(reader: &mut Decoder<impl Reader>) -> Result<Self> {
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
                    let salt = Vec::decode(reader)?;
                    let rounds = u32::decode(reader)?;
                    validate_bcrypt_rounds(rounds)?;
                    Ok(Self::Bcrypt { salt, rounds })
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
            Self::Bcrypt { salt, rounds } => {
                validate_bcrypt_rounds(*rounds).map_err(|_| encoding::Error::Overflow)?;
                [12, salt.len()].checked_sum()?
            }
        };

        [self.algorithm().encoded_len()?, kdfopts_prefixed_len].checked_sum()
    }

    fn encode(&self, writer: &mut impl Writer) -> encoding::Result<()> {
        // Validate before writing any part of the KDF.
        self.encoded_len()?;
        self.algorithm().encode(writer)?;

        match self {
            Self::None => 0usize.encode(writer)?,
            #[cfg(feature = "alloc")]
            Self::Bcrypt { salt, rounds } => {
                [8, salt.len()].checked_sum()?.encode(writer)?;
                salt.encode(writer)?;
                rounds.encode(writer)?;
            }
        }

        Ok(())
    }
}

/// Check the bcrypt round count before encoding, decoding, or key derivation.
#[cfg(feature = "alloc")]
fn validate_bcrypt_rounds(rounds: u32) -> Result<()> {
    if !(1..=MAX_BCRYPT_ROUNDS).contains(&rounds) {
        return Err(Error::Crypto);
    }
    Ok(())
}

#[cfg(all(test, feature = "alloc"))]
mod tests {
    use super::{Kdf, MAX_BCRYPT_ROUNDS};
    use crate::Error;
    use alloc::vec::Vec;
    use encoding::{Decode, Encode, Reader};

    #[test]
    fn bcrypt_rounds_boundaries() {
        let mut encoded = Kdf::Bcrypt {
            salt: b"salt".to_vec(),
            rounds: 1,
        }
        .encode_vec()
        .unwrap();

        for (rounds, valid) in [
            (0, false),
            (1, true),
            (MAX_BCRYPT_ROUNDS, true),
            (MAX_BCRYPT_ROUNDS + 1, false),
            (u32::MAX, false),
        ] {
            let kdf = Kdf::Bcrypt {
                salt: b"salt".to_vec(),
                rounds,
            };
            // Modify the wire encoding so invalid rounds can still be tested on decode.
            let offset = encoded.len() - 4;
            encoded[offset..].copy_from_slice(&rounds.to_be_bytes());

            let mut output = Vec::new();
            let expected = if valid {
                assert_eq!(kdf.encoded_len(), Ok(encoded.len()));
                kdf.encode(&mut output).unwrap();
                assert_eq!(output, encoded);
                Ok(kdf)
            } else {
                assert_eq!(kdf.encoded_len(), Err(encoding::Error::Overflow));
                assert_eq!(kdf.encode(&mut output), Err(encoding::Error::Overflow));
                assert!(output.is_empty());
                Err(Error::Crypto)
            };
            let mut decoder = encoded.as_slice().into_decoder().unwrap();
            assert_eq!(Kdf::decode(&mut decoder), expected, "rounds: {rounds}");
            if valid {
                decoder.finish(()).unwrap();
            }
        }
    }

    #[cfg(feature = "encryption")]
    #[test]
    fn derive_bcrypt_invalid_rounds() {
        // Fail immediately if invalid rounds reach bcrypt instead of running an expensive KDF.
        struct UnreadPassword;

        impl AsRef<[u8]> for UnreadPassword {
            fn as_ref(&self) -> &[u8] {
                panic!("invalid rounds must be rejected before accessing the password");
            }
        }

        for rounds in [0, MAX_BCRYPT_ROUNDS + 1, u32::MAX] {
            let kdf = Kdf::Bcrypt {
                salt: b"salt".to_vec(),
                rounds,
            };
            let mut output = [0xa5; 32];
            assert_eq!(kdf.derive(UnreadPassword, &mut output), Err(Error::Crypto));
            assert_eq!(output, [0xa5; 32]);
        }
    }
}
