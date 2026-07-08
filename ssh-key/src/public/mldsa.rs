//! ML-DSA public keys.
//!
//! Module-Lattice-Based Digital Signature Algorithm (ML-DSA) as specified in [FIPS204].
//!
//! [FIPS204]: https://csrc.nist.gov/pubs/fips/204/final

use crate::{Algorithm, MlDsaParams, Result};
use alloc::boxed::Box;
use encoding::{Encode, Reader, Writer};
use ml_dsa::{EncodedVerifyingKey, MlDsa44, MlDsa65, MlDsa87};

/// ML-DSA public key.
///
///
/// [draft-sfluhrer-ssh-mldsa]: https://datatracker.ietf.org/doc/draft-sfluhrer-ssh-mldsa/
/// [FIPS204]: https://csrc.nist.gov/pubs/fips/204/final
#[derive(Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub enum MlDsaPublicKey {
    /// ML-DSA-44 public key.
    MlDsa44(Box<EncodedVerifyingKey<MlDsa44>>),

    /// ML-DSA-65 public key.
    MlDsa65(Box<EncodedVerifyingKey<MlDsa65>>),

    /// ML-DSA-87 public key.
    MlDsa87(Box<EncodedVerifyingKey<MlDsa87>>),
}

impl MlDsaPublicKey {
    /// Maximum size in bytes of a FIPS 204 public key across all parameter sets
    /// (i.e. the ML-DSA-87 public key size).
    const MAX_SIZE: usize = 2592;

    /// Create a new ML-DSA public key from raw FIPS 204 public key bytes for the
    /// given parameter set.
    ///
    /// # Errors
    /// Returns [`Error::Encoding`] with [`encoding::Error::Length`] if the key
    /// length does not match the parameter set's public key size.
    pub fn new(params: MlDsaParams, key: impl AsRef<[u8]>) -> Result<Self> {
        let key = key.as_ref();

        Ok(match params {
            MlDsaParams::MlDsa44 => Self::MlDsa44(Box::new(
                EncodedVerifyingKey::<MlDsa44>::try_from(key).map_err(|_| encoding::Error::Length)?,
            )),
            MlDsaParams::MlDsa65 => Self::MlDsa65(Box::new(
                EncodedVerifyingKey::<MlDsa65>::try_from(key).map_err(|_| encoding::Error::Length)?,
            )),
            MlDsaParams::MlDsa87 => Self::MlDsa87(Box::new(
                EncodedVerifyingKey::<MlDsa87>::try_from(key).map_err(|_| encoding::Error::Length)?,
            )),
        })
    }

    /// Get the [`MlDsaParams`] parameter set for this public key.
    #[must_use]
    pub fn params(&self) -> MlDsaParams {
        match self {
            Self::MlDsa44(_) => MlDsaParams::MlDsa44,
            Self::MlDsa65(_) => MlDsaParams::MlDsa65,
            Self::MlDsa87(_) => MlDsaParams::MlDsa87,
        }
    }

    /// Get the [`Algorithm`] for this public key.
    #[must_use]
    pub fn algorithm(&self) -> Algorithm {
        Algorithm::MlDsa {
            params: self.params(),
        }
    }

    /// Get the raw FIPS 204 public key bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Self::MlDsa44(key) => key.as_slice(),
            Self::MlDsa65(key) => key.as_slice(),
            Self::MlDsa87(key) => key.as_slice(),
        }
    }

    /// Decode an ML-DSA public key for the given parameter set.
    ///
    /// The parameter set is not encoded in the key body; it is taken from the
    /// SSH algorithm identifier (see [`MlDsaPublicKey`]).
    pub(crate) fn decode_as(reader: &mut impl Reader, params: MlDsaParams) -> Result<Self> {
        let mut buf = [0u8; Self::MAX_SIZE];
        let key = reader.read_byten(&mut buf)?;
        Self::new(params, key)
    }
}

impl AsRef<[u8]> for MlDsaPublicKey {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl Encode for MlDsaPublicKey {
    fn encoded_len(&self) -> encoding::Result<usize> {
        self.as_bytes().encoded_len()
    }

    fn encode(&self, writer: &mut impl Writer) -> encoding::Result<()> {
        self.as_bytes().encode(writer)
    }
}
