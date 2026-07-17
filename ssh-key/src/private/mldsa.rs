//! ML-DSA private keys.
//!
//! Module-Lattice-Based Digital Signature Algorithm (ML-DSA) as specified in [FIPS204].
//!
//! [FIPS204]: https://csrc.nist.gov/pubs/fips/204/final

use crate::{Algorithm, Error, MlDsaParams, Result, public::MlDsaPublicKey};
use alloc::vec::Vec;
use core::fmt;
use ctutils::{Choice, CtEq};
use encoding::{CheckedSum, Encode, Reader, Writer};
use zeroize::{Zeroize, Zeroizing};

#[cfg(feature = "rand_core")]
use rand_core::CryptoRng;

/// Size of an ML-DSA seed in bytes. This is the same for all parameter sets.
const SEED_SIZE: usize = 32;

/// ML-DSA private key.
/// This is the seed representation, not the expanded private key.
#[derive(Clone)]
pub struct MlDsaPrivateKey([u8; SEED_SIZE]);

impl MlDsaPrivateKey {
    /// Size of an ML-DSA seed in bytes.
    pub const BYTE_SIZE: usize = SEED_SIZE;

    /// Generate a random ML-DSA seed.
    #[cfg(feature = "rand_core")]
    pub fn random<R: CryptoRng + ?Sized>(rng: &mut R) -> Self {
        let mut seed = [0u8; SEED_SIZE];
        rng.fill_bytes(&mut seed);
        Self(seed)
    }

    /// Parse an ML-DSA seed from bytes.
    #[must_use]
    pub fn from_bytes(bytes: &[u8; SEED_SIZE]) -> Self {
        Self(*bytes)
    }

    /// Convert to the inner seed byte array.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; SEED_SIZE] {
        self.0
    }
}

impl AsRef<[u8; SEED_SIZE]> for MlDsaPrivateKey {
    fn as_ref(&self) -> &[u8; SEED_SIZE] {
        &self.0
    }
}

impl CtEq for MlDsaPrivateKey {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.as_ref().ct_eq(other.as_ref())
    }
}

impl Eq for MlDsaPrivateKey {}

impl PartialEq for MlDsaPrivateKey {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl TryFrom<&[u8]> for MlDsaPrivateKey {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self> {
        Ok(MlDsaPrivateKey::from_bytes(bytes.try_into()?))
    }
}

impl fmt::Debug for MlDsaPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MlDsaPrivateKey").finish_non_exhaustive()
    }
}

impl Drop for MlDsaPrivateKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// ML-DSA private/public keypair.
///
/// The SSH encoding of the keypair consists of the [`MlDsaPublicKey`] followed
/// by the 32-byte seed encoded as an SSH `string`.
#[derive(Clone)]
pub struct MlDsaKeypair {
    /// Public key.
    pub public: MlDsaPublicKey,

    /// Private key (seed).
    pub private: MlDsaPrivateKey,
}

impl MlDsaKeypair {
    /// Get the [`MlDsaParams`] parameter set for this keypair.
    #[must_use]
    pub fn params(&self) -> MlDsaParams {
        self.public.params()
    }

    /// Get the [`Algorithm`] for this keypair.
    #[must_use]
    pub fn algorithm(&self) -> Algorithm {
        self.public.algorithm()
    }

    /// Decode an ML-DSA keypair for the given parameter set.
    ///
    /// The parameter set is not encoded in the key body; it is taken from the
    /// SSH algorithm identifier.
    ///
    /// # Errors
    /// - Returns [`Error::Encoding`] in the event of an encoding error.
    /// - Returns [`Error::PublicKey`] if the encoded public key does not match
    ///   the key derived from the seed.
    pub(crate) fn decode_as(reader: &mut impl Reader, params: MlDsaParams) -> Result<Self> {
        let public = MlDsaPublicKey::decode_as(reader, params)?;

        let mut seed = Zeroizing::new([0u8; SEED_SIZE]);
        reader.read_prefixed(|reader| reader.read(&mut *seed))?;

        let keypair = Self {
            public,
            private: MlDsaPrivateKey::from_bytes(&seed),
        };

        keypair.validate()?;

        Ok(keypair)
    }
}

impl CtEq for MlDsaKeypair {
    fn ct_eq(&self, other: &Self) -> Choice {
        Choice::from(u8::from(self.public == other.public)) & self.private.ct_eq(&other.private)
    }
}

impl Eq for MlDsaKeypair {}

impl PartialEq for MlDsaKeypair {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl Encode for MlDsaKeypair {
    fn encoded_len(&self) -> encoding::Result<usize> {
        [self.public.encoded_len()?, 4, SEED_SIZE].checked_sum()
    }

    fn encode(&self, writer: &mut impl Writer) -> encoding::Result<()> {
        self.public.encode(writer)?;
        Zeroizing::new(self.private.to_bytes())
            .as_slice()
            .encode(writer)?;
        Ok(())
    }
}

impl fmt::Debug for MlDsaKeypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MlDsaKeypair")
            .field("public", &self.public)
            .finish_non_exhaustive()
    }
}

impl From<MlDsaKeypair> for MlDsaPublicKey {
    fn from(keypair: MlDsaKeypair) -> MlDsaPublicKey {
        keypair.public
    }
}

impl From<&MlDsaKeypair> for MlDsaPublicKey {
    fn from(keypair: &MlDsaKeypair) -> MlDsaPublicKey {
        keypair.public.clone()
    }
}

/// Derive the raw FIPS 204 public key bytes from a seed for the concrete parameter set `P`.
fn derive_public<P: ml_dsa::MlDsaParams>(seed: &[u8; SEED_SIZE]) -> Vec<u8> {
    use signature::Keypair;

    let seed = ml_dsa::B32::from(*seed);
    let signing_key = ml_dsa::SigningKey::<P>::from_seed(&seed);
    signing_key.verifying_key().encode().as_slice().to_vec()
}

/// Sign a message with "pure" ML-DSA (empty context) for the concrete parameter set `P`.
fn sign_with_params<P: ml_dsa::MlDsaParams>(seed: &[u8; SEED_SIZE], msg: &[u8]) -> Result<Vec<u8>> {
    use signature::Signer;

    let seed = ml_dsa::B32::from(*seed);
    let signing_key = ml_dsa::SigningKey::<P>::from_seed(&seed);

    // The `Signer` impl uses "pure" ML-DSA with an empty context string, as
    // required by draft-sfluhrer-ssh-mldsa.
    let signature = signing_key.try_sign(msg)?;
    Ok(signature.encode().as_slice().to_vec())
}

impl MlDsaKeypair {
    /// Generate a random ML-DSA keypair for the given parameter set.
    ///
    /// # Errors
    /// Returns [`Error::Encoding`] if key derivation produces a malformed key
    /// (should not occur for valid parameter sets).
    pub fn random<R: CryptoRng + ?Sized>(rng: &mut R, params: MlDsaParams) -> Result<Self> {
        Self::from_seed(params, &MlDsaPrivateKey::random(rng).to_bytes())
    }

    /// Derive an ML-DSA keypair from a 32-byte seed for the given parameter set.
    ///
    /// # Errors
    /// Returns [`Error::Encoding`] if key derivation produces a malformed key
    /// (should not occur for valid parameter sets).
    pub fn from_seed(params: MlDsaParams, seed: &[u8; SEED_SIZE]) -> Result<Self> {
        let key = match params {
            MlDsaParams::MlDsa44 => derive_public::<ml_dsa::MlDsa44>(seed),
            MlDsaParams::MlDsa65 => derive_public::<ml_dsa::MlDsa65>(seed),
            MlDsaParams::MlDsa87 => derive_public::<ml_dsa::MlDsa87>(seed),
        };

        Ok(Self {
            public: MlDsaPublicKey::new(params, key)?,
            private: MlDsaPrivateKey::from_bytes(seed),
        })
    }

    /// Sign a message, producing the raw ML-DSA signature bytes.
    pub(crate) fn sign_msg(&self, msg: &[u8]) -> Result<Vec<u8>> {
        let seed = self.private.as_ref();
        match self.public.params() {
            MlDsaParams::MlDsa44 => sign_with_params::<ml_dsa::MlDsa44>(seed, msg),
            MlDsaParams::MlDsa65 => sign_with_params::<ml_dsa::MlDsa65>(seed, msg),
            MlDsaParams::MlDsa87 => sign_with_params::<ml_dsa::MlDsa87>(seed, msg),
        }
    }

    /// Verify that the stored public key matches the key derived from the seed.
    fn validate(&self) -> Result<()> {
        let expected = match self.public.params() {
            MlDsaParams::MlDsa44 => derive_public::<ml_dsa::MlDsa44>(self.private.as_ref()),
            MlDsaParams::MlDsa65 => derive_public::<ml_dsa::MlDsa65>(self.private.as_ref()),
            MlDsaParams::MlDsa87 => derive_public::<ml_dsa::MlDsa87>(self.private.as_ref()),
        };

        if expected.as_slice() == self.public.as_bytes() {
            Ok(())
        } else {
            Err(Error::PublicKey)
        }
    }
}
