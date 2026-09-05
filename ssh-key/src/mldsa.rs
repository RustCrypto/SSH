//! Module-Lattice-Based Digital Signature Algorithm (ML-DSA) as specified in [FIPS204].
//!
//! This module is deliberately crate-private. There is no adopted specification for *pure* ML-DSA
//! SSH keys, and this is only used in composite signatures.

use crate::{Error, Result};
use alloc::{boxed::Box, vec::Vec};
use core::fmt;
use ctutils::{Choice, CtEq};
use ml_dsa::{EncodedVerifyingKey, MlDsa44, MlDsa65, MlDsa87};
use zeroize::{Zeroize, Zeroizing};

/// Size of an ML-DSA seed in bytes. This is the same for all parameter sets.
pub(crate) const SEED_SIZE: usize = 32;

/// ML-DSA parameter sets as specified in [FIPS204].
///
/// Each parameter set corresponds to a NIST security category.
///
/// [FIPS204]: https://csrc.nist.gov/pubs/fips/204/final
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub(crate) enum MlDsaParams {
    /// ML-DSA-44 (security category 2).
    MlDsa44,

    /// ML-DSA-65 (security category 3).
    #[allow(dead_code)] // no composite algorithm uses ML-DSA-65
    MlDsa65,

    /// ML-DSA-87 (security category 5).
    #[allow(dead_code)] // used once `mldsa87-p384` is implemented
    MlDsa87,
}

impl MlDsaParams {
    /// Size in bytes of a FIPS 204 public key for this parameter set.
    pub(crate) const fn public_key_size(self) -> usize {
        match self {
            Self::MlDsa44 => 1312,
            Self::MlDsa65 => 1952,
            Self::MlDsa87 => 2592,
        }
    }

    /// Size in bytes of a FIPS 204 signature for this parameter set.
    pub(crate) const fn signature_size(self) -> usize {
        match self {
            Self::MlDsa44 => 2420,
            Self::MlDsa65 => 3309,
            Self::MlDsa87 => 4627,
        }
    }
}

/// ML-DSA public key: the raw FIPS 204 encoded verifying key.
#[derive(Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub(crate) enum MlDsaPublicKey {
    /// ML-DSA-44 public key.
    MlDsa44(Box<EncodedVerifyingKey<MlDsa44>>),

    /// ML-DSA-65 public key.
    MlDsa65(Box<EncodedVerifyingKey<MlDsa65>>),

    /// ML-DSA-87 public key.
    MlDsa87(Box<EncodedVerifyingKey<MlDsa87>>),
}

impl MlDsaPublicKey {
    /// Create a new ML-DSA public key from raw FIPS 204 public key bytes for the given parameter
    /// set.
    ///
    /// # Errors
    /// Returns [`Error::Encoding`] with [`encoding::Error::Length`] if the key length does not
    /// match the parameter set's public key size.
    pub(crate) fn new(params: MlDsaParams, key: &[u8]) -> Result<Self> {
        Ok(match params {
            MlDsaParams::MlDsa44 => Self::MlDsa44(Box::new(decode_public::<MlDsa44>(key)?)),
            MlDsaParams::MlDsa65 => Self::MlDsa65(Box::new(decode_public::<MlDsa65>(key)?)),
            MlDsaParams::MlDsa87 => Self::MlDsa87(Box::new(decode_public::<MlDsa87>(key)?)),
        })
    }

    /// Get the raw FIPS 204 public key bytes.
    pub(crate) fn as_bytes(&self) -> &[u8] {
        match self {
            Self::MlDsa44(key) => key.as_slice(),
            Self::MlDsa65(key) => key.as_slice(),
            Self::MlDsa87(key) => key.as_slice(),
        }
    }

    /// Verify an ML-DSA signature over `msg` with the given FIPS 204 context string.
    ///
    /// # Errors
    /// Returns [`Error::Signature`] if the signature is malformed or invalid.
    pub(crate) fn verify_with_ctx(&self, msg: &[u8], ctx: &[u8], signature: &[u8]) -> Result<()> {
        match self {
            Self::MlDsa44(key) => verify_with_ctx::<MlDsa44>(key, msg, ctx, signature),
            Self::MlDsa65(key) => verify_with_ctx::<MlDsa65>(key, msg, ctx, signature),
            Self::MlDsa87(key) => verify_with_ctx::<MlDsa87>(key, msg, ctx, signature),
        }
    }
}

/// ML-DSA private key.
///
/// This is the seed representation, not the expanded private key. The expanded key is derived
/// on demand.
#[derive(Clone)]
pub(crate) struct MlDsaPrivateKey([u8; SEED_SIZE]);

impl MlDsaPrivateKey {
    /// Parse an ML-DSA seed from bytes.
    pub(crate) fn from_bytes(bytes: &[u8; SEED_SIZE]) -> Self {
        Self(*bytes)
    }

    /// Derive the public key for the given parameter set.
    ///
    /// # Errors
    /// Returns [`Error::Encoding`] if key derivation produces a malformed key, which should not
    /// occur for a valid parameter set.
    pub(crate) fn public_key(&self, params: MlDsaParams) -> Result<MlDsaPublicKey> {
        let key = match params {
            MlDsaParams::MlDsa44 => derive_public::<MlDsa44>(&self.0),
            MlDsaParams::MlDsa65 => derive_public::<MlDsa65>(&self.0),
            MlDsaParams::MlDsa87 => derive_public::<MlDsa87>(&self.0),
        };

        MlDsaPublicKey::new(params, &key)
    }

    /// Sign `msg` with the deterministic (hedged-variant-free) FIPS 204 signing procedure, using
    /// the given context string.
    ///
    /// # Errors
    /// Returns [`Error::Crypto`] if the signature cannot be produced.
    pub(crate) fn sign_deterministic(
        &self,
        params: MlDsaParams,
        msg: &[u8],
        ctx: &[u8],
    ) -> Result<Vec<u8>> {
        match params {
            MlDsaParams::MlDsa44 => sign_deterministic::<MlDsa44>(&self.0, msg, ctx),
            MlDsaParams::MlDsa65 => sign_deterministic::<MlDsa65>(&self.0, msg, ctx),
            MlDsaParams::MlDsa87 => sign_deterministic::<MlDsa87>(&self.0, msg, ctx),
        }
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
        Ok(Self::from_bytes(bytes.try_into()?))
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

/// Decode raw FIPS 204 public key bytes for the concrete parameter set `P`.
fn decode_public<P: ml_dsa::MlDsaParams>(key: &[u8]) -> Result<EncodedVerifyingKey<P>> {
    EncodedVerifyingKey::<P>::try_from(key).map_err(|_| encoding::Error::Length.into())
}

/// Expand a signing key from a seed for the concrete parameter set `P`.
fn signing_key<P: ml_dsa::MlDsaParams>(seed: &[u8; SEED_SIZE]) -> ml_dsa::SigningKey<P> {
    let seed = Zeroizing::new(ml_dsa::B32::from(*seed));
    ml_dsa::SigningKey::<P>::from_seed(&seed)
}

/// Derive the raw FIPS 204 public key bytes from a seed for the concrete parameter set `P`.
fn derive_public<P: ml_dsa::MlDsaParams>(seed: &[u8; SEED_SIZE]) -> Vec<u8> {
    use signature::Keypair;

    signing_key::<P>(seed)
        .verifying_key()
        .encode()
        .as_slice()
        .to_vec()
}

/// Sign `msg` with the concrete parameter set `P` and the given context string.
fn sign_deterministic<P: ml_dsa::MlDsaParams>(
    seed: &[u8; SEED_SIZE],
    msg: &[u8],
    ctx: &[u8],
) -> Result<Vec<u8>> {
    let signature = signing_key::<P>(seed)
        .expanded_key()
        .sign_deterministic(msg, ctx)
        .map_err(|_| Error::Crypto)?;

    Ok(signature.encode().as_slice().to_vec())
}

/// Verify an ML-DSA signature over `msg` with the concrete parameter set `P` and the given context
/// string.
fn verify_with_ctx<P: ml_dsa::MlDsaParams>(
    key: &EncodedVerifyingKey<P>,
    msg: &[u8],
    ctx: &[u8],
    signature: &[u8],
) -> Result<()> {
    let signature = ml_dsa::Signature::<P>::try_from(signature).map_err(|_| Error::Signature)?;

    if ml_dsa::VerifyingKey::<P>::decode(key).verify_with_context(msg, ctx, &signature) {
        Ok(())
    } else {
        Err(Error::Signature)
    }
}
