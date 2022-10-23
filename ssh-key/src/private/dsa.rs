//! Digital Signature Algorithm (DSA) private keys.

use crate::{public::DsaPublicKey, Error, MPInt, Result};
use core::fmt;
use encoding::{CheckedSum, Decode, Encode, Reader, Writer};
use zeroize::Zeroize;

#[cfg(feature = "subtle")]
use subtle::{Choice, ConstantTimeEq};

#[cfg(all(feature = "dsa", feature = "rand_core"))]
use rand_core::{CryptoRng, RngCore};

/// Digital Signature Algorithm (DSA) private key.
///
/// Uniformly random integer `x`, such that `0 < x < q`, i.e. `x` is in the
/// range `[1, q–1]`.
///
/// Described in [FIPS 186-4 § 4.1](https://csrc.nist.gov/publications/detail/fips/186/4/final).
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
#[derive(Clone)]
pub struct DsaPrivateKey {
    /// Integer representing a DSA private key.
    inner: MPInt,
}

impl DsaPrivateKey {
    /// Get the serialized private key as bytes.
    pub fn as_bytes(&self) -> &[u8] {
        self.inner.as_bytes()
    }

    /// Get the inner [`MPInt`].
    pub fn as_mpint(&self) -> &MPInt {
        &self.inner
    }
}

impl AsRef<[u8]> for DsaPrivateKey {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl Decode for DsaPrivateKey {
    type Error = Error;

    fn decode(reader: &mut impl Reader) -> Result<Self> {
        Ok(Self {
            inner: MPInt::decode(reader)?,
        })
    }
}

impl Drop for DsaPrivateKey {
    fn drop(&mut self) {
        self.inner.zeroize();
    }
}

impl Encode for DsaPrivateKey {
    type Error = Error;

    fn encoded_len(&self) -> Result<usize> {
        self.inner.encoded_len()
    }

    fn encode(&self, writer: &mut impl Writer) -> Result<()> {
        self.inner.encode(writer)
    }
}

impl fmt::Debug for DsaPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DsaPrivateKey").finish_non_exhaustive()
    }
}

#[cfg(feature = "dsa")]
#[cfg_attr(docsrs, doc(cfg(feature = "dsa")))]
impl TryFrom<DsaPrivateKey> for dsa::BigUint {
    type Error = Error;

    fn try_from(key: DsaPrivateKey) -> Result<dsa::BigUint> {
        dsa::BigUint::try_from(&key.inner)
    }
}

#[cfg(feature = "dsa")]
#[cfg_attr(docsrs, doc(cfg(feature = "dsa")))]
impl TryFrom<&DsaPrivateKey> for dsa::BigUint {
    type Error = Error;

    fn try_from(key: &DsaPrivateKey) -> Result<dsa::BigUint> {
        dsa::BigUint::try_from(&key.inner)
    }
}

#[cfg(feature = "dsa")]
#[cfg_attr(docsrs, doc(cfg(feature = "dsa")))]
impl TryFrom<dsa::SigningKey> for DsaPrivateKey {
    type Error = Error;

    fn try_from(key: dsa::SigningKey) -> Result<DsaPrivateKey> {
        DsaPrivateKey::try_from(&key)
    }
}

#[cfg(feature = "dsa")]
#[cfg_attr(docsrs, doc(cfg(feature = "dsa")))]
impl TryFrom<&dsa::SigningKey> for DsaPrivateKey {
    type Error = Error;

    fn try_from(key: &dsa::SigningKey) -> Result<DsaPrivateKey> {
        Ok(DsaPrivateKey {
            inner: key.x().try_into()?,
        })
    }
}

#[cfg(feature = "subtle")]
#[cfg_attr(docsrs, doc(cfg(feature = "subtle")))]
impl ConstantTimeEq for DsaPrivateKey {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.inner.ct_eq(&other.inner)
    }
}

#[cfg(feature = "subtle")]
#[cfg_attr(docsrs, doc(cfg(feature = "subtle")))]
impl PartialEq for DsaPrivateKey {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

#[cfg(feature = "subtle")]
#[cfg_attr(docsrs, doc(cfg(feature = "subtle")))]
impl Eq for DsaPrivateKey {}

/// Digital Signature Algorithm (DSA) private/public keypair.
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
#[derive(Clone)]
pub struct DsaKeypair {
    /// Public key.
    pub public: DsaPublicKey,

    /// Private key.
    pub private: DsaPrivateKey,
}

impl DsaKeypair {
    /// Key size.
    #[cfg(all(feature = "dsa", feature = "rand_core"))]
    #[allow(deprecated)]
    pub(crate) const KEY_SIZE: dsa::KeySize = dsa::KeySize::DSA_1024_160;

    /// Generate a random DSA private key.
    #[cfg(all(feature = "dsa", feature = "rand_core"))]
    #[cfg_attr(docsrs, doc(cfg(all(feature = "dsa", feature = "rand_core"))))]
    pub fn random(mut rng: impl CryptoRng + RngCore) -> Result<Self> {
        let components = dsa::Components::generate(&mut rng, Self::KEY_SIZE);
        dsa::SigningKey::generate(&mut rng, components).try_into()
    }
}

impl Decode for DsaKeypair {
    type Error = Error;

    fn decode(reader: &mut impl Reader) -> Result<Self> {
        let public = DsaPublicKey::decode(reader)?;
        let private = DsaPrivateKey::decode(reader)?;
        Ok(DsaKeypair { public, private })
    }
}

impl Encode for DsaKeypair {
    type Error = Error;

    fn encoded_len(&self) -> Result<usize> {
        Ok([self.public.encoded_len()?, self.private.encoded_len()?].checked_sum()?)
    }

    fn encode(&self, writer: &mut impl Writer) -> Result<()> {
        self.public.encode(writer)?;
        self.private.encode(writer)
    }
}

impl From<DsaKeypair> for DsaPublicKey {
    fn from(keypair: DsaKeypair) -> DsaPublicKey {
        keypair.public
    }
}

impl From<&DsaKeypair> for DsaPublicKey {
    fn from(keypair: &DsaKeypair) -> DsaPublicKey {
        keypair.public.clone()
    }
}

impl fmt::Debug for DsaKeypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DsaKeypair")
            .field("public", &self.public)
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "dsa")]
#[cfg_attr(docsrs, doc(cfg(feature = "dsa")))]
impl TryFrom<DsaKeypair> for dsa::SigningKey {
    type Error = Error;

    fn try_from(key: DsaKeypair) -> Result<dsa::SigningKey> {
        dsa::SigningKey::try_from(&key)
    }
}

#[cfg(feature = "dsa")]
#[cfg_attr(docsrs, doc(cfg(feature = "dsa")))]
impl TryFrom<&DsaKeypair> for dsa::SigningKey {
    type Error = Error;

    fn try_from(key: &DsaKeypair) -> Result<dsa::SigningKey> {
        Ok(dsa::SigningKey::from_components(
            dsa::VerifyingKey::try_from(&key.public)?,
            dsa::BigUint::try_from(&key.private)?,
        )?)
    }
}

#[cfg(feature = "dsa")]
#[cfg_attr(docsrs, doc(cfg(feature = "dsa")))]
impl TryFrom<dsa::SigningKey> for DsaKeypair {
    type Error = Error;

    fn try_from(key: dsa::SigningKey) -> Result<DsaKeypair> {
        DsaKeypair::try_from(&key)
    }
}

#[cfg(feature = "dsa")]
#[cfg_attr(docsrs, doc(cfg(feature = "dsa")))]
impl TryFrom<&dsa::SigningKey> for DsaKeypair {
    type Error = Error;

    fn try_from(key: &dsa::SigningKey) -> Result<DsaKeypair> {
        Ok(DsaKeypair {
            private: key.try_into()?,
            public: key.verifying_key().try_into()?,
        })
    }
}

#[cfg(feature = "subtle")]
#[cfg_attr(docsrs, doc(cfg(feature = "subtle")))]
impl ConstantTimeEq for DsaKeypair {
    fn ct_eq(&self, other: &Self) -> Choice {
        Choice::from((self.public == other.public) as u8) & self.private.ct_eq(&other.private)
    }
}

#[cfg(feature = "subtle")]
#[cfg_attr(docsrs, doc(cfg(feature = "subtle")))]
impl PartialEq for DsaKeypair {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

#[cfg(feature = "subtle")]
#[cfg_attr(docsrs, doc(cfg(feature = "subtle")))]
impl Eq for DsaKeypair {}
