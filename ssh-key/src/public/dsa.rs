//! Digital Signature Algorithm (DSA) public keys.

use crate::{Error, MPInt, Result};
use encoding::{CheckedSum, Decode, Encode, Reader, Writer};

/// Digital Signature Algorithm (DSA) public key.
///
/// Described in [FIPS 186-4 § 4.1](https://csrc.nist.gov/publications/detail/fips/186/4/final).
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub struct DsaPublicKey {
    /// Prime modulus.
    pub p: MPInt,

    /// Prime divisor of `p - 1`.
    pub q: MPInt,

    /// Generator of a subgroup of order `q` in the multiplicative group
    /// `GF(p)`, such that `1 < g < p`.
    pub g: MPInt,

    /// The public key, where `y = gˣ mod p`.
    pub y: MPInt,
}

impl Decode for DsaPublicKey {
    type Error = Error;

    fn decode(reader: &mut impl Reader) -> Result<Self> {
        let p = MPInt::decode(reader)?;
        let q = MPInt::decode(reader)?;
        let g = MPInt::decode(reader)?;
        let y = MPInt::decode(reader)?;
        Ok(Self { p, q, g, y })
    }
}

impl Encode for DsaPublicKey {
    type Error = Error;

    fn encoded_len(&self) -> Result<usize> {
        Ok([
            self.p.encoded_len()?,
            self.q.encoded_len()?,
            self.g.encoded_len()?,
            self.y.encoded_len()?,
        ]
        .checked_sum()?)
    }

    fn encode(&self, writer: &mut impl Writer) -> Result<()> {
        self.p.encode(writer)?;
        self.q.encode(writer)?;
        self.g.encode(writer)?;
        self.y.encode(writer)
    }
}

#[cfg(feature = "dsa")]
#[cfg_attr(docsrs, doc(cfg(feature = "dsa")))]
impl TryFrom<DsaPublicKey> for dsa::VerifyingKey {
    type Error = Error;

    fn try_from(key: DsaPublicKey) -> Result<dsa::VerifyingKey> {
        dsa::VerifyingKey::try_from(&key)
    }
}

#[cfg(feature = "dsa")]
#[cfg_attr(docsrs, doc(cfg(feature = "dsa")))]
impl TryFrom<&DsaPublicKey> for dsa::VerifyingKey {
    type Error = Error;

    fn try_from(key: &DsaPublicKey) -> Result<dsa::VerifyingKey> {
        let components = dsa::Components::from_components(
            dsa::BigUint::try_from(&key.p)?,
            dsa::BigUint::try_from(&key.q)?,
            dsa::BigUint::try_from(&key.g)?,
        )?;

        dsa::VerifyingKey::from_components(components, dsa::BigUint::try_from(&key.y)?)
            .map_err(|_| Error::Crypto)
    }
}

#[cfg(feature = "dsa")]
#[cfg_attr(docsrs, doc(cfg(feature = "dsa")))]
impl TryFrom<dsa::VerifyingKey> for DsaPublicKey {
    type Error = Error;

    fn try_from(key: dsa::VerifyingKey) -> Result<DsaPublicKey> {
        DsaPublicKey::try_from(&key)
    }
}

#[cfg(feature = "dsa")]
#[cfg_attr(docsrs, doc(cfg(feature = "dsa")))]
impl TryFrom<&dsa::VerifyingKey> for DsaPublicKey {
    type Error = Error;

    fn try_from(key: &dsa::VerifyingKey) -> Result<DsaPublicKey> {
        Ok(DsaPublicKey {
            p: key.components().p().try_into()?,
            q: key.components().q().try_into()?,
            g: key.components().g().try_into()?,
            y: key.y().try_into()?,
        })
    }
}
