//! Rivest–Shamir–Adleman (RSA) public keys.

use crate::{Error, Mpint, Result};
use core::hash::{Hash, Hasher};
use encoding::{CheckedSum, Decode, Decoder, Encode, Reader, Writer};

#[cfg(feature = "rsa")]
use {
    encoding::Uint,
    rsa::{pkcs1v15, traits::PublicKeyParts},
    sha2::{Digest, digest::const_oid::AssociatedOid},
};

/// RSA public key.
///
/// Described in [RFC4253 § 6.6](https://datatracker.ietf.org/doc/html/rfc4253#section-6.6).
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct RsaPublicKey {
    /// RSA public exponent.
    e: Mpint,

    /// RSA modulus.
    n: Mpint,

    /// Length of this key in bits.
    bits: u32,
}

impl RsaPublicKey {
    /// Create a new [`RsaPublicKey`] with the given components:
    ///
    /// - `e`: RSA public exponent.
    /// - `n`: RSA modulus.
    ///
    /// # Errors
    /// Returns [`Error::FormatEncoding`] if either component is zero.
    pub fn new(e: Mpint, n: Mpint) -> Result<Self> {
        if e.is_zero() || n.is_zero() {
            return Err(Error::FormatEncoding);
        }

        let bits = u32::try_from(n.as_bytes().len() * 8).map_err(|_| Error::FormatEncoding)?;

        Ok(Self { e, n, bits })
    }

    /// Get the RSA public exponent.
    #[must_use]
    pub fn e(&self) -> &Mpint {
        &self.e
    }

    /// Get the RSA modulus.
    #[must_use]
    pub fn n(&self) -> &Mpint {
        &self.n
    }

    /// Get the size of the RSA modulus in bits.
    #[must_use]
    pub fn key_size(&self) -> u32 {
        self.bits
    }
}

impl Decode for RsaPublicKey {
    type Error = Error;

    fn decode(reader: &mut Decoder<impl Reader>) -> Result<Self> {
        let e = Mpint::decode(reader)?;
        let n = Mpint::decode(reader)?;
        Self::new(e, n)
    }
}

impl Encode for RsaPublicKey {
    fn encoded_len(&self) -> encoding::Result<usize> {
        [self.e.encoded_len()?, self.n.encoded_len()?].checked_sum()
    }

    fn encode(&self, writer: &mut impl Writer) -> encoding::Result<()> {
        self.e.encode(writer)?;
        self.n.encode(writer)
    }
}

impl Hash for RsaPublicKey {
    #[inline]
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.e.as_bytes().hash(state);
        self.n.as_bytes().hash(state);
    }
}

#[cfg(feature = "rsa")]
impl TryFrom<RsaPublicKey> for rsa::PublicKey {
    type Error = Error;

    fn try_from(key: RsaPublicKey) -> Result<rsa::PublicKey> {
        rsa::PublicKey::try_from(&key)
    }
}

#[cfg(feature = "rsa")]
impl TryFrom<&RsaPublicKey> for rsa::PublicKey {
    type Error = Error;

    fn try_from(key: &RsaPublicKey) -> Result<rsa::PublicKey> {
        let n = Uint::from(&key.n);
        let e = Uint::from(&key.e);
        let ret = rsa::PublicKey::new(n, e).map_err(|_| Error::Crypto)?;

        Ok(ret)
    }
}

#[cfg(feature = "rsa")]
impl TryFrom<rsa::PublicKey> for RsaPublicKey {
    type Error = Error;

    fn try_from(key: rsa::PublicKey) -> Result<RsaPublicKey> {
        RsaPublicKey::try_from(&key)
    }
}

#[cfg(feature = "rsa")]
impl TryFrom<&rsa::PublicKey> for RsaPublicKey {
    type Error = Error;

    fn try_from(key: &rsa::PublicKey) -> Result<RsaPublicKey> {
        RsaPublicKey::new(key.e().try_into()?, key.n().as_ref().try_into()?)
    }
}

#[cfg(feature = "rsa")]
impl<D> TryFrom<&RsaPublicKey> for pkcs1v15::VerifyingKey<D>
where
    D: Digest + AssociatedOid,
{
    type Error = Error;

    fn try_from(key: &RsaPublicKey) -> Result<pkcs1v15::VerifyingKey<D>> {
        Ok(pkcs1v15::VerifyingKey::new(key.try_into()?))
    }
}
