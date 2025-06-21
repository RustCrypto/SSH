//! Rivest–Shamir–Adleman (RSA) private keys.

use crate::{Error, Mpint, Result, public::RsaPublicKey};
use core::fmt;
use encoding::{CheckedSum, Decode, Encode, Reader, Writer};
use subtle::{Choice, ConstantTimeEq};
use zeroize::Zeroize;

#[cfg(feature = "rsa")]
use {
    encoding::Uint,
    rand_core::CryptoRng,
    rsa::{
        pkcs1v15,
        traits::{PrivateKeyParts, PublicKeyParts},
    },
    sha2::{Digest, digest::const_oid::AssociatedOid},
};

/// RSA private key.
#[derive(Clone)]
pub struct RsaPrivateKey {
    /// RSA private exponent.
    d: Mpint,

    /// CRT coefficient: `(inverse of q) mod p`.
    iqmp: Mpint,

    /// First prime factor of `n`.
    p: Mpint,

    /// Second prime factor of `n`.
    q: Mpint,
}

impl RsaPrivateKey {
    /// Create a new RSA private key with the following components:
    ///
    /// - `d`: RSA private exponent.
    /// - `iqmp`: CRT coefficient: `(inverse of q) mod p`.
    /// - `p`: First prime factor of `n`.
    /// - `q`: Second prime factor of `n`.
    pub fn new(d: Mpint, iqmp: Mpint, p: Mpint, q: Mpint) -> Result<Self> {
        if d.is_positive() && iqmp.is_positive() && p.is_positive() && q.is_positive() {
            Ok(Self { d, iqmp, p, q })
        } else {
            Err(Error::FormatEncoding)
        }
    }

    /// RSA private exponent.
    pub fn d(&self) -> &Mpint {
        &self.d
    }

    /// CRT coefficient: `(inverse of q) mod p`.
    pub fn iqmp(&self) -> &Mpint {
        &self.iqmp
    }

    /// First prime factor of `n`.
    pub fn p(&self) -> &Mpint {
        &self.p
    }

    /// Second prime factor of `n`.
    pub fn q(&self) -> &Mpint {
        &self.q
    }
}

impl ConstantTimeEq for RsaPrivateKey {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.d.ct_eq(&other.d)
            & self.iqmp.ct_eq(&self.iqmp)
            & self.p.ct_eq(&other.p)
            & self.q.ct_eq(&other.q)
    }
}

impl Eq for RsaPrivateKey {}

impl PartialEq for RsaPrivateKey {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl Decode for RsaPrivateKey {
    type Error = Error;

    fn decode(reader: &mut impl Reader) -> Result<Self> {
        let d = Mpint::decode(reader)?;
        let iqmp = Mpint::decode(reader)?;
        let p = Mpint::decode(reader)?;
        let q = Mpint::decode(reader)?;
        Self::new(d, iqmp, p, q)
    }
}

impl Encode for RsaPrivateKey {
    fn encoded_len(&self) -> encoding::Result<usize> {
        [
            self.d.encoded_len()?,
            self.iqmp.encoded_len()?,
            self.p.encoded_len()?,
            self.q.encoded_len()?,
        ]
        .checked_sum()
    }

    fn encode(&self, writer: &mut impl Writer) -> encoding::Result<()> {
        self.d.encode(writer)?;
        self.iqmp.encode(writer)?;
        self.p.encode(writer)?;
        self.q.encode(writer)?;
        Ok(())
    }
}

impl Drop for RsaPrivateKey {
    fn drop(&mut self) {
        self.d.zeroize();
        self.iqmp.zeroize();
        self.p.zeroize();
        self.q.zeroize();
    }
}

/// RSA private/public keypair.
#[derive(Clone)]
pub struct RsaKeypair {
    /// Public key.
    public: RsaPublicKey,

    /// Private key.
    private: RsaPrivateKey,
}

impl RsaKeypair {
    /// Minimum allowed RSA key size.
    #[cfg(feature = "rsa")]
    pub(crate) const MIN_KEY_SIZE: usize = 2048;

    /// Generate a random RSA keypair of the given size.
    #[cfg(feature = "rsa")]
    pub fn random<R: CryptoRng + ?Sized>(rng: &mut R, bit_size: usize) -> Result<Self> {
        if bit_size >= Self::MIN_KEY_SIZE {
            rsa::RsaPrivateKey::new(rng, bit_size)?.try_into()
        } else {
            Err(Error::Crypto)
        }
    }

    /// Create a new keypair from the given `public` and `private` key components.
    pub fn new(public: RsaPublicKey, private: RsaPrivateKey) -> Result<Self> {
        // TODO(tarcieri): perform validation that the public and private components match?
        Ok(Self { public, private })
    }

    /// Get the size of the RSA modulus in bits.
    pub fn key_size(&self) -> u32 {
        self.public.key_size()
    }

    /// Get the public component of the keypair.
    pub fn public(&self) -> &RsaPublicKey {
        &self.public
    }

    /// Get the private component of the keypair.
    pub fn private(&self) -> &RsaPrivateKey {
        &self.private
    }
}

impl ConstantTimeEq for RsaKeypair {
    fn ct_eq(&self, other: &Self) -> Choice {
        Choice::from((self.public == other.public) as u8) & self.private.ct_eq(&other.private)
    }
}

impl Eq for RsaKeypair {}

impl PartialEq for RsaKeypair {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl Decode for RsaKeypair {
    type Error = Error;

    fn decode(reader: &mut impl Reader) -> Result<Self> {
        let n = Mpint::decode(reader)?;
        let e = Mpint::decode(reader)?;
        let public = RsaPublicKey::new(e, n)?;
        let private = RsaPrivateKey::decode(reader)?;
        Self::new(public, private)
    }
}

impl Encode for RsaKeypair {
    fn encoded_len(&self) -> encoding::Result<usize> {
        [
            self.public.n().encoded_len()?,
            self.public.e().encoded_len()?,
            self.private.encoded_len()?,
        ]
        .checked_sum()
    }

    fn encode(&self, writer: &mut impl Writer) -> encoding::Result<()> {
        self.public.n().encode(writer)?;
        self.public.e().encode(writer)?;
        self.private.encode(writer)
    }
}

impl From<RsaKeypair> for RsaPublicKey {
    fn from(keypair: RsaKeypair) -> RsaPublicKey {
        keypair.public
    }
}

impl From<&RsaKeypair> for RsaPublicKey {
    fn from(keypair: &RsaKeypair) -> RsaPublicKey {
        keypair.public.clone()
    }
}

impl fmt::Debug for RsaKeypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RsaKeypair")
            .field("public", &self.public)
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "rsa")]
impl TryFrom<RsaKeypair> for rsa::RsaPrivateKey {
    type Error = Error;

    fn try_from(key: RsaKeypair) -> Result<rsa::RsaPrivateKey> {
        rsa::RsaPrivateKey::try_from(&key)
    }
}

#[cfg(feature = "rsa")]
impl TryFrom<&RsaKeypair> for rsa::RsaPrivateKey {
    type Error = Error;

    fn try_from(key: &RsaKeypair) -> Result<rsa::RsaPrivateKey> {
        let ret = rsa::RsaPrivateKey::from_components(
            Uint::try_from(key.public.n())?,
            Uint::try_from(key.public.e())?,
            Uint::try_from(&key.private.d)?,
            vec![
                Uint::try_from(&key.private.p)?,
                Uint::try_from(&key.private.q)?,
            ],
        )?;

        if ret.size().saturating_mul(8) >= RsaKeypair::MIN_KEY_SIZE {
            Ok(ret)
        } else {
            Err(Error::Crypto)
        }
    }
}

#[cfg(feature = "rsa")]
impl TryFrom<rsa::RsaPrivateKey> for RsaKeypair {
    type Error = Error;

    fn try_from(key: rsa::RsaPrivateKey) -> Result<RsaKeypair> {
        RsaKeypair::try_from(&key)
    }
}

#[cfg(feature = "rsa")]
impl TryFrom<&rsa::RsaPrivateKey> for RsaKeypair {
    type Error = Error;

    fn try_from(key: &rsa::RsaPrivateKey) -> Result<RsaKeypair> {
        // Multi-prime keys are not supported
        if key.primes().len() > 2 {
            return Err(Error::Crypto);
        }

        let public = RsaPublicKey::try_from(key.to_public_key())?;

        let p = &key.primes()[0];
        let q = &key.primes()[1];
        let iqmp = key.crt_coefficient().ok_or(Error::Crypto)?;

        let private = RsaPrivateKey {
            d: key.d().try_into()?,
            iqmp: iqmp.try_into()?,
            p: p.try_into()?,
            q: q.try_into()?,
        };

        Ok(RsaKeypair { public, private })
    }
}

#[cfg(feature = "rsa")]
impl<D> TryFrom<&RsaKeypair> for pkcs1v15::SigningKey<D>
where
    D: Digest + AssociatedOid,
{
    type Error = Error;

    fn try_from(keypair: &RsaKeypair) -> Result<pkcs1v15::SigningKey<D>> {
        Ok(pkcs1v15::SigningKey::new(keypair.try_into()?))
    }
}
