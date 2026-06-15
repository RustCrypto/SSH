//! ML-DSA-44 + Ed25519 public keys.
//!

use crate::{Error, Result};
use core::fmt;
#[cfg(feature = "ed25519")]
use libcrux_ml_dsa::ml_dsa_44::generate_key_pair;
use encoding::{CheckedSum, Decode, Encode, Reader, Writer};
use crate::private::Mldsa44Ed25519PrivateKey;

/// ML-DSA-44 + Ed25519 public key.
///
/// Encodings for Ed25519 public keys are described in [RFC8709 § 4]:
///
/// > The "ssh-ed25519" key format has the following encoding:
/// >
/// > **string** "ssh-ed25519"
/// >
/// > **string** key
/// >
/// > Here, 'key' is the 32-octet public key described in RFC8032
///
/// [RFC8709 § 4]: https://datatracker.ietf.org/doc/html/rfc8709#section-4
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub struct Mldsa44Ed25519PublicKey(pub [u8; Self::BYTE_SIZE]);

impl Mldsa44Ed25519PublicKey {
    pub const MLDSA_SIZE: usize = 1312;
    pub const ED25519_SIZE: usize = 32;

    /// Size of a composite ML-DSA-44 + Ed25519 public key in bytes.
    pub const BYTE_SIZE: usize = Self::MLDSA_SIZE + Self::ED25519_SIZE;
}

impl AsRef<[u8; Self::BYTE_SIZE]> for Mldsa44Ed25519PublicKey {
    fn as_ref(&self) -> &[u8; Self::BYTE_SIZE] {
        &self.0
    }
}

impl Decode for Mldsa44Ed25519PublicKey {
    type Error = Error;

    fn decode(reader: &mut impl Reader) -> Result<Self> {
        let mut bytes = [0u8; Self::BYTE_SIZE];
        reader.read_prefixed(|reader| reader.read(&mut bytes))?;
        Ok(Self(bytes))
    }
}

impl Encode for Mldsa44Ed25519PublicKey {
    fn encoded_len(&self) -> encoding::Result<usize> {
        [4, Self::BYTE_SIZE].checked_sum()
    }

    fn encode(&self, writer: &mut impl Writer) -> encoding::Result<()> {
        self.0.as_slice().encode(writer)?;
        Ok(())
    }
}

impl TryFrom<&[u8]> for Mldsa44Ed25519PublicKey {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self> {
        Ok(Self(bytes.try_into()?))
    }
}

impl fmt::Display for Mldsa44Ed25519PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:X}")
    }
}

impl fmt::LowerHex for Mldsa44Ed25519PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.as_ref() {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl fmt::UpperHex for Mldsa44Ed25519PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.as_ref() {
            write!(f, "{byte:02X}")?;
        }
        Ok(())
    }
}

#[cfg(feature = "ed25519")]
impl TryFrom<Mldsa44Ed25519PublicKey> for ed25519_dalek::VerifyingKey {
    type Error = Error;

    fn try_from(key: Mldsa44Ed25519PublicKey) -> Result<ed25519_dalek::VerifyingKey> {
        ed25519_dalek::VerifyingKey::try_from(&key)
    }
}

#[cfg(feature = "ed25519")]
impl TryFrom<&Mldsa44Ed25519PublicKey> for ed25519_dalek::VerifyingKey {
    type Error = Error;

    fn try_from(key: &Mldsa44Ed25519PublicKey) -> Result<ed25519_dalek::VerifyingKey> {
        ed25519_dalek::VerifyingKey::from_bytes(key.as_ref()).map_err(|_| Error::Crypto)
    }
}

#[cfg(feature = "ed25519")]
impl From<Mldsa44Ed25519PrivateKey> for Mldsa44Ed25519PublicKey {
    fn from(key: Mldsa44Ed25519PrivateKey) -> Mldsa44Ed25519PublicKey {
        Mldsa44Ed25519PublicKey::from(&key)
    }
}

#[cfg(feature = "ed25519")]
impl From<&Mldsa44Ed25519PrivateKey> for Mldsa44Ed25519PublicKey {
    fn from(key: &Mldsa44Ed25519PrivateKey) -> Mldsa44Ed25519PublicKey {
        let mldsa44_key_pair = generate_key_pair(key.mldsa44_seed);
        let ed25519_key_pair = ed25519_dalek::SigningKey::from_bytes(&key.ed25519_seed);
        let mut public_key = [0u8; Mldsa44Ed25519PublicKey::BYTE_SIZE];
        public_key[..Mldsa44Ed25519PublicKey::MLDSA_SIZE].copy_from_slice(mldsa44_key_pair.verification_key);
        public_key[Mldsa44Ed25519PublicKey::MLDSA_SIZE..].copy_from_slice(ed25519_key_pair.verifying_key().as_bytes());
        Mldsa44Ed25519PublicKey(public_key)
    }
}
