//! ML-DSA-44 + Ed25519 private keys.
//!
//! Based on draft-miller-sshm-mldsa44-ed25519-composite-sigs-00

// TODO: move from ed25519 to a separate feature flag

use crate::{Error, Result, public::Mldsa44Ed25519PublicKey};
use core::fmt;
use ctutils::{Choice, CtEq};
use encoding::{CheckedSum, Decode, Encode, Reader, Writer};
use zeroize::{Zeroize, Zeroizing};

#[cfg(feature = "rand_core")]
use rand_core::CryptoRng;
use rand_core::Rng;
use crate::private::Ed25519PrivateKey;

/// ML-DSA-44 + Ed25519 private key.
#[derive(Clone)]
pub struct Mldsa44Ed25519PrivateKey {
    pub(crate) mldsa44_seed: [u8; Self::MLDSA44_SEED_SIZE],
    pub(crate) ed25519_seed: [u8; Self::ED25519_SEED_SIZE],
}

impl Mldsa44Ed25519PrivateKey {
    /// Size of a composite ML-DSA-44 + Ed25519 private key in bytes.
    pub const MLDSA44_SEED_SIZE: usize = 32;
    pub const ED25519_SEED_SIZE: usize = 32;
    pub const BYTE_SIZE: usize = Self::MLDSA44_SEED_SIZE + Self::ED25519_SEED_SIZE;

    /// Generate a random composite ML-DSA-44 + Ed25519 private key.
    #[cfg(feature = "rand_core")]
    pub fn random<R: CryptoRng + ?Sized>(rng: &mut R) -> Self {
        let mut mldsa44_seed = [0u8; Self::MLDSA44_SEED_SIZE];
        let mut ed25519_seed = [0u8; Self::ED25519_SEED_SIZE];
        rng.fill_bytes(&mut mldsa44_seed);
        rng.fill_bytes(&mut ed25519_seed);
        Self{mldsa44_seed, ed25519_seed}
    }

    /// Parse ML-DSA-44 + Ed25519 private key from bytes.
    #[must_use]
    pub fn from_bytes(bytes: &[u8; Self::BYTE_SIZE]) -> Self {
        let (mldsa44_bytes, ed25519_bytes) = bytes.split_at(Mldsa44Ed25519PrivateKey::MLDSA44_SEED_SIZE);
        let mldsa44_seed: [u8; Mldsa44Ed25519PrivateKey::MLDSA44_SEED_SIZE] = mldsa44_bytes.try_into().expect("Data copy error");
        let ed25519_seed: [u8; Mldsa44Ed25519PrivateKey::ED25519_SEED_SIZE] = ed25519_bytes.try_into().expect("Data copy error");
        Self{mldsa44_seed, ed25519_seed}
    }

    /// Convert to the inner byte array.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; Self::BYTE_SIZE] {
        let mut bytes = [0u8; Self::BYTE_SIZE];
        bytes[..Self::MLDSA44_SEED_SIZE].copy_from_slice(&self.mldsa44_seed);
        bytes[Self::MLDSA44_SEED_SIZE..].copy_from_slice(&self.ed25519_seed);
        bytes
    }
}

impl CtEq for Mldsa44Ed25519PrivateKey {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.mldsa44_seed.ct_eq(&other.mldsa44_seed)
            & self.ed25519_seed.ct_eq(&other.ed25519_seed)
    }
}

impl Eq for Mldsa44Ed25519PrivateKey {}

impl PartialEq for Mldsa44Ed25519PrivateKey {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl TryFrom<&[u8]> for Mldsa44Ed25519PrivateKey {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self> {
        Ok(Mldsa44Ed25519PrivateKey::from_bytes(bytes.try_into()?))
    }
}

impl fmt::Debug for Mldsa44Ed25519PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Mldsa44Ed25519PrivateKey").finish_non_exhaustive()
    }
}

impl fmt::LowerHex for Mldsa44Ed25519PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.as_ref() {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl fmt::UpperHex for Mldsa44Ed25519PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.as_ref() {
            write!(f, "{byte:02X}")?;
        }
        Ok(())
    }
}

impl Drop for Mldsa44Ed25519PrivateKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[cfg(feature = "ed25519")]
impl From<Mldsa44Ed25519PrivateKey> for ed25519_dalek::SigningKey {
    fn from(key: Mldsa44Ed25519PrivateKey) -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from(&key)
    }
}

#[cfg(feature = "ed25519")]
impl From<&Mldsa44Ed25519PrivateKey> for ed25519_dalek::SigningKey {
    fn from(key: &Mldsa44Ed25519PrivateKey) -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(key.as_ref())
    }
}

#[cfg(feature = "ed25519")]
impl From<ed25519_dalek::SigningKey> for Mldsa44Ed25519PrivateKey {
    fn from(key: ed25519_dalek::SigningKey) -> Mldsa44Ed25519PrivateKey {
        Mldsa44Ed25519PrivateKey::from(&key)
    }
}

#[cfg(feature = "ed25519")]
impl From<&ed25519_dalek::SigningKey> for Mldsa44Ed25519PrivateKey {
    fn from(key: &ed25519_dalek::SigningKey) -> Mldsa44Ed25519PrivateKey {
        Mldsa44Ed25519PrivateKey(key.to_bytes())
    }
}

#[cfg(feature = "ed25519")]
impl From<Mldsa44Ed25519PrivateKey> for Mldsa44Ed25519PublicKey {
    fn from(private: Mldsa44Ed25519PrivateKey) -> Mldsa44Ed25519PublicKey {
        Mldsa44Ed25519PublicKey::from(&private)
    }
}

#[cfg(feature = "ed25519")]
impl From<&Mldsa44Ed25519PrivateKey> for Mldsa44Ed25519PublicKey {
    fn from(private: &Mldsa44Ed25519PrivateKey) -> Mldsa44Ed25519PublicKey {
        ed25519_dalek::SigningKey::from(private)
            .verifying_key()
            .into()
    }
}

/// Ed25519 private/public keypair.
#[derive(Clone)]
pub struct Mldsa44Ed25519Keypair {
    /// Public key.
    pub public: Mldsa44Ed25519PublicKey,

    /// Private key.
    pub private: Mldsa44Ed25519PrivateKey,
}

impl Mldsa44Ed25519Keypair {
    /// Size of an Ed25519 keypair in bytes.
    pub const BYTE_SIZE: usize = 64;

    /// Generate a random Ed25519 private keypair.
    #[cfg(feature = "ed25519")]
    pub fn random<R: CryptoRng + ?Sized>(rng: &mut R) -> Self {
        let mut bytes = [0u8; Mldsa44Ed25519PrivateKey::BYTE_SIZE];
        rng.fill_bytes(&mut bytes);
        Mldsa44Ed25519PrivateKey::from_bytes(&bytes).into()
    }

    /// Expand a keypair from a 32-byte seed value.
    #[cfg(feature = "ed25519")]
    #[must_use]
    pub fn from_seed(seed: &[u8; Mldsa44Ed25519PrivateKey::BYTE_SIZE]) -> Self {
        Mldsa44Ed25519PrivateKey::from_bytes(seed).into()
    }

    /// Parse ML-DSA-44 and Ed25519 seeds from 64-bytes private key
    ///
    /// # Errors
    /// Returns [`Error::Crypto`] if the public key does not match the private key.
    pub fn from_bytes(bytes: &[u8; Self::BYTE_SIZE]) -> Result<Self> {
        let (mldsa44_bytes, ed25519_bytes) = bytes.split_at(Mldsa44Ed25519PrivateKey::MLDSA44_SEED_SIZE);
        let mldsa44_seed: [u8; Mldsa44Ed25519PrivateKey::MLDSA44_SEED_SIZE] = mldsa44_bytes.try_into()?;
        let ed25519_seed: [u8; Mldsa44Ed25519PrivateKey::ED25519_SEED_SIZE] = ed25519_bytes.try_into()?;

        let private = Mldsa44Ed25519PrivateKey{mldsa44_seed, ed25519_seed};
        let public = Mldsa44Ed25519PublicKey::from(&private);

        Ok(Mldsa44Ed25519Keypair { private, public })
    }

    /// Serialize an Ed25519 keypair as bytes.
    #[must_use]
    #[allow(clippy::integer_division_remainder_used, reason = "constant")]
    pub fn to_bytes(&self) -> [u8; Self::BYTE_SIZE] {
        let mut result = [0u8; Self::BYTE_SIZE];
        result[..(Self::BYTE_SIZE / 2)].copy_from_slice(self.private.as_ref());
        result[(Self::BYTE_SIZE / 2)..].copy_from_slice(self.public.as_ref());
        result
    }
}

impl CtEq for Mldsa44Ed25519Keypair {
    fn ct_eq(&self, other: &Self) -> Choice {
        Choice::from(u8::from(self.public == other.public)) & self.private.ct_eq(&other.private)
    }
}

impl Eq for Mldsa44Ed25519Keypair {}

impl PartialEq for Mldsa44Ed25519Keypair {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl Decode for Mldsa44Ed25519Keypair {
    type Error = Error;

    fn decode(reader: &mut impl Reader) -> Result<Self> {
        // Decode private key
        let public = Mldsa44Ed25519PublicKey::decode(reader)?;

        // The OpenSSH serialization of Ed25519 keys is repetitive and includes
        // a serialization of `private_key[32] || public_key[32]` immediately
        // following the public key.
        let mut bytes = Zeroizing::new([0u8; Self::BYTE_SIZE]);
        reader.read_prefixed(|reader| reader.read(&mut *bytes))?;

        let keypair = Self::from_bytes(&bytes)?;

        // Ensure public key matches the one one the keypair
        if keypair.public == public {
            Ok(keypair)
        } else {
            Err(Error::Crypto)
        }
    }
}

impl Encode for Mldsa44Ed25519Keypair {
    fn encoded_len(&self) -> encoding::Result<usize> {
        [4, self.public.encoded_len()?, Self::BYTE_SIZE].checked_sum()
    }

    fn encode(&self, writer: &mut impl Writer) -> encoding::Result<()> {
        self.public.encode(writer)?;
        Zeroizing::new(self.to_bytes()).as_slice().encode(writer)?;
        Ok(())
    }
}

impl From<Mldsa44Ed25519Keypair> for Mldsa44Ed25519PublicKey {
    fn from(keypair: Mldsa44Ed25519Keypair) -> Mldsa44Ed25519PublicKey {
        keypair.public
    }
}

impl From<&Mldsa44Ed25519Keypair> for Mldsa44Ed25519PublicKey {
    fn from(keypair: &Mldsa44Ed25519Keypair) -> Mldsa44Ed25519PublicKey {
        keypair.public
    }
}

impl TryFrom<&[u8]> for Mldsa44Ed25519Keypair {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self> {
        Mldsa44Ed25519Keypair::from_bytes(bytes.try_into()?)
    }
}

impl fmt::Debug for Mldsa44Ed25519Keypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Mldsa44Ed25519Keypair")
            .field("public", &self.public)
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "ed25519")]
impl From<Mldsa44Ed25519PrivateKey> for Mldsa44Ed25519Keypair {
    fn from(private: Mldsa44Ed25519PrivateKey) -> Mldsa44Ed25519Keypair {
        let public = Mldsa44Ed25519PublicKey::from(&private);
        Mldsa44Ed25519Keypair { private, public }
    }
}

