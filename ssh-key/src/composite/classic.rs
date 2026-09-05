//! Classic (non-post-quantum) halves of composite algorithms.

use super::Classic;
use crate::{Error, Result, private::Ed25519PrivateKey, public::Ed25519PublicKey};
use alloc::vec::Vec;

/// Ed25519 classic half of a composite algorithm.
pub(crate) struct Ed25519Classic {}

impl Classic for Ed25519Classic {
    type Public = Ed25519PublicKey;
    type Private = Ed25519PrivateKey;

    const PUBLIC_KEY_SIZE: usize = Ed25519PublicKey::BYTE_SIZE;
    const PRIVATE_KEY_SIZE: usize = Ed25519PrivateKey::BYTE_SIZE;
    const SIGNATURE_SIZE: usize = ed25519_dalek::SIGNATURE_LENGTH;

    fn public_from_bytes(bytes: &[u8]) -> Result<Self::Public> {
        Ed25519PublicKey::try_from(bytes)
    }

    fn public_as_bytes(public: &Self::Public) -> &[u8] {
        public.0.as_slice()
    }

    fn private_from_bytes(bytes: &[u8]) -> Result<Self::Private> {
        Ed25519PrivateKey::try_from(bytes)
    }

    fn private_as_bytes(private: &Self::Private) -> &[u8] {
        private.as_ref().as_slice()
    }

    fn derive_public(private: &Self::Private) -> Result<Self::Public> {
        Ok(Ed25519PublicKey::from(private))
    }

    fn sign(private: &Self::Private, m_prime: &[u8]) -> Result<Vec<u8>> {
        use signature::Signer;

        let signature = ed25519_dalek::SigningKey::from(private)
            .try_sign(m_prime)
            .map_err(|_| Error::Crypto)?;

        Ok(signature.to_bytes().to_vec())
    }

    fn verify(public: &Self::Public, m_prime: &[u8], signature: &[u8]) -> Result<()> {
        use signature::Verifier;

        let signature =
            ed25519_dalek::Signature::from_slice(signature).map_err(|_| Error::Signature)?;

        ed25519_dalek::VerifyingKey::try_from(public)?
            .verify(m_prime, &signature)
            .map_err(|_| Error::Signature)
    }
}
