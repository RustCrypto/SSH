//! Post-quantum halves of composite algorithms.
//!
//! This is the only part of the composite layer that knows which post-quantum scheme is in play.

use super::PostQuantum;
use crate::{
    Result,
    mldsa::{self, MlDsaParams, MlDsaPrivateKey, MlDsaPublicKey},
};
use alloc::vec::Vec;

/// ML-DSA-44
pub(crate) struct MlDsa44PostQuantum {}

impl MlDsa44PostQuantum {
    /// Parameter set this marker pins.
    const PARAMS: MlDsaParams = MlDsaParams::MlDsa44;
}

impl PostQuantum for MlDsa44PostQuantum {
    type Public = MlDsaPublicKey;
    type Private = MlDsaPrivateKey;

    const PUBLIC_KEY_SIZE: usize = Self::PARAMS.public_key_size();
    const PRIVATE_KEY_SIZE: usize = mldsa::SEED_SIZE;
    const SIGNATURE_SIZE: usize = Self::PARAMS.signature_size();

    fn public_from_bytes(bytes: &[u8]) -> Result<Self::Public> {
        MlDsaPublicKey::new(Self::PARAMS, bytes)
    }

    fn public_as_bytes(public: &Self::Public) -> &[u8] {
        public.as_bytes()
    }

    fn private_from_bytes(bytes: &[u8]) -> Result<Self::Private> {
        MlDsaPrivateKey::try_from(bytes)
    }

    fn private_as_bytes(private: &Self::Private) -> &[u8] {
        private.as_ref().as_slice()
    }

    fn derive_public(private: &Self::Private) -> Result<Self::Public> {
        private.public_key(Self::PARAMS)
    }

    fn sign(private: &Self::Private, m_prime: &[u8], ctx: &[u8]) -> Result<Vec<u8>> {
        private.sign_deterministic(Self::PARAMS, m_prime, ctx)
    }

    fn verify(public: &Self::Public, m_prime: &[u8], ctx: &[u8], signature: &[u8]) -> Result<()> {
        public.verify_with_ctx(m_prime, ctx, signature)
    }
}
