//! `draft-miller-sshm-composite-sigs` instantiated for ML-DSA-44 ([FIPS204]) and Ed25519 ([RFC8032]).

use super::{
    Classic, PostQuantum, classic::Ed25519Classic, composite_key, postquantum::MlDsa44PostQuantum,
};
use crate::{Algorithm, Error, Result, private::Ed25519PrivateKey, public::Ed25519PublicKey};
use alloc::vec::Vec;
use core::fmt;
use ctutils::CtEq;
use encoding::{CheckedSum, Decode, Encode, Reader, Writer};

composite_key! {
    label = b"COMPSIG-MLDSA44-Ed25519-SHA512",
    algorithm = Algorithm::MlDsa44Ed25519,
    postquantum = MlDsa44PostQuantum,
    postquantum_name = mldsa,
    classic = Ed25519Classic,
    classic_name = ed25519,
    classic_public = Ed25519PublicKey,
    classic_private = Ed25519PrivateKey,

    /// MLDSA44-Ed25519-SHA512 composite public key.
    ///
    /// Encoded as `mldsa_pk (1312) || ed25519_pk (32)`.
    public_key = MlDsa44Ed25519PublicKey,

    /// MLDSA44-Ed25519-SHA512 composite private key.
    ///
    /// This is the seed representation: `mldsa_seed (32) || ed25519_seed (32)`. Both halves are
    /// re-expanded from these seeds on demand.
    private_key = MlDsa44Ed25519PrivateKey,

    /// MLDSA44-Ed25519-SHA512 composite private/public keypair.
    ///
    /// The SSH encoding is the [`MlDsa44Ed25519PublicKey`] followed by the 64-byte seed pair
    /// encoded as an SSH `string`.
    keypair = MlDsa44Ed25519Keypair,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Known-answer vectors from `draft-ietf-lamps-pq-composite-sigs`, as shipped in OpenSSH's
    /// `regress/unittests/crypto/testdata`.
    const KAT_M: &[u8] = include_bytes!("../../tests/examples/mldsa44_ed25519_kat_m.bin");
    const KAT_CTX: &[u8] = include_bytes!("../../tests/examples/mldsa44_ed25519_kat_ctx.bin");
    const KAT_PK: &[u8] = include_bytes!("../../tests/examples/mldsa44_ed25519_kat_pk.bin");
    const KAT_SK: &[u8] = include_bytes!("../../tests/examples/mldsa44_ed25519_kat_sk.bin");
    const KAT_S: &[u8] = include_bytes!("../../tests/examples/mldsa44_ed25519_kat_s.bin");
    const KAT_S_WITH_CONTEXT: &[u8] =
        include_bytes!("../../tests/examples/mldsa44_ed25519_kat_s_with_context.bin");

    fn kat_public_key() -> MlDsa44Ed25519PublicKey {
        MlDsa44Ed25519PublicKey::new(KAT_PK).expect("KAT public key should parse")
    }

    fn kat_keypair() -> MlDsa44Ed25519Keypair {
        MlDsa44Ed25519Keypair::from_seed(KAT_SK.try_into().expect("KAT private key is 64 bytes"))
            .expect("KAT private key should expand")
    }

    /// The composite sizes must be the sum of the two halves' sizes, in both directions.
    #[test]
    fn kat_sizes() {
        assert_eq!(MlDsa44Ed25519PublicKey::BYTE_SIZE, KAT_PK.len());
        assert_eq!(MlDsa44Ed25519PrivateKey::BYTE_SIZE, KAT_SK.len());
        assert_eq!(MlDsa44Ed25519PublicKey::SIGNATURE_SIZE, KAT_S.len());
        assert_eq!(KAT_S_WITH_CONTEXT.len(), KAT_S.len());

        assert_eq!(
            MlDsa44Ed25519PublicKey::BYTE_SIZE,
            <MlDsa44PostQuantum as PostQuantum>::PUBLIC_KEY_SIZE
                + <Ed25519Classic as Classic>::PUBLIC_KEY_SIZE
        );
        assert_eq!(
            MlDsa44Ed25519PrivateKey::BYTE_SIZE,
            <MlDsa44PostQuantum as PostQuantum>::PRIVATE_KEY_SIZE
                + <Ed25519Classic as Classic>::PRIVATE_KEY_SIZE
        );
    }

    /// Expanding the two seeds must reproduce the published public key exactly. This pins the
    /// concatenation order and the seed split.
    #[test]
    fn kat_key_expansion() {
        assert_eq!(kat_keypair().public, kat_public_key());
        assert_eq!(kat_public_key().to_bytes(), KAT_PK);
    }

    #[test]
    fn kat_verify_without_context() {
        kat_public_key()
            .verify_with_ctx(KAT_M, &[], KAT_S)
            .expect("KAT signature should verify");
    }

    #[test]
    fn kat_verify_with_context() {
        kat_public_key()
            .verify_with_ctx(KAT_M, KAT_CTX, KAT_S_WITH_CONTEXT)
            .expect("KAT signature should verify");
    }

    #[test]
    fn kat_context_is_bound() {
        let public = kat_public_key();
        assert!(public.verify_with_ctx(KAT_M, KAT_CTX, KAT_S).is_err());
        assert!(
            public
                .verify_with_ctx(KAT_M, &[], KAT_S_WITH_CONTEXT)
                .is_err()
        );
    }

    #[test]
    fn round_trip() {
        let keypair = kat_keypair();

        for ctx in [&[][..], KAT_CTX] {
            let signature = keypair
                .sign_with_ctx(KAT_M, ctx)
                .expect("signing should succeed");

            keypair
                .public
                .verify_with_ctx(KAT_M, ctx, &signature)
                .expect("own signature should verify");
        }
    }

    #[test]
    fn tampered_message_is_rejected() {
        let mut msg = KAT_M.to_vec();
        msg[0] ^= 1;
        assert!(kat_public_key().verify_with_ctx(&msg, &[], KAT_S).is_err());
    }

    #[test]
    fn wrong_signature_length_is_rejected() {
        let public = kat_public_key();
        assert!(
            public
                .verify_with_ctx(KAT_M, &[], &KAT_S[..KAT_S.len() - 1])
                .is_err()
        );
        assert!(public.verify_with_ctx(KAT_M, &[], &[]).is_err());
    }

    #[test]
    fn wrong_public_key_length_is_rejected() {
        assert!(MlDsa44Ed25519PublicKey::new(&KAT_PK[..KAT_PK.len() - 1]).is_err());
        assert!(MlDsa44Ed25519PublicKey::new([]).is_err());
    }

    /// A `string` whose length prefix does not match the composite key size must be rejected, not
    /// truncated to the first [`MlDsa44Ed25519PublicKey::BYTE_SIZE`] bytes.
    #[test]
    fn wrong_encoded_length_is_rejected() {
        use encoding::Encode;

        let mut encoded = Vec::new();
        KAT_PK.encode(&mut encoded).unwrap();

        assert!(MlDsa44Ed25519PublicKey::decode(&mut &encoded[..]).is_ok());

        // Append a trailing byte and grow the length prefix to cover it.
        let mut over_long = encoded.clone();
        over_long.push(0);
        let len = u32::try_from(KAT_PK.len() + 1).unwrap();
        over_long[..4].copy_from_slice(&len.to_be_bytes());

        assert!(MlDsa44Ed25519PublicKey::decode(&mut &over_long[..]).is_err());
    }

    /// The seed pair must round-trip through the concatenated encoding.
    #[test]
    fn private_key_bytes_round_trip() {
        let keypair = kat_keypair();
        assert_eq!(keypair.private.to_bytes(), KAT_SK);
        assert_eq!(
            MlDsa44Ed25519PrivateKey::from_bytes(&keypair.private.to_bytes()).unwrap(),
            keypair.private
        );
    }
}
