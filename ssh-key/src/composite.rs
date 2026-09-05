//! Composite signature algorithms.
//!
//! Composite algorithms pair a post-quantum signature scheme with a classic one as specified in
//! [draft-miller-sshm-composite-sigs]. A signature is only valid if *both* halves are
//! valid, so the composite is no weaker than its stronger half.
//!
//! Keys and signatures are plain concatenations of the two halves, post-quantum first:
//!
//! ```text
//! public key  = pq_pk      || classic_pk
//! private key = pq_seed    || classic_seed
//! signature   = pq_sig     || classic_sig
//! ```
//!
//! Both halves sign the same message representative `M'`, which binds a domain-separation prefix,
//! the algorithm label, and the caller's context string to a SHA-512 digest of the message.
//!
//! ```text
//! M' = PREFIX || LABEL || u8(ctx.len()) || ctx || SHA512(msg)
//! ```
//!
//! The post-quantum half additionally passes `LABEL` as its own context string; the classic half
//! signs `M'` directly. Because neither half signs the message itself, the `Signer`/`Verifier`
//! impls of the underlying key types cannot be reused — only the key types themselves and their
//! conversions to the backing crypto crates, via the [`Classic`] and [`PostQuantum`] traits.
//!
//! For example, `ssh-mldsa44-ed25519@openssh.com` instantiates this with ML-DSA-44 and Ed25519:
//!
//! ```text
//! public key  (1344) = mldsa_pk   (1312) || ed25519_pk   (32)
//! private key   (64) = mldsa_seed   (32) || ed25519_seed (32)
//! signature   (2484) = mldsa_sig  (2420) || ed25519_sig  (64)
//! ```
//!
//! [draft-miller-sshm-composite-sigs]: https://www.ietf.org/archive/id/draft-miller-sshm-composite-sigs-01.html

mod classic;
mod mldsa44_ed25519;
mod postquantum;

pub use mldsa44_ed25519::{
    MlDsa44Ed25519Keypair, MlDsa44Ed25519PrivateKey, MlDsa44Ed25519PublicKey,
};

use crate::{Error, Result};
use alloc::{vec, vec::Vec};
use core::{fmt::Debug, hash::Hash};
use ctutils::CtEq;
use sha2::{Digest, Sha512};

/// Domain-separation prefix shared by all composite signature algorithms.
const PREFIX: &[u8] = b"CompositeAlgorithmSignatures2025";

/// Size of a SHA-512 digest in bytes.
const DIGEST_SIZE: usize = 64;

/// Maximum length of a context string, since its length is encoded as a `u8`.
const MAX_CTX_SIZE: usize = 255;

/// The classic (non-post-quantum) half of a composite algorithm.
///
/// Implementors are marker types; the trait exists to bundle a pair of existing SSH key
/// types with the raw sign/verify operations over the composite message representative `M'`.
///
/// See [`classic`] for the implementations.
pub(crate) trait Classic {
    /// Public key type, e.g. `Ed25519PublicKey`.
    type Public: Clone + Debug + Eq + Ord + Hash;

    /// Private key type, e.g. `Ed25519PrivateKey`.
    type Private: Clone + CtEq;

    /// Size of an encoded public key in bytes.
    const PUBLIC_KEY_SIZE: usize;

    /// Size of an encoded private key in bytes.
    const PRIVATE_KEY_SIZE: usize;

    /// Size of an encoded signature in bytes.
    const SIGNATURE_SIZE: usize;

    /// Parse a public key from exactly [`Self::PUBLIC_KEY_SIZE`] bytes.
    fn public_from_bytes(bytes: &[u8]) -> Result<Self::Public>;

    /// Get the encoded form of a public key.
    fn public_as_bytes(public: &Self::Public) -> &[u8];

    /// Parse a private key from exactly [`Self::PRIVATE_KEY_SIZE`] bytes.
    fn private_from_bytes(bytes: &[u8]) -> Result<Self::Private>;

    /// Get the encoded form of a private key.
    fn private_as_bytes(private: &Self::Private) -> &[u8];

    /// Derive the public key matching a private key.
    fn derive_public(private: &Self::Private) -> Result<Self::Public>;

    /// Sign the composite message representative `M'`.
    fn sign(private: &Self::Private, m_prime: &[u8]) -> Result<Vec<u8>>;

    /// Verify a signature over the composite message representative `M'`.
    fn verify(public: &Self::Public, m_prime: &[u8], signature: &[u8]) -> Result<()>;
}

/// The post-quantum half of a composite algorithm.
///
/// This is [`Classic`] plus a context string on the signing operations: the composite construction
/// passes the algorithm label to the post-quantum scheme as its own context, on top of binding it
/// into `M'`.
///
/// See [`postquantum`] for the implementations.
pub(crate) trait PostQuantum {
    /// Public key type, e.g. `MlDsaPublicKey`.
    type Public: Clone + Debug + Eq + Ord + Hash;

    /// Private key (seed) type, e.g. `MlDsaPrivateKey`.
    type Private: Clone + CtEq;

    /// Size of an encoded public key in bytes.
    const PUBLIC_KEY_SIZE: usize;

    /// Size of an encoded private key in bytes.
    const PRIVATE_KEY_SIZE: usize;

    /// Size of an encoded signature in bytes.
    const SIGNATURE_SIZE: usize;

    /// Parse a public key from exactly [`Self::PUBLIC_KEY_SIZE`] bytes.
    fn public_from_bytes(bytes: &[u8]) -> Result<Self::Public>;

    /// Get the encoded form of a public key.
    fn public_as_bytes(public: &Self::Public) -> &[u8];

    /// Parse a private key from exactly [`Self::PRIVATE_KEY_SIZE`] bytes.
    fn private_from_bytes(bytes: &[u8]) -> Result<Self::Private>;

    /// Get the encoded form of a private key.
    fn private_as_bytes(private: &Self::Private) -> &[u8];

    /// Derive the public key matching a private key.
    fn derive_public(private: &Self::Private) -> Result<Self::Public>;

    /// Sign the composite message representative `M'` with the given context string.
    fn sign(private: &Self::Private, m_prime: &[u8], ctx: &[u8]) -> Result<Vec<u8>>;

    /// Verify a signature over the composite message representative `M'` with the given context
    /// string.
    fn verify(public: &Self::Public, m_prime: &[u8], ctx: &[u8], signature: &[u8]) -> Result<()>;
}

/// Build the message representative `M'` signed by both halves.
///
/// # Errors
/// Returns [`Error::Crypto`] if `ctx` is longer than [`MAX_CTX_SIZE`] bytes.
fn construct_m_prime(label: &[u8], msg: &[u8], ctx: &[u8]) -> Result<Vec<u8>> {
    if ctx.len() > MAX_CTX_SIZE {
        return Err(Error::Crypto);
    }

    // Conversion cannot fail: bounds-checked against MAX_CTX_SIZE above.
    let ctx_len = u8::try_from(ctx.len()).map_err(|_| Error::Crypto)?;

    let mut m_prime = Vec::with_capacity(PREFIX.len() + label.len() + 1 + ctx.len() + DIGEST_SIZE);
    m_prime.extend_from_slice(PREFIX);
    m_prime.extend_from_slice(label);
    m_prime.push(ctx_len);
    m_prime.extend_from_slice(ctx);
    m_prime.extend_from_slice(&Sha512::digest(msg));

    Ok(m_prime)
}

/// Produce a composite signature over `msg` with the given context string.
///
/// # Errors
/// Returns [`Error::Crypto`] if `ctx` is longer than [`MAX_CTX_SIZE`] bytes or if either half's
/// signature cannot be produced.
fn sign<P: PostQuantum, C: Classic>(
    label: &[u8],
    pq: &P::Private,
    classic: &C::Private,
    msg: &[u8],
    ctx: &[u8],
) -> Result<Vec<u8>> {
    let m_prime = construct_m_prime(label, msg, ctx)?;

    // Note the post-quantum context string is `label`, *not* `ctx`; `ctx` is already bound into
    // `M'` for both halves.
    let pq_sig = P::sign(pq, &m_prime, label)?;
    let classic_sig = C::sign(classic, &m_prime)?;

    let mut signature = vec![0u8; P::SIGNATURE_SIZE + C::SIGNATURE_SIZE];
    let (pq_out, classic_out) = signature.split_at_mut(P::SIGNATURE_SIZE);
    pq_out.copy_from_slice(&pq_sig);
    classic_out.copy_from_slice(&classic_sig);

    Ok(signature)
}

/// Verify a composite signature over `msg` with the given context string.
///
/// Both halves must verify; a failure in either is fatal.
///
/// # Errors
/// Returns [`Error::Signature`] if the signature is malformed or invalid, or [`Error::Crypto`] if
/// `ctx` is longer than [`MAX_CTX_SIZE`] bytes.
fn verify<P: PostQuantum, C: Classic>(
    label: &[u8],
    pq: &P::Public,
    classic: &C::Public,
    msg: &[u8],
    ctx: &[u8],
    signature: &[u8],
) -> Result<()> {
    if signature.len() != P::SIGNATURE_SIZE + C::SIGNATURE_SIZE {
        return Err(Error::Signature);
    }

    let m_prime = construct_m_prime(label, msg, ctx)?;
    let (pq_sig, classic_sig) = signature.split_at(P::SIGNATURE_SIZE);

    P::verify(pq, &m_prime, label, pq_sig)?;
    C::verify(classic, &m_prime, classic_sig)
}

/// Macro for generating a composite key type given a classic and post-quantum key based on
/// [draft-miller-sshm-composite-sigs].
macro_rules! composite_key {
    (
        label = $label:expr,
        algorithm = $algorithm:expr,
        postquantum = $pq:ty,
        postquantum_name = $pq_name:ident,
        classic = $classic:ty,
        classic_name = $classic_name:ident,
        classic_public = $classic_public:ty,
        classic_private = $classic_private:ty,
        $(#[$public_doc:meta])*
        public_key = $public_key:ident,
        $(#[$private_doc:meta])*
        private_key = $private_key:ident,
        $(#[$keypair_doc:meta])*
        keypair = $keypair:ident,
    ) => {
        /// Label identifying this composite algorithm. Also used as the context string of the
        /// post-quantum half.
        const LABEL: &[u8] = $label;

        $(#[$public_doc])*
        #[derive(Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
        pub struct $public_key {
            $pq_name: <$pq as PostQuantum>::Public,
            $classic_name: $classic_public,
        }

        impl $public_key {
            /// Size of an encoded composite public key in bytes.
            pub const BYTE_SIZE: usize =
                <$pq as PostQuantum>::PUBLIC_KEY_SIZE + <$classic as Classic>::PUBLIC_KEY_SIZE;

            /// Size of an encoded composite signature in bytes.
            pub const SIGNATURE_SIZE: usize =
                <$pq as PostQuantum>::SIGNATURE_SIZE + <$classic as Classic>::SIGNATURE_SIZE;

            /// Create a composite public key from the two concatenated public keys.
            ///
            /// # Errors
            /// Returns [`Error::Encoding`] with [`encoding::Error::Length`] if `key` is not
            /// exactly [`Self::BYTE_SIZE`] bytes, or if either half's key is malformed.
            pub fn new(key: impl AsRef<[u8]>) -> Result<Self> {
                let key = key.as_ref();

                if key.len() != Self::BYTE_SIZE {
                    return Err(encoding::Error::Length.into());
                }

                let (pq, classic) = key.split_at(<$pq as PostQuantum>::PUBLIC_KEY_SIZE);

                Ok(Self {
                    $pq_name: <$pq as PostQuantum>::public_from_bytes(pq)?,
                    $classic_name: <$classic as Classic>::public_from_bytes(classic)?,
                })
            }

            /// Get the [`Algorithm`] for this public key.
            ///
            /// [`Algorithm`]: crate::Algorithm
            #[must_use]
            pub fn algorithm(&self) -> $crate::Algorithm {
                $algorithm
            }

            /// Get the classic half of this composite public key.
            #[must_use]
            pub fn $classic_name(&self) -> &$classic_public {
                &self.$classic_name
            }

            /// Get the concatenated encoding of this composite public key.
            #[must_use]
            pub fn to_bytes(&self) -> Vec<u8> {
                let mut bytes = Vec::with_capacity(Self::BYTE_SIZE);
                bytes.extend_from_slice(<$pq as PostQuantum>::public_as_bytes(&self.$pq_name));
                bytes.extend_from_slice(<$classic as Classic>::public_as_bytes(
                    &self.$classic_name,
                ));
                bytes
            }

            /// Verify a composite signature over `msg` with the given context string.
            ///
            /// # Errors
            /// Returns [`Error::Signature`] if the signature is malformed or invalid.
            pub(crate) fn verify_with_ctx(
                &self,
                msg: &[u8],
                ctx: &[u8],
                signature: &[u8],
            ) -> Result<()> {
                $crate::composite::verify::<$pq, $classic>(
                    LABEL,
                    &self.$pq_name,
                    &self.$classic_name,
                    msg,
                    ctx,
                    signature,
                )
            }

            /// Verify a composite signature over `msg`, using an empty context string as SSH
            /// requires.
            ///
            /// # Errors
            /// Returns [`Error::Signature`] if the signature is malformed or invalid.
            pub(crate) fn verify_msg(&self, msg: &[u8], signature: &[u8]) -> Result<()> {
                self.verify_with_ctx(msg, &[], signature)
            }
        }

        impl TryFrom<&[u8]> for $public_key {
            type Error = Error;

            fn try_from(bytes: &[u8]) -> Result<Self> {
                Self::new(bytes)
            }
        }

        impl Decode for $public_key {
            type Error = Error;

            fn decode(reader: &mut impl Reader) -> Result<Self> {
                // Decode the whole `string` rather than reading `BYTE_SIZE` out of it, so that an
                // over-long length prefix is rejected instead of silently truncated.
                Self::new(Vec::decode(reader)?)
            }
        }

        impl Encode for $public_key {
            fn encoded_len(&self) -> encoding::Result<usize> {
                self.to_bytes().as_slice().encoded_len()
            }

            fn encode(&self, writer: &mut impl Writer) -> encoding::Result<()> {
                self.to_bytes().as_slice().encode(writer)
            }
        }

        impl fmt::Display for $public_key {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                for byte in self.to_bytes() {
                    write!(f, "{byte:02x}")?;
                }
                Ok(())
            }
        }

        $(#[$private_doc])*
        #[derive(Clone)]
        pub struct $private_key {
            $pq_name: <$pq as PostQuantum>::Private,
            $classic_name: $classic_private,
        }

        impl $private_key {
            /// Size of an encoded composite private key in bytes.
            pub const BYTE_SIZE: usize =
                <$pq as PostQuantum>::PRIVATE_KEY_SIZE + <$classic as Classic>::PRIVATE_KEY_SIZE;

            /// Generate a random composite private key.
            ///
            /// # Errors
            /// Returns [`Error::Encoding`] with [`encoding::Error::Length`] if either half's seed is
            /// the wrong length, which cannot happen for a correctly sized input.
            #[cfg(feature = "rand_core")]
            pub fn random<R: rand_core::CryptoRng + ?Sized>(rng: &mut R) -> Result<Self> {
                let mut seed = zeroize::Zeroizing::new([0u8; Self::BYTE_SIZE]);
                rng.fill_bytes(seed.as_mut_slice());
                Self::from_bytes(&seed)
            }

            /// Parse a composite private key from the two concatenated seeds.
            ///
            /// # Errors
            /// Returns [`Error::Encoding`] with [`encoding::Error::Length`] if either half's seed is
            /// the wrong length, which cannot happen for a correctly sized input.
            pub fn from_bytes(bytes: &[u8; Self::BYTE_SIZE]) -> Result<Self> {
                let (pq, classic) = bytes.split_at(<$pq as PostQuantum>::PRIVATE_KEY_SIZE);

                Ok(Self {
                    $pq_name: <$pq as PostQuantum>::private_from_bytes(pq)?,
                    $classic_name: <$classic as Classic>::private_from_bytes(classic)?,
                })
            }

            /// Get the concatenated encoding of this composite private key.
            #[must_use]
            pub fn to_bytes(&self) -> [u8; Self::BYTE_SIZE] {
                let mut bytes = [0u8; Self::BYTE_SIZE];
                let (pq, classic) = bytes.split_at_mut(<$pq as PostQuantum>::PRIVATE_KEY_SIZE);
                pq.copy_from_slice(<$pq as PostQuantum>::private_as_bytes(&self.$pq_name));
                classic.copy_from_slice(<$classic as Classic>::private_as_bytes(
                    &self.$classic_name,
                ));
                bytes
            }

            /// Get the classic half of this composite private key.
            #[must_use]
            pub fn $classic_name(&self) -> &$classic_private {
                &self.$classic_name
            }

            /// Re-derive the composite public key from the two seeds.
            ///
            /// # Errors
            /// Returns [`Error::Encoding`] if key derivation produces a malformed key, which
            /// should not occur.
            pub fn public_key(&self) -> Result<$public_key> {
                Ok($public_key {
                    $pq_name: <$pq as PostQuantum>::derive_public(&self.$pq_name)?,
                    $classic_name: <$classic as Classic>::derive_public(
                        &self.$classic_name,
                    )?,
                })
            }

            /// Get private key bytes for calculating the deterministic checkint hash
            pub(crate) fn checkint_bytes(&self) -> &[u8] {
                <$pq as PostQuantum>::private_as_bytes(&self.$pq_name)
            }
        }

        impl TryFrom<&[u8]> for $private_key {
            type Error = Error;

            fn try_from(bytes: &[u8]) -> Result<Self> {
                Self::from_bytes(bytes.try_into()?)
            }
        }

        impl CtEq for $private_key {
            fn ct_eq(&self, other: &Self) -> ctutils::Choice {
                self.$pq_name.ct_eq(&other.$pq_name)
                    & self.$classic_name.ct_eq(&other.$classic_name)
            }
        }

        impl Eq for $private_key {}

        impl PartialEq for $private_key {
            fn eq(&self, other: &Self) -> bool {
                self.ct_eq(other).into()
            }
        }

        impl fmt::Debug for $private_key {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_struct(stringify!($private_key)).finish_non_exhaustive()
            }
        }

        $(#[$keypair_doc])*
        #[derive(Clone)]
        pub struct $keypair {
            /// Public key.
            pub public: $public_key,

            /// Private key.
            pub private: $private_key,
        }

        impl $keypair {
            /// Generate a random composite keypair.
            ///
            /// # Errors
            /// Returns [`Error::Encoding`] if key derivation produces a malformed key, which
            /// should not occur.
            #[cfg(feature = "rand_core")]
            pub fn random<R: rand_core::CryptoRng + ?Sized>(rng: &mut R) -> Result<Self> {
                Self::new($private_key::random(rng)?)
            }

            /// Derive a composite keypair from the two concatenated seeds.
            ///
            /// # Errors
            /// Returns [`Error::Encoding`] if key derivation produces a malformed key, which
            /// should not occur.
            pub fn from_seed(seed: &[u8; $private_key::BYTE_SIZE]) -> Result<Self> {
                Self::new($private_key::from_bytes(seed)?)
            }

            /// Get the [`Algorithm`] for this keypair.
            ///
            /// [`Algorithm`]: crate::Algorithm
            #[must_use]
            pub fn algorithm(&self) -> $crate::Algorithm {
                $algorithm
            }

            /// Pair a private key with the public key derived from it.
            fn new(private: $private_key) -> Result<Self> {
                Ok(Self {
                    public: private.public_key()?,
                    private,
                })
            }

            /// Sign `msg` with the given context string.
            ///
            /// # Errors
            /// Returns [`Error::Crypto`] if either half's signature cannot be produced.
            pub(crate) fn sign_with_ctx(&self, msg: &[u8], ctx: &[u8]) -> Result<Vec<u8>> {
                $crate::composite::sign::<$pq, $classic>(
                    LABEL,
                    &self.private.$pq_name,
                    &self.private.$classic_name,
                    msg,
                    ctx,
                )
            }

            /// Sign `msg`, using an empty context string as SSH requires.
            ///
            /// # Errors
            /// Returns [`Error::Crypto`] if either half's signature cannot be produced.
            pub(crate) fn sign_msg(&self, msg: &[u8]) -> Result<Vec<u8>> {
                self.sign_with_ctx(msg, &[])
            }

            /// Check that the stored public key matches the one derived from the seeds.
            ///
            /// A mismatch means the private key cannot produce signatures verifiable under the
            /// advertised public key, so the keypair is rejected outright.
            fn validate(&self) -> Result<()> {
                // Both sides are public key material, so a non-constant-time comparison is fine.
                if self.private.public_key()? == self.public {
                    Ok(())
                } else {
                    Err(Error::PublicKey)
                }
            }
        }

        impl CtEq for $keypair {
            fn ct_eq(&self, other: &Self) -> ctutils::Choice {
                ctutils::Choice::from(u8::from(self.public == other.public))
                    & self.private.ct_eq(&other.private)
            }
        }

        impl Eq for $keypair {}

        impl PartialEq for $keypair {
            fn eq(&self, other: &Self) -> bool {
                self.ct_eq(other).into()
            }
        }

        impl Decode for $keypair {
            type Error = Error;

            fn decode(reader: &mut impl Reader) -> Result<Self> {
                let public = $public_key::decode(reader)?;

                let seed = zeroize::Zeroizing::new(Vec::decode(reader)?);

                let keypair = Self {
                    public,
                    private: $private_key::try_from(seed.as_slice())?,
                };

                keypair.validate()?;
                Ok(keypair)
            }
        }

        impl Encode for $keypair {
            fn encoded_len(&self) -> encoding::Result<usize> {
                [
                    self.public.encoded_len()?,
                    4,
                    $private_key::BYTE_SIZE,
                ]
                .checked_sum()
            }

            fn encode(&self, writer: &mut impl Writer) -> encoding::Result<()> {
                self.public.encode(writer)?;
                zeroize::Zeroizing::new(self.private.to_bytes())
                    .as_slice()
                    .encode(writer)?;
                Ok(())
            }
        }

        impl fmt::Debug for $keypair {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_struct(stringify!($keypair))
                    .field("public", &self.public)
                    .finish_non_exhaustive()
            }
        }

        impl From<$keypair> for $public_key {
            fn from(keypair: $keypair) -> $public_key {
                keypair.public
            }
        }

        impl From<&$keypair> for $public_key {
            fn from(keypair: &$keypair) -> $public_key {
                keypair.public.clone()
            }
        }

        impl signature::Signer<$crate::Signature> for $keypair {
            fn try_sign(&self, message: &[u8]) -> signature::Result<$crate::Signature> {
                Ok($crate::Signature::new(self.algorithm(), self.sign_msg(message)?)?)
            }
        }

        impl signature::Verifier<$crate::Signature> for $public_key {
            fn verify(
                &self,
                message: &[u8],
                signature: &$crate::Signature,
            ) -> signature::Result<()> {
                // The signature's algorithm must match this key.
                if signature.algorithm() != self.algorithm() {
                    return Err(Error::Signature.into());
                }

                Ok(self.verify_msg(message, signature.as_bytes())?)
            }
        }
    };
}

pub(crate) use composite_key;
