//! Signatures (e.g. CA signatures over SSH certificates)

use crate::{private, public, Algorithm, Error, Mpint, PrivateKey, PublicKey, Result};
use alloc::vec::Vec;
use core::fmt;
use encoding::{CheckedSum, Decode, Encode, Reader, Writer};
use signature::{SignatureEncoding, Signer, Verifier};

#[cfg(feature = "ed25519")]
use crate::{private::Ed25519Keypair, public::Ed25519PublicKey};

#[cfg(feature = "dsa")]
use {
    crate::{private::DsaKeypair, public::DsaPublicKey},
    bigint::BigUint,
    sha1::Sha1,
    signature::{DigestSigner, DigestVerifier},
};

#[cfg(any(feature = "p256", feature = "p384"))]
use crate::{
    private::{EcdsaKeypair, EcdsaPrivateKey},
    public::EcdsaPublicKey,
    EcdsaCurve,
};

#[cfg(feature = "rsa")]
use {
    crate::{private::RsaKeypair, public::RsaPublicKey, HashAlg},
    sha2::Sha512,
};

#[cfg(any(feature = "ed25519", feature = "rsa"))]
use sha2::Sha256;

#[cfg(any(feature = "dsa", feature = "ed25519"))]
use sha2::Digest;

const DSA_SIGNATURE_SIZE: usize = 40;
const ED25519_SIGNATURE_SIZE: usize = 64;
const SK_ED25519_SIGNATURE_TRAILER_SIZE: usize = 5; // flags(u8), counter(u32)
const SK_ED25519_SIGNATURE_SIZE: usize = ED25519_SIGNATURE_SIZE + SK_ED25519_SIGNATURE_TRAILER_SIZE;

/// Trait for signing keys which produce a [`Signature`].
///
/// This trait is automatically impl'd for any types which impl the
/// [`Signer`] trait for the SSH [`Signature`] type and also support a [`From`]
/// conversion for [`public::KeyData`].
pub trait SigningKey: Signer<Signature> {
    /// Get the [`public::KeyData`] for this signing key.
    fn public_key(&self) -> public::KeyData;
}

impl<T> SigningKey for T
where
    T: Signer<Signature>,
    public::KeyData: for<'a> From<&'a T>,
{
    fn public_key(&self) -> public::KeyData {
        self.into()
    }
}

/// Low-level digital signature (e.g. DSA, ECDSA, Ed25519).
///
/// These are low-level signatures used as part of the OpenSSH certificate
/// format to represent signatures by certificate authorities (CAs), as well
/// as the higher-level [`SshSig`][`crate::SshSig`] format, which provides
/// general-purpose signing functionality using SSH keys.
///
/// From OpenSSH's [PROTOCOL.certkeys] specification:
///
/// > Signatures are computed and encoded according to the rules defined for
/// > the CA's public key algorithm ([RFC4253 section 6.6] for ssh-rsa and
/// > ssh-dss, [RFC5656] for the ECDSA types, and [RFC8032] for Ed25519).
///
/// RSA signature support is implemented using the SHA2 family extensions as
/// described in [RFC8332].
///
/// [PROTOCOL.certkeys]: https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL.certkeys?annotate=HEAD
/// [RFC4253 section 6.6]: https://datatracker.ietf.org/doc/html/rfc4253#section-6.6
/// [RFC5656]: https://datatracker.ietf.org/doc/html/rfc5656
/// [RFC8032]: https://datatracker.ietf.org/doc/html/rfc8032
/// [RFC8332]: https://datatracker.ietf.org/doc/html/rfc8332
#[derive(Clone, Eq, PartialEq, PartialOrd, Ord)]
pub struct Signature {
    /// Signature algorithm.
    algorithm: Algorithm,

    /// Raw signature serialized as algorithm-specific byte encoding.
    data: Vec<u8>,
}

impl Signature {
    /// Create a new signature with the given algorithm and raw signature data.
    ///
    /// See specifications in toplevel [`Signature`] documentation for how to
    /// format the raw signature data for a given algorithm.
    ///
    /// # Returns
    /// - [`Error::Encoding`] if the signature is not the correct length.
    pub fn new(algorithm: Algorithm, data: impl Into<Vec<u8>>) -> Result<Self> {
        let data = data.into();

        // Validate signature is well-formed per OpensSH encoding
        match algorithm {
            Algorithm::Dsa if data.len() == DSA_SIGNATURE_SIZE => (),
            Algorithm::Ecdsa { curve } => {
                let reader = &mut data.as_slice();

                for _ in 0..2 {
                    let component = Mpint::decode(reader)?;

                    if component.as_positive_bytes().ok_or(Error::Crypto)?.len()
                        != curve.field_size()
                    {
                        return Err(encoding::Error::Length.into());
                    }
                }

                reader.finish(())?;
            }
            Algorithm::Ed25519 if data.len() == ED25519_SIGNATURE_SIZE => (),
            Algorithm::SkEd25519 if data.len() == SK_ED25519_SIGNATURE_SIZE => (),
            Algorithm::Rsa { hash: Some(_) } => (),
            _ => return Err(encoding::Error::Length.into()),
        }

        Ok(Self { algorithm, data })
    }

    /// Get the [`Algorithm`] associated with this signature.
    pub fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    /// Get the raw signature as bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Placeholder signature used by the certificate builder.
    ///
    /// This is guaranteed generate an error if anything attempts to encode it.
    pub(crate) fn placeholder() -> Self {
        Self {
            algorithm: Algorithm::default(),
            data: Vec::new(),
        }
    }

    /// Check if this signature is the placeholder signature.
    pub(crate) fn is_placeholder(&self) -> bool {
        self.algorithm == Algorithm::default() && self.data.is_empty()
    }
}

impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl Decode for Signature {
    type Error = Error;

    fn decode(reader: &mut impl Reader) -> Result<Self> {
        let algorithm = Algorithm::decode(reader)?;
        let mut data = Vec::decode(reader)?;

        if algorithm == Algorithm::SkEd25519 {
            let flags = u8::decode(reader)?;
            let counter = u32::decode(reader)?;

            data.push(flags);
            data.extend(counter.to_be_bytes());
        }

        Self::new(algorithm, data)
    }
}

impl Encode for Signature {
    fn encoded_len(&self) -> encoding::Result<usize> {
        [
            self.algorithm().encoded_len()?,
            self.as_bytes().encoded_len()?,
        ]
        .checked_sum()
    }

    fn encode(&self, writer: &mut impl Writer) -> encoding::Result<()> {
        if self.is_placeholder() {
            return Err(encoding::Error::Length);
        }

        self.algorithm().encode(writer)?;

        if self.algorithm == Algorithm::SkEd25519 {
            let signature_length = self
                .as_bytes()
                .len()
                .checked_sub(SK_ED25519_SIGNATURE_TRAILER_SIZE)
                .ok_or(encoding::Error::Length)?;
            self.as_bytes()[..signature_length].encode(writer)?;
            writer.write(&self.as_bytes()[signature_length..])?;
        } else {
            self.as_bytes().encode(writer)?;
        }

        Ok(())
    }
}

impl SignatureEncoding for Signature {
    type Repr = Vec<u8>;
}

/// Decode [`Signature`] from an [`Algorithm`]-prefixed OpenSSH-encoded bytestring.
impl TryFrom<&[u8]> for Signature {
    type Error = Error;

    fn try_from(mut bytes: &[u8]) -> Result<Self> {
        Self::decode(&mut bytes)
    }
}

impl TryFrom<Signature> for Vec<u8> {
    type Error = Error;

    fn try_from(signature: Signature) -> Result<Vec<u8>> {
        let mut ret = Vec::<u8>::new();
        signature.encode(&mut ret)?;
        Ok(ret)
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Signature {{ algorithm: {:?}, data: {:X} }}",
            self.algorithm, self
        )
    }
}

impl fmt::LowerHex for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.as_ref() {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl fmt::UpperHex for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.as_ref() {
            write!(f, "{byte:02X}")?;
        }
        Ok(())
    }
}

impl Signer<Signature> for PrivateKey {
    fn try_sign(&self, message: &[u8]) -> signature::Result<Signature> {
        self.key_data().try_sign(message)
    }
}

impl Signer<Signature> for private::KeypairData {
    #[allow(unused_variables)]
    fn try_sign(&self, message: &[u8]) -> signature::Result<Signature> {
        match self {
            #[cfg(feature = "dsa")]
            Self::Dsa(keypair) => keypair.try_sign(message),
            #[cfg(any(feature = "p256", feature = "p384"))]
            Self::Ecdsa(keypair) => keypair.try_sign(message),
            #[cfg(feature = "ed25519")]
            Self::Ed25519(keypair) => keypair.try_sign(message),
            #[cfg(feature = "rsa")]
            Self::Rsa(keypair) => keypair.try_sign(message),
            _ => Err(self.algorithm()?.unsupported_error().into()),
        }
    }
}

impl Verifier<Signature> for PublicKey {
    fn verify(&self, message: &[u8], signature: &Signature) -> signature::Result<()> {
        self.key_data().verify(message, signature)
    }
}

impl Verifier<Signature> for public::KeyData {
    #[allow(unused_variables)]
    fn verify(&self, message: &[u8], signature: &Signature) -> signature::Result<()> {
        match self {
            #[cfg(feature = "dsa")]
            Self::Dsa(pk) => pk.verify(message, signature),
            #[cfg(any(feature = "p256", feature = "p384"))]
            Self::Ecdsa(pk) => pk.verify(message, signature),
            #[cfg(feature = "ed25519")]
            Self::Ed25519(pk) => pk.verify(message, signature),
            #[cfg(feature = "ed25519")]
            Self::SkEd25519(pk) => pk.verify(message, signature),
            #[cfg(feature = "rsa")]
            Self::Rsa(pk) => pk.verify(message, signature),
            #[allow(unreachable_patterns)]
            _ => Err(self.algorithm().unsupported_error().into()),
        }
    }
}

#[cfg(feature = "dsa")]
impl Signer<Signature> for DsaKeypair {
    fn try_sign(&self, message: &[u8]) -> signature::Result<Signature> {
        let signature = dsa::SigningKey::try_from(self)?
            .try_sign_digest(Sha1::new_with_prefix(message))
            .map_err(|_| signature::Error::new())?;

        // Note that we need to roll our own signature encoding, as [RFC4253 section 6.6]
        // specifies two raw 80 bit integer but the dsa::SigningKey serialization
        // encodes to a der format.
        let mut buf: Vec<u8> = Vec::new();
        buf.append(&mut signature.r().to_bytes_be());
        buf.append(&mut signature.s().to_bytes_be());

        if buf.len() != DSA_SIGNATURE_SIZE {
            return Err(signature::Error::new());
        }

        Ok(Signature {
            algorithm: Algorithm::Dsa,
            data: buf,
        })
    }
}

#[cfg(feature = "dsa")]
impl Verifier<Signature> for DsaPublicKey {
    fn verify(&self, message: &[u8], signature: &Signature) -> signature::Result<()> {
        match signature.algorithm {
            Algorithm::Dsa => {
                let data = signature.data.as_slice();
                if data.len() != DSA_SIGNATURE_SIZE {
                    return Err(signature::Error::new());
                }
                let (r, s) = data.split_at(DSA_SIGNATURE_SIZE / 2);
                let signature = dsa::Signature::from_components(
                    BigUint::from_bytes_be(r),
                    BigUint::from_bytes_be(s),
                )?;
                dsa::VerifyingKey::try_from(self)?
                    .verify_digest(Sha1::new_with_prefix(message), &signature)
                    .map_err(|_| signature::Error::new())
            }
            _ => Err(signature.algorithm().unsupported_error().into()),
        }
    }
}

#[cfg(feature = "ed25519")]
impl TryFrom<Signature> for ed25519_dalek::Signature {
    type Error = Error;

    fn try_from(signature: Signature) -> Result<ed25519_dalek::Signature> {
        ed25519_dalek::Signature::try_from(&signature)
    }
}

#[cfg(feature = "ed25519")]
impl TryFrom<&Signature> for ed25519_dalek::Signature {
    type Error = Error;

    fn try_from(signature: &Signature) -> Result<ed25519_dalek::Signature> {
        match signature.algorithm {
            Algorithm::Ed25519 | Algorithm::SkEd25519 => {
                Ok(ed25519_dalek::Signature::try_from(signature.as_bytes())?)
            }
            _ => Err(Error::AlgorithmUnknown),
        }
    }
}

#[cfg(feature = "ed25519")]
impl Signer<Signature> for Ed25519Keypair {
    fn try_sign(&self, message: &[u8]) -> signature::Result<Signature> {
        let signature = ed25519_dalek::SigningKey::try_from(self)?.sign(message);

        Ok(Signature {
            algorithm: Algorithm::Ed25519,
            data: signature.to_vec(),
        })
    }
}

#[cfg(feature = "ed25519")]
impl Verifier<Signature> for Ed25519PublicKey {
    fn verify(&self, message: &[u8], signature: &Signature) -> signature::Result<()> {
        let signature = ed25519_dalek::Signature::try_from(signature)?;
        ed25519_dalek::VerifyingKey::try_from(self)?.verify(message, &signature)
    }
}

#[cfg(feature = "ed25519")]
impl Verifier<Signature> for public::SkEd25519 {
    fn verify(&self, message: &[u8], signature: &Signature) -> signature::Result<()> {
        let signature_len = signature
            .as_bytes()
            .len()
            .checked_sub(SK_ED25519_SIGNATURE_TRAILER_SIZE)
            .ok_or(Error::Encoding(encoding::Error::Length))?;
        let signature_bytes = &signature.as_bytes()[..signature_len];
        let flags_and_counter = &signature.as_bytes()[signature_len..];

        #[allow(clippy::integer_arithmetic)]
        let mut signed_data =
            Vec::with_capacity((2 * Sha256::output_size()) + SK_ED25519_SIGNATURE_TRAILER_SIZE);
        signed_data.extend(Sha256::digest(self.application()));
        signed_data.extend(flags_and_counter);
        signed_data.extend(Sha256::digest(message));

        let signature = ed25519_dalek::Signature::try_from(signature_bytes)?;
        ed25519_dalek::VerifyingKey::try_from(self.public_key())?.verify(&signed_data, &signature)
    }
}

#[cfg(feature = "p256")]
impl TryFrom<p256::ecdsa::Signature> for Signature {
    type Error = Error;

    fn try_from(signature: p256::ecdsa::Signature) -> Result<Signature> {
        Signature::try_from(&signature)
    }
}

#[cfg(feature = "p384")]
impl TryFrom<p384::ecdsa::Signature> for Signature {
    type Error = Error;

    fn try_from(signature: p384::ecdsa::Signature) -> Result<Signature> {
        Signature::try_from(&signature)
    }
}

#[cfg(feature = "p256")]
impl TryFrom<&p256::ecdsa::Signature> for Signature {
    type Error = Error;

    fn try_from(signature: &p256::ecdsa::Signature) -> Result<Signature> {
        let (r, s) = signature.split_bytes();

        #[allow(clippy::integer_arithmetic)]
        let mut data = Vec::with_capacity(32 * 2 + 4 * 2 + 2);

        Mpint::from_positive_bytes(&r)?.encode(&mut data)?;
        Mpint::from_positive_bytes(&s)?.encode(&mut data)?;

        Ok(Signature {
            algorithm: Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP256,
            },
            data,
        })
    }
}

#[cfg(feature = "p384")]
impl TryFrom<&p384::ecdsa::Signature> for Signature {
    type Error = Error;

    fn try_from(signature: &p384::ecdsa::Signature) -> Result<Signature> {
        let (r, s) = signature.split_bytes();

        #[allow(clippy::integer_arithmetic)]
        let mut data = Vec::with_capacity(48 * 2 + 4 * 2 + 2);

        Mpint::from_positive_bytes(&r)?.encode(&mut data)?;
        Mpint::from_positive_bytes(&s)?.encode(&mut data)?;

        Ok(Signature {
            algorithm: Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP384,
            },
            data,
        })
    }
}

#[cfg(feature = "p256")]
impl TryFrom<Signature> for p256::ecdsa::Signature {
    type Error = Error;

    fn try_from(signature: Signature) -> Result<p256::ecdsa::Signature> {
        p256::ecdsa::Signature::try_from(&signature)
    }
}

#[cfg(feature = "p384")]
impl TryFrom<Signature> for p384::ecdsa::Signature {
    type Error = Error;

    fn try_from(signature: Signature) -> Result<p384::ecdsa::Signature> {
        p384::ecdsa::Signature::try_from(&signature)
    }
}

#[cfg(feature = "p256")]
impl TryFrom<&Signature> for p256::ecdsa::Signature {
    type Error = Error;

    fn try_from(signature: &Signature) -> Result<p256::ecdsa::Signature> {
        const FIELD_SIZE: usize = 32;

        match signature.algorithm {
            Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP256,
            } => {
                let reader = &mut signature.as_bytes();
                let r = Mpint::decode(reader)?;
                let s = Mpint::decode(reader)?;

                match (r.as_positive_bytes(), s.as_positive_bytes()) {
                    (Some(r), Some(s)) if r.len() == FIELD_SIZE && s.len() == FIELD_SIZE => {
                        Ok(p256::ecdsa::Signature::from_scalars(
                            *p256::FieldBytes::from_slice(r),
                            *p256::FieldBytes::from_slice(s),
                        )?)
                    }
                    _ => Err(Error::Crypto),
                }
            }
            _ => Err(signature.algorithm.unsupported_error()),
        }
    }
}

#[cfg(feature = "p384")]
impl TryFrom<&Signature> for p384::ecdsa::Signature {
    type Error = Error;

    fn try_from(signature: &Signature) -> Result<p384::ecdsa::Signature> {
        const FIELD_SIZE: usize = 48;

        match signature.algorithm {
            Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP256,
            } => {
                let reader = &mut signature.as_bytes();
                let r = Mpint::decode(reader)?;
                let s = Mpint::decode(reader)?;

                match (r.as_positive_bytes(), s.as_positive_bytes()) {
                    (Some(r), Some(s)) if r.len() == FIELD_SIZE && s.len() == FIELD_SIZE => {
                        Ok(p384::ecdsa::Signature::from_scalars(
                            *p384::FieldBytes::from_slice(r),
                            *p384::FieldBytes::from_slice(s),
                        )?)
                    }
                    _ => Err(Error::Crypto),
                }
            }
            _ => Err(signature.algorithm.unsupported_error()),
        }
    }
}

#[cfg(any(feature = "p256", feature = "p384"))]
impl Signer<Signature> for EcdsaKeypair {
    fn try_sign(&self, message: &[u8]) -> signature::Result<Signature> {
        match self {
            #[cfg(feature = "p256")]
            Self::NistP256 { private, .. } => private.try_sign(message),
            #[cfg(feature = "p384")]
            Self::NistP384 { private, .. } => private.try_sign(message),
            _ => Err(self.algorithm().unsupported_error().into()),
        }
    }
}

#[cfg(feature = "p256")]
impl Signer<Signature> for EcdsaPrivateKey<32> {
    fn try_sign(&self, message: &[u8]) -> signature::Result<Signature> {
        let signing_key = p256::ecdsa::SigningKey::from_slice(self.as_ref())?;
        let signature: p256::ecdsa::Signature = signing_key.try_sign(message)?;
        Ok(signature.try_into()?)
    }
}

#[cfg(feature = "p384")]
impl Signer<Signature> for EcdsaPrivateKey<48> {
    fn try_sign(&self, message: &[u8]) -> signature::Result<Signature> {
        let signing_key = p384::ecdsa::SigningKey::from_slice(self.as_ref())?;
        let signature: p384::ecdsa::Signature = signing_key.try_sign(message)?;
        Ok(signature.try_into()?)
    }
}

#[cfg(any(feature = "p256", feature = "p384"))]
impl Verifier<Signature> for EcdsaPublicKey {
    fn verify(&self, message: &[u8], signature: &Signature) -> signature::Result<()> {
        match signature.algorithm {
            Algorithm::Ecdsa { curve } => match curve {
                #[cfg(feature = "p256")]
                EcdsaCurve::NistP256 => {
                    let verifying_key = p256::ecdsa::VerifyingKey::try_from(self)?;
                    let signature = p256::ecdsa::Signature::try_from(signature)?;
                    verifying_key.verify(message, &signature)
                }

                #[cfg(feature = "p384")]
                EcdsaCurve::NistP384 => {
                    let verifying_key = p384::ecdsa::VerifyingKey::try_from(self)?;
                    let signature = p384::ecdsa::Signature::try_from(signature)?;
                    verifying_key.verify(message, &signature)
                }

                _ => Err(signature.algorithm().unsupported_error().into()),
            },
            _ => Err(signature.algorithm().unsupported_error().into()),
        }
    }
}

#[cfg(feature = "rsa")]
impl Signer<Signature> for RsaKeypair {
    fn try_sign(&self, message: &[u8]) -> signature::Result<Signature> {
        let data = rsa::pkcs1v15::SigningKey::<Sha512>::try_from(self)?
            .try_sign(message)
            .map_err(|_| signature::Error::new())?;

        Ok(Signature {
            algorithm: Algorithm::Rsa {
                hash: Some(HashAlg::Sha512),
            },
            data: data.to_vec(),
        })
    }
}

#[cfg(feature = "rsa")]
impl Verifier<Signature> for RsaPublicKey {
    fn verify(&self, message: &[u8], signature: &Signature) -> signature::Result<()> {
        match signature.algorithm {
            Algorithm::Rsa { hash: Some(hash) } => {
                let signature = rsa::pkcs1v15::Signature::try_from(signature.data.as_ref())?;

                match hash {
                    HashAlg::Sha256 => rsa::pkcs1v15::VerifyingKey::<Sha256>::try_from(self)?
                        .verify(message, &signature)
                        .map_err(|_| signature::Error::new()),
                    HashAlg::Sha512 => rsa::pkcs1v15::VerifyingKey::<Sha512>::try_from(self)?
                        .verify(message, &signature)
                        .map_err(|_| signature::Error::new()),
                }
            }
            _ => Err(signature.algorithm().unsupported_error().into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Signature;
    use crate::{Algorithm, EcdsaCurve, HashAlg};
    use alloc::vec::Vec;
    use encoding::Encode;
    use hex_literal::hex;

    #[cfg(feature = "ed25519")]
    use {
        super::Ed25519Keypair,
        signature::{Signer, Verifier},
    };

    const DSA_SIGNATURE: &[u8] = &hex!("000000077373682d6473730000002866725bf3c56100e975e21fff28a60f73717534d285ea3e1beefc2891f7189d00bd4d94627e84c55c");
    const ECDSA_SHA2_P256_SIGNATURE: &[u8] = &hex!("0000001365636473612d736861322d6e6973747032353600000048000000201298ab320720a32139cda8a40c97a13dc54ce032ea3c6f09ea9e87501e48fa1d0000002046e4ac697a6424a9870b9ef04ca1182cd741965f989bd1f1f4a26fd83cf70348");
    const ED25519_SIGNATURE: &[u8] = &hex!("0000000b7373682d65643235353139000000403d6b9906b76875aef1e7b2f1e02078a94f439aebb9a4734da1a851a81e22ce0199bbf820387a8de9c834c9c3cc778d9972dcbe70f68d53cc6bc9e26b02b46d04");
    const SK_ED25519_SIGNATURE: &[u8] = &hex!("0000001a736b2d7373682d65643235353139406f70656e7373682e636f6d000000402f5670b6f93465d17423878a74084bf331767031ed240c627c8eb79ab8fa1b935a1fd993f52f5a13fec1797f8a434f943a6096246aea8dd5c8aa922cba3d95060100000009");
    const RSA_SHA512_SIGNATURE: &[u8] = &hex!("0000000c7273612d736861322d3531320000018085a4ad1a91a62c00c85de7bb511f38088ff2bce763d76f4786febbe55d47624f9e2cffce58a680183b9ad162c7f0191ea26cab001ac5f5055743eced58e9981789305c208fc98d2657954e38eb28c7e7f3fbe92393a14324ed77aebb772a41aa7a107b38cb9bd1d9ad79b275135d1d7e019bb1d56d74f2450be6db0771f48f6707d3fcf9789592ca2e55595acc16b6e8d0139b56c5d1360b3a1e060f4151a3d7841df2c2a8c94d6f8a1bf633165ee0bcadac5642763df0dd79d3235ae5506595145f199d8abe8f9980411bf70a16e30f273736324d047043317044c36374d6a5ed34cac251e01c6795e4578393f9090bf4ae3e74a0009275a197315fc9c62f1c9aec1ba3b2d37c3b207e5500df19e090e7097ebc038fb9c9e35aea9161479ba6b5190f48e89e1abe51e8ec0e120ef89776e129687ca52d1892c8e88e6ef062a7d96b8a87682ca6a42ff1df0cdf5815c3645aeed7267ca7093043db0565e0f109b796bf117b9d2bb6d6debc0c67a4c9fb3aae3e29b00c7bd70f6c11cf53c295ff");

    /// Example test vector for signing.
    #[cfg(feature = "ed25519")]
    const EXAMPLE_MSG: &[u8] = b"Hello, world!";

    #[test]
    fn decode_dsa() {
        let signature = Signature::try_from(DSA_SIGNATURE).unwrap();
        assert_eq!(Algorithm::Dsa, signature.algorithm());
    }

    #[test]
    fn decode_ecdsa_sha2_p256() {
        let signature = Signature::try_from(ECDSA_SHA2_P256_SIGNATURE).unwrap();
        assert_eq!(
            Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP256
            },
            signature.algorithm()
        );
    }

    #[test]
    fn decode_ed25519() {
        let signature = Signature::try_from(ED25519_SIGNATURE).unwrap();
        assert_eq!(Algorithm::Ed25519, signature.algorithm());
    }

    #[test]
    fn decode_sk_ed25519() {
        let signature = Signature::try_from(SK_ED25519_SIGNATURE).unwrap();
        assert_eq!(Algorithm::SkEd25519, signature.algorithm());
    }

    #[test]
    fn decode_rsa() {
        let signature = Signature::try_from(RSA_SHA512_SIGNATURE).unwrap();
        assert_eq!(
            Algorithm::Rsa {
                hash: Some(HashAlg::Sha512)
            },
            signature.algorithm()
        );
    }

    #[test]
    fn encode_dsa() {
        let signature = Signature::try_from(DSA_SIGNATURE).unwrap();

        let mut result = Vec::new();
        signature.encode(&mut result).unwrap();
        assert_eq!(DSA_SIGNATURE, &result);
    }

    #[test]
    fn encode_ecdsa_sha2_p256() {
        let signature = Signature::try_from(ECDSA_SHA2_P256_SIGNATURE).unwrap();

        let mut result = Vec::new();
        signature.encode(&mut result).unwrap();
        assert_eq!(ECDSA_SHA2_P256_SIGNATURE, &result);
    }

    #[test]
    fn encode_ed25519() {
        let signature = Signature::try_from(ED25519_SIGNATURE).unwrap();

        let mut result = Vec::new();
        signature.encode(&mut result).unwrap();
        assert_eq!(ED25519_SIGNATURE, &result);
    }

    #[test]
    fn encode_sk_ed25519() {
        let signature = Signature::try_from(SK_ED25519_SIGNATURE).unwrap();

        let mut result = Vec::new();
        signature.encode(&mut result).unwrap();
        assert_eq!(SK_ED25519_SIGNATURE, &result);
    }

    #[cfg(feature = "ed25519")]
    #[test]
    fn sign_and_verify_ed25519() {
        let keypair = Ed25519Keypair::from_seed(&[42; 32]);
        let signature = keypair.sign(EXAMPLE_MSG);
        assert!(keypair.public.verify(EXAMPLE_MSG, &signature).is_ok());
    }

    #[test]
    fn placeholder() {
        assert!(!Signature::try_from(ED25519_SIGNATURE)
            .unwrap()
            .is_placeholder());

        let placeholder = Signature::placeholder();
        assert!(placeholder.is_placeholder());

        let mut writer = Vec::new();
        assert_eq!(
            placeholder.encode(&mut writer),
            Err(encoding::Error::Length)
        );
    }
}
