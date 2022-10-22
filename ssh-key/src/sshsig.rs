//! `sshsig` implementation.

use crate::{
    checked::CheckedSum,
    decode::Decode,
    encode::Encode,
    pem::{self, PemLabel},
    public,
    reader::Reader,
    writer::Writer,
    Algorithm, Error, HashAlg, Result, Signature, SigningKey, PEM_LINE_WIDTH,
};
use alloc::{borrow::ToOwned, string::String, string::ToString, vec::Vec};
use base64ct::LineEnding;
use core::str::FromStr;
use signature::{Signer, Verifier};

type Version = u32;

/// `sshsig` provides a general-purpose signature format based on SSH keys and
/// wire formats.
///
/// These signatures can be produced using `ssh-keygen -Y sign`. They're
/// encoded as PEM and begin with the following:
///
/// ```text
/// -----BEGIN SSH SIGNATURE-----
/// ```
///
/// See [PROTOCOL.sshsig] for more information.
///
/// [PROTOCOL.sshsig]: https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL.sshsig?annotate=HEAD
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SshSig {
    version: Version,
    public_key: public::KeyData,
    namespace: String,
    reserved: Vec<u8>,
    hash_alg: HashAlg,
    signature: Signature,
}

impl SshSig {
    /// Supported version.
    pub const VERSION: Version = 1;

    /// The preamble is the six-byte sequence "SSHSIG".
    ///
    /// It is included to ensure that manual signatures can never be confused
    /// with any message signed during SSH user or host authentication.
    const MAGIC_PREAMBLE: &'static [u8] = b"SSHSIG";

    /// Decode signature from PEM which begins with the following:
    ///
    /// ```text
    /// -----BEGIN SSH SIGNATURE-----
    /// ```
    pub fn from_pem(pem: impl AsRef<[u8]>) -> Result<Self> {
        let mut reader = pem::Decoder::new_wrapped(pem.as_ref(), PEM_LINE_WIDTH)?;
        Self::validate_pem_label(reader.type_label())?;
        let signature = Self::decode(&mut reader)?;
        reader.finish(signature)
    }

    /// Encode signature as PEM which begins with the following:
    ///
    /// ```text
    /// -----BEGIN SSH SIGNATURE-----
    /// ```
    pub fn to_pem(&self, line_ending: LineEnding) -> Result<String> {
        let encoded_len = pem::encapsulated_len_wrapped(
            Self::PEM_LABEL,
            PEM_LINE_WIDTH,
            line_ending,
            self.encoded_len()?,
        )?;

        let mut buf = vec![0u8; encoded_len];
        let mut writer =
            pem::Encoder::new_wrapped(Self::PEM_LABEL, PEM_LINE_WIDTH, line_ending, &mut buf)?;

        self.encode(&mut writer)?;
        let actual_len = writer.finish()?;
        buf.truncate(actual_len);
        Ok(String::from_utf8(buf)?)
    }

    /// Sign the given message with the provided signing key.
    pub fn sign<S: SigningKey>(
        signing_key: &S,
        namespace: &str,
        hash_alg: HashAlg,
        msg: &[u8],
    ) -> Result<Self> {
        if namespace.is_empty() {
            return Err(Error::Namespace);
        }

        let public_key = signing_key.public_key();
        let namespace = namespace.to_owned();
        let reserved = Vec::new();
        let hash = hash_alg.digest(msg);

        let signature = SignedData {
            namespace: namespace.as_str(),
            reserved: reserved.as_slice(),
            hash_alg,
            hash: hash.as_slice(),
        }
        .sign(signing_key)?;

        Ok(Self {
            version: Self::VERSION,
            public_key,
            namespace,
            reserved,
            hash_alg,
            signature,
        })
    }

    /// Verify the given message against this signature.
    ///
    /// Note that this method does not verify the public key or namespace
    /// are correct and thus is crate-private so as to ensure these parameters
    /// are always authenticated by users of the public API.
    pub(crate) fn verify(&self, msg: &[u8]) -> Result<()> {
        let signed_data = SignedData {
            namespace: self.namespace.as_str(),
            reserved: self.reserved.as_slice(),
            hash_alg: self.hash_alg,
            hash: self.hash_alg.digest(msg).as_slice(),
        }
        .to_bytes()?;

        Ok(self.public_key.verify(&signed_data, &self.signature)?)
    }

    /// Get the signature algorithm.
    pub fn algorithm(&self) -> Algorithm {
        self.signature.algorithm()
    }

    /// Get version number for this signature.
    ///
    /// Verifiers MUST reject signatures with versions greater than those
    /// they support.
    pub fn version(&self) -> Version {
        self.version
    }

    /// Get public key which corresponds to the signing key that produced
    /// this signature.
    pub fn public_key(&self) -> &public::KeyData {
        &self.public_key
    }

    /// Get the namespace (i.e. domain identifier) for this signature.
    ///
    /// The purpose of the namespace value is to specify a unambiguous
    /// interpretation domain for the signature, e.g. file signing.
    /// This prevents cross-protocol attacks caused by signatures
    /// intended for one intended domain being accepted in another.
    /// The namespace value MUST NOT be the empty string.
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    /// Get reserved data associated with this signature. Typically empty.
    ///
    /// The reserved value is present to encode future information
    /// (e.g. tags) into the signature. Implementations should ignore
    /// the reserved field if it is not empty.
    pub fn reserved(&self) -> &[u8] {
        &self.reserved
    }

    /// Get the hash algorithm used to produce this signature.
    ///
    /// Data to be signed is first hashed with the specified `hash_alg`.
    /// This is done to limit the amount of data presented to the signature
    /// operation, which may be of concern if the signing key is held in limited
    /// or slow hardware or on a remote ssh-agent. The supported hash algorithms
    /// are "sha256" and "sha512".
    pub fn hash_alg(&self) -> HashAlg {
        self.hash_alg
    }

    /// Get the structured signature over the given message.
    pub fn signature(&self) -> &Signature {
        &self.signature
    }

    /// Get the bytes which comprise the serialized signature.
    pub fn signature_bytes(&self) -> &[u8] {
        self.signature.as_bytes()
    }
}

impl Decode for SshSig {
    fn decode(reader: &mut impl Reader) -> Result<Self> {
        let mut magic_preamble = [0u8; Self::MAGIC_PREAMBLE.len()];
        reader.read(&mut magic_preamble)?;

        if magic_preamble != Self::MAGIC_PREAMBLE {
            return Err(Error::FormatEncoding);
        }

        let version = Version::decode(reader)?;

        if version > Self::VERSION {
            return Err(Error::Version { number: version });
        }

        let public_key = reader.read_nested(public::KeyData::decode)?;
        let namespace = String::decode(reader)?;

        if namespace.is_empty() {
            return Err(Error::Namespace);
        }

        let reserved = Vec::decode(reader)?;
        let hash_alg = HashAlg::decode(reader)?;
        let signature = reader.read_nested(Signature::decode)?;

        Ok(Self {
            version,
            public_key,
            namespace,
            reserved,
            hash_alg,
            signature,
        })
    }
}

impl Encode for SshSig {
    fn encoded_len(&self) -> Result<usize> {
        [
            Self::MAGIC_PREAMBLE.len(),
            self.version.encoded_len()?,
            4, // public key length prefix (uint32)
            self.public_key.encoded_len()?,
            self.namespace.encoded_len()?,
            self.reserved.encoded_len()?,
            self.hash_alg.encoded_len()?,
            4, // signature length prefix (uint32)
            self.signature.encoded_len()?,
        ]
        .checked_sum()
    }

    fn encode(&self, writer: &mut impl Writer) -> Result<()> {
        writer.write(Self::MAGIC_PREAMBLE)?;
        self.version.encode(writer)?;
        self.public_key.encode_nested(writer)?;
        self.namespace.encode(writer)?;
        self.reserved.encode(writer)?;
        self.hash_alg.encode(writer)?;
        self.signature.encode_nested(writer)?;
        Ok(())
    }
}

impl FromStr for SshSig {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Self::from_pem(s)
    }
}

impl PemLabel for SshSig {
    const PEM_LABEL: &'static str = "SSH SIGNATURE";
}

impl ToString for SshSig {
    fn to_string(&self) -> String {
        self.to_pem(LineEnding::default())
            .expect("SSH signature encoding error")
    }
}

/// Data to be signed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SignedData<'a> {
    namespace: &'a str,
    reserved: &'a [u8],
    hash_alg: HashAlg,
    hash: &'a [u8],
}

impl<'a> SignedData<'a> {
    fn sign<S>(&self, signer: &S) -> Result<Signature>
    where
        S: Signer<Signature>,
    {
        Ok(signer.try_sign(&self.to_bytes()?)?)
    }

    fn to_bytes(self) -> Result<Vec<u8>> {
        let mut signed_bytes = Vec::with_capacity(self.encoded_len()?);
        self.encode(&mut signed_bytes)?;
        Ok(signed_bytes)
    }
}

impl<'a> Encode for SignedData<'a> {
    fn encoded_len(&self) -> Result<usize> {
        [
            SshSig::MAGIC_PREAMBLE.len(),
            self.namespace.encoded_len()?,
            self.reserved.encoded_len()?,
            self.hash_alg.encoded_len()?,
            self.hash.encoded_len()?,
        ]
        .checked_sum()
    }

    fn encode(&self, writer: &mut impl Writer) -> Result<()> {
        writer.write(SshSig::MAGIC_PREAMBLE)?;
        self.namespace.encode(writer)?;
        self.reserved.encode(writer)?;
        self.hash_alg.encode(writer)?;
        self.hash.encode(writer)?;
        Ok(())
    }
}
