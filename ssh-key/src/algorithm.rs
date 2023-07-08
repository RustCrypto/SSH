//! Algorithm support.

use crate::{Error, Result};
use core::{fmt, str};
use encoding::{Label, LabelError};

#[cfg(feature = "alloc")]
use {
    alloc::vec::Vec,
    sha2::{Digest, Sha256, Sha512},
    tinystr::TinyAsciiStr,
};

/// bcrypt-pbkdf
const BCRYPT: &str = "bcrypt";

/// OpenSSH certificate for DSA public key
const CERT_DSA: &str = "ssh-dss-cert-v01@openssh.com";

/// OpenSSH certificate for ECDSA (NIST P-256) public key
const CERT_ECDSA_SHA2_P256: &str = "ecdsa-sha2-nistp256-cert-v01@openssh.com";

/// OpenSSH certificate for ECDSA (NIST P-384) public key
const CERT_ECDSA_SHA2_P384: &str = "ecdsa-sha2-nistp384-cert-v01@openssh.com";

/// OpenSSH certificate for ECDSA (NIST P-521) public key
const CERT_ECDSA_SHA2_P521: &str = "ecdsa-sha2-nistp521-cert-v01@openssh.com";

/// OpenSSH certificate for Ed25519 public key
const CERT_ED25519: &str = "ssh-ed25519-cert-v01@openssh.com";

/// OpenSSH certificate with RSA public key
const CERT_RSA: &str = "ssh-rsa-cert-v01@openssh.com";

/// OpenSSH certificate for ECDSA (NIST P-256) U2F/FIDO security key
const CERT_SK_ECDSA_SHA2_P256: &str = "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com";

/// OpenSSH certificate for Ed25519 U2F/FIDO security key
const CERT_SK_SSH_ED25519: &str = "sk-ssh-ed25519-cert-v01@openssh.com";

/// ECDSA with SHA-256 + NIST P-256
const ECDSA_SHA2_P256: &str = "ecdsa-sha2-nistp256";

/// ECDSA with SHA-256 + NIST P-256
const ECDSA_SHA2_P384: &str = "ecdsa-sha2-nistp384";

/// ECDSA with SHA-256 + NIST P-256
const ECDSA_SHA2_P521: &str = "ecdsa-sha2-nistp521";

/// None
const NONE: &str = "none";

/// RSA with SHA-256 as described in RFC8332 § 3
const RSA_SHA2_256: &str = "rsa-sha2-256";

/// RSA with SHA-512 as described in RFC8332 § 3
const RSA_SHA2_512: &str = "rsa-sha2-512";

/// SHA-256 hash function
const SHA256: &str = "sha256";

/// SHA-512 hash function
const SHA512: &str = "sha512";

/// Digital Signature Algorithm
const SSH_DSA: &str = "ssh-dss";

/// Ed25519
const SSH_ED25519: &str = "ssh-ed25519";

/// RSA
const SSH_RSA: &str = "ssh-rsa";

/// U2F/FIDO security key with ECDSA/NIST P-256
const SK_ECDSA_SHA2_P256: &str = "sk-ecdsa-sha2-nistp256@openssh.com";

/// U2F/FIDO security key with Ed25519
const SK_SSH_ED25519: &str = "sk-ssh-ed25519@openssh.com";

/// The suffix added to the `name` in a `name@domainname` algorithm string identifier.
#[cfg(feature = "alloc")]
const CERT_STR_SUFFIX: &str = "-cert-v01";

/// According to [RFC4251 § 6], algorithm names are ASCII strings that are at most 64
/// characters long.
///
/// [RFC4251 § 6]: https://www.rfc-editor.org/rfc/rfc4251.html#section-6
#[cfg(feature = "alloc")]
const MAX_ALGORITHM_NAME_LEN: usize = 64;

/// The maximum length of the certificate string identifier is [`MAX_ALGORITHM_NAME_LEN`] +
/// `"-cert-v01".len()` (the certificate identifier is obtained by inserting `"-cert-v01"` in the
/// algorithm name).
#[cfg(feature = "alloc")]
const MAX_CERT_STR_LEN: usize = MAX_ALGORITHM_NAME_LEN + CERT_STR_SUFFIX.len();

/// A string representing an additional algorithm name in the `name@domainname` format (see
/// [RFC4251 § 6]).
///
/// Additional algorithm names must be non-empty printable ASCII strings no longer than 64
/// characters.
///
/// This also provides a `name-cert-v01@domainnname` string identifier for the corresponding
/// OpenSSH certificate format, derived from the specified `name@domainname` string.
///
/// NOTE: RFC4251 specifies additional validation criteria for algorithm names, but we do not
/// implement all of them here.
///
/// [RFC4251 § 6]: https://www.rfc-editor.org/rfc/rfc4251.html#section-6
//
// NOTE: We use TinyAsciiStr instead of String to allow Algorithm to implement Copy.
#[cfg(feature = "alloc")]
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub struct AlgorithmName {
    /// The string identifier which corresponds to this algorithm.
    id: TinyAsciiStr<MAX_ALGORITHM_NAME_LEN>,
    /// The string identifier which corresponds to the OpenSSH certificate format.
    ///
    /// This is derived from the algorithm name by inserting `"-cert-v01"` immediately after the
    /// name preceding the at-symbol (`@`).
    certificate_str: TinyAsciiStr<MAX_CERT_STR_LEN>,
}

#[cfg(feature = "alloc")]
impl AlgorithmName {
    /// Get the string identifier which corresponds to this algorithm name.
    pub fn as_str(&self) -> &str {
        &self.id
    }

    /// Get the string identifier which corresponds to the OpenSSH certificate format.
    pub fn certificate_str(&self) -> &str {
        &self.certificate_str
    }

    /// Create a new [`AlgorithmName`] from an OpenSSH certificate format string identifier.
    pub fn from_certificate_str(id: &str) -> core::result::Result<Self, LabelError> {
        if id.len() > MAX_CERT_STR_LEN {
            return Err(LabelError::new(id));
        }

        let certificate_str = TinyAsciiStr::from_str(id).map_err(|_| LabelError::new(id))?;

        // Derive the algorithm name from the certificate format string identifier:
        let (name, domain) = id.split_once('@').ok_or_else(|| LabelError::new(id))?;

        // TODO: validate name and domain_name according to the criteria from RFC4251
        if name.is_empty() || domain.is_empty() || domain.contains('@') {
            return Err(LabelError::new(id));
        }

        let name = name
            .strip_suffix(CERT_STR_SUFFIX)
            .ok_or_else(|| LabelError::new(id))?;

        let algorithm_name =
            TinyAsciiStr::from_str(&format!("{name}@{domain}")).map_err(|_| LabelError::new(id))?;

        Ok(Self {
            id: algorithm_name,
            certificate_str,
        })
    }
}

#[cfg(feature = "alloc")]
impl str::FromStr for AlgorithmName {
    type Err = LabelError;

    fn from_str(id: &str) -> core::result::Result<Self, LabelError> {
        if id.len() > MAX_ALGORITHM_NAME_LEN {
            return Err(LabelError::new(id));
        }

        let algorithm_name = TinyAsciiStr::from_str(id).map_err(|_| LabelError::new(id))?;

        // Derive the certificate format string identifier from the algorithm name:
        let (name, domain) = id.split_once('@').ok_or_else(|| LabelError::new(id))?;

        // TODO: validate name and domain_name according to the criteria from RFC4251
        if name.is_empty() || domain.is_empty() || domain.contains('@') {
            return Err(LabelError::new(id));
        }

        let certificate_str = TinyAsciiStr::from_str(&format!("{name}{CERT_STR_SUFFIX}@{domain}"))
            .map_err(|_| LabelError::new(id))?;

        Ok(Self {
            id: algorithm_name,
            certificate_str,
        })
    }
}

/// SSH key algorithms.
///
/// This type provides a registry of supported digital signature algorithms
/// used for SSH keys.
#[derive(Copy, Clone, Debug, Default, Eq, Hash, PartialEq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum Algorithm {
    /// Digital Signature Algorithm
    Dsa,

    /// Elliptic Curve Digital Signature Algorithm
    Ecdsa {
        /// Elliptic curve with which to instantiate ECDSA.
        curve: EcdsaCurve,
    },

    /// Ed25519
    #[default]
    Ed25519,

    /// RSA
    Rsa {
        /// Hash function to use with RSASSA-PKCS#1v15 signatures as specified
        /// using [RFC8332] algorithm identifiers.
        ///
        /// If `hash` is set to `None`, then `ssh-rsa` is used as the algorithm
        /// name.
        ///
        /// [RFC8332]: https://datatracker.ietf.org/doc/html/rfc8332
        hash: Option<HashAlg>,
    },

    /// FIDO/U2F key with ECDSA/NIST-P256 + SHA-256
    SkEcdsaSha2NistP256,

    /// FIDO/U2F key with Ed25519
    SkEd25519,

    /// Other
    #[cfg(feature = "alloc")]
    Other(AlgorithmName),
}

impl Algorithm {
    /// Decode algorithm from the given string identifier.
    ///
    /// # Supported algorithms
    /// - `ecdsa-sha2-nistp256`
    /// - `ecdsa-sha2-nistp384`
    /// - `ecdsa-sha2-nistp521`
    /// - `ssh-dss`
    /// - `ssh-ed25519`
    /// - `ssh-rsa`
    /// - `sk-ecdsa-sha2-nistp256@openssh.com` (FIDO/U2F key)
    /// - `sk-ssh-ed25519@openssh.com` (FIDO/U2F key)
    ///
    /// Any other algorithms are mapped to the [`Algorithm::Other`] variant.
    pub fn new(id: &str) -> Result<Self> {
        Ok(id.parse()?)
    }

    /// Decode algorithm from the given string identifier as used by
    /// the OpenSSH certificate format.
    ///
    /// OpenSSH certificate algorithms end in `*-cert-v01@openssh.com`.
    /// See [PROTOCOL.certkeys] for more information.
    ///
    /// # Supported algorithms
    /// - `ssh-rsa-cert-v01@openssh.com`
    /// - `ssh-dss-cert-v01@openssh.com`
    /// - `ecdsa-sha2-nistp256-cert-v01@openssh.com`
    /// - `ecdsa-sha2-nistp384-cert-v01@openssh.com`
    /// - `ecdsa-sha2-nistp521-cert-v01@openssh.com`
    /// - `ssh-ed25519-cert-v01@openssh.com`
    /// - `sk-ecdsa-sha2-nistp256-cert-v01@openssh.com` (FIDO/U2F key)
    /// - `sk-ssh-ed25519-cert-v01@openssh.com` (FIDO/U2F key)
    ///
    /// Any other algorithms are mapped to the [`Algorithm::Other`] variant.
    ///
    /// [PROTOCOL.certkeys]: https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL.certkeys?annotate=HEAD
    pub fn new_certificate(id: &str) -> Result<Self> {
        match id {
            CERT_DSA => Ok(Algorithm::Dsa),
            CERT_ECDSA_SHA2_P256 => Ok(Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP256,
            }),
            CERT_ECDSA_SHA2_P384 => Ok(Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP384,
            }),
            CERT_ECDSA_SHA2_P521 => Ok(Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP521,
            }),
            CERT_ED25519 => Ok(Algorithm::Ed25519),
            CERT_RSA => Ok(Algorithm::Rsa { hash: None }),
            CERT_SK_ECDSA_SHA2_P256 => Ok(Algorithm::SkEcdsaSha2NistP256),
            CERT_SK_SSH_ED25519 => Ok(Algorithm::SkEd25519),
            #[cfg(feature = "alloc")]
            _ => Ok(Algorithm::Other(AlgorithmName::from_certificate_str(id)?)),
            #[cfg(not(feature = "alloc"))]
            _ => Err(Error::AlgorithmUnknown),
        }
    }

    /// Get the string identifier which corresponds to this algorithm.
    pub fn as_str(&self) -> &str {
        match self {
            Algorithm::Dsa => SSH_DSA,
            Algorithm::Ecdsa { curve } => match curve {
                EcdsaCurve::NistP256 => ECDSA_SHA2_P256,
                EcdsaCurve::NistP384 => ECDSA_SHA2_P384,
                EcdsaCurve::NistP521 => ECDSA_SHA2_P521,
            },
            Algorithm::Ed25519 => SSH_ED25519,
            Algorithm::Rsa { hash } => match hash {
                None => SSH_RSA,
                Some(HashAlg::Sha256) => RSA_SHA2_256,
                Some(HashAlg::Sha512) => RSA_SHA2_512,
            },
            Algorithm::SkEcdsaSha2NistP256 => SK_ECDSA_SHA2_P256,
            Algorithm::SkEd25519 => SK_SSH_ED25519,
            #[cfg(feature = "alloc")]
            Algorithm::Other(algorithm) => algorithm.as_str(),
        }
    }

    /// Get the string identifier which corresponds to the OpenSSH certificate
    /// format.
    ///
    /// OpenSSH certificate algorithms end in `*-cert-v01@openssh.com`.
    /// See [PROTOCOL.certkeys] for more information.
    ///
    /// [PROTOCOL.certkeys]: https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL.certkeys?annotate=HEAD
    pub fn as_certificate_str(&self) -> &str {
        match self {
            Algorithm::Dsa => CERT_DSA,
            Algorithm::Ecdsa { curve } => match curve {
                EcdsaCurve::NistP256 => CERT_ECDSA_SHA2_P256,
                EcdsaCurve::NistP384 => CERT_ECDSA_SHA2_P384,
                EcdsaCurve::NistP521 => CERT_ECDSA_SHA2_P521,
            },
            Algorithm::Ed25519 => CERT_ED25519,
            Algorithm::Rsa { .. } => CERT_RSA,
            Algorithm::SkEcdsaSha2NistP256 => CERT_SK_ECDSA_SHA2_P256,
            Algorithm::SkEd25519 => CERT_SK_SSH_ED25519,
            #[cfg(feature = "alloc")]
            Algorithm::Other(algorithm) => algorithm.certificate_str(),
        }
    }

    /// Is the algorithm DSA?
    pub fn is_dsa(self) -> bool {
        self == Algorithm::Dsa
    }

    /// Is the algorithm ECDSA?
    pub fn is_ecdsa(self) -> bool {
        matches!(self, Algorithm::Ecdsa { .. })
    }

    /// Is the algorithm Ed25519?
    pub fn is_ed25519(self) -> bool {
        self == Algorithm::Ed25519
    }

    /// Is the algorithm RSA?
    pub fn is_rsa(self) -> bool {
        matches!(self, Algorithm::Rsa { .. })
    }

    /// Return an error indicating this algorithm is unsupported.
    #[allow(dead_code)]
    pub(crate) fn unsupported_error(self) -> Error {
        Error::AlgorithmUnsupported { algorithm: self }
    }
}

impl AsRef<str> for Algorithm {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl Label for Algorithm {}

impl fmt::Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl str::FromStr for Algorithm {
    type Err = LabelError;

    fn from_str(id: &str) -> core::result::Result<Self, LabelError> {
        match id {
            SSH_DSA => Ok(Algorithm::Dsa),
            ECDSA_SHA2_P256 => Ok(Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP256,
            }),
            ECDSA_SHA2_P384 => Ok(Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP384,
            }),
            ECDSA_SHA2_P521 => Ok(Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP521,
            }),
            RSA_SHA2_256 => Ok(Algorithm::Rsa {
                hash: Some(HashAlg::Sha256),
            }),
            RSA_SHA2_512 => Ok(Algorithm::Rsa {
                hash: Some(HashAlg::Sha512),
            }),
            SSH_ED25519 => Ok(Algorithm::Ed25519),
            SSH_RSA => Ok(Algorithm::Rsa { hash: None }),
            SK_ECDSA_SHA2_P256 => Ok(Algorithm::SkEcdsaSha2NistP256),
            SK_SSH_ED25519 => Ok(Algorithm::SkEd25519),
            #[cfg(feature = "alloc")]
            _ => Ok(Algorithm::Other(AlgorithmName::from_str(id)?)),
            #[cfg(not(feature = "alloc"))]
            _ => Err(LabelError::new(id)),
        }
    }
}

/// Elliptic curves supported for use with ECDSA.
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub enum EcdsaCurve {
    /// NIST P-256 (a.k.a. prime256v1, secp256r1)
    NistP256,

    /// NIST P-384 (a.k.a. secp384r1)
    NistP384,

    /// NIST P-521 (a.k.a. secp521r1)
    NistP521,
}

impl EcdsaCurve {
    /// Decode elliptic curve from the given string identifier.
    ///
    /// # Supported curves
    ///
    /// - `nistp256`
    /// - `nistp384`
    /// - `nistp521`
    pub fn new(id: &str) -> Result<Self> {
        Ok(id.parse()?)
    }

    /// Get the string identifier which corresponds to this ECDSA elliptic curve.
    pub fn as_str(self) -> &'static str {
        match self {
            EcdsaCurve::NistP256 => "nistp256",
            EcdsaCurve::NistP384 => "nistp384",
            EcdsaCurve::NistP521 => "nistp521",
        }
    }

    /// Get the number of bytes needed to encode a field element for this curve.
    #[cfg(feature = "alloc")]
    pub(crate) const fn field_size(self) -> usize {
        match self {
            EcdsaCurve::NistP256 => 32,
            EcdsaCurve::NistP384 => 48,
            EcdsaCurve::NistP521 => 66,
        }
    }
}

impl AsRef<str> for EcdsaCurve {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl Label for EcdsaCurve {}

impl fmt::Display for EcdsaCurve {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl str::FromStr for EcdsaCurve {
    type Err = LabelError;

    fn from_str(id: &str) -> core::result::Result<Self, LabelError> {
        match id {
            "nistp256" => Ok(EcdsaCurve::NistP256),
            "nistp384" => Ok(EcdsaCurve::NistP384),
            "nistp521" => Ok(EcdsaCurve::NistP521),
            _ => Err(LabelError::new(id)),
        }
    }
}

/// Hashing algorithms a.k.a. digest functions.
#[derive(Copy, Clone, Debug, Default, Eq, Hash, PartialEq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum HashAlg {
    /// SHA-256
    #[default]
    Sha256,

    /// SHA-512
    Sha512,
}

impl HashAlg {
    /// Decode elliptic curve from the given string identifier.
    ///
    /// # Supported hash algorithms
    ///
    /// - `sha256`
    /// - `sha512`
    pub fn new(id: &str) -> Result<Self> {
        Ok(id.parse()?)
    }

    /// Get the string identifier for this hash algorithm.
    pub fn as_str(self) -> &'static str {
        match self {
            HashAlg::Sha256 => SHA256,
            HashAlg::Sha512 => SHA512,
        }
    }

    /// Get the size of a digest produced by this hash function.
    pub const fn digest_size(self) -> usize {
        match self {
            HashAlg::Sha256 => 32,
            HashAlg::Sha512 => 64,
        }
    }

    /// Compute a digest of the given message using this hash function.
    #[cfg(feature = "alloc")]
    pub fn digest(self, msg: &[u8]) -> Vec<u8> {
        match self {
            HashAlg::Sha256 => Sha256::digest(msg).to_vec(),
            HashAlg::Sha512 => Sha512::digest(msg).to_vec(),
        }
    }
}

impl Label for HashAlg {}

impl AsRef<str> for HashAlg {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for HashAlg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl str::FromStr for HashAlg {
    type Err = LabelError;

    fn from_str(id: &str) -> core::result::Result<Self, LabelError> {
        match id {
            SHA256 => Ok(HashAlg::Sha256),
            SHA512 => Ok(HashAlg::Sha512),
            _ => Err(LabelError::new(id)),
        }
    }
}

/// Key Derivation Function (KDF) algorithms.
#[derive(Copy, Clone, Debug, Default, Eq, Hash, PartialEq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum KdfAlg {
    /// None.
    None,

    /// bcrypt-pbkdf.
    #[default]
    Bcrypt,
}

impl KdfAlg {
    /// Decode KDF algorithm from the given `kdfname`.
    ///
    /// # Supported KDF names
    /// - `none`
    pub fn new(kdfname: &str) -> Result<Self> {
        Ok(kdfname.parse()?)
    }

    /// Get the string identifier which corresponds to this algorithm.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => NONE,
            Self::Bcrypt => BCRYPT,
        }
    }

    /// Is the KDF algorithm "none"?
    pub fn is_none(self) -> bool {
        self == Self::None
    }
}

impl Label for KdfAlg {}

impl AsRef<str> for KdfAlg {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for KdfAlg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl str::FromStr for KdfAlg {
    type Err = LabelError;

    fn from_str(kdfname: &str) -> core::result::Result<Self, LabelError> {
        match kdfname {
            NONE => Ok(Self::None),
            BCRYPT => Ok(Self::Bcrypt),
            _ => Err(LabelError::new(kdfname)),
        }
    }
}
