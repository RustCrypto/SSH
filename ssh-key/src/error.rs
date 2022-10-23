//! Error types

use core::fmt;

#[cfg(feature = "alloc")]
use crate::certificate;

/// Result type with `ssh-key`'s [`Error`] as the error type.
pub type Result<T> = core::result::Result<T, Error>;

/// Error type.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Error {
    /// Algorithm-related errors.
    Algorithm,

    /// Certificate field is invalid or already set.
    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    CertificateFieldInvalid(certificate::Field),

    /// Certificate validation failed.
    CertificateValidation,

    /// Cryptographic errors.
    Crypto,

    /// Cannot perform operation on decrypted private key.
    Decrypted,

    /// ECDSA key encoding errors.
    #[cfg(feature = "ecdsa")]
    #[cfg_attr(docsrs, doc(cfg(feature = "ecdsa")))]
    Ecdsa(sec1::Error),

    /// Encoding errors.
    Encoding(encoding::Error),

    /// Cannot perform operation on encrypted private key.
    Encrypted,

    /// Other format encoding errors.
    FormatEncoding,

    /// Input/output errors.
    #[cfg(feature = "std")]
    #[cfg_attr(docsrs, doc(cfg(feature = "std")))]
    Io(std::io::ErrorKind),

    /// Namespace invalid.
    Namespace,

    /// Public key is incorrect.
    PublicKey,

    /// Invalid timestamp (e.g. in a certificate)
    Time,

    /// Unexpected trailing data at end of message.
    TrailingData {
        /// Number of bytes of remaining data at end of message.
        remaining: usize,
    },

    /// Unsupported version.
    Version {
        /// Version number.
        number: u32,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Algorithm => write!(f, "unknown or unsupported algorithm"),
            #[cfg(feature = "alloc")]
            Error::CertificateFieldInvalid(field) => {
                write!(f, "certificate field invalid: {}", field)
            }
            Error::CertificateValidation => write!(f, "certificate validation failed"),
            Error::Crypto => write!(f, "cryptographic error"),
            Error::Decrypted => write!(f, "private key is already decrypted"),
            #[cfg(feature = "ecdsa")]
            Error::Ecdsa(err) => write!(f, "ECDSA encoding error: {}", err),
            Error::Encoding(err) => write!(f, "{}", err),
            Error::Encrypted => write!(f, "private key is encrypted"),
            Error::FormatEncoding => write!(f, "format encoding error"),
            #[cfg(feature = "std")]
            Error::Io(err) => write!(f, "I/O error: {}", std::io::Error::from(*err)),
            Error::Namespace => write!(f, "namespace invalid"),
            Error::PublicKey => write!(f, "public key is incorrect"),
            Error::Time => write!(f, "invalid time"),
            Error::TrailingData { remaining } => write!(
                f,
                "unexpected trailing data at end of message ({} bytes)",
                remaining
            ),
            Error::Version { number: version } => write!(f, "version unsupported: {}", version),
        }
    }
}

impl From<core::array::TryFromSliceError> for Error {
    fn from(_: core::array::TryFromSliceError) -> Error {
        Error::Encoding(encoding::Error::Length)
    }
}

impl From<core::str::Utf8Error> for Error {
    fn from(err: core::str::Utf8Error) -> Error {
        Error::Encoding(err.into())
    }
}

impl From<encoding::Error> for Error {
    fn from(err: encoding::Error) -> Error {
        Error::Encoding(err)
    }
}

impl From<encoding::base64::Error> for Error {
    fn from(err: encoding::base64::Error) -> Error {
        Error::Encoding(err.into())
    }
}

impl From<encoding::pem::Error> for Error {
    fn from(err: encoding::pem::Error) -> Error {
        Error::Encoding(err.into())
    }
}

#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
impl From<alloc::string::FromUtf8Error> for Error {
    fn from(err: alloc::string::FromUtf8Error) -> Error {
        Error::Encoding(err.into())
    }
}

#[cfg(feature = "ecdsa")]
#[cfg_attr(docsrs, doc(cfg(feature = "ecdsa")))]
impl From<sec1::Error> for Error {
    fn from(err: sec1::Error) -> Error {
        Error::Ecdsa(err)
    }
}

#[cfg(feature = "rsa")]
#[cfg_attr(docsrs, doc(cfg(feature = "rsa")))]
impl From<rsa::errors::Error> for Error {
    fn from(_: rsa::errors::Error) -> Error {
        Error::Crypto
    }
}

#[cfg(feature = "signature")]
#[cfg_attr(docsrs, doc(cfg(feature = "signature")))]
impl From<signature::Error> for Error {
    fn from(_: signature::Error) -> Error {
        Error::Crypto
    }
}

#[cfg(feature = "signature")]
#[cfg_attr(docsrs, doc(cfg(feature = "signature")))]
impl From<Error> for signature::Error {
    fn from(_: Error) -> signature::Error {
        signature::Error::new()
    }
}

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Error {
        Error::Io(err.kind())
    }
}

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
impl From<std::time::SystemTimeError> for Error {
    fn from(_: std::time::SystemTimeError) -> Error {
        Error::Time
    }
}

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
impl std::error::Error for Error {}
