use core::ops::Deref;
use core::str::{self, FromStr};
use encoding::LabelError;

/// The suffix added to the `name` in a `name@domainname` algorithm string identifier.
const CERT_STR_SUFFIX: &str = "-cert-v01";

/// According to [RFC4251 § 6], algorithm names are ASCII strings that are at most 64
/// characters long.
///
/// [RFC4251 § 6]: https://www.rfc-editor.org/rfc/rfc4251.html#section-6
const MAX_ALGORITHM_NAME_LEN: usize = 64;

/// The maximum length of the certificate string identifier is [`MAX_ALGORITHM_NAME_LEN`] +
/// `"-cert-v01".len()` (the certificate identifier is obtained by inserting `"-cert-v01"` in the
/// algorithm name).
const MAX_CERT_STR_LEN: usize = MAX_ALGORITHM_NAME_LEN + CERT_STR_SUFFIX.len();

#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
struct AsciiStr<const N: usize> {
    inner: [u8; N],
    len: usize,
}

impl<const N: usize> FromStr for AsciiStr<N> {
    type Err = LabelError;

    fn from_str(id: &str) -> Result<Self, LabelError> {
        if id.len() > N || !id.is_ascii() {
            return Err(LabelError::new(id));
        }

        let len = id.len();
        let mut inner = [0u8; N];
        inner[..len].copy_from_slice(id.as_bytes());

        Ok(Self { inner, len })
    }
}

impl<const N: usize> Deref for AsciiStr<N> {
    type Target = str;
    #[inline]
    fn deref(&self) -> &str {
        // This conversion should **not** fail, as `self.inner` can only ever be constructed from
        // valid `&str`s.
        str::from_utf8(&self.inner[..self.len])
            .expect("AsciiStr can only be built from valid strings")
    }
}

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
// NOTE: We use AsciiStr instead of String to allow Algorithm to implement Copy.
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub struct AlgorithmName {
    /// The string identifier which corresponds to this algorithm.
    id: AsciiStr<MAX_ALGORITHM_NAME_LEN>,
    /// The string identifier which corresponds to the OpenSSH certificate format.
    ///
    /// This is derived from the algorithm name by inserting `"-cert-v01"` immediately after the
    /// name preceding the at-symbol (`@`).
    certificate_str: AsciiStr<MAX_CERT_STR_LEN>,
}

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
    pub fn from_certificate_str(id: &str) -> Result<Self, LabelError> {
        let certificate_str = AsciiStr::from_str(id)?;

        // Derive the algorithm name from the certificate format string identifier:
        let (name, domain) = id.split_once('@').ok_or_else(|| LabelError::new(id))?;

        // TODO: validate name and domain_name according to the criteria from RFC4251
        if name.is_empty() || domain.is_empty() || domain.contains('@') {
            return Err(LabelError::new(id));
        }

        let name = name
            .strip_suffix(CERT_STR_SUFFIX)
            .ok_or_else(|| LabelError::new(id))?;

        let algorithm_name = AsciiStr::from_str(&format!("{name}@{domain}"))?;

        Ok(Self {
            id: algorithm_name,
            certificate_str,
        })
    }
}

impl FromStr for AlgorithmName {
    type Err = LabelError;

    fn from_str(id: &str) -> Result<Self, LabelError> {
        let algorithm_name = AsciiStr::from_str(id)?;

        // Derive the certificate format string identifier from the algorithm name:
        let (name, domain) = id.split_once('@').ok_or_else(|| LabelError::new(id))?;

        // TODO: validate name and domain_name according to the criteria from RFC4251
        if name.is_empty() || domain.is_empty() || domain.contains('@') {
            return Err(LabelError::new(id));
        }

        let certificate_str = AsciiStr::from_str(&format!("{name}{CERT_STR_SUFFIX}@{domain}"))?;

        Ok(Self {
            id: algorithm_name,
            certificate_str,
        })
    }
}
