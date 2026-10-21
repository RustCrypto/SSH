//! Multiple precision integer.

use crate::{CheckedSum, Decode, Encode, Error, Reader, Result, Writer};
use alloc::{boxed::Box, vec::Vec};
use core::fmt;

#[cfg(feature = "bigint")]
use crate::Uint;

#[cfg(feature = "ctutils")]
use ctutils::{Choice, CtEq};

#[cfg(any(feature = "bigint", feature = "zeroize"))]
use zeroize::Zeroize;
#[cfg(feature = "bigint")]
use zeroize::Zeroizing;

/// Multiple precision integer, a.k.a. `mpint`.
///
/// Described in [RFC4251 § 5](https://datatracker.ietf.org/doc/html/rfc4251#section-5):
///
/// > Represents multiple precision integers in two's complement format,
/// > stored as a string, 8 bits per byte, MSB first.  Negative numbers
/// > have the value 1 as the most significant bit of the first byte of
/// > the data partition.  If the most significant bit would be set for
/// > a positive number, the number MUST be preceded by a zero byte.
/// > Unnecessary leading bytes with the value 0 or 255 MUST NOT be
/// > included.  The value zero MUST be stored as a string with zero
/// > bytes of data.
/// >
/// > By convention, a number that is used in modular computations in
/// > Z_n SHOULD be represented in the range 0 <= x < n.
///
/// ## Examples
///
/// | value (hex)     | representation (hex) |
/// |-----------------|----------------------|
/// | 0               | `00 00 00 00`
/// | 9a378f9b2e332a7 | `00 00 00 08 09 a3 78 f9 b2 e3 32 a7`
/// | 80              | `00 00 00 02 00 80`
/// |-1234            | `00 00 00 02 ed cc`
/// | -deadbeef       | `00 00 00 05 ff 21 52 41 11`
#[cfg_attr(not(feature = "ctutils"), derive(Clone))]
#[cfg_attr(feature = "ctutils", derive(Clone, Ord, PartialOrd))] // TODO: constant time (Partial)`Ord`?
pub struct Mpint {
    /// Inner big endian-serialized integer value
    inner: Box<[u8]>,
}

impl Mpint {
    /// Create a new multiple precision integer from the given big endian-encoded byte slice.
    ///
    /// Note that this method expects a leading zero on positive integers whose MSB is set, but does
    /// *NOT* expect a 4-byte length prefix.
    ///
    /// # Errors
    /// Returns [`Error::MpintEncoding`] in the event of an unnecessary leading `0`.
    ///
    /// This matches the encoding rules of RFC 4251 § 5. [`Decode::decode`] is
    /// deliberately more lenient, as it must be able to read non-canonical
    /// encodings which other SSH implementations produce.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        bytes.try_into()
    }

    /// Create a new multiple precision integer from the given big endian encoded byte slice
    /// representing a positive integer.
    ///
    /// The input may begin with leading zeros, which will be stripped when converted to [`Mpint`]
    /// encoding.
    #[must_use]
    pub fn from_positive_bytes(mut bytes: &[u8]) -> Self {
        // Strip leading zeros
        while bytes.first().copied() == Some(0) {
            bytes = &bytes[1..];
        }

        // Add a leading zero to the output if necessary
        let inner = match bytes.first().copied() {
            Some(n) if n >= 0x80 => {
                let mut inner = Vec::with_capacity(bytes.len().saturating_add(1));
                inner.push(0);
                inner.extend_from_slice(bytes);
                inner
            }
            _ => Vec::from(bytes),
        };

        Self {
            inner: inner.into_boxed_slice(),
        }
    }

    /// Get the big integer data encoded as big endian bytes.
    ///
    /// This slice will contain a leading zero if the value is positive but the
    /// MSB is also set. Use [`Mpint::as_positive_bytes`] to ensure the number
    /// is positive and strip the leading zero byte if it exists.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.inner
    }

    /// Get the bytes of a positive integer.
    ///
    /// # Returns
    /// - `Some(bytes)` if the number is positive. The leading zero byte will be stripped.
    /// - `None` if the value is negative
    #[must_use]
    pub fn as_positive_bytes(&self) -> Option<&[u8]> {
        match self.as_bytes() {
            [0x00, rest @ ..] => Some(rest),
            [byte, ..] if *byte < 0x80 => Some(self.as_bytes()),
            _ => None,
        }
    }

    /// Is this [`Mpint`] positive?
    #[must_use]
    pub fn is_positive(&self) -> bool {
        self.as_positive_bytes().is_some()
    }

    /// Normalize a big endian-encoded integer as read from the wire.
    ///
    /// RFC 4251 § 5 requires redundant leading `0x00` bytes to be omitted, but
    /// several SSH implementations send them anyway (e.g. in `ssh-rsa` host
    /// keys, as observed with older Huawei network devices). OpenSSH tolerates
    /// this when reading a peer's message: `sshbuf_get_bignum2_bytes_direct`
    /// trims leading zeros instead of failing, so do the same here.
    ///
    /// Redundant leading zero bytes are stripped, and a single `0x00` is
    /// re-added if the remaining value is positive with its MSB set, i.e. the
    /// result is always canonically encoded. Values which are already canonical
    /// (including negative values) are returned unchanged.
    fn normalize_decode(bytes: Box<[u8]>) -> Self {
        let Some(first_nonzero) = bytes.iter().position(|byte| *byte != 0) else {
            // The value is zero, which RFC 4251 § 5 encodes as an empty string.
            return Self {
                inner: Box::default(),
            };
        };

        if first_nonzero == 0 {
            return Self { inner: bytes };
        }

        let rest = &bytes[first_nonzero..];

        let inner = match rest.first() {
            // Positive, but the MSB is set: exactly one `0x00` prefix is needed.
            Some(byte) if *byte >= 0x80 => {
                let mut inner = Vec::with_capacity(rest.len().saturating_add(1));
                inner.push(0);
                inner.extend_from_slice(rest);
                inner.into_boxed_slice()
            }
            _ => Vec::from(rest).into_boxed_slice(),
        };

        Self { inner }
    }
}

impl AsRef<[u8]> for Mpint {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

#[cfg(feature = "ctutils")]
impl CtEq for Mpint {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.as_ref().ct_eq(other.as_ref())
    }
}

#[cfg(feature = "ctutils")]
impl Eq for Mpint {}

#[cfg(feature = "ctutils")]
impl PartialEq for Mpint {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl Decode for Mpint {
    type Error = Error;

    fn decode(reader: &mut impl Reader) -> Result<Self> {
        Ok(Self::normalize_decode(
            Vec::decode(reader)?.into_boxed_slice(),
        ))
    }
}

impl Encode for Mpint {
    fn encoded_len(&self) -> Result<usize> {
        [4, self.as_bytes().len()].checked_sum()
    }

    fn encode(&self, writer: &mut impl Writer) -> Result<()> {
        self.as_bytes().encode(writer)?;
        Ok(())
    }
}

impl TryFrom<&[u8]> for Mpint {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self> {
        Vec::from(bytes).into_boxed_slice().try_into()
    }
}

impl TryFrom<Box<[u8]>> for Mpint {
    type Error = Error;

    fn try_from(bytes: Box<[u8]>) -> Result<Self> {
        match &*bytes {
            // Unnecessary leading 0
            [0x00] => Err(Error::MpintEncoding),
            // Unnecessary leading 0
            [0x00, n, ..] if *n < 0x80 => Err(Error::MpintEncoding),
            _ => Ok(Self { inner: bytes }),
        }
    }
}

#[cfg(feature = "zeroize")]
impl Zeroize for Mpint {
    fn zeroize(&mut self) {
        self.inner.zeroize();
    }
}

impl fmt::Debug for Mpint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Mpint({self:X})")
    }
}

impl fmt::Display for Mpint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:X}")
    }
}

impl fmt::LowerHex for Mpint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.as_bytes() {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl fmt::UpperHex for Mpint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.as_bytes() {
            write!(f, "{byte:02X}")?;
        }
        Ok(())
    }
}

#[cfg(feature = "bigint")]
impl From<&Uint> for Mpint {
    fn from(uint: &Uint) -> Mpint {
        let bytes = Zeroizing::new(uint.to_be_bytes());
        Mpint::from_positive_bytes(&bytes)
    }
}

#[cfg(feature = "bigint")]
impl From<Uint> for Mpint {
    fn from(uint: Uint) -> Mpint {
        Mpint::from(&uint)
    }
}

#[cfg(feature = "bigint")]
impl TryFrom<Mpint> for Uint {
    type Error = Error;

    fn try_from(mpint: Mpint) -> Result<Uint> {
        Uint::try_from(&mpint)
    }
}

#[cfg(feature = "bigint")]
impl TryFrom<&Mpint> for Uint {
    type Error = Error;

    fn try_from(mpint: &Mpint) -> Result<Uint> {
        // TODO(tarcieri): enforce a maximum size?
        let bytes = mpint.as_positive_bytes().ok_or(Error::MpintEncoding)?;
        Ok(Uint::from_be_slice_vartime(bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::Mpint;
    use crate::Decode;
    use alloc::vec::Vec;
    use hex_literal::hex;

    /// Decode a raw `mpint` payload as it would be read off the wire, i.e. with a
    /// 4-byte length prefix, so the [`Decode`] implementation itself is exercised.
    fn decode(bytes: &[u8]) -> Mpint {
        let len = u32::try_from(bytes.len()).unwrap().to_be_bytes();
        let mut prefixed = Vec::with_capacity(bytes.len().saturating_add(4));
        prefixed.extend_from_slice(&len);
        prefixed.extend_from_slice(bytes);
        Mpint::decode(&mut &prefixed[..]).unwrap()
    }

    #[test]
    fn decode_0() {
        let n = Mpint::from_bytes(b"").unwrap();
        assert_eq!(b"", n.as_bytes());
    }

    #[test]
    fn reject_extra_leading_zeroes() {
        assert!(Mpint::from_bytes(&hex!("00")).is_err());
        assert!(Mpint::from_bytes(&hex!("00 00")).is_err());
        assert!(Mpint::from_bytes(&hex!("00 01")).is_err());
    }

    /// Decoding from the wire tolerates and normalizes non-canonical encodings.
    ///
    /// Mirrors OpenSSH's `sshbuf_get_bignum2_bytes_direct()`, which trims leading
    /// zero bytes instead of rejecting the message.
    #[test]
    fn decode_tolerates_extra_leading_zeroes() {
        assert_eq!(decode(&hex!("00 01")).as_bytes(), &hex!("01"));
        assert_eq!(decode(&hex!("00 00 01")).as_bytes(), &hex!("01"));
        // A leading zero must be re-added: the MSB of the remaining value is set.
        assert_eq!(decode(&hex!("00 00 80 01")).as_bytes(), &hex!("00 80 01"));
        assert_eq!(decode(&hex!("00 00 00 80")).as_bytes(), &hex!("00 80"));
    }

    /// The value zero is normalized to its canonical empty encoding.
    #[test]
    fn decode_normalizes_zero() {
        assert_eq!(decode(b"").as_bytes(), b"");
        assert_eq!(decode(&hex!("00")).as_bytes(), b"");
        assert_eq!(decode(&hex!("00 00")).as_bytes(), b"");
    }

    /// Canonical encodings and negative values are preserved verbatim.
    #[test]
    fn decode_preserves_canonical_encodings() {
        assert_eq!(decode(&hex!("00 80")).as_bytes(), &hex!("00 80"));
        assert_eq!(
            decode(&hex!("09 a3 78 f9 b2 e3 32 a7")).as_bytes(),
            &hex!("09 a3 78 f9 b2 e3 32 a7")
        );
        // NOTE: negative values must not be re-signed by normalization.
        assert_eq!(decode(&hex!("ed cc")).as_bytes(), &hex!("ed cc"));
        assert_eq!(
            decode(&hex!("ff 21 52 41 11")).as_bytes(),
            &hex!("ff 21 52 41 11")
        );
        assert!(decode(&hex!("ed cc")).as_positive_bytes().is_none());
    }

    /// A normalized integer is indistinguishable from its canonical encoding.
    #[test]
    fn decode_normalizes_to_canonical_value() {
        let normalized = decode(&hex!("00 00 80 01"));
        let canonical = Mpint::from_bytes(&hex!("00 80 01")).unwrap();
        assert_eq!(normalized.as_bytes(), canonical.as_bytes());
        assert_eq!(
            normalized.as_positive_bytes().unwrap(),
            canonical.as_positive_bytes().unwrap()
        );
    }

    #[test]
    fn decode_9a378f9b2e332a7() {
        assert!(Mpint::from_bytes(&hex!("09 a3 78 f9 b2 e3 32 a7")).is_ok());
    }

    #[test]
    fn decode_80() {
        let n = Mpint::from_bytes(&hex!("00 80")).unwrap();

        // Leading zero stripped
        assert_eq!(&hex!("80"), n.as_positive_bytes().unwrap());
    }
    #[test]
    fn from_positive_bytes_strips_leading_zeroes() {
        assert_eq!(Mpint::from_positive_bytes(&hex!("00")).as_ref(), b"");
        assert_eq!(Mpint::from_positive_bytes(&hex!("00 00")).as_ref(), b"");
        assert_eq!(Mpint::from_positive_bytes(&hex!("00 01")).as_ref(), b"\x01");
    }

    // TODO(tarcieri): drop support for negative numbers?
    #[test]
    fn decode_neg_1234() {
        let n = Mpint::from_bytes(&hex!("ed cc")).unwrap();
        assert!(n.as_positive_bytes().is_none());
    }

    // TODO(tarcieri): drop support for negative numbers?
    #[test]
    fn decode_neg_deadbeef() {
        let n = Mpint::from_bytes(&hex!("ff 21 52 41 11")).unwrap();
        assert!(n.as_positive_bytes().is_none());
    }
}
