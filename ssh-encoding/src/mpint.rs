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
    /// Maximum size in bytes accepted by fallible constructors and bigint conversions,
    /// excluding an optional leading sign byte. Matches OpenSSH's 16384-bit limit.
    pub const MAX_SIZE: usize = 2048;

    /// Create a new multiple precision integer from the given big endian-encoded byte slice.
    ///
    /// Note that this method expects a leading zero on positive integers whose MSB is set, but does
    /// *NOT* expect a 4-byte length prefix.
    ///
    /// # Errors
    /// Returns [`Error::MpintEncoding`] in the event of an unnecessary leading `0`.
    /// Returns [`Error::Length`] if the integer exceeds [`Self::MAX_SIZE`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        bytes.try_into()
    }

    /// Create a new multiple precision integer from the given big endian encoded byte slice
    /// representing a positive integer.
    ///
    /// The input may begin with leading zeros, which will be stripped when converted to [`Mpint`]
    /// encoding.
    ///
    /// This infallible constructor does not enforce [`Self::MAX_SIZE`]. Conversion to a bigint
    /// still rejects oversized values.
    // TODO(tarcieri): make this fallible and enforce `MAX_SIZE` in the next breaking release.
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

    /// Validate the size and encoding before allocating or accepting an owned buffer.
    fn validate(bytes: &[u8]) -> Result<()> {
        let value = match bytes {
            [0x00 | 0xff, rest @ ..] => rest,
            _ => bytes,
        };

        if value.len() > Self::MAX_SIZE {
            return Err(Error::Length);
        }

        match bytes {
            // Unnecessary leading 0
            [0x00] => Err(Error::MpintEncoding),
            [0x00, n, ..] if *n < 0x80 => Err(Error::MpintEncoding),
            _ => Ok(()),
        }
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
        reader.read_prefixed(|reader| {
            let len = reader.remaining_len();
            if len > Self::MAX_SIZE + 1 {
                return Err(Error::Length);
            }

            let mut bytes = vec![0; len];
            reader.read(&mut bytes)?;
            bytes.into_boxed_slice().try_into()
        })
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
        Self::validate(bytes)?;
        Ok(Self {
            inner: bytes.into(),
        })
    }
}

impl TryFrom<Box<[u8]>> for Mpint {
    type Error = Error;

    fn try_from(bytes: Box<[u8]>) -> Result<Self> {
        Self::validate(&bytes)?;
        Ok(Self { inner: bytes })
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

// TODO(tarcieri): replace with TryFrom and enforce `MAX_SIZE` in the next breaking release.
#[cfg(feature = "bigint")]
impl From<&Uint> for Mpint {
    fn from(uint: &Uint) -> Mpint {
        let bytes = Zeroizing::new(uint.to_be_bytes());
        Mpint::from_positive_bytes(&bytes)
    }
}

// TODO(tarcieri): replace with TryFrom and enforce `MAX_SIZE` in the next breaking release.
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
        let bytes = mpint.as_positive_bytes().ok_or(Error::MpintEncoding)?;
        if bytes.len() > Mpint::MAX_SIZE {
            return Err(Error::Length);
        }

        Ok(Uint::from_be_slice_vartime(bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::Mpint;
    use crate::{Decode, Encode, Error, Reader};
    use alloc::vec::Vec;
    use hex_literal::hex;

    #[test]
    fn size_limits() {
        // Include positive and negative values, with and without a leading sign byte.
        for (first, size, valid) in [
            (0x7f, Mpint::MAX_SIZE, true),
            (0x80, Mpint::MAX_SIZE, true),
            (0x00, Mpint::MAX_SIZE + 1, true),
            (0xff, Mpint::MAX_SIZE + 1, true),
            (0x01, Mpint::MAX_SIZE + 1, false),
            (0x80, Mpint::MAX_SIZE + 1, false),
            (0x00, Mpint::MAX_SIZE + 2, false),
            (0xff, Mpint::MAX_SIZE + 2, false),
        ] {
            let mut bytes = vec![if first == 0xff { 0x7f } else { 0x80 }; size];
            bytes[0] = first;
            let borrowed = Mpint::from_bytes(&bytes);
            let owned = Mpint::try_from(bytes.clone().into_boxed_slice());
            let mut encoded = Vec::new();
            bytes.encode(&mut encoded).unwrap();
            let decoded = Mpint::decode(&mut encoded.as_slice());

            for result in [borrowed, owned, decoded] {
                if valid {
                    assert_eq!(result.unwrap().as_bytes(), bytes);
                } else {
                    assert!(matches!(result, Err(Error::Length)));
                }
            }
        }
    }

    #[test]
    fn reject_oversized_before_reading_body() {
        // A reader whose body cannot be read demonstrates rejection at the length check.
        struct Unreadable;

        impl Reader for Unreadable {
            fn read<'o>(&mut self, _: &'o mut [u8]) -> crate::Result<&'o [u8]> {
                panic!("oversized mpint body must not be read");
            }

            fn remaining_len(&self) -> usize {
                Mpint::MAX_SIZE + 2
            }

            fn read_prefixed<T, E, F>(&mut self, f: F) -> Result<T, E>
            where
                E: From<Error>,
                F: FnOnce(&mut Self) -> Result<T, E>,
            {
                f(self)
            }
        }

        assert!(matches!(Mpint::decode(&mut Unreadable), Err(Error::Length)));
    }

    #[cfg(feature = "bigint")]
    #[test]
    fn bigint_size_limits() {
        use crate::Uint;

        for size in [Mpint::MAX_SIZE, Mpint::MAX_SIZE + 1] {
            let bytes = vec![0x80; size];
            let uint = Uint::from_be_slice_vartime(&bytes);
            // All infallible constructors remain available, but cannot bypass the bigint limit.
            for mpint in [
                Mpint::from_positive_bytes(&bytes),
                Mpint::from(&uint),
                Mpint::from(uint.clone()),
            ] {
                let borrowed = Uint::try_from(&mpint);
                let owned = Uint::try_from(mpint);
                for result in [borrowed, owned] {
                    if size == Mpint::MAX_SIZE {
                        assert_eq!(result.unwrap(), uint);
                    } else {
                        assert!(matches!(result, Err(Error::Length)));
                    }
                }
            }
        }
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
