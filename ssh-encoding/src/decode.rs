//! Decoder-side implementation of the SSH protocol's data type representations
//! as described in [RFC4251 § 5].
//!
//! [RFC4251 § 5]: https://datatracker.ietf.org/doc/html/rfc4251#section-5

use crate::{reader::Reader, Error, Result};

#[cfg(feature = "alloc")]
use alloc::{string::String, vec::Vec};

#[cfg(feature = "bytes")]
use bytes::Bytes;

/// Maximum size of a `usize` this library will accept.
const MAX_SIZE: usize = 0xFFFFF;

/// Decoding trait.
///
/// This trait describes how to decode a given type.
pub trait Decode: Sized {
    /// Type returned in the event of a decoding error.
    type Error: From<Error>;

    /// Attempt to decode a value of this type using the provided [`Reader`].
    fn decode(reader: &mut impl Reader) -> core::result::Result<Self, Self::Error>;
}

/// Decode a single `byte` from the input data.
impl Decode for u8 {
    type Error = Error;

    fn decode(reader: &mut impl Reader) -> Result<Self> {
        let mut buf = [0];
        reader.read(&mut buf)?;
        Ok(buf[0])
    }
}

/// Decode a `boolean` as described in [RFC4251 § 5]:
///
/// > A boolean value is stored as a single byte.  The value 0
/// > represents FALSE, and the value 1 represents TRUE.  All non-zero
/// > values MUST be interpreted as TRUE; however, applications MUST NOT
/// > store values other than 0 and 1.
///
/// [RFC4251 § 5]: https://datatracker.ietf.org/doc/html/rfc4251#section-5
impl Decode for bool {
    type Error = Error;

    fn decode(reader: &mut impl Reader) -> Result<Self> {
        let byte = u8::decode(reader)?;
        match byte {
            0 => Ok(false),
            _ => Ok(true),
        }
    }
}

/// Decode a `uint32` as described in [RFC4251 § 5]:
///
/// > Represents a 32-bit unsigned integer.  Stored as four bytes in the
/// > order of decreasing significance (network byte order).
/// > For example: the value 699921578 (0x29b7f4aa) is stored as 29 b7 f4 aa.
///
/// [RFC4251 § 5]: https://datatracker.ietf.org/doc/html/rfc4251#section-5
impl Decode for u32 {
    type Error = Error;

    fn decode(reader: &mut impl Reader) -> Result<Self> {
        let mut bytes = [0u8; 4];
        reader.read(&mut bytes)?;
        Ok(u32::from_be_bytes(bytes))
    }
}

/// Decode a `uint64` as described in [RFC4251 § 5]:
///
/// > Represents a 64-bit unsigned integer.  Stored as eight bytes in
/// > the order of decreasing significance (network byte order).
///
/// [RFC4251 § 5]: https://datatracker.ietf.org/doc/html/rfc4251#section-5
impl Decode for u64 {
    type Error = Error;

    fn decode(reader: &mut impl Reader) -> Result<Self> {
        let mut bytes = [0u8; 8];
        reader.read(&mut bytes)?;
        Ok(u64::from_be_bytes(bytes))
    }
}

/// Decode a `usize`.
///
/// Uses [`Decode`] impl on `u32` and then converts to a `usize`, handling
/// potential overflow if `usize` is smaller than `u32`.
///
/// Enforces a library-internal limit of 1048575, as the main use case for
/// `usize` is length prefixes.
impl Decode for usize {
    type Error = Error;

    fn decode(reader: &mut impl Reader) -> Result<Self> {
        let n = usize::try_from(u32::decode(reader)?)?;

        if n <= MAX_SIZE {
            Ok(n)
        } else {
            Err(Error::Overflow)
        }
    }
}

/// Decodes a byte array from `byte[n]` as described in [RFC4251 § 5]:
///
/// > A byte represents an arbitrary 8-bit value (octet).  Fixed length
/// > data is sometimes represented as an array of bytes, written
/// > `byte[n]`, where n is the number of bytes in the array.
///
/// [RFC4251 § 5]: https://datatracker.ietf.org/doc/html/rfc4251#section-5
impl<const N: usize> Decode for [u8; N] {
    type Error = Error;

    fn decode(reader: &mut impl Reader) -> Result<Self> {
        reader.read_prefixed(|reader| {
            let mut result = [(); N].map(|_| 0);
            reader.read(&mut result)?;
            Ok(result)
        })
    }
}

/// Decodes `Vec<u8>` from `string` as described in [RFC4251 § 5]:
///
/// > Arbitrary length binary string.  Strings are allowed to contain
/// > arbitrary binary data, including null characters and 8-bit
/// > characters.  They are stored as a uint32 containing its length
/// > (number of bytes that follow) and zero (= empty string) or more
/// > bytes that are the value of the string.  Terminating null
/// > characters are not used.
///
/// [RFC4251 § 5]: https://datatracker.ietf.org/doc/html/rfc4251#section-5
#[cfg(feature = "alloc")]
impl Decode for Vec<u8> {
    type Error = Error;

    fn decode(reader: &mut impl Reader) -> Result<Self> {
        reader.read_prefixed(|reader| {
            let mut result = vec![0u8; reader.remaining_len()];
            reader.read(&mut result)?;
            Ok(result)
        })
    }
}

#[cfg(feature = "alloc")]
impl Decode for String {
    type Error = Error;

    fn decode(reader: &mut impl Reader) -> Result<Self> {
        String::from_utf8(Vec::decode(reader)?).map_err(|_| Error::CharacterEncoding)
    }
}

#[cfg(feature = "alloc")]
impl Decode for Vec<String> {
    type Error = Error;

    fn decode(reader: &mut impl Reader) -> Result<Self> {
        reader.read_prefixed(|reader| {
            let mut entries = Self::new();

            while !reader.is_finished() {
                entries.push(String::decode(reader)?);
            }

            Ok(entries)
        })
    }
}

/// Decodes `Bytes` from `byte[n]` as described in [RFC4251 § 5]:
///
/// > A byte represents an arbitrary 8-bit value (octet).  Fixed length
/// > data is sometimes represented as an array of bytes, written
/// > `byte[n]`, where n is the number of bytes in the array.
///
/// [RFC4251 § 5]: https://datatracker.ietf.org/doc/html/rfc4251#section-5
#[cfg(feature = "bytes")]
impl Decode for Bytes {
    type Error = Error;

    fn decode(reader: &mut impl Reader) -> Result<Self> {
        Vec::<u8>::decode(reader).map(Into::into)
    }
}
