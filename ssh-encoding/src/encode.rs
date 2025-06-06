//! Encoder-side implementation of the SSH protocol's data type representations
//! as described in [RFC4251 § 5].
//!
//! [RFC4251 § 5]: https://datatracker.ietf.org/doc/html/rfc4251#section-5

use crate::{Error, checked::CheckedSum, writer::Writer};
use core::str;

#[cfg(feature = "alloc")]
use alloc::{string::String, vec::Vec};

#[cfg(feature = "bytes")]
use bytes::{Bytes, BytesMut};

/// Encoding trait.
///
/// This trait describes how to encode a given type.
pub trait Encode {
    /// Get the length of this type encoded in bytes, prior to Base64 encoding.
    fn encoded_len(&self) -> Result<usize, Error>;

    /// Encode this value using the provided [`Writer`].
    fn encode(&self, writer: &mut impl Writer) -> Result<(), Error>;

    /// Return the length of this type after encoding when prepended with a
    /// `uint32` length prefix.
    fn encoded_len_prefixed(&self) -> Result<usize, Error> {
        [4, self.encoded_len()?].checked_sum()
    }

    /// Encode this value, first prepending a `uint32` length prefix
    /// set to [`Encode::encoded_len`].
    fn encode_prefixed(&self, writer: &mut impl Writer) -> Result<(), Error> {
        self.encoded_len()?.encode(writer)?;
        self.encode(writer)
    }

    /// Encode this value, returning a `Vec<u8>` containing the encoded message.
    #[cfg(feature = "alloc")]
    fn encode_vec(&self) -> Result<Vec<u8>, Error> {
        let mut ret = Vec::with_capacity(self.encoded_len()?);
        self.encode(&mut ret)?;
        Ok(ret)
    }

    /// Encode this value, returning a [`BytesMut`] containing the encoded message.
    #[cfg(feature = "bytes")]
    fn encode_bytes(&self) -> Result<BytesMut, Error> {
        let mut ret = BytesMut::with_capacity(self.encoded_len()?);
        self.encode(&mut ret)?;
        Ok(ret)
    }
}

/// Encode a single `byte` to the writer.
impl Encode for u8 {
    fn encoded_len(&self) -> Result<usize, Error> {
        Ok(1)
    }

    fn encode(&self, writer: &mut impl Writer) -> Result<(), Error> {
        writer.write(&[*self])
    }
}

/// Encode a `boolean` as described in [RFC4251 § 5]:
///
/// > A boolean value is stored as a single byte.  The value 0
/// > represents FALSE, and the value 1 represents TRUE.  All non-zero
/// > values MUST be interpreted as TRUE; however, applications MUST NOT
/// > store values other than 0 and 1.
///
/// [RFC4251 § 5]: https://datatracker.ietf.org/doc/html/rfc4251#section-5
impl Encode for bool {
    fn encoded_len(&self) -> Result<usize, Error> {
        Ok(1)
    }

    fn encode(&self, writer: &mut impl Writer) -> Result<(), Error> {
        if *self {
            1u8.encode(writer)
        } else {
            0u8.encode(writer)
        }
    }
}

/// Encode a `uint32` as described in [RFC4251 § 5]:
///
/// > Represents a 32-bit unsigned integer.  Stored as four bytes in the
/// > order of decreasing significance (network byte order).
/// > For example: the value 699921578 (0x29b7f4aa) is stored as 29 b7 f4 aa.
///
/// [RFC4251 § 5]: https://datatracker.ietf.org/doc/html/rfc4251#section-5
impl Encode for u32 {
    fn encoded_len(&self) -> Result<usize, Error> {
        Ok(4)
    }

    fn encode(&self, writer: &mut impl Writer) -> Result<(), Error> {
        writer.write(&self.to_be_bytes())
    }
}

/// Encode a `uint64` as described in [RFC4251 § 5]:
///
/// > Represents a 64-bit unsigned integer.  Stored as eight bytes in
/// > the order of decreasing significance (network byte order).
///
/// [RFC4251 § 5]: https://datatracker.ietf.org/doc/html/rfc4251#section-5
impl Encode for u64 {
    fn encoded_len(&self) -> Result<usize, Error> {
        Ok(8)
    }

    fn encode(&self, writer: &mut impl Writer) -> Result<(), Error> {
        writer.write(&self.to_be_bytes())
    }
}

/// Encode a `usize` as a `uint32` as described in [RFC4251 § 5].
///
/// Uses [`Encode`] impl on `u32` after converting from a `usize`, handling
/// potential overflow if `usize` is bigger than `u32`.
///
/// [RFC4251 § 5]: https://datatracker.ietf.org/doc/html/rfc4251#section-5
impl Encode for usize {
    fn encoded_len(&self) -> Result<usize, Error> {
        Ok(4)
    }

    fn encode(&self, writer: &mut impl Writer) -> Result<(), Error> {
        u32::try_from(*self)?.encode(writer)
    }
}

/// Encodes `[u8]` into `string` as described in [RFC4251 § 5]:
///
/// > Arbitrary length binary string.  Strings are allowed to contain
/// > arbitrary binary data, including null characters and 8-bit
/// > characters.  They are stored as a uint32 containing its length
/// > (number of bytes that follow) and zero (= empty string) or more
/// > bytes that are the value of the string.  Terminating null
/// > characters are not used.
///
/// [RFC4251 § 5]: https://datatracker.ietf.org/doc/html/rfc4251#section-5
impl Encode for [u8] {
    fn encoded_len(&self) -> Result<usize, Error> {
        [4, self.len()].checked_sum()
    }

    fn encode(&self, writer: &mut impl Writer) -> Result<(), Error> {
        self.len().encode(writer)?;
        writer.write(self)
    }
}

/// Encodes byte array using `byte[n]` encoding as described in [RFC4251 § 5]:
///
/// > A byte represents an arbitrary 8-bit value (octet).  Fixed length
/// > data is sometimes represented as an array of bytes, written
/// > `byte[n]`, where n is the number of bytes in the array.
///
/// Note that unlike `string`, this type is encoded without a length prefix,
/// but instead implicitly obtains its length as `N`.
///
/// [RFC4251 § 5]: https://datatracker.ietf.org/doc/html/rfc4251#section-5
impl<const N: usize> Encode for [u8; N] {
    fn encoded_len(&self) -> Result<usize, Error> {
        Ok(N)
    }

    fn encode(&self, writer: &mut impl Writer) -> Result<(), Error> {
        writer.write(self)
    }
}

/// Encode a `string` as described in [RFC4251 § 5]:
///
/// > Arbitrary length binary string.  Strings are allowed to contain
/// > arbitrary binary data, including null characters and 8-bit
/// > characters.  They are stored as a uint32 containing its length
/// > (number of bytes that follow) and zero (= empty string) or more
/// > bytes that are the value of the string.  Terminating null
/// > characters are not used.
/// >
/// > Strings are also used to store text.  In that case, US-ASCII is
/// > used for internal names, and ISO-10646 UTF-8 for text that might
/// > be displayed to the user.  The terminating null character SHOULD
/// > NOT normally be stored in the string.  For example: the US-ASCII
/// > string "testing" is represented as 00 00 00 07 t e s t i n g.  The
/// > UTF-8 mapping does not alter the encoding of US-ASCII characters.
///
/// [RFC4251 § 5]: https://datatracker.ietf.org/doc/html/rfc4251#section-5
impl Encode for &str {
    fn encoded_len(&self) -> Result<usize, Error> {
        self.as_bytes().encoded_len()
    }

    fn encode(&self, writer: &mut impl Writer) -> Result<(), Error> {
        self.as_bytes().encode(writer)
    }
}

#[cfg(feature = "alloc")]
impl Encode for Vec<u8> {
    fn encoded_len(&self) -> Result<usize, Error> {
        self.as_slice().encoded_len()
    }

    fn encode(&self, writer: &mut impl Writer) -> Result<(), Error> {
        self.as_slice().encode(writer)
    }
}

#[cfg(feature = "alloc")]
impl Encode for String {
    fn encoded_len(&self) -> Result<usize, Error> {
        self.as_str().encoded_len()
    }

    fn encode(&self, writer: &mut impl Writer) -> Result<(), Error> {
        self.as_str().encode(writer)
    }
}

#[cfg(feature = "alloc")]
impl Encode for Vec<String> {
    fn encoded_len(&self) -> Result<usize, Error> {
        self.iter().try_fold(4usize, |acc, string| {
            acc.checked_add(string.encoded_len()?).ok_or(Error::Length)
        })
    }

    fn encode(&self, writer: &mut impl Writer) -> Result<(), Error> {
        self.encoded_len()?
            .checked_sub(4)
            .ok_or(Error::Length)?
            .encode(writer)?;

        for entry in self {
            entry.encode(writer)?;
        }

        Ok(())
    }
}

#[cfg(feature = "bytes")]
impl Encode for Bytes {
    fn encoded_len(&self) -> Result<usize, Error> {
        self.as_ref().encoded_len()
    }

    fn encode(&self, writer: &mut impl Writer) -> Result<(), Error> {
        self.as_ref().encode(writer)
    }
}
