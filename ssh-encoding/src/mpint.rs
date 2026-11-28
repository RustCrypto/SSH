//! Multiple precision integer.

use crate::{CheckedSum, Decode, Decoder, Encode, Error, Reader, Result, Writer};
use alloc::boxed::Box;
use core::fmt;

#[cfg(feature = "bigint")]
use crate::Uint;
#[cfg(feature = "zeroize")]
use zeroize::Zeroize;
#[cfg(feature = "ctutils")]
use {
    core::cmp::Ordering,
    ctutils::{Choice, CtEq, CtLt, CtSelect},
};

/// Multiple precision integer, a.k.a. `mpint`.
///
/// This type supports the non-negative subset of [RFC4251 § 5], matching [OpenSSH].
/// Values are limited to 16384-bits. Negative SSH encodings are rejected.
///
/// [`Self::from_bytes`] and [`Self::as_bytes`] use an unsigned big endian magnitude,
/// without a length prefix or sign padding. Leading zeros are stripped and zero
/// is represented by an empty slice.
///
/// [`Decode`] accepts redundant leading zeros like OpenSSH, but limits the input
/// to [`Self::MAX_SIZE`] bytes plus one leading zero byte *before* stripping zeros.
/// [`Encode`] always emits the canonical SSH encoding, including a leading zero
/// when the most significant bit is set and an empty string for zero.
///
/// With the `ctutils` feature, constant-time order and equality operations on equal-length
/// magnitudes are supported. Lengths are not treated as secret. Byte conversion, decoding, and
/// encoding are variable-time.
///
/// ## Examples
///
/// | value (hex)     | SSH encoding (hex) |
/// |-----------------|--------------------|
/// | 0               | `00 00 00 00` |
/// | 9a378f9b2e332a7  | `00 00 00 08 09 a3 78 f9 b2 e3 32 a7` |
/// | 80              | `00 00 00 02 00 80` |
///
/// [RFC4251 § 5]: https://datatracker.ietf.org/doc/html/rfc4251#section-5
/// [OpenSSH]: https://github.com/openssh/openssh-portable/blob/1d28115e040b792075a391de01b0f0c033a4850a/sshbuf-getput-basic.c#L598
#[derive(Clone)]
#[cfg_attr(not(feature = "ctutils"), derive(Eq, PartialEq))]
pub struct Mpint {
    /// Unsigned big endian magnitude without leading zeros. Empty for zero.
    inner: Box<[u8]>,
}

impl Mpint {
    /// Maximum magnitude size in bytes, excluding SSH sign padding.
    ///
    /// This 16384-bit limit is enforced by every constructor and decoder.
    pub const MAX_SIZE: usize = 2048;

    /// Create an integer from its unsigned big endian magnitude.
    ///
    /// Leading zeros are stripped. The most significant bit is part of the magnitude,
    /// not a sign bit. This method does not expect an SSH length prefix or sign padding.
    ///
    /// # Errors
    /// Returns [`Error::Length`] if the magnitude exceeds [`Self::MAX_SIZE`].
    /// Returns [`Error::Alloc`] if reserving capacity fails.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let bytes = strip_leading_zeros(bytes);
        if bytes.len() > Self::MAX_SIZE {
            return Err(Error::Length);
        }

        let mut inner = crate::vec_with_reserve(bytes.len())?;
        inner.extend_from_slice(bytes);

        Ok(Self {
            inner: inner.into_boxed_slice(),
        })
    }

    /// Get the unsigned big endian magnitude, without leading zeros or SSH sign padding.
    ///
    /// Returns an empty slice for zero.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.inner
    }

    /// Is this integer zero?
    #[must_use]
    pub fn is_zero(&self) -> bool {
        self.inner.is_empty()
    }

    /// Does the SSH encoding require a leading zero to avoid a negative sign bit?
    fn needs_padding(&self) -> bool {
        self.inner.first().is_some_and(|byte| *byte >= 0x80)
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
        self.as_bytes().ct_eq(other.as_bytes())
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

#[cfg(feature = "ctutils")]
impl Ord for Mpint {
    fn cmp(&self, other: &Self) -> Ordering {
        // Canonical magnitudes with different byte lengths can be ordered by length.
        match self.inner.len().cmp(&other.inner.len()) {
            Ordering::Equal => {}
            ordering => return ordering,
        }

        // Visit every byte, with more significant differences taking precedence.
        let mut ordering = Ordering::Equal;
        for (a, b) in self.inner.iter().zip(other.inner.iter()).rev() {
            ordering = ordering.ct_select(&Ordering::Less, a.ct_lt(b));
            ordering = ordering.ct_select(&Ordering::Greater, b.ct_lt(a));
        }
        ordering
    }
}

#[cfg(feature = "ctutils")]
impl PartialOrd for Mpint {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Decode for Mpint {
    type Error = Error;

    fn decode(reader: &mut Decoder<impl Reader>) -> Result<Self> {
        reader.read_prefixed(|reader| {
            let len = reader.remaining_len();

            if len > Self::MAX_SIZE + 1 {
                return Err(Error::Length);
            } else if len == 0 {
                return Self::from_bytes(&[]);
            }

            let mut first = u8::decode(reader)?;

            if first >= 0x80 {
                return Err(Error::MpintEncoding);
            } else if first != 0 && len > Self::MAX_SIZE {
                return Err(Error::Length);
            }

            // Like OpenSSH, accept redundant leading zeros, including noncanonical zero.
            while first == 0 {
                if reader.is_finished() {
                    return Self::from_bytes(&[]);
                }
                first = u8::decode(reader)?;
            }

            let mut bytes = crate::vec_zeroed(reader.remaining_len() + 1)?;
            bytes[0] = first;
            reader.read(&mut bytes[1..])?;

            Ok(Self {
                inner: bytes.into_boxed_slice(),
            })
        })
    }
}

impl Encode for Mpint {
    fn encoded_len(&self) -> Result<usize> {
        [4, self.inner.len(), usize::from(self.needs_padding())].checked_sum()
    }

    fn encode(&self, writer: &mut impl Writer) -> Result<()> {
        let padding = self.needs_padding();
        (self.inner.len() + usize::from(padding)).encode(writer)?;

        if padding {
            0u8.encode(writer)?;
        }

        writer.write(self.as_bytes())
    }
}

impl TryFrom<&[u8]> for Mpint {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self> {
        Self::from_bytes(bytes)
    }
}

impl TryFrom<Box<[u8]>> for Mpint {
    type Error = Error;

    fn try_from(bytes: Box<[u8]>) -> Result<Self> {
        if bytes.first() == Some(&0) {
            let result = Self::from_bytes(&bytes);
            #[cfg(feature = "zeroize")]
            {
                let mut bytes = bytes;
                bytes.zeroize();
            }
            result
        } else if bytes.len() > Self::MAX_SIZE {
            Err(Error::Length)
        } else {
            Ok(Self { inner: bytes })
        }
    }
}

#[cfg(feature = "zeroize")]
impl Zeroize for Mpint {
    fn zeroize(&mut self) {
        self.inner.zeroize();
        // Preserve the canonical representation of zero after clearing the buffer.
        self.inner = Box::default();
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
        if self.is_zero() {
            return f.write_str("0");
        }

        for byte in self.as_bytes() {
            write!(f, "{byte:02x}")?;
        }

        Ok(())
    }
}

impl fmt::UpperHex for Mpint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_zero() {
            return f.write_str("0");
        }

        for byte in self.as_bytes() {
            write!(f, "{byte:02X}")?;
        }

        Ok(())
    }
}

#[cfg(feature = "bigint")]
impl TryFrom<&Uint> for Mpint {
    type Error = Error;

    fn try_from(uint: &Uint) -> Result<Self> {
        // Reject oversized values before allocating their byte representation.
        // TODO(tarcieri): use `bit_width_vartime` when we bump `crypto-bigint` version
        #[allow(deprecated, reason = "crypto-bigint v0.7.0 compatibility")]
        let bits = uint.bits_vartime();

        if bits > u32::try_from(Self::MAX_SIZE * 8)? {
            return Err(Error::Length);
        }

        // Serialize directly into the fallibly allocated magnitude buffer.
        let mut inner = crate::vec_with_reserve(usize::try_from(bits.div_ceil(8))?)?;

        for limb in uint.as_limbs().iter().rev() {
            let bytes = limb.0.to_be_bytes();

            let bytes = if inner.is_empty() {
                strip_leading_zeros(&bytes)
            } else {
                &bytes
            };

            inner.extend_from_slice(bytes);
        }

        Ok(Self {
            inner: inner.into_boxed_slice(),
        })
    }
}

#[cfg(feature = "bigint")]
impl TryFrom<Uint> for Mpint {
    type Error = Error;

    fn try_from(uint: Uint) -> Result<Self> {
        Self::try_from(&uint)
    }
}

#[cfg(feature = "bigint")]
impl From<Mpint> for Uint {
    fn from(mpint: Mpint) -> Uint {
        Uint::from(&mpint)
    }
}

#[cfg(feature = "bigint")]
impl From<&Mpint> for Uint {
    fn from(mpint: &Mpint) -> Uint {
        Uint::from_be_slice_vartime(mpint.as_bytes())
    }
}

/// Strip leading zeros from an unsigned big endian magnitude.
fn strip_leading_zeros(mut bytes: &[u8]) -> &[u8] {
    while bytes.first() == Some(&0) {
        bytes = &bytes[1..];
    }
    bytes
}

#[cfg(test)]
mod tests {
    use super::Mpint;
    use crate::{Decode, Encode, Error, Reader};
    use alloc::{format, vec, vec::Vec};
    use hex_literal::hex;

    #[test]
    fn unsigned_bytes() {
        for (bytes, expected) in [
            (&b""[..], &b""[..]),
            (&hex!("00")[..], &b""[..]),
            (&hex!("00 00")[..], &b""[..]),
            (&hex!("00 01")[..], &hex!("01")[..]),
            (&hex!("00 00 80")[..], &hex!("80")[..]),
            (&hex!("80")[..], &hex!("80")[..]),
            (&hex!("ff")[..], &hex!("ff")[..]),
        ] {
            for n in [
                Mpint::from_bytes(bytes).unwrap(),
                Mpint::try_from(bytes).unwrap(),
                Mpint::try_from(Vec::from(bytes).into_boxed_slice()).unwrap(),
            ] {
                assert_eq!(n.as_bytes(), expected);
                assert_eq!(n.is_zero(), expected.is_empty());
            }
        }
    }

    #[test]
    fn ssh_encodings() {
        for (bytes, encoded) in [
            (&b""[..], &hex!("00000000")[..]),
            (&hex!("01")[..], &hex!("00000001 01")[..]),
            (&hex!("7f")[..], &hex!("00000001 7f")[..]),
            (&hex!("80")[..], &hex!("00000002 0080")[..]),
            (&hex!("ff")[..], &hex!("00000002 00ff")[..]),
            (
                &hex!("09 a3 78 f9 b2 e3 32 a7")[..],
                &hex!("00000008 09 a3 78 f9 b2 e3 32 a7")[..],
            ),
        ] {
            let n = Mpint::from_bytes(bytes).unwrap();
            let mut output = Vec::new();
            n.encode(&mut output).unwrap();
            assert_eq!(output, encoded);
            assert_eq!(n.encoded_len().unwrap(), output.len());
            assert_eq!(
                Mpint::decode(&mut encoded.into_decoder().unwrap()).unwrap(),
                n
            );
        }
    }

    #[test]
    fn normalize_ssh_padding() {
        for bytes in [
            &hex!("00")[..],
            &hex!("00 00")[..],
            &hex!("00 01")[..],
            &hex!("00 00 80")[..],
        ] {
            let mut encoded = Vec::new();
            bytes.encode(&mut encoded).unwrap();
            let n = Mpint::decode(&mut encoded.as_slice().into_decoder().unwrap()).unwrap();
            assert_eq!(n, Mpint::from_bytes(bytes).unwrap());
            let mut canonical = Vec::new();
            n.encode(&mut canonical).unwrap();
            assert!(canonical.len() < encoded.len());
        }
    }

    #[test]
    fn reject_negative() {
        for bytes in [
            &hex!("80")[..],
            &hex!("ff")[..],
            &hex!("ed cc")[..],
            &hex!("ff 21 52 41 11")[..],
        ] {
            let mut encoded = Vec::new();
            bytes.encode(&mut encoded).unwrap();
            let mut reader = encoded.as_slice().into_decoder().unwrap();
            assert_eq!(Mpint::decode(&mut reader), Err(Error::MpintEncoding));
            assert_eq!(reader.finish(()), Err(Error::Failed));
        }
    }

    #[test]
    fn size_limits() {
        for size in [Mpint::MAX_SIZE, Mpint::MAX_SIZE + 1] {
            for first in [0x01, 0x7f, 0x80, 0xff] {
                let mut bytes = vec![0xff; size];
                bytes[0] = first;
                // Leading zeros in an unsigned input do not change the magnitude.
                for padding in [0, 1, 2] {
                    let mut padded = vec![0; padding];
                    padded.extend_from_slice(&bytes);
                    for result in [
                        Mpint::from_bytes(&padded),
                        Mpint::try_from(padded.clone().into_boxed_slice()),
                    ] {
                        if size == Mpint::MAX_SIZE {
                            let n = result.unwrap();
                            assert_eq!(n.as_bytes(), bytes);
                            let mut encoded = Vec::new();
                            n.encode(&mut encoded).unwrap();
                            assert_eq!(n.encoded_len().unwrap(), encoded.len());
                            assert_eq!(
                                Mpint::decode(&mut encoded.as_slice().into_decoder().unwrap())
                                    .unwrap(),
                                n
                            );
                        } else {
                            assert_eq!(result, Err(Error::Length));
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn ssh_size_limits_before_normalization() {
        for (first, size, valid) in [
            (0x7f, Mpint::MAX_SIZE, true),
            (0x00, Mpint::MAX_SIZE + 1, true),
            (0x01, Mpint::MAX_SIZE + 1, false),
            (0x00, Mpint::MAX_SIZE + 2, false),
        ] {
            // Even all-zero encodings must obey the wire size limit.
            for rest in [0, 0xff] {
                let mut bytes = vec![rest; size];
                bytes[0] = first;
                let mut encoded = Vec::new();
                bytes.encode(&mut encoded).unwrap();
                let result = Mpint::decode(&mut encoded.as_slice().into_decoder().unwrap());
                if valid {
                    assert_eq!(result.unwrap(), Mpint::from_bytes(&bytes).unwrap());
                } else {
                    assert_eq!(result, Err(Error::Length));
                }
            }
        }
    }

    #[test]
    fn reject_oversized_before_reading_body() {
        struct Unreadable {
            prefix: Option<[u8; 4]>,
        }

        impl Reader for Unreadable {
            fn read<'o>(&mut self, out: &'o mut [u8]) -> crate::Result<&'o [u8]> {
                let prefix = self
                    .prefix
                    .take()
                    .expect("oversized mpint body must not be read");
                out.copy_from_slice(&prefix);
                Ok(out)
            }

            fn remaining_len(&self) -> usize {
                Mpint::MAX_SIZE + 2 + if self.prefix.is_some() { 4 } else { 0 }
            }
        }

        let reader = Unreadable {
            prefix: Some(u32::try_from(Mpint::MAX_SIZE + 2).unwrap().to_be_bytes()),
        };
        assert_eq!(
            Mpint::decode(&mut reader.into_decoder().unwrap()),
            Err(Error::Length)
        );
    }

    #[test]
    #[cfg(feature = "ctutils")]
    fn numeric_ordering() {
        let values = [
            0u32, 1, 0x7f, 0x80, 0xff, 0x100, 0x101, 0x1ff, 0x200, 0xffff, 0x10000,
        ];
        for a in values {
            for b in values {
                let x = Mpint::from_bytes(&a.to_be_bytes()).unwrap();
                let y = Mpint::from_bytes(&b.to_be_bytes()).unwrap();
                assert_eq!(x == y, a == b);
                assert_eq!(x.cmp(&y), a.cmp(&b));
                assert_eq!(x.partial_cmp(&y), a.partial_cmp(&b));
            }
        }
    }

    #[test]
    fn formatting() {
        let zero = Mpint::from_bytes(&[]).unwrap();
        assert_eq!(
            format!("{zero} {zero:x} {zero:X} {zero:?}"),
            "0 0 0 Mpint(0)"
        );
        let n = Mpint::from_bytes(&hex!("00 ab cd")).unwrap();
        assert_eq!(
            format!("{n} {n:x} {n:X} {n:?}"),
            "ABCD abcd ABCD Mpint(ABCD)"
        );
    }

    #[cfg(feature = "zeroize")]
    #[test]
    fn zeroize_preserves_invariants() {
        use zeroize::Zeroize;
        let mut n = Mpint::from_bytes(&hex!("80 ff")).unwrap();
        n.zeroize();
        assert!(n.is_zero());
        assert_eq!(n, Mpint::from_bytes(&[]).unwrap());
        let mut encoded = Vec::new();
        n.encode(&mut encoded).unwrap();
        assert_eq!(encoded, hex!("00000000"));
    }

    #[cfg(feature = "bigint")]
    #[test]
    fn bigint_conversions() {
        use crate::Uint;
        for bytes in [
            vec![],
            vec![0],
            vec![0x80],
            hex!("12 34 56 78 9a bc de f0 00 01").to_vec(),
            vec![0xff; Mpint::MAX_SIZE],
            vec![0xff; Mpint::MAX_SIZE + 1],
        ] {
            let uint = Uint::from_be_slice_vartime(&bytes);
            for result in [Mpint::try_from(&uint), Mpint::try_from(uint.clone())] {
                if bytes.len() <= Mpint::MAX_SIZE {
                    let n = result.unwrap();
                    assert_eq!(n, Mpint::from_bytes(&bytes).unwrap());
                    assert_eq!(Uint::from(&n), uint);
                    assert_eq!(Uint::from(n), uint);
                } else {
                    assert_eq!(result, Err(Error::Length));
                }
            }
        }
        // Precision larger than the cap is allowed when the magnitude fits.
        let mut padded = vec![0; Mpint::MAX_SIZE + 1];
        padded[Mpint::MAX_SIZE] = 1;
        let uint = Uint::from_be_slice_vartime(&padded);
        assert_eq!(Mpint::try_from(&uint).unwrap().as_bytes(), &[1]);
    }
}
