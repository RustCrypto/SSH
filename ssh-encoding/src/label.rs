//! Convenience trait for decoding/encoding string labels.

use crate::{Decode, Encode, Reader, Writer};
use core::str::FromStr;

/// Maximum size of any algorithm name/identifier.
const MAX_LABEL_SIZE: usize = 48;

/// Labels for e.g. cryptographic algorithms.
///
/// Receives a blanket impl of [`Decode`] and [`Encode`].
pub trait Label: AsRef<str> + FromStr<Err = Self::Error> {
    /// Type returned in the event of an encoding error.
    type Error: From<crate::Error>;
}

impl<T: Label> Decode for T {
    type Error = T::Error;

    fn decode(reader: &mut impl Reader) -> Result<Self, T::Error> {
        let mut buf = [0u8; MAX_LABEL_SIZE];
        reader.read_string(buf.as_mut())?.parse()
    }
}

impl<T: Label> Encode for T {
    type Error = T::Error;

    fn encoded_len(&self) -> Result<usize, T::Error> {
        Ok(self.as_ref().encoded_len()?)
    }

    fn encode(&self, writer: &mut impl Writer) -> Result<(), T::Error> {
        Ok(self.as_ref().encode(writer)?)
    }
}
