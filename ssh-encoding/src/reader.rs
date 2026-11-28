//! Reader trait and associated implementations.

use crate::{Decoder, Error, Result};

/// Byte reader for raw or incrementally decoded input.
///
/// Use [`Reader::into_decoder`] to decode SSH protocol data types. Readers only supply bytes;
/// the decoder enforces nested length boundaries and complete consumption.
pub trait Reader: Sized {
    /// Read as much data as is needed to exactly fill `out`.
    ///
    /// Returns `out` reborrowed as an immutable byte slice. On success, [`Reader::remaining_len`]
    /// must decrease by exactly `out.len()` bytes. A read error may leave the reader partially
    /// advanced; the enclosing decoder will reject subsequent reads.
    ///
    /// # Errors
    /// Returns an error if the exact amount of data could not be read or decoded.
    fn read<'o>(&mut self, out: &'o mut [u8]) -> Result<&'o [u8]>;

    /// Get the length of the remaining decoded data.
    fn remaining_len(&self) -> usize;

    /// Consume this reader, wrapping it in a decoder for SSH protocol data types.
    ///
    /// # Errors
    /// Returns [`Error::Length`] if the remaining decoded input exceeds `MAX_MSG_SIZE`.
    fn into_decoder(self) -> Result<Decoder<Self>> {
        Decoder::new(self)
    }
}

impl Reader for &[u8] {
    fn read<'o>(&mut self, out: &'o mut [u8]) -> Result<&'o [u8]> {
        if self.len() >= out.len() {
            let (head, tail) = self.split_at(out.len());
            *self = tail;
            out.copy_from_slice(head);
            Ok(out)
        } else {
            Err(Error::Length)
        }
    }

    fn remaining_len(&self) -> usize {
        self.len()
    }
}

impl<R: Reader> Reader for &mut R {
    fn read<'o>(&mut self, out: &'o mut [u8]) -> Result<&'o [u8]> {
        (**self).read(out)
    }

    fn remaining_len(&self) -> usize {
        (**self).remaining_len()
    }
}
