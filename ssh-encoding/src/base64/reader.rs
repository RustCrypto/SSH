//! Base64 reader support (constant-time).

use crate::{Reader, Result};
use core::fmt::{self, Debug};

/// Inner constant-time Base64 reader type from the `base64ct` crate.
type Inner<'i> = base64ct::Decoder<'i, base64ct::Base64>;

/// Constant-time Base64 reader implementation.
pub struct Base64Reader<'i> {
    /// Inner Base64 reader.
    inner: Inner<'i>,
}

impl<'i> Base64Reader<'i> {
    /// Create a new Base64 reader for a byte slice containing contiguous (non-newline-delimited)
    /// Base64-encoded data.
    ///
    /// # Errors
    /// Returns [`crate::Error::Base64`] if the `input` buffer is empty.
    pub fn new(input: &'i [u8]) -> Result<Self> {
        let inner = Inner::new(input)?;

        Ok(Self { inner })
    }
}

impl Debug for Base64Reader<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Base64Reader")
            .field("remaining_len", &self.remaining_len())
            .finish_non_exhaustive()
    }
}

impl Reader for Base64Reader<'_> {
    fn read<'o>(&mut self, out: &'o mut [u8]) -> Result<&'o [u8]> {
        Ok(self.inner.decode(out)?)
    }

    fn remaining_len(&self) -> usize {
        self.inner.remaining_len()
    }
}
