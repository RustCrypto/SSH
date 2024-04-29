//! Base64 reader support (constant-time).

use crate::{Reader, Result};

/// Inner constant-time Base64 reader type from the `base64ct` crate.
type Inner<'i> = base64ct::Decoder<'i, base64ct::Base64>;

/// Constant-time Base64 reader implementation.
pub struct Base64Reader<'i> {
    inner: Inner<'i>,
}

impl<'i> Base64Reader<'i> {
    /// Create a new Base64 reader for a byte slice containing contiguous (non-newline-delimited)
    /// Base64-encoded data.
    ///
    /// # Returns
    /// - `Ok(reader)` on success.
    /// - `Err(Error::Base64)` if the input buffer is empty.
    pub fn new(input: &'i [u8]) -> Result<Self> {
        Ok(Self {
            inner: Inner::new(input)?,
        })
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
