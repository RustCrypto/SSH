//! Base64 writer support (constant-time).

use crate::{Result, Writer};

/// Inner constant-time Base64 reader type from the `base64ct` crate.
type Inner<'o> = base64ct::Encoder<'o, base64ct::Base64>;

/// Constant-time Base64 writer implementation.
pub struct Base64Writer<'o> {
    inner: Inner<'o>,
}

impl<'o> Base64Writer<'o> {
    /// Create a new Base64 writer which writes output to the given byte slice.
    ///
    /// Output constructed using this method is not line-wrapped.
    pub fn new(output: &'o mut [u8]) -> Result<Self> {
        Ok(Self {
            inner: Inner::new(output)?,
        })
    }

    /// Finish encoding data, returning the resulting Base64 as a `str`.
    pub fn finish(self) -> Result<&'o str> {
        Ok(self.inner.finish()?)
    }
}

impl Writer for Base64Writer<'_> {
    fn write(&mut self, bytes: &[u8]) -> Result<()> {
        Ok(self.inner.encode(bytes)?)
    }
}
