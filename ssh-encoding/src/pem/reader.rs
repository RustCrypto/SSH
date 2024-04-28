use super::LINE_WIDTH;
use crate::{Decode, Error, Reader, Result};

/// Inner PEM decoder.
type Inner<'i> = pem_rfc7468::Decoder<'i>;

/// Constant-time PEM reader.
pub struct PemReader<'i> {
    /// Inner PEM reader.
    inner: Inner<'i>,

    /// Custom length of remaining data, used for nested length-prefixed reading.
    remaining_len: usize,
}

impl<'i> PemReader<'i> {
    /// Create a new PEM reader.
    ///
    /// Uses [`LINE_WIDTH`] as the default line width (i.e. 70 chars).
    pub fn new(pem: &'i [u8]) -> Result<Self> {
        let inner = Inner::new_wrapped(pem, LINE_WIDTH)?;
        let remaining_len = inner.remaining_len();

        Ok(Self {
            inner,
            remaining_len,
        })
    }

    /// Get the PEM type label for the input document.
    pub fn type_label(&self) -> &'i str {
        self.inner.type_label()
    }
}

impl_reader_for_newtype!(PemReader<'_>);
