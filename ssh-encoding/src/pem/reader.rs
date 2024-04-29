use super::LINE_WIDTH;
use crate::{Reader, Result};

/// Inner PEM decoder.
type Inner<'i> = pem_rfc7468::Decoder<'i>;

/// Constant-time PEM reader.
pub struct PemReader<'i> {
    inner: Inner<'i>,
}

impl<'i> PemReader<'i> {
    /// TODO
    pub fn new(pem: &'i [u8]) -> Result<Self> {
        Ok(Self {
            inner: Inner::new_wrapped(pem, LINE_WIDTH)?,
        })
    }

    /// Get the PEM type label for the input document.
    pub fn type_label(&self) -> &'i str {
        self.inner.type_label()
    }
}

impl Reader for PemReader<'_> {
    fn read<'o>(&mut self, out: &'o mut [u8]) -> Result<&'o [u8]> {
        Ok(self.inner.decode(out)?)
    }

    fn remaining_len(&self) -> usize {
        self.inner.remaining_len()
    }
}
