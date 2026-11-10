use crate::{Reader, Result};

/// Inner PEM decoder.
type Inner<'i> = pem_rfc7468::Decoder<'i>;

/// Constant-time PEM reader.
pub(crate) struct PemReader<'i> {
    /// Inner PEM reader.
    inner: Inner<'i>,
}

impl<'i> PemReader<'i> {
    /// Create a new PEM reader which autodetects the line width of the input.
    pub(crate) fn new(pem: &'i [u8]) -> Result<Self> {
        let inner = Inner::new_detect_wrap(pem)?;

        Ok(Self { inner })
    }

    /// Get the PEM type label for the input document.
    pub(crate) fn type_label(&self) -> &'i str {
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
