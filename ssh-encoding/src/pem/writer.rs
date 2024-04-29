use super::{LineEnding, LINE_WIDTH};
use crate::{Result, Writer};

/// Inner PEM encoder.
type Inner<'o> = pem_rfc7468::Encoder<'static, 'o>;

/// Constant-time PEM writer.
pub struct PemWriter<'o> {
    inner: Inner<'o>,
}

impl<'o> PemWriter<'o> {
    /// Create a new PEM writer with the default options which writes output into the provided
    /// buffer.
    ///
    /// Uses 70-character line wrapping to be equivalent to OpenSSH.
    pub fn new(
        type_label: &'static str,
        line_ending: LineEnding,
        out: &'o mut [u8],
    ) -> Result<Self> {
        Ok(Self {
            inner: Inner::new_wrapped(type_label, LINE_WIDTH, line_ending, out)?,
        })
    }

    /// Finish encoding PEM, writing the post-encapsulation boundary.
    ///
    /// On success, returns the total number of bytes written to the output
    /// buffer.
    pub fn finish(self) -> Result<usize> {
        Ok(self.inner.finish()?)
    }
}

impl<'o> Writer for PemWriter<'o> {
    fn write(&mut self, bytes: &[u8]) -> Result<()> {
        Ok(self.inner.encode(bytes)?)
    }
}
