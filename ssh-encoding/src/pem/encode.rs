use super::{writer::PemWriter, LineEnding, PemLabel};
use crate::{Encode, Error};
use core::str;

#[cfg(feature = "alloc")]
use {super::LINE_WIDTH, alloc::string::String};

/// Encoding trait for PEM documents.
///
/// This is an extension trait which is auto-impl'd for types which impl the
/// [`Encode`] and [`PemLabel`] traits.
pub trait EncodePem: Encode + PemLabel {
    /// Encode this type using the [`Encode`] trait, writing the resulting PEM
    /// document into the provided `out` buffer.
    fn encode_pem<'o>(&self, line_ending: LineEnding, out: &'o mut [u8]) -> Result<&'o str, Error>;

    /// Encode this type using the [`Encode`] trait, writing the resulting PEM
    /// document to a returned [`String`].
    #[cfg(feature = "alloc")]
    fn encode_pem_string(&self, line_ending: LineEnding) -> Result<String, Error>;
}

impl<T: Encode + PemLabel> EncodePem for T {
    fn encode_pem<'o>(&self, line_ending: LineEnding, out: &'o mut [u8]) -> Result<&'o str, Error> {
        let mut writer = PemWriter::new(Self::PEM_LABEL, line_ending, out).map_err(Error::from)?;
        self.encode(&mut writer)?;

        let encoded_len = writer.finish().map_err(Error::from)?;
        str::from_utf8(&out[..encoded_len]).map_err(Error::from)
    }

    #[cfg(feature = "alloc")]
    fn encode_pem_string(&self, line_ending: LineEnding) -> Result<String, Error> {
        let encoded_len = pem_rfc7468::encapsulated_len_wrapped(
            Self::PEM_LABEL,
            LINE_WIDTH,
            line_ending,
            self.encoded_len()?,
        )
        .map_err(Error::from)?;

        let mut buf = vec![0u8; encoded_len];
        let actual_len = self.encode_pem(line_ending, &mut buf)?.len();
        buf.truncate(actual_len);
        String::from_utf8(buf).map_err(Error::from)
    }
}
