use super::{PemLabel, reader::PemReader};
use crate::{Decode, Decoder, Error};

/// Decoding trait for PEM documents.
///
/// This is an extension trait which is auto-impl'd for types which impl the [`Decode`],
/// [`PemLabel`], and [`Sized`] traits.
#[diagnostic::on_unimplemented(
    note = "Consider adding impls of `Decode` and `PemLabel` to `{Self}`"
)]
pub trait DecodePem: Decode + PemLabel + Sized {
    /// Decode the provided PEM-encoded string, interpreting the Base64-encoded body of the document
    /// using the [`Decode`] trait.
    ///
    /// # Errors
    /// - Returns [`Error::Pem`] in the event of PEM decoding errors.
    /// - Propagates errors returned from the [`Decode::decode`] method.
    fn decode_pem(pem: impl AsRef<[u8]>) -> Result<Self, Self::Error>;
}

impl<T: Decode + PemLabel + Sized> DecodePem for T {
    fn decode_pem(pem: impl AsRef<[u8]>) -> Result<Self, Self::Error> {
        let reader = PemReader::new(pem.as_ref())?;
        Self::validate_pem_label(reader.type_label()).map_err(Error::from)?;

        let mut decoder = Decoder::from(reader);
        let ret = Self::decode(&mut decoder)?;
        Ok(decoder.finish(ret)?)
    }
}
