/// Block cipher algorithms supported by this crate which can be used with the low-level API.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub enum Algorithm {
    /// Advanced Encryption Standard (preferred).
    #[cfg(feature = "aes")]
    Aes,

    /// 3DES a.k.a. triple DES (legacy).
    #[cfg(feature = "tdes")]
    Tdes,
}

impl Algorithm {
    /// Size of a block for the given cipher in bytes.
    pub fn block_size(self) -> usize {
        match self {
            #[cfg(feature = "aes")]
            Self::Aes => crate::AES_BLOCK_SIZE,
            #[cfg(feature = "tdes")]
            Self::Tdes => crate::TDES_BLOCK_SIZE,
        }
    }
}
