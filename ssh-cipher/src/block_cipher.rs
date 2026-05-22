//! Low-level block cipher interface for SSH symmetric ciphers.

mod algorithm;

pub use ::cipher::BlockSizeUser;
pub use algorithm::Algorithm;

/// Block ciphers used by SSH.
pub trait BlockCipher: BlockSizeUser {
    /// Block cipher algorithm.
    const ALGORITHM: Algorithm;
}

/// Supported block cipher modes of operation.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum BlockMode {
    /// Cipher block chaining.
    Cbc,

    /// Counter mode.
    Ctr,
}
