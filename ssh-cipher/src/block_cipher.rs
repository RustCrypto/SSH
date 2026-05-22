//! Low-level block cipher interface.
//!
//! This module provides APIs which enable streaming and "peeking" when using unauthenticated block
//! cipher modes such as CBC and CTR.

#[cfg(feature = "aes")]
mod aes;
mod decryptor;
mod encryptor;

pub use self::{decryptor::Decryptor, encryptor::Encryptor};

#[cfg(feature = "aes")]
pub(crate) use self::aes::Aes;
