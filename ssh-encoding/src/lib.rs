#![no_std]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg"
)]
#![forbid(unsafe_code)]
#![warn(
    clippy::alloc_instead_of_core,
    clippy::arithmetic_side_effects,
    clippy::mod_module_files,
    clippy::panic,
    clippy::panic_in_result_fn,
    clippy::std_instead_of_alloc,
    clippy::std_instead_of_core,
    clippy::unwrap_used,
    missing_docs,
    rust_2018_idioms,
    unused_lifetimes,
    unused_qualifications
)]

#[cfg(feature = "alloc")]
#[macro_use]
extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

mod checked;
mod decode;
mod encode;
mod error;
mod label;
mod reader;
mod writer;

#[cfg(feature = "base64")]
pub mod base64;
#[cfg(feature = "pem")]
pub mod pem;

pub use crate::{
    checked::CheckedSum,
    decode::Decode,
    encode::Encode,
    error::{Error, Result},
    label::{Label, LabelError},
    reader::{NestedReader, Reader},
    writer::Writer,
};

#[cfg(feature = "base64")]
pub use crate::{base64::Base64Reader, base64::Base64Writer};

#[cfg(feature = "pem")]
pub use crate::pem::{DecodePem, EncodePem};
