#![doc = include_str!("../README.md")]

//! ## About
//! Custom derive support for the [`ssh-encoding`] crate.
//!
//! Note that this crate shouldn't be used directly, but instead accessed
//! by using the `derive` feature of the `der` crate, which re-exports this crate's
//! macros from the toplevel.
//!
//! [`ssh-encoding`]: ../ssh-encoding

#![crate_type = "proc-macro"]
#![forbid(unsafe_code)]
#![warn(
    clippy::unwrap_used,
    rust_2018_idioms,
    trivial_casts,
    unused_qualifications
)]

macro_rules! abort {
    ( $tokens:expr, $message:expr $(,)? ) => {
        return Err(syn::Error::new_spanned($tokens, $message))
    };
}

mod decode;
mod encode;
mod field_ir;

use crate::{decode::DeriveDecode, encode::DeriveEncode, field_ir::FieldIr};
use proc_macro::TokenStream;
use syn::{parse_macro_input, DeriveInput};

/// Derive the [`Decode`][1] trait on a `struct`.
///
/// [1]: https://docs.rs/ssh-derive/latest/ssh-derive/trait.Decode.html
#[proc_macro_derive(Decode, attributes(ssh))]
pub fn derive_decode(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    match DeriveDecode::new(input) {
        Ok(t) => t.to_tokens().into(),
        Err(e) => e.to_compile_error().into(),
    }
}

/// Derive the [`Encode`][1] trait on a `struct`.
///
/// [1]: https://docs.rs/ssh-derive/latest/ssh-derive/trait.Encode.html
#[proc_macro_derive(Encode, attributes(ssh))]
pub fn derive_encode(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    match DeriveEncode::new(input) {
        Ok(t) => t.to_tokens().into(),
        Err(e) => e.to_compile_error().into(),
    }
}
