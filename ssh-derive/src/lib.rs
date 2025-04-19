#![doc = include_str!("../README.md")]

//! ## About
//! Custom derive support for the [`ssh-encoding`] crate.
//!
//! Note that this crate shouldn't be used directly, but instead accessed
//! by using the `derive` feature of the [`ssh-encoding`] crate, which re-exports this crate's
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

mod attributes;
mod decode;
mod encode;

use proc_macro::TokenStream;
use syn::{DeriveInput, parse_macro_input};

/// Derive the [`Decode`][1] trait on a `struct`.
///
/// [1]: https://docs.rs/ssh-derive/latest/ssh-derive/trait.Decode.html
#[proc_macro_derive(Decode, attributes(ssh))]
pub fn derive_decode(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    match decode::try_derive_decode(input) {
        Ok(t) => t.into(),
        Err(e) => e.to_compile_error().into(),
    }
}

/// Derive the [`Encode`][1] trait on a `struct`.
///
/// [1]: https://docs.rs/ssh-derive/latest/ssh-derive/trait.Encode.html
#[proc_macro_derive(Encode, attributes(ssh))]
pub fn derive_encode(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    match encode::try_derive_encode(input) {
        Ok(t) => t.into(),
        Err(e) => e.to_compile_error().into(),
    }
}
