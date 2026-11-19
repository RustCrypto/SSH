#![crate_type = "proc-macro"]
#![doc = include_str!("../README.md")]

//! ## About
//! Custom derive support for the [`ssh-encoding`] crate.
//!
//! Note that this crate shouldn't be used directly, but instead accessed
//! by using the `derive` feature of the [`ssh-encoding`] crate, which re-exports this crate's
//! macros from the toplevel.
//!
//! [`ssh-encoding`]: ../ssh-encoding

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

#[cfg(test)]
mod tests {
    use super::{decode, encode};
    use quote::quote;

    #[test]
    fn reject_ssh_attributes_on_variants() {
        for derive in [encode::try_derive_encode, decode::try_derive_decode] {
            for option in [quote!(length_prefixed), quote!(unknown)] {
                let input = syn::parse_quote! {
                    #[repr(u8)]
                    enum Message {
                        #[ssh(#option)]
                        Data(u8) = 1,
                    }
                };
                let err = derive(input).expect_err("variant attribute should be rejected");
                assert_eq!(
                    err.to_string(),
                    "`#[ssh(...)]` is unsupported on enum variants"
                );
            }
        }
    }
}
