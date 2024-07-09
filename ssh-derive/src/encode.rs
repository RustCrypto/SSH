//! Support for deriving the `Encode` trait on structs.

use crate::FieldIr;
use proc_macro2::TokenStream;
use quote::quote;
use syn::{DeriveInput, Generics, Ident};

/// Derive the `Encode` trait for a struct
pub(crate) struct DeriveEncode {
    /// Name of the struct.
    ident: Ident,

    /// Generics of the struct.
    generics: Generics,

    /// Fields of the struct.
    fields: Vec<FieldIr>,
}

impl DeriveEncode {
    /// Parse [`DeriveInput`].
    pub fn new(input: DeriveInput) -> syn::Result<Self> {
        let data = match input.data {
            syn::Data::Struct(data) => data,
            _ => abort!(
                input.ident,
                "can't derive `Encode` on this type: only `struct` types are allowed",
            ),
        };

        let fields = FieldIr::from_fields(data.fields)?;

        Ok(Self {
            ident: input.ident,
            generics: input.generics.clone(),
            fields,
        })
    }

    /// Lower the derived output into a [`TokenStream`].
    pub fn to_tokens(&self) -> TokenStream {
        let ident = &self.ident;
        let (_, generics, where_clause) = self.generics.split_for_impl();

        let mut lowerer = FieldLowerer::new();
        for field in &self.fields {
            lowerer.add_field(field);
        }
        let (encoded_len_body, encode_body) = lowerer.into_tokens();

        quote! {
            impl #generics ::ssh_encoding::Encode for #ident #generics #where_clause {
                fn encoded_len(&self) -> ssh_encoding::Result<usize> {
                    [
                        #(#encoded_len_body)*,
                    ]
                    .checked_sum()
                }

                fn encode(&self, writer: &mut impl Writer) -> ssh_encoding::Result<()> {
                    #(#encode_body)*;
                    Ok(())
                }
            }
        }
    }
}

/// AST lowerer for field decoders.
struct FieldLowerer {
    /// Encoded length calculation in progress.
    encoded_len_body: Vec<TokenStream>,

    /// Encoder-in-progress.
    encode_body: Vec<TokenStream>,
}

impl FieldLowerer {
    /// Create a new field decoder lowerer.
    fn new() -> Self {
        Self {
            encoded_len_body: Vec::default(),
            encode_body: Vec::default(),
        }
    }

    /// Add a field to the lowerer.
    fn add_field(&mut self, field: &FieldIr) {
        let ident = field.ident.clone();

        let field_length = quote! { self.#ident.encoded_len()? };
        self.encoded_len_body.push(field_length);

        let field_encoder = quote! { self.#ident.encode()? };
        self.encode_body.push(field_encoder);
    }

    /// Return the resulting tokens.
    fn into_tokens(self) -> (Vec<TokenStream>, Vec<TokenStream>) {
        (self.encoded_len_body, self.encode_body)
    }
}
