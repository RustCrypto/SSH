//! Support for deriving the `Decode` trait on structs.

use crate::FieldIr;
use proc_macro2::TokenStream;
use quote::quote;
use syn::{DeriveInput, Generics, Ident};

/// Derive the `Decode` trait for a struct
pub(crate) struct DeriveDecode {
    /// Name of the struct.
    ident: Ident,

    /// Generics of the struct.
    generics: Generics,

    /// Fields of the struct.
    fields: Vec<FieldIr>,
}

impl DeriveDecode {
    /// Parse [`DeriveInput`].
    pub fn new(input: DeriveInput) -> syn::Result<Self> {
        let data = match input.data {
            syn::Data::Struct(data) => data,
            _ => abort!(
                input.ident,
                "can't derive `Decode` on this type: only `struct` types are allowed",
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
        let body = lowerer.into_tokens();

        quote! {
            #[automatically_derived]
            impl #generics ::ssh_encoding::Decode for #ident #generics #where_clause {
                type Error = ::ssh_encoding::Error;

                fn decode(reader: &mut impl ::ssh_encoding::Reader) -> Result<Self, Self::Error> {
                    Ok(Self {
                        #(#body),*
                    })
                }
            }
        }
    }
}

/// AST lowerer for field decoders.
struct FieldLowerer {
    /// Decoder-in-progress.
    body: Vec<TokenStream>,
}

impl FieldLowerer {
    /// Create a new field decoder lowerer.
    fn new() -> Self {
        Self {
            body: Vec::default(),
        }
    }

    /// Add a field to the lowerer.
    fn add_field(&mut self, field: &FieldIr) {
        let ident = field.ident.clone();
        let ty = field.ty.clone();
        let field = quote! { #ident: <#ty as ::ssh_encoding::Decode>::decode(reader)? };
        self.body.push(field);
    }

    /// Return the resulting tokens.
    fn into_tokens(self) -> Vec<TokenStream> {
        self.body
    }
}
