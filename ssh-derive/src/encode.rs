//! Support for deriving the `Encode` trait on structs.

use proc_macro2::TokenStream;
use quote::{quote, ToTokens};
use syn::{spanned::Spanned, DataEnum, DataStruct, DeriveInput};

use crate::attributes::{ContainerAttributes, FieldAttributes};

pub(crate) fn try_derive_encode(input: DeriveInput) -> syn::Result<TokenStream> {
    match input.data {
        syn::Data::Struct(ref data) => try_derive_encode_for_struct(&input, data),
        syn::Data::Enum(ref data) => try_derive_encode_for_enum(&input, data),
        syn::Data::Union(_) => abort!(input.ident, "can't derive `Encode` on union types",),
    }
}

fn try_derive_encode_for_struct(
    input: &DeriveInput,
    DataStruct { fields, .. }: &DataStruct,
) -> syn::Result<TokenStream> {
    let container_attributes = ContainerAttributes::try_from(input)?;
    let names = fields_variables(fields, true);
    let (field_lengths, field_encoders) = derive_for_fields(fields, names)?;
    let (length_prefix_len, length_prefix_encoder) =
        maybe_length_prefix(container_attributes.length_prefixed);
    let struct_name = &input.ident;
    let (impl_generics, type_generics, where_clause) = input.generics.split_for_impl();

    Ok(quote! {
        #[automatically_derived]
        impl #impl_generics ::ssh_encoding::Encode for #struct_name #type_generics #where_clause {
            fn encoded_len(&self) -> ::ssh_encoding::Result<usize> {
                use ::ssh_encoding::CheckedSum;
                [
                    #length_prefix_len
                    #(#field_lengths),*
                ].checked_sum()
            }

            fn encode(&self, writer: &mut impl ::ssh_encoding::Writer) -> ::ssh_encoding::Result<()> {
                #length_prefix_encoder
                #(#field_encoders)*
                Ok(())
            }
        }
    })
}

fn try_derive_encode_for_enum(
    input: &DeriveInput,
    DataEnum { variants, .. }: &DataEnum,
) -> syn::Result<TokenStream> {
    let enum_name = &input.ident;
    let container_attributes = ContainerAttributes::try_from(input)?;
    let (length_arms, encode_arms) =
        derive_for_variants(&container_attributes, variants.iter(), enum_name)?;
    let (impl_generics, type_generics, where_clause) = input.generics.split_for_impl();

    Ok(quote! {
        #[automatically_derived]
        impl #impl_generics ::ssh_encoding::Encode for #enum_name #type_generics #where_clause {
            fn encoded_len(&self) -> ::ssh_encoding::Result<usize> {
                use ::ssh_encoding::CheckedSum;
                match self {
                    #(#length_arms)*
                }
            }
            fn encode(&self, writer: &mut impl ::ssh_encoding::Writer) -> ::ssh_encoding::Result<()> {
                match self {
                    #(#encode_arms)*
                }
                Ok(())
            }
        }
    })
}

/// Generate encoding code for the given fields, bound to the given names.
///
/// This will also handle length-prefixing the container if it is marked as such.
fn derive_for_fields(
    fields: &syn::Fields,
    names: Vec<TokenStream>,
) -> syn::Result<(Vec<TokenStream>, Vec<TokenStream>)> {
    let mut lengths = Vec::new();
    let mut encoders = Vec::new();
    for (field, name) in fields.iter().zip(names) {
        let attrs = FieldAttributes::try_from(field)?;
        if attrs.length_prefixed {
            lengths.push(quote! { ::ssh_encoding::Encode::encoded_len_prefixed(#name)? });
            encoders.push(quote! { ::ssh_encoding::Encode::encode_prefixed(#name, writer)?; });
        } else {
            lengths.push(quote! { ::ssh_encoding::Encode::encoded_len(#name)? });
            encoders.push(quote! { ::ssh_encoding::Encode::encode(#name, writer)?; });
        }
    }

    Ok((lengths, encoders))
}

fn derive_for_variants<'a>(
    container_attributes: &ContainerAttributes,
    variants: impl Iterator<Item = &'a syn::Variant>,
    enum_name: &'a syn::Ident,
) -> syn::Result<(Vec<TokenStream>, Vec<TokenStream>)> {
    let mut length_arms = Vec::new();
    let mut encode_arms = Vec::new();
    for variant in variants {
        let variant_name = &variant.ident;
        let names = fields_variables(&variant.fields, false);
        let match_variant = match &variant.fields {
            syn::Fields::Unit => quote! {},
            syn::Fields::Named(_) => quote! { {#(#names),*} },
            syn::Fields::Unnamed(_) => quote! { (#(#names),*)  },
        };

        let discriminant_type =
            container_attributes
                .discriminant_type
                .clone()
                .ok_or_else(|| {
                    syn::Error::new(
                        variant.span(),
                        "enum must have a repr attribute to derive `Encode`",
                    )
                })?;
        let discriminant = variant
            .discriminant
            .as_ref()
            .map(|(_, variant)| variant)
            .ok_or_else(|| {
                syn::Error::new(
                    variant.span(),
                    "enum variants must have an explicit discriminant to derive `Encode`",
                )
            })?;
        let (field_lengths, field_encoders) = derive_for_fields(&variant.fields, names)?;
        let (length_prefix_len, length_prefix_encoder) =
            maybe_length_prefix(container_attributes.length_prefixed);
        length_arms.push(quote! {
            #enum_name::#variant_name #match_variant => {
                [
                    #length_prefix_len
                    ::core::mem::size_of::<#discriminant_type>(),
                    #(#field_lengths),*
                ].checked_sum()
            }
        });
        encode_arms.push(quote! {
            #enum_name::#variant_name #match_variant => {
                #length_prefix_encoder
                ::ssh_encoding::Encode::encode(&(#discriminant as #discriminant_type), writer)?;
                #(#field_encoders)*
            }
        });
    }

    Ok((length_arms, encode_arms))
}

/// Generate length prefixing code or empty token streams if not needed.
fn maybe_length_prefix(length_prefix: bool) -> (TokenStream, TokenStream) {
    if length_prefix {
        (
            quote! { ::ssh_encoding::Encode::encoded_len(&0usize)?, },
            quote! {{
                let len = ::ssh_encoding::Encode::encoded_len(self)? - ::ssh_encoding::Encode::encoded_len(&0usize)?;
                ::ssh_encoding::Encode::encode(&len, writer)?;
            }},
        )
    } else {
        (quote! {}, quote! {})
    }
}

/// Generate a list of field variables for a struct or enum variant.
///
/// If `use_self` is true, the fields are accessed using `self.<name>` (for struct fields).
/// Otherwise, the fields are accessed directly (for enum variants and match expressions).
fn fields_variables(fields: &syn::Fields, use_self: bool) -> Vec<TokenStream> {
    match &fields {
        syn::Fields::Unit => Vec::new(),
        syn::Fields::Named(field_names) => field_names
            .named
            .iter()
            .map(|field| {
                (
                    field
                        .ident
                        .as_ref()
                        .expect("named fields are named")
                        .to_token_stream(),
                    matches!(field.ty, syn::Type::Reference(_)),
                )
            })
            .map(|(name, is_ref)| match (use_self, is_ref) {
                (true, true) => quote! { self.#name }, // Avoid double referencing.
                (true, false) => quote! { &self.#name }, // Reference the field.
                (false, _) => name, // Not via self, so variable should already be a reference.
            })
            .collect(),

        syn::Fields::Unnamed(field_types) => field_types
            .unnamed
            .iter()
            .enumerate()
            .map(|(i, field)| {
                if use_self {
                    let index = syn::Index::from(i);
                    if let syn::Type::Reference(_) = field.ty {
                        quote! { self.#index }
                    } else {
                        quote! { &self.#index }
                    }
                } else {
                    syn::Ident::new(&format!("field_{i}"), fields.span()).to_token_stream()
                }
            })
            .collect(),
    }
}
