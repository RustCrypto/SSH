//! Support for deriving the `Decode` trait on structs.

use proc_macro2::TokenStream;
use quote::quote;
use syn::{spanned::Spanned, DataEnum, DataStruct, DeriveInput};

use crate::attributes::{ContainerAttributes, FieldAttributes};

pub(crate) fn try_derive_decode(input: DeriveInput) -> syn::Result<TokenStream> {
    match input.data {
        syn::Data::Struct(ref data) => try_derive_decode_for_struct(&input, data),
        syn::Data::Enum(ref data) => try_derive_decode_for_enum(&input, data),
        syn::Data::Union(_) => abort!(input.ident, "can't derive `Decode` on union types",),
    }
}

fn try_derive_decode_for_struct(
    input: &DeriveInput,
    DataStruct { fields, .. }: &DataStruct,
) -> syn::Result<TokenStream> {
    let container_attributes = ContainerAttributes::try_from(input)?;
    let struct_name = &input.ident;
    let body = derive_for_fields(fields, quote! { Self })?;
    let body = maybe_length_prefixed(container_attributes.length_prefixed, &body);
    let (impl_generics, type_generics, where_clause) = input.generics.split_for_impl();

    Ok(quote! {
        #[automatically_derived]
        impl #impl_generics ::ssh_encoding::Decode for #struct_name #type_generics #where_clause {
            type Error = ::ssh_encoding::Error;

            fn decode(reader: &mut impl ::ssh_encoding::Reader) -> ::core::result::Result<Self, Self::Error> {
                #body
            }
        }
    })
}

fn try_derive_decode_for_enum(
    input: &DeriveInput,
    DataEnum { variants, .. }: &DataEnum,
) -> syn::Result<TokenStream> {
    let container_attributes = ContainerAttributes::try_from(input)?;
    let enum_name = &input.ident;
    let discriminant_type = container_attributes
        .discriminant_type
        .clone()
        .ok_or_else(|| {
            syn::Error::new(
                input.ident.span(),
                "enums must have a repr attribute to derive `Decode`",
            )
        })?;
    let variant_arms = variants
        .iter()
        .map(|variant| {
            let variant_name = &variant.ident;
            let discriminant = variant
                .discriminant
                .as_ref()
                .map(|(_, variant)| variant)
                .ok_or_else(|| {
                    syn::Error::new(
                        variant.span(),
                        "enum variants must have an explicit discriminant to derive `Decode`",
                    )
                })?;
            let body = derive_for_fields(&variant.fields, quote! { #enum_name::#variant_name })?;
            Ok(quote! { #discriminant => { #body } })
        })
        .collect::<syn::Result<Vec<_>>>()?;
    let (impl_generics, type_generics, where_clause) = input.generics.split_for_impl();

    let body = quote! {
        let discriminant = <#discriminant_type as ::ssh_encoding::Decode>::decode(reader)?;
        match discriminant {
            #(#variant_arms,)*
            _ => return Err(::ssh_encoding::Error::InvalidDiscriminant(discriminant.into()).into()),
        }
    };
    let body = maybe_length_prefixed(container_attributes.length_prefixed, &body);

    Ok(quote! {
        #[automatically_derived]
        impl #impl_generics ::ssh_encoding::Decode for #enum_name #type_generics #where_clause {
            type Error = ::ssh_encoding::Error;

            fn decode(reader: &mut impl ::ssh_encoding::Reader) -> ::core::result::Result<Self, Self::Error> {
                #body
            }
        }
    })
}

/// Generate decoding code for the given fields.
///
/// This will also handle length-prefixed containers if it is marked as such.
fn derive_for_fields(
    fields: &syn::Fields,
    output_type_or_variant: TokenStream,
) -> syn::Result<TokenStream> {
    let mut field_decoders = Vec::with_capacity(fields.len());

    for field in fields {
        let attrs = FieldAttributes::try_from(field)?;
        let ty = &field.ty;
        field_decoders.push(
            if attrs.length_prefixed {
                quote! { reader.read_prefixed(|reader| <#ty as ::ssh_encoding::Decode>::decode(reader))? }
            } else {
                quote! { <#ty as ::ssh_encoding::Decode>::decode(reader)? }
            }
        );
    }

    let body = match fields {
        syn::Fields::Unit => output_type_or_variant,
        syn::Fields::Named(named) => {
            let named = named
                .named
                .iter()
                .map(|field| field.ident.as_ref().expect("named fields are named"));
            quote! { #output_type_or_variant { #(#named: #field_decoders),* } }
        }
        syn::Fields::Unnamed(_) => {
            quote! { #output_type_or_variant ( #(#field_decoders),* ) }
        }
    };

    Ok(body)
}

fn maybe_length_prefixed(length_prefix: bool, body: &TokenStream) -> TokenStream {
    if length_prefix {
        quote! {
            reader.read_prefixed(|reader| {
                Ok::<_, ::ssh_encoding::Error>({#body})
            })
        }
    } else {
        quote! { Ok({#body}) }
    }
}
