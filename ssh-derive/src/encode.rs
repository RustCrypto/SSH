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

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use proc_macro2::Span;
    use quote::quote;

    macro_rules! assert_eq_tokens {
        ($left:expr, $right:expr) => {
            assert_eq!($left.to_string(), $right.to_string());
        };
    }

    #[test]
    fn test_field_variables_unit() {
        let fields = syn::Fields::Unit;
        assert!(fields_variables(&fields, true).is_empty());
        assert!(fields_variables(&fields, false).is_empty());
    }

    #[test]
    fn test_field_variables_named() {
        let fields = syn::Fields::Named(syn::parse_quote! {{ a: u8, b: &u8 }});
        let names = fields_variables(&fields, true);
        assert_eq_tokens!(names[0], quote! { &self.a });
        assert_eq_tokens!(names[1], quote! { self.b });
        let names = fields_variables(&fields, false);
        assert_eq_tokens!(names[0], quote! { a });
        assert_eq_tokens!(names[1], quote! { b });
    }

    #[test]
    fn test_field_variables_unnamed() {
        let fields = syn::Fields::Unnamed(syn::parse_quote! { (u8, &u8) });
        let names = fields_variables(&fields, true);
        assert_eq_tokens!(names[0], quote! { &self.0 });
        assert_eq_tokens!(names[1], quote! { self.1 });
        let names = fields_variables(&fields, false);
        assert_eq_tokens!(names[0], quote! { field_0 });
        assert_eq_tokens!(names[1], quote! { field_1 });
    }

    #[test]
    fn test_maybe_length_prefix() {
        let (len, encoder) = maybe_length_prefix(true);
        assert_eq_tokens!(
            len,
            quote! { ::ssh_encoding::Encode::encoded_len(&0usize)?, }
        );
        assert_eq_tokens!(
            encoder,
            quote! {{
                let len = ::ssh_encoding::Encode::encoded_len(self)? - ::ssh_encoding::Encode::encoded_len(&0usize)?;
                ::ssh_encoding::Encode::encode(&len, writer)?;
            }}
        );

        let (len, encoder) = maybe_length_prefix(false);
        assert_eq_tokens!(len, quote! {});
        assert_eq_tokens!(encoder, quote! {});
    }

    #[test]
    fn test_derive_for_fields() {
        let fields =
            syn::Fields::Named(syn::parse_quote! {{ a: u8, #[ssh(length_prefixed)] b: &u8 }});
        let names = fields_variables(&fields, true);
        let (lengths, encoders) = derive_for_fields(&fields, names).unwrap();
        assert_eq_tokens!(
            lengths[0],
            quote! { ::ssh_encoding::Encode::encoded_len(&self.a)? }
        );
        assert_eq_tokens!(
            encoders[0],
            quote! { ::ssh_encoding::Encode::encode(&self.a, writer)?; }
        );
        assert_eq_tokens!(
            lengths[1],
            quote! { ::ssh_encoding::Encode::encoded_len_prefixed(self.b)? }
        );
        assert_eq_tokens!(
            encoders[1],
            quote! { ::ssh_encoding::Encode::encode_prefixed(self.b, writer)?; }
        );
    }

    #[test]
    fn test_derive_for_fields_bad_attribute() {
        let fields = syn::Fields::Named(syn::parse_quote! {{ #[ssh(not_an_attribute)] a: u8 }});
        let names = fields_variables(&fields, true);
        let err = derive_for_fields(&fields, names).unwrap_err();
        assert_eq!(err.to_string(), "unknown attribute");
    }

    #[test]
    fn test_derive_for_variants_no_repr() {
        let variant: syn::Variant = syn::parse_quote! { Bar };
        let enum_name = syn::Ident::new("Foo", variant.span());
        let container_attributes = ContainerAttributes {
            discriminant_type: None,
            length_prefixed: false,
        };
        let err = derive_for_variants(&container_attributes, std::iter::once(&variant), &enum_name)
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "enum must have a repr attribute to derive `Encode`"
        );
    }

    #[test]
    fn test_derive_for_variants_no_explicit_discriminant() {
        let variant: syn::Variant = syn::parse_quote! { Bar }; // Variant without ` = 123` discriminant.
        let enum_name = syn::Ident::new("Foo", variant.span());
        let container_attributes = ContainerAttributes {
            discriminant_type: Some(quote! { u8 }),
            length_prefixed: false,
        };
        let err = derive_for_variants(&container_attributes, std::iter::once(&variant), &enum_name)
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "enum variants must have an explicit discriminant to derive `Encode`"
        );
    }

    #[test]
    fn test_derive_for_variants() {
        let variants: [syn::Variant; 2] = [
            syn::parse_quote! { Foo(u8, u8) = 1 },
            syn::parse_quote! { Bar { a: u8, #[ssh(length_prefixed)] b: &u8 } = 2 },
        ];
        let enum_name = syn::Ident::new("Enum", Span::call_site());
        let container_attributes = ContainerAttributes {
            discriminant_type: Some(quote! { u8 }),
            length_prefixed: false,
        };
        let (length_arms, encode_arms) =
            derive_for_variants(&container_attributes, variants.iter(), &enum_name).unwrap();
        assert_eq_tokens!(
            length_arms[0],
            quote! {
                Enum::Foo (field_0, field_1) => {
                    [
                        ::core::mem::size_of::<u8>(),
                        ::ssh_encoding::Encode::encoded_len(field_0)?,
                        ::ssh_encoding::Encode::encoded_len(field_1)?
                    ].checked_sum()
                }
            }
        );
        assert_eq_tokens!(
            encode_arms[0],
            quote! {
                Enum::Foo(field_0, field_1) => {
                    ::ssh_encoding::Encode::encode(&(1 as u8), writer)?;
                    ::ssh_encoding::Encode::encode(field_0, writer)?;
                    ::ssh_encoding::Encode::encode(field_1, writer)?;
                }
            }
        );
        assert_eq_tokens!(
            length_arms[1],
            quote! {
                Enum::Bar {a, b} => {
                    [
                        ::core::mem::size_of::<u8>(),
                        ::ssh_encoding::Encode::encoded_len(a)?,
                        ::ssh_encoding::Encode::encoded_len_prefixed(b)?
                    ].checked_sum()
                }
            }
        );
        assert_eq_tokens!(
            encode_arms[1],
            quote! {
                Enum::Bar {a, b} => {
                    ::ssh_encoding::Encode::encode(&(2 as u8), writer)?;
                    ::ssh_encoding::Encode::encode(a, writer)?;
                    ::ssh_encoding::Encode::encode_prefixed(b, writer)?;
                }
            }
        );
    }

    #[test]
    fn test_derive_for_struct() {
        let input: DeriveInput = syn::parse_quote! {
            #[ssh(length_prefixed)]
            struct Foo {
                a: u8,
                #[ssh(length_prefixed)]
                b: &u8,
            }
        };
        let output = try_derive_encode(input).unwrap();
        assert_eq_tokens!(
            output,
            quote! {
                #[automatically_derived]
                impl ::ssh_encoding::Encode for Foo {
                    fn encoded_len(&self) -> ::ssh_encoding::Result<usize> {
                        use ::ssh_encoding::CheckedSum;
                        [
                            ::ssh_encoding::Encode::encoded_len(&0usize)?,
                            ::ssh_encoding::Encode::encoded_len(&self.a)?,
                            ::ssh_encoding::Encode::encoded_len_prefixed(self.b)?
                        ].checked_sum()
                    }

                    fn encode(&self, writer: &mut impl ::ssh_encoding::Writer) -> ::ssh_encoding::Result<()> {
                        {
                            let len = ::ssh_encoding::Encode::encoded_len(self)? - ::ssh_encoding::Encode::encoded_len(&0usize)?;
                            ::ssh_encoding::Encode::encode(&len, writer)?;
                        }
                        ::ssh_encoding::Encode::encode(&self.a, writer)?;
                        ::ssh_encoding::Encode::encode_prefixed(self.b, writer)?;
                        Ok(())
                    }
                }
            }
        );
    }

    #[test]
    fn test_derive_for_enum() {
        let input: DeriveInput = syn::parse_quote! {
            #[repr(u8)]
            enum Enum {
                Foo(u8, u8) = 1,
                Bar { a: u8, #[ssh(length_prefixed)] b: &u8 } = 2,
            }
        };
        let output = try_derive_encode(input).unwrap();
        assert_eq_tokens!(
            output,
            quote! {
                #[automatically_derived]
                impl ::ssh_encoding::Encode for Enum {
                    fn encoded_len(&self) -> ::ssh_encoding::Result<usize> {
                        use ::ssh_encoding::CheckedSum;
                        match self {
                            Enum::Foo (field_0, field_1) => {
                                [
                                    ::core::mem::size_of::<u8>(),
                                    ::ssh_encoding::Encode::encoded_len(field_0)?,
                                    ::ssh_encoding::Encode::encoded_len(field_1)?
                                ].checked_sum()
                            }
                            Enum::Bar {a, b} => {
                                [
                                    ::core::mem::size_of::<u8>(),
                                    ::ssh_encoding::Encode::encoded_len(a)?,
                                    ::ssh_encoding::Encode::encoded_len_prefixed(b)?
                                ].checked_sum()
                            }
                        }
                    }
                    fn encode(&self, writer: &mut impl ::ssh_encoding::Writer) -> ::ssh_encoding::Result<()> {
                        match self {
                            Enum::Foo(field_0, field_1) => {
                                ::ssh_encoding::Encode::encode(&(1 as u8), writer)?;
                                ::ssh_encoding::Encode::encode(field_0, writer)?;
                                ::ssh_encoding::Encode::encode(field_1, writer)?;
                            }
                            Enum::Bar {a, b} => {
                                ::ssh_encoding::Encode::encode(&(2 as u8), writer)?;
                                ::ssh_encoding::Encode::encode(a, writer)?;
                                ::ssh_encoding::Encode::encode_prefixed(b, writer)?;
                            }
                        }
                        Ok(())
                    }
                }
            }
        );
    }
}
