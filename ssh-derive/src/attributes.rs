use proc_macro2::TokenStream;
use quote::quote;

pub(crate) struct ContainerAttributes {
    pub(crate) length_prefixed: bool,
    pub(crate) discriminant_type: Option<TokenStream>,
}

impl TryFrom<&syn::DeriveInput> for ContainerAttributes {
    type Error = syn::Error;

    fn try_from(input: &syn::DeriveInput) -> Result<Self, Self::Error> {
        let mut length_prefixed = false;
        let mut discriminant_type = None;
        for attr in &input.attrs {
            if attr.path().is_ident("ssh") {
                attr.parse_nested_meta(|meta| {
                    // #[ssh(length_prefixed)]
                    if meta.path.is_ident("length_prefixed") {
                        length_prefixed = true;
                    } else {
                        return Err(syn::Error::new_spanned(meta.path, "unknown attribute"));
                    }
                    Ok(())
                })?;
            } else if attr.path().is_ident("repr") {
                attr.parse_nested_meta(|meta| {
                    // #[repr(u8)]  or similar
                    // https://doc.rust-lang.org/reference/type-layout.html#primitive-representations
                    if meta.path.is_ident("u8") {
                        discriminant_type = Some(quote! {u8});
                    } else if meta.path.is_ident("u16") {
                        discriminant_type = Some(quote! {u16});
                    } else if meta.path.is_ident("u32") {
                        discriminant_type = Some(quote! {u32});
                    } else if meta.path.is_ident("u64") {
                        discriminant_type = Some(quote! {u64});
                    } else if meta.path.is_ident("u128") {
                        discriminant_type = Some(quote! {u128});
                    } else if meta.path.is_ident("usize") {
                        discriminant_type = Some(quote! {usize});
                    } else if meta.path.is_ident("i8") {
                        discriminant_type = Some(quote! {i8});
                    } else if meta.path.is_ident("i16") {
                        discriminant_type = Some(quote! {i16});
                    } else if meta.path.is_ident("i32") {
                        discriminant_type = Some(quote! {i32});
                    } else if meta.path.is_ident("i64") {
                        discriminant_type = Some(quote! {i64});
                    } else if meta.path.is_ident("i128") {
                        discriminant_type = Some(quote! {i128});
                    } else if meta.path.is_ident("isize") {
                        discriminant_type = Some(quote! {isize});
                    } else {
                        return Err(syn::Error::new_spanned(
                            meta.path,
                            "unsupported repr for deriving Encode/Decode, must be a primitive integer type",
                        ));
                    }
                    Ok(())
                })?;
            }
        }

        Ok(Self {
            length_prefixed,
            discriminant_type,
        })
    }
}

pub(crate) struct FieldAttributes {
    pub(crate) length_prefixed: bool,
}

impl TryFrom<&syn::Field> for FieldAttributes {
    type Error = syn::Error;

    fn try_from(field: &syn::Field) -> Result<Self, Self::Error> {
        let mut length_prefixed = false;
        for attr in &field.attrs {
            if attr.path().is_ident("ssh") {
                attr.parse_nested_meta(|meta| {
                    // #[ssh(length_prefixed)]
                    if meta.path.is_ident("length_prefixed") {
                        length_prefixed = true;
                    } else {
                        return Err(syn::Error::new_spanned(meta.path, "unknown attribute"));
                    }
                    Ok(())
                })?;
            }
        }

        Ok(Self { length_prefixed })
    }
}
