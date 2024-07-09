use syn::{Field, Fields, Ident, Type};

/// Intermediate representation for a struct field.
pub(crate) struct FieldIr {
    /// Field name.
    pub ident: Ident,

    /// Field type.
    pub ty: Type,
}

impl FieldIr {
    pub fn from_fields(fields: Fields) -> syn::Result<Vec<Self>> {
        fields.iter().map(FieldIr::new).collect()
    }

    /// Create a new [`FieldIr`] from the input [`Field`].
    pub fn new(field: &Field) -> syn::Result<Self> {
        let ident = field.ident.as_ref().cloned().ok_or_else(|| {
            syn::Error::new_spanned(
                field,
                "no name on struct field i.e. tuple structs unsupported",
            )
        })?;

        Ok(Self {
            ident,
            ty: field.ty.clone(),
        })
    }
}
