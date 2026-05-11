#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg"
)]

pub use cipher::{self, Cipher};
pub use encoding::{self, Decode, Encode, Reader, Writer};
pub use key::{
    self, Algorithm, Fingerprint, HashAlg, Kdf, KdfAlg, private::PrivateKey, public::PublicKey,
};

#[cfg(feature = "alloc")]
pub use key::{Signature, certificate::Certificate};
