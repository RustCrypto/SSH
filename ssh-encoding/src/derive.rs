//! # Deriving [`Encode`] and [`Decode`]
//!
//! The traits [`Encode`] and [`Decode`] can be derived for any struct or enum where all its fields
//! implement [`Encode`] and [`Decode`].
//!
//! [`Encode`]: [crate::Encode]
//! [`Decode`]: [crate::Decode]
//! ## Example
//!
//! Here is an example of how you could define a handful of the SSH message types.
#![cfg_attr(feature = "alloc", doc = "```")]
#![cfg_attr(not(feature = "alloc"), doc = "```ignore")]
//! use ssh_encoding::{Decode, Encode};
//!
//! #[derive(Debug, PartialEq, Encode, Decode)]
//! #[repr(u8)]
//! enum Message {
//!     Disconnect {
//!         reason_code: u32,
//!         description: String,
//!         language_tag: String,
//!     } = 1,
//!     EcdhInit {
//!         client_public_key: Vec<u8>,
//!     } = 30,
//!     EcdhReply {
//!         host_key: HostKey,
//!         server_public_key: Vec<u8>,
//!         #[ssh(length_prefixed)]
//!         host_signature: HostSignature,
//!     } = 31,
//! }
//!
//! #[derive(Debug, PartialEq, Encode, Decode)]
//! #[ssh(length_prefixed)]
//! struct HostKey {
//!     key_type: String,
//!     ecdsa_curve_identifier: String,
//!     ecdsa_public_key: Vec<u8>,
//! }
//!
//! #[derive(Debug, PartialEq, Encode, Decode)]
//! struct HostSignature {
//!     signature_type: String,
//!     signature: Vec<u8>,
//! }
//!
//! let message = Message::EcdhReply {
//!     host_key: HostKey {
//!         key_type: "ecdsa-sha2-nistp256".into(),
//!         ecdsa_curve_identifier: "nistp256".into(),
//!         ecdsa_public_key: vec![0x01, 0x02, 0x03],
//!     },
//!     server_public_key: vec![0x04, 0x05, 0x06],
//!     host_signature: HostSignature {
//!         signature_type: "ecdsa-sha2-nistp256".into(),
//!         signature: vec![0x07, 0x08, 0x09],
//!     },
//! };
//!
//! let encoded = message.encode_vec().unwrap();
//! assert_eq!(&encoded[..13], &[31, 0, 0, 0, 42, 0, 0, 0, 19, 101, 99, 100, 115]);
//! let decoded = Message::decode(&mut &encoded[..]).unwrap();
//! assert_eq!(message, decoded);
//! ```
