//! Tests for the `Decode` trait.

use hex_literal::hex;
use ssh_encoding::{Decode, Decoder, Error};

#[cfg(feature = "alloc")]
use ssh_encoding::Reader;

#[test]
fn decode_u8() {
    let mut bytes = Decoder::new(hex!("42").as_slice()).unwrap();
    let ret = u8::decode(&mut bytes).unwrap();
    assert_eq!(ret, 0x42u8);
}

#[test]
fn decode_boolean() {
    let mut bytes = Decoder::new(hex!("01").as_slice()).unwrap();
    let ret = bool::decode(&mut bytes).unwrap();
    assert!(ret);

    // "All non-zero values MUST be interpreted as TRUE"
    let mut bytes = Decoder::new(hex!("FF").as_slice()).unwrap();
    let ret = bool::decode(&mut bytes).unwrap();
    assert!(ret);
}

#[test]
fn decode_u32() {
    let mut bytes = Decoder::new(hex!("DEADBEEF").as_slice()).unwrap();
    let ret = u32::decode(&mut bytes).unwrap();
    assert_eq!(ret, 0xDEADBEEFu32);
}

#[test]
fn decode_u64() {
    let mut bytes = Decoder::new(hex!("0000DEADBEEFCAFE").as_slice()).unwrap();
    let ret = u64::decode(&mut bytes).unwrap();
    assert_eq!(ret, 0xDEADBEEFCAFEu64);
}

#[test]
fn decode_usize() {
    let mut bytes = Decoder::new(hex!("000FFFFF").as_slice()).unwrap();
    let ret = usize::decode(&mut bytes).unwrap();
    assert_eq!(ret, 0xFFFFFusize);
}

/// `usize` decoder has a sanity limit of 0xFFFFF.
#[test]
fn reject_oversize_usize() {
    let mut bytes = Decoder::new(hex!("00100000").as_slice()).unwrap();
    let err = usize::decode(&mut bytes).err().unwrap();
    assert_eq!(err, Error::Overflow);
}

#[test]
fn decode_byte_array() {
    let mut bytes = Decoder::new(hex!("6578616d706c65").as_slice()).unwrap();
    let ret = <[u8; 7]>::decode(&mut bytes).unwrap();
    assert_eq!(&ret, b"example");
}

#[cfg(feature = "alloc")]
#[test]
fn decode_byte_vec() {
    let mut bytes = Decoder::new(hex!("000000076578616d706c65").as_slice()).unwrap();
    let ret = Vec::<u8>::decode(&mut bytes).unwrap();
    assert_eq!(&ret, b"example");
}

#[cfg(feature = "alloc")]
#[test]
fn decode_string() {
    let mut bytes = Decoder::new(hex!("000000076578616d706c65").as_slice()).unwrap();
    let ret = String::decode(&mut bytes).unwrap();
    assert_eq!(&ret, "example");
}

#[cfg(feature = "alloc")]
#[test]
fn decode_string_vec() {
    let mut bytes = hex!("0000001500000003666f6f000000036261720000000362617a")
        .as_slice()
        .into_decoder()
        .unwrap();
    let ret = Vec::<String>::decode(&mut bytes).unwrap();
    assert_eq!(ret.len(), 3);
    assert_eq!(ret[0], "foo");
    assert_eq!(ret[1], "bar");
    assert_eq!(ret[2], "baz");
}

#[test]
fn read_prefixed_rejects_unread_bytes_in_slice() {
    let mut reader = Decoder::new([0, 0, 0, 2, 0xAA, 0xBB].as_slice()).unwrap();
    let result: Result<u8, Error> = reader.read_prefixed(u8::decode);
    assert_eq!(result, Err(Error::TrailingData { remaining: 1 }));
}
