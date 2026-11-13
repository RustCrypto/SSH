//! Shared decoder behavior across byte, Base64, and PEM readers.

#![allow(clippy::unwrap_used, reason = "tests")]

use hex_literal::hex;
use ssh_encoding::{Decode, Decoder, Error, Reader};

/// Run the same parser and completion check through every enabled input representation.
fn check_backends<T>(bytes: &[u8], expected: Result<T, Error>)
where
    T: Decode<Error = Error> + core::fmt::Debug + Eq,
{
    let mut decoder = Decoder::new(bytes).unwrap();
    let result = T::decode(&mut decoder).and_then(|value| decoder.finish(value));
    assert_eq!(result, expected);

    #[cfg(feature = "base64")]
    {
        use base64ct::{Base64, Encoding};
        use ssh_encoding::Base64Reader;

        let mut buffer = [0; 256];
        let base64 = Base64::encode(bytes, &mut buffer).expect("test input fits in buffer");
        let reader = Base64Reader::new(base64.as_bytes()).expect("valid Base64 test input");
        let mut decoder: Decoder<_> = reader.into_decoder().unwrap();
        let result = T::decode(&mut decoder).and_then(|value| decoder.finish(value));
        assert_eq!(result, expected);
    }

    #[cfg(feature = "pem")]
    {
        use ssh_encoding::{
            DecodePem,
            pem::{LineEnding, PemLabel},
        };

        struct PemValue<T>(T);

        impl<T> PemLabel for PemValue<T> {
            const PEM_LABEL: &'static str = "TEST";
        }

        impl<T: Decode> Decode for PemValue<T> {
            type Error = T::Error;

            fn decode(decoder: &mut Decoder<impl Reader>) -> Result<Self, Self::Error> {
                T::decode(decoder).map(Self)
            }
        }

        let mut buffer = [0; 512];
        let pem = pem_rfc7468::encode("TEST", LineEnding::LF, bytes, &mut buffer)
            .expect("test input fits in buffer");
        let result = PemValue::<T>::decode_pem(pem).map(|value| value.0);
        assert_eq!(result, expected);
    }
}

#[test]
fn nested_scopes_and_siblings() {
    #[derive(Debug, Eq, PartialEq)]
    struct Value;

    impl Decode for Value {
        type Error = Error;

        fn decode(decoder: &mut Decoder<impl Reader>) -> Result<Self, Error> {
            decoder.read_prefixed(|decoder| {
                assert_eq!(decoder.remaining_len(), 9);
                assert_eq!(decoder.read_prefixed(u8::decode)?, 0xaa);
                assert_eq!(decoder.remaining_len(), 4);
                decoder.read_prefixed(|decoder| {
                    assert!(decoder.is_finished());
                    decoder.read(&mut [])?;
                    Ok::<_, Error>(())
                })
            })?;
            assert_eq!(decoder.remaining_len(), 1);
            assert_eq!(u8::decode(decoder)?, 0xbb);
            Ok(Self)
        }
    }

    check_backends(&hex!("00000009 00000001 aa 00000000 bb"), Ok(Value));
}

#[test]
fn unread_body_is_rejected() {
    #[derive(Debug, Eq, PartialEq)]
    struct Value;

    impl Decode for Value {
        type Error = Error;

        fn decode(decoder: &mut Decoder<impl Reader>) -> Result<Self, Error> {
            decoder.read_prefixed(u8::decode)?;
            Ok(Self)
        }
    }

    check_backends::<Value>(
        &hex!("00000002 aabb cc"),
        Err(Error::TrailingData { remaining: 1 }),
    );
}

#[test]
fn reads_cannot_consume_sibling_bytes() {
    #[derive(Debug, Eq, PartialEq)]
    struct Value;

    impl Decode for Value {
        type Error = Error;

        fn decode(decoder: &mut Decoder<impl Reader>) -> Result<Self, Error> {
            decoder.read_prefixed(<[u8; 3]>::decode)?;
            Ok(Self)
        }
    }

    check_backends::<Value>(&hex!("00000002 aabb cc"), Err(Error::Length));
}

#[test]
fn nested_length_cannot_extend_into_sibling() {
    #[derive(Debug, Eq, PartialEq)]
    struct Value;

    impl Decode for Value {
        type Error = Error;

        fn decode(decoder: &mut Decoder<impl Reader>) -> Result<Self, Error> {
            decoder.read_prefixed(|decoder| decoder.read_prefixed(<[u8; 2]>::decode))?;
            Ok(Self)
        }
    }

    check_backends::<Value>(&hex!("00000005 00000002 aa bb"), Err(Error::Length));
}

#[test]
fn top_level_trailing_data_is_rejected() {
    check_backends::<u8>(&hex!("aabb"), Err(Error::TrailingData { remaining: 1 }));
}

#[test]
fn recursive_decoding_keeps_the_same_reader_type() {
    #[derive(Debug, Eq, PartialEq)]
    struct Depth(usize);

    impl Decode for Depth {
        type Error = Error;

        fn decode(decoder: &mut Decoder<impl Reader>) -> Result<Self, Error> {
            if decoder.remaining_len() == 1 {
                assert_eq!(u8::decode(decoder)?, 0x42);
                Ok(Self(0))
            } else {
                // This must compile without recursively instantiating nested reader types.
                decoder
                    .read_prefixed(Self::decode)
                    .map(|depth| Self(depth.0 + 1))
            }
        }
    }

    check_backends(&hex!("00000009 00000005 00000001 42"), Ok(Depth(3)));
}

#[test]
fn callback_error_restores_scope_and_invalidates_decoder() {
    #[derive(Debug, Eq, PartialEq)]
    struct Value;

    #[derive(Debug, Eq, PartialEq)]
    enum CustomError {
        Encoding(Error),
        Callback,
    }

    impl From<Error> for CustomError {
        fn from(error: Error) -> Self {
            Self::Encoding(error)
        }
    }

    impl Decode for Value {
        type Error = Error;

        fn decode(decoder: &mut Decoder<impl Reader>) -> Result<Self, Error> {
            let result = decoder.read_prefixed(|decoder| {
                assert_eq!(u8::decode(decoder)?, 0xaa);
                Err::<(), _>(CustomError::Callback)
            });
            assert_eq!(result, Err(CustomError::Callback));
            assert_eq!(decoder.remaining_len(), 2);
            assert_eq!(u8::decode(decoder), Err(Error::Failed));
            assert_eq!(decoder.ensure_finished(), Err(Error::Failed));
            Err(Error::Failed)
        }
    }

    check_backends::<Value>(&hex!("00000002 aabb cc"), Err(Error::Failed));
}

#[test]
fn ignored_read_error_cannot_make_scope_succeed() {
    let mut decoder = Decoder::new([0xaa, 0xbb].as_slice()).unwrap();
    let result = decoder.read_nested(1, |decoder| {
        assert_eq!(u8::decode(decoder)?, 0xaa);
        assert_eq!(u8::decode(decoder), Err(Error::Length));
        Ok::<_, Error>(())
    });
    assert_eq!(result, Err(Error::Failed));
    assert_eq!(decoder.remaining_len(), 1);
}

#[test]
fn unwinding_restores_scope_and_invalidates_decoder() {
    use core::panic::AssertUnwindSafe;
    use std::panic::catch_unwind;

    let mut decoder = Decoder::new([0xaa, 0xbb, 0xcc].as_slice()).unwrap();
    let result = catch_unwind(AssertUnwindSafe(|| {
        decoder.read_nested::<(), Error, _>(2, |decoder| {
            assert_eq!(u8::decode(decoder)?, 0xaa);
            panic!("callback failed");
        })
    }));
    assert!(result.is_err());
    assert_eq!(decoder.remaining_len(), 2);
    assert_eq!(u8::decode(&mut decoder), Err(Error::Failed));
}

#[test]
fn partially_advanced_reader_cannot_be_reused_after_error() {
    struct PartialReader<'a>(&'a [u8]);

    impl Reader for PartialReader<'_> {
        fn read<'o>(&mut self, _: &'o mut [u8]) -> Result<&'o [u8], Error> {
            self.0 = &self.0[1..];
            Err(Error::CharacterEncoding)
        }

        fn remaining_len(&self) -> usize {
            self.0.len()
        }
    }

    let mut reader = PartialReader(&[0xaa, 0xbb]);
    let mut decoder = Decoder::new(&mut reader).unwrap();
    assert_eq!(u8::decode(&mut decoder), Err(Error::CharacterEncoding));
    assert_eq!(u8::decode(&mut decoder), Err(Error::Failed));
    assert_eq!(decoder.finish(()), Err(Error::Failed));
    assert_eq!(reader.remaining_len(), 1);
}
