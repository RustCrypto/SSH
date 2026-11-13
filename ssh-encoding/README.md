# [RustCrypto]: SSH Encoding

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
[![Build Status][build-image]][build-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Project Chat][chat-image]][chat-link]

[Documentation][docs-link]

## About

Pure Rust implementation of SSH data type decoders/encoders as described
in [RFC4251].

## Decoding

Convert a reader into a `Decoder` to start decoding SSH data types:

```rust
use ssh_encoding::{Decode, Reader};

let mut decoder = [0, 0, 0, 4, 0, 0, 0, 42]
    .as_slice()
    .into_decoder()
    .expect("input too long");
let value = decoder.read_prefixed(u32::decode).expect("invalid u32");
assert_eq!(decoder.finish(value).expect("remaining data"), 42);
```

`Reader` supplies bytes and their remaining length. `Decoder<R>` owns the reader and
handles nested bounds, complete consumption, and failure state. Nested callbacks use
the same decoder type and store enclosing bounds on the call stack without allocation.
`Decode` implementations accept `&mut Decoder<impl Reader>`.

Construct a decoder with `Decoder::new(reader)` or `reader.into_decoder()`.
Both return an error if the remaining binary input exceeds `MAX_SIZE` (128 MiB),
matching OpenSSH's hard buffer limit. The limit is checked once at construction;
nested scopes are already bounded by their parent.

Raw byte slices implement `Reader`. With the corresponding features enabled,
`Base64Reader` decodes Base64 incrementally, and `DecodePem` wraps a PEM reader in
the same decoder internally.

For Base64 and PEM, the limit applies to the decoded binary length. Applications
must separately bound textual input and file reads before constructing a reader.

## License

Licensed under either of:

 * [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
 * [MIT license](http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

[//]: # (badges)

[crate-image]: https://img.shields.io/crates/v/ssh-encoding?logo=rust
[crate-link]: https://crates.io/crates/ssh-encoding
[docs-image]: https://docs.rs/ssh-encoding/badge.svg
[docs-link]: https://docs.rs/ssh-encoding/
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.87+-blue.svg
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/346919-SSH
[build-image]: https://github.com/RustCrypto/SSH/actions/workflows/ssh-encoding.yml/badge.svg
[build-link]: https://github.com/RustCrypto/SSH/actions/workflows/ssh-encoding.yml

[//]: # (links)

[RustCrypto]: https://github.com/rustcrypto
[RFC4251]: https://datatracker.ietf.org/doc/html/rfc4251
