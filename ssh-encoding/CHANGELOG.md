# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.3.0 (2026-05-25)
### Added
- `boolean` encode/decode support ([#214])
- `Base64Reader`/`Base64Writer` newtypes ([#220])
- `base64` module ([#222])
- PEM line width detection ([#252])
- `Encode::{encode_vec, encode_bytes}` ([#267])
- `DigestWriter` ([#268])
- `digest` feature ([#271])
- `core::error::Error` support ([#303])
- Custom derive for `Encode`/`Decode` via `derive` feature ([#348])
- Propagate `base64ct` errors ([#358])
- `Mpint` type ([#359])
- Implement `Encode` for string-like type sequences ([#377])
- `diagnostic::on_unimplemented` hints ([#514])

### Changed
- `[u8; N]` no longer encodes a length prefix but treats `N` as statically known ([#342])
- Upgrade to 2024 edition; MSRV 1.85 ([#354])
- Bump `hex-literal` dependency to v1 ([#355])
- Migrate from `subtle` to `ctutils` ([#507])

### Removed
- `NestedReader` ([#226])
- `sha2` dependency - now generic around digests ([#271])
- `std` feature ([#303])

[#214]: https://github.com/RustCrypto/SSH/pull/214
[#220]: https://github.com/RustCrypto/SSH/pull/220
[#222]: https://github.com/RustCrypto/SSH/pull/222
[#226]: https://github.com/RustCrypto/SSH/pull/226
[#252]: https://github.com/RustCrypto/SSH/pull/252
[#267]: https://github.com/RustCrypto/SSH/pull/267
[#268]: https://github.com/RustCrypto/SSH/pull/268
[#271]: https://github.com/RustCrypto/SSH/pull/271
[#303]: https://github.com/RustCrypto/SSH/pull/303
[#342]: https://github.com/RustCrypto/SSH/pull/342
[#348]: https://github.com/RustCrypto/SSH/pull/348
[#354]: https://github.com/RustCrypto/SSH/pull/354
[#355]: https://github.com/RustCrypto/SSH/pull/355
[#358]: https://github.com/RustCrypto/SSH/pull/358
[#359]: https://github.com/RustCrypto/SSH/pull/359
[#377]: https://github.com/RustCrypto/SSH/pull/377
[#507]: https://github.com/RustCrypto/SSH/pull/507
[#514]: https://github.com/RustCrypto/SSH/pull/514

## 0.2.0 (2023-08-11)
### Added
- `LabelError` ([#124])
- `bytes` feature ([#138])

### Changed
- Bump `pem-rfc7468` to v0.7 ([#84])

### Removed
- `Encoding::Error` ([#124])

[#84]: https://github.com/RustCrypto/SSH/pull/84
[#124]: https://github.com/RustCrypto/SSH/pull/124
[#138]: https://github.com/RustCrypto/SSH/pull/138

## 0.1.0 (2022-10-23)
- Initial release
