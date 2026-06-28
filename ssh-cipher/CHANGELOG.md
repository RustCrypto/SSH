# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.3.0 (2026-06-28)
### Added
- `Decryptor` and `Encryptor` ([#253], [#533], [#534])
- `ChaCha20Poly1305` implementing SSH-flavored construction with `aead` API ([#256], [#370])
- `zeroize` feature ([#283])
- `core::error::Error` support ([#303])
- `getrandom` and `rand_core` feature passthroughs ([#535])
- `encoding` feature ([#560])

### Changed
- Upgrade to 2024 edition; MSRV 1.85 ([#354])
- Migrate from `subtle` to `ctutils` ([#507])
- Consolidate `aes` feature instead of per-block-mode features ([#530])
- Upgrade low-level symmetric crypto dependencies ([#516])
  - `aes` v0.9
  - `ctr` v0.10
  - `chacha20` v0.10
  - `des` v0.9
  - `poly1305` v0.9
- Upgrade `ssh-encoding` to v0.3 ([#537])
- Upgrade AEAD dependencies ([#557])
  - `aead` 0.6
  - `aes-gcm` v0.11

### Removed
- `std` feature ([#303])

[#253]: https://github.com/RustCrypto/SSH/pull/253
[#256]: https://github.com/RustCrypto/SSH/pull/256
[#283]: https://github.com/RustCrypto/SSH/pull/283
[#303]: https://github.com/RustCrypto/SSH/pull/303
[#354]: https://github.com/RustCrypto/SSH/pull/354
[#370]: https://github.com/RustCrypto/SSH/pull/370
[#507]: https://github.com/RustCrypto/SSH/pull/507
[#516]: https://github.com/RustCrypto/SSH/pull/516
[#530]: https://github.com/RustCrypto/SSH/pull/530
[#533]: https://github.com/RustCrypto/SSH/pull/533
[#534]: https://github.com/RustCrypto/SSH/pull/534
[#535]: https://github.com/RustCrypto/SSH/pull/535
[#537]: https://github.com/RustCrypto/SSH/pull/537
[#557]: https://github.com/RustCrypto/SSH/pull/557
[#560]: https://github.com/RustCrypto/SSH/pull/560

## 0.2.0 (2023-08-11)
- Initial release

## 0.1.0
- Skipped to synchronize versions with `ssh-encoding`
