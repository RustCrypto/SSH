# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.4.3 (2022-09-25)
### Changed
- Move source code repository to <https://github.com/RustCrypto/SSH> ([#1])

[#1]: https://github.com/RustCrypto/SSH/pull/1

## 0.4.2 (2022-05-02)
### Added
- Support for parsing keys out of the ssh known_hosts file format
- Export `RsaPrivateKey`
- `From` conversions between algorithmic-specific key types and `PublicKey`/`PrivateKey`

## 0.4.1 (2022-04-26)
### Added
- Internal `UnixTime` helper type

### Changed
- Bump `pem-rfc7468` dependency to v0.6.0
- Further restrict maximum allowed timestamps

## 0.4.0 (2022-04-12)
### Added
- Private key decryption support
- Private key encryption support
- Ed25519 keygen/sign/verify support using `ed25519-dalek`
- Private key encryption
- Certificate decoder
- Certificate encoder
- Certificate validation support
- FIDO/U2F (`sk-*`) certificate and key support
- `certificate::Builder` (i.e. SSH CA support)
- ECDSA/NIST P-256 keygen/sign/verify support using `p256` crate
- RSA keygen/sign/verify support using `rsa` crate
- SHA-512 fingerprint support
- `serde` support

### Changed
- Consolidate `KdfAlg` and `KdfOpts` into `Kdf`
- Rename `CipherAlg` => `Cipher`

### Removed
- `PrivateKey::kdf_alg`

## 0.3.0 (2022-03-16)
### Added
- `FromStr` impls for key types
- `PublicKey` encoder
- `AuthorizedKeys` parser
- `PrivateKey::public_key` and `From` conversions
- `PrivateKey` encoder
- Validate private key padding bytes
- File I/O methods for `PrivateKey` and `PublicKey`
- SHA-256 fingerprint support

### Changed
- Use `pem-rfc7468` for private key PEM parser
- Make `PublicKey`/`PrivateKey` fields private

## 0.2.0 (2021-12-29)
### Added
- OpenSSH private key decoder
- `MPInt::as_positive_bytes`

### Changed
- `MPInt` validates the correct number of leading zeroes are used

## 0.1.0 (2021-12-02)
- Initial release
