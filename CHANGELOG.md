# Changelog

## [0.10.0] - 2023-10-02

### Changed

- Update `ring` dependency to version `0.10.0`.

## [0.9.0] - 2023-05-02

### Changed

- Update `rsa` dependency to version `0.9.0`.
- Use Rust `1.65.0` as minimum supported version.

## [0.8.0] - 2023-03-30

### Changed

- Update `p256` dependency to version `0.13.0`.

## [0.7.0] - 2023-03-02

### Changed

- Update `p256` dependency to version `0.12.0`.

- Update `rsa` dependency to version `0.8.0`.

- Update `signature` dependency to version `2.0`.

- Add wrapper for `p256` signatures.

- Remove generic signatures with `AsRef<[u8]>` to reduce code generated in final binaries.

## [0.6.0] - 2022-10-17

### Changed

- Use `base64ct` instead of `base64` for base64 encoding/decoding.

- Update dependency to `rsa` `0.7` and use `rsa::pkcs1v15::{SigningKey, VerifyingKey}` directly.

  Removed wrappers for RSA keys and implement `Signer` and `Verifier` directly with the keys.

  Requires `sha2` crate with `oid` feature and `signature` crate.

  See updated tests for examples.

## [0.5.0] - 2022-06-09

### Added

- Add `no_std` functionality

### Changed

- Update p256 to 0.11.0

## [0.4.0] - 2022-05-03

### Added

- Add `Error` associated type to `Signer` traits.

### Changed

- Fix serialize_encode_and_sign to use references for arguments.

  Remove `unwrap()` calls and use unspecified Error.

- Add documentation

- Update to rsa 0.6.1

### Removed

- Remove private modules

## [0.3.0] - 2022-01-02

### Changed

- Add docs.rs cfg attributes.

- Use Rust Edition 2021.

## [0.2.1] - 2022-01-01

### Changed

- Update to document all features on doc.rs.

## [0.2.0] - 2022-01-01

### Changed

- Major refactor to basic functions for signing and verifying a JWT.

- Allow different crypto implementations which are enabled via cargo features.

## [0.1.0] - 2019-11-06

### Added

- Initial implementation.

[Unreleased]: https://github.com/bluk/min_jwt/compare/v0.10.0...HEAD
[0.10.0]: https://github.com/bluk/min_jwt/compare/v0.9.0...v0.10.0
[0.9.0]: https://github.com/bluk/min_jwt/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/bluk/min_jwt/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/bluk/min_jwt/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/bluk/min_jwt/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/bluk/min_jwt/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/bluk/min_jwt/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/bluk/min_jwt/compare/v0.2.1...v0.3.0
[0.2.1]: https://github.com/bluk/min_jwt/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/bluk/min_jwt/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/bluk/min_jwt/releases/tag/v0.1.0
