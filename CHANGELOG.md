# Changelog

## [Unreleased] - 2022-09-14

### Changed

- Use `base64ct` instead of `base64` for base64 encoding/decoding.

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

[Unreleased]: https://github.com/bluk/min_jwt/compare/v0.5.0...HEAD
[0.5.0]: https://github.com/bluk/min_jwt/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/bluk/min_jwt/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/bluk/min_jwt/compare/v0.2.1...v0.3.0
[0.2.1]: https://github.com/bluk/min_jwt/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/bluk/min_jwt/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/bluk/min_jwt/releases/tag/v0.1.0
