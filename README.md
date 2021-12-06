# Minimal JSON Web Token

A minimal JSON Web Token library.

By default, the signers and verifiers are built on top of [ring][ring].

There are many fully featured crates for JSON Web Tokens, but this crate's goals
are:

* Be usable across many platforms

* To not abstract away the underlying crytography library used

To that end, this crate could be considered as providing a few helper functions
to enable easier usage of JWTs.

## License

Licensed under either of [Apache License, Version 2.0][LICENSE_APACHE] or [MIT
License][LICENSE_MIT] at your option.

### Contributions

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

[LICENSE_APACHE]: LICENSE-APACHE
[LICENSE_MIT]: LICENSE-MIT
[ring]: https://github.com/briansmith/ring
