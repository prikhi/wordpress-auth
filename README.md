# Haskell Wordpress Authentication

This repository contains Haskell packages for authenticating Wordpress cookies
& nonces.

The `wordpress-auth` package contains the base types, transformations, &
validations. The `servant-auth-wordpress` package provides a `Servant`
AuthHandler that validates cookies and nonces, as well as utility functions for
rolling your own AuthHandler.


## Contribute

Contributions, documentation, & tests are always welcome.

The API is still evolving - if you have trouble using this library or
integrating it with some framework, please open an issue letting me know what
you need.


## License

All packages in this repository are licensed with BSD 3-clause, but exceptions
are possible.
