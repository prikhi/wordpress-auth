# wordpress-auth

This package is used for validating Cookie data & Nonces from Wordpress.

You may find it useful if you're trying to serve a Haskell application
alongside a Wordpress site. By validating the Cookies set by Wordpress, you
can access the currently logged-in Wordpress user in Haskell without having
to devise a Wordpress-to-Haskell authentication scheme.

It includes a generalized authentication function, as well as various
helpers, validators, & hashers if you'd like to build a custom
authentication process.

Servant users may want to just use the `servant-auth-wordpress` package.

## License

BSD 3-clause, exceptions possible.
