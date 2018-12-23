# servant-auth-wordpress

This package provides a Servant AuthHandler that validates Wordpress's
@LOGGED_IN@ authentication Cookie & the @wp_rest@ Nonce, returning either
an Authorized user with data or an Anonymous user, or calling an error
handler.

This allows you to access the currently logged in User when making AJAX
requests from a Wordpress site.

Check out the @wordpress-auth@ package for lower-level Wordpress Cookie &
Nonce manipulation.

## License

BSD 3-clause, exceptions possible.
