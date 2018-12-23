{- | This module presents a Servant 'AuthHandler' that validates
a @LOGGED_IN@ Wordpress Cookie & the @"wp_rest"@ Nonce.

You'll need to build a 'WPAuthConfig' for your application to pass to
the 'wpAuthHandler' function. The config defines some specifics about your
Wordpress site, as well as functions to pull a User's authentication data
& to handle authentication failures.

You must define the `ServerData` type instance yourself:

> type instance "AuthServerData" ("AuthProtect" \"wp\") = WPAuthorization (Entity User)

For more information, be sure to check out the
<https://haskell-servant.readthedocs.io/en/stable/tutorial/Authentication.html#generalized-authentication Generalized Authentication>
section of the servant tutorial.

If you want to build your own custom 'AuthHandler', check out the
"Wordpress.Auth" module.

-}
module Servant.Auth.Wordpress
    (
    -- * Auth Handlers
      wpAuthHandler
    , wpAuthorizedOnlyHandler
    , WPAuthorization(..)
    -- * Configs
    , WPAuthConfig(..)
    , CookieName(..)
    , AuthScheme(..)
    , WordpressKey
    , wpConfigKey
    , WordpressSalt
    , wpConfigSalt
    , UserAuthData(..)
    , WordpressUserId(..)
    , WordpressUserPass(..)
    , SessionToken(..)
    , decodeSessionTokens
    -- * Errors
    , WPAuthError(..)
    , CookieHeaderError(..)
    , CookieParseError(..)
    , CookieValidationError(..)
    )
where

import           Network.Wai                    ( Request
                                                , requestHeaders
                                                , queryString
                                                )
import           Servant                        ( Handler )
import           Servant.Server.Experimental.Auth
                                                ( AuthHandler
                                                , mkAuthHandler
                                                )
import           Wordpress.Auth                 ( WPAuthConfig(..)
                                                , UserAuthData(..)
                                                , WPAuthorization(..)
                                                , authorizeWordpressRequest
                                                , WPAuthError(..)
                                                , AuthScheme(..)
                                                , CookieName(..)
                                                , CookieHeaderError(..)
                                                , CookieParseError(..)
                                                , CookieValidationError(..)
                                                , WordpressUserId(..)
                                                , WordpressUserPass(..)
                                                , SessionToken(..)
                                                , decodeSessionTokens
                                                , WordpressKey
                                                , wpConfigKey
                                                , WordpressSalt
                                                , wpConfigSalt
                                                , findCookie
                                                )


-- | A Servant Authentication Handler that valiates a @logged_in@ Cookie
-- & a @wp_rest@ Nonce.
wpAuthHandler
    :: WPAuthConfig Handler a -> AuthHandler Request (WPAuthorization a)
wpAuthHandler = mkAuthHandler . handler

-- | This is similar to 'wpAuthHandler' but it allows you to throw an error
-- for anonymous users with valid nonces - restricting handlers to only
-- logged in users.
wpAuthorizedOnlyHandler
    :: WPAuthConfig Handler a
    -> (WPAuthError -> Handler a)
    -> AuthHandler Request a
wpAuthorizedOnlyHandler cfg authFailure = mkAuthHandler $ \req -> do
    result <- handler cfg req
    case result of
        WPAuthorizedUser uData -> return uData
        WPAnonymousUser        -> do
            name <- getCookieName cfg
            authFailure
                $ either EHeader (const $ EHeader NoCookieMatches)
                $ findCookie name (requestHeaders req)


handler :: WPAuthConfig Handler a -> Request -> Handler (WPAuthorization a)
handler cfg req =
    authorizeWordpressRequest cfg (requestHeaders req) (queryString req)
