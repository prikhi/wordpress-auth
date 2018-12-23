{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{- | This module presents a Servant 'AuthHandler' that validates
a @LOGGED_IN@ Wordpress Cookie & the @"wp_rest"@ Nonce.

You'll need to build a 'WordpressConfig' for your application to pass to
the 'wpAuthHandler' function. The config defines some specifics about your
Wordpress configuration, as well as functions to pull a User's
authentication data & to handle authentication failures.

You must define the `ServerData` type instance yourself:

@
 type instance "AuthServerData" ("AuthProtect" \"wp\") = Entity User
@

-}
module Servant.Auth.Wordpress where

import           Control.Monad                  ( (<=<)
                                                , void
                                                , unless
                                                )
import           Control.Monad.Except           ( ExceptT
                                                , runExceptT
                                                , liftEither
                                                , withExceptT
                                                , throwError
                                                , lift
                                                , liftIO
                                                )
import           Data.Text                      ( Text )
import           Data.Time.Clock                ( NominalDiffTime )
import           Data.Time.Clock.POSIX          ( getPOSIXTime )
import           Network.Wai                    ( Request
                                                , requestHeaders
                                                , queryString
                                                )
import           Servant                        ( Handler )
import           Servant.Server.Experimental.Auth
                                                ( AuthHandler
                                                , mkAuthHandler
                                                )
import           Wordpress.Auth                 ( AuthScheme
                                                , CookieName
                                                , CookieHeaderError
                                                , CookieParseError
                                                , CookieValidationError
                                                , WPCookie(username, token)
                                                , WordpressUserId
                                                , WordpressUserPass
                                                , SessionToken
                                                , findCookie
                                                , parseWordpressCookie
                                                , validateCookie
                                                , findNonce
                                                , wordpressNonceTick
                                                , validateNonce
                                                )

-- | A Servant Authentication Handler that valiates a @logged_in@ Cookie
-- & a @wp_rest@ Nonce.
wpAuthHandler :: forall a . WordpressConfig a -> AuthHandler Request a
wpAuthHandler cfg = mkAuthHandler handler
  where
    handler :: Request -> Handler a
    handler req =
        either (onAuthenticationFailure cfg) return <=< runExceptT $ do
            name        <- lift $ cookieName cfg
            rawCookie <- liftWith EHeader $ findCookie name (requestHeaders req)
            wpCookie    <- liftWith EParse $ parseWordpressCookie rawCookie

            currentTime <- liftIO getPOSIXTime
            UserAuthData { userData, wpUser, wpPass, wpTokens } <-
                lift (getUserData cfg (username wpCookie))
                    >>= liftMaybe UserDataNotFound
            void $ liftWith EValid $ validateCookie (loggedInScheme cfg)
                                                    currentTime
                                                    wpCookie
                                                    wpPass
                                                    wpTokens

            nonce <- liftMaybe NoNonce
                $ findNonce (requestHeaders req) (queryString req)
            let nonceTick = wordpressNonceTick (nonceLifetime cfg) currentTime
                nonceIsValid = validateNonce (nonceScheme cfg)
                                             (Just $ token wpCookie)
                                             nonceTick
                                             (Just wpUser)
                                             "wp_rest"
                                             nonce
            unless nonceIsValid $ throwError InvalidNonce
            return userData
    liftMaybe :: Monad m => e -> Maybe b -> ExceptT e m b
    liftMaybe e m = liftEither $ maybe (Left e) Right m
    liftWith :: Monad m => (e2 -> e1) -> Either e2 b -> ExceptT e1 m b
    liftWith e = withExceptT e . liftEither


-- | Configuration data specific to your Wordpress site & Haskell
-- application.
data WordpressConfig a
    = WordpressConfig
        { cookieName :: Handler CookieName
        -- ^ A monadic action that generates a `CookieName`. You can simply
        -- return a constant value, or do something more complex like
        -- querying your database for the `siteurl` option.
        , loggedInScheme :: AuthScheme
        -- ^ The @LOGGED_IN_KEY@ & @LOGGED_IN_SALT@ from your
        -- @wp-config.php@.
        , nonceScheme :: AuthScheme
        -- ^ The @NONCE_KEY@ & @NONCE_SALT@ from your @wp-config.php@.
        , nonceLifetime :: NominalDiffTime
        -- ^ The nonce lifetime of your Wordpress site. Wordpress defaults
        -- to 1 day.
        , getUserData :: Text -> Handler (Maybe (UserAuthData a))
        -- ^ A function to pull your custom data & the user data needed for
        -- authentication. See the 'UserAuthData' type.
        , onAuthenticationFailure :: WordpressAuthenticationError -> Handler a
        }

-- | The data needed for authentication, along with some arbitrary data
-- that is returned to your route on successful validations.
data UserAuthData a =
    UserAuthData
        { userData :: a
        -- ^ Arbitrary data you want to pass to your route handler. E.g., if
        -- you query your users table for the @ID@ & @user_pass@, you can
        -- return your whole User type so you don't have to make another
        -- database call in your handler.
        , wpUser :: WordpressUserId
        -- ^ The @ID@ field of the User.
        , wpPass :: WordpressUserPass
        -- ^ The @user_pass@ field of the User.
        , wpTokens :: [SessionToken]
        -- ^ The @session_tokens@ usermeta for the User. You can use
        -- 'Wordpress.Auth.decodeSessionTokens' to parse the raw meta value.
        }
    deriving (Show, Eq)

-- | Potential errors during authentication.
data WordpressAuthenticationError
    = EHeader CookieHeaderError
    -- ^ Header Error.
    | EParse CookieParseError
    -- ^ Parsing Error.
    | EValid CookieValidationError
    -- ^ Validation Error.
    | UserDataNotFound
    -- ^ The `getUserData` function returned `Nothing`.
    | NoNonce
    -- ^ The `Request` has no @X-WP-Nonce@ header.
    | InvalidNonce
    -- ^ The nonce couldn't be validated.
    deriving (Show, Eq)
