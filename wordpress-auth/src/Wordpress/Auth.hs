{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-| The `Wordpress.Auth` module is used for checking the validity of
various Wordpress authentication schemes.

This is useful if you want a Haskell application to be able to serve
authenticated API requests to a Wordpress site without having to devise
a Wordpress-to-Haskell authentication system.

You will need some constants from your Wordpress site's @wp-config.php@,
like the @NONCE_KEY@ & @NONCE_SALT@, you could supply these via
environmental variables:

@
 loggedInScheme <- 'AuthScheme'
     \<$> ('wpConfigKey' . T.pack \<$> getEnv \"LOGGED_IN_KEY\")
     \<*> ('wpConfigSalt' . T.pack \<$> getEnv \"LOGGED_IN_SALT\")
@

Then you'll want to pull the specific cookie's text out of the Cookie
header & use 'parseWordpressCookie' to build your 'WPCookie'. You should
then use the `username` field of the cookie to query your Wordpress
database for the User's @ID@ & @user_pass@ fields as well as the
@session_tokens@ User Meta.

Equiped with these and the current time(via
'Data.Time.Clock.POSIX.getPOSIXTime'), you can then validate the cookie:

@
 passwordFragment = 'WordpressUserPass' myUserTablesUserPassFieldValue
 sessionTokens    = 'decodeSessionTokens' myUserMetaTablesSessionTokensMetaValue
 cookieIsValid    = 'validateCookie' loggedInScheme currentTime cookie
                                   passwordFrament sessionTokens
@

If this is a REST request or a form submission, you should *always*
validate the nonce, even for requests with no auth cookies. The nonce can
be pulled out of the @X-WP-Nonce@ header or the @_wpnonce@ query parameter.

@
 nonceTick <- 'wordpressNonceTick' (60 * 60 * 24) currentTime
 let validNonce = 'validateNonce' nonceScheme (Just cookie) nonceTick
                                (Just $ 'WordpressUserId' userId)
                                "wp_rest" myNonceText
@

TODO: The current library is completely pure, add helpers that pull current
      time, get cookie & nonce from request, then validate. Support Wai
      & Network.HTTP Requests(via typeclass?).

TODO: Add pure functions for pulling cookies by name & nonces from header
      or query parameters

TODO: Add something like an authenticateRestRequest function that returns
      Authorized, Anonymous, or AuthError.
-}
module Wordpress.Auth
    (
    -- * Cookies
      WPCookie(..)
    , CookieToken(..)
    , parseWordpressCookie
    , CookieParseError(..)
    , WordpressUserId(..)
    , WordpressUserPass(..)
    , validateCookie
    , validateCookieHash
    -- * Session Tokens
    , SessionToken(..)
    , decodeSessionTokens
    , validateSessionToken
    -- * Nonces
    , NonceTick(..)
    , wordpressNonceTick
    , validateNonce
    -- * Hashing / Salting
    , wordpressHash
    , wordpressSalt
    , AuthScheme(..)
    , WordpressKey
    , WordpressSalt
    , wpConfigKey
    , wpConfigSalt
    )
where

import qualified Crypto.Hash.MD5               as MD5
import qualified Crypto.Hash.SHA256            as SHA256
import qualified Data.ByteString               as B
import qualified Data.ByteString.Base16        as Base16
import qualified Data.ByteString.Lazy          as LBS
import qualified Data.List                     as L
import           Data.Maybe                     ( mapMaybe
                                                , isJust
                                                )
import           Data.PHPSession                ( PHPSessionValue(..)
                                                , decodePHPSessionValue
                                                )
import qualified Data.Text                     as T
import           Data.Text                      ( Text )
import           Data.Text.Encoding             ( encodeUtf8
                                                , decodeUtf8
                                                )
import           Data.Time.Clock                ( NominalDiffTime )
import           Data.Time.Clock.POSIX          ( POSIXTime )
import           Text.Read                      ( readMaybe )


-- Cookies

-- | This represents a Cookie set by a Wordpress authentication scheme
-- (`auth`, `auth_sec`, & `logged_in`).
data WPCookie
    = WPCookie
        { username :: Text
        -- ^ The `user_login` column for the Wordpress User.
        , expiration :: POSIXTime
        -- ^ The expiration time of the Cookie.
        , token :: CookieToken
        -- ^ The Wordpress User's session token.
        , hmac :: Text
        -- ^ A SHA256 HMAC hash of the token & some user data.
        }
    deriving (Show, Eq)

-- | A User's Wordpress Session Token from an auth cookie.
newtype CookieToken
    = CookieToken { cookieToken :: Text }
    deriving (Show, Eq)

data CookieParseError
    = MalformedCookie
    -- ^ The cookie did not have 4 fields separated by `|` characters.
    | InvalidExpiration
    -- ^ The expiration field of the cookie is not an Integer.
    deriving (Show, Eq)

-- | Parse a `WPCookie` from the body text of an `auth`, `auth_sec`, or
-- `logged_in` cookie.
parseWordpressCookie :: Text -> Either CookieParseError WPCookie
parseWordpressCookie rawCookie = case T.splitOn "|" rawCookie of
    [username, expiration_, token_, hmac] ->
        let token = CookieToken token_
        in  case fromInteger <$> readMaybe (T.unpack expiration_) of
                Just expiration -> Right WPCookie { .. }
                Nothing         -> Left InvalidExpiration
    _ -> Left MalformedCookie

-- | The @ID@ field from the @users@ table of a Wordpress site.
newtype WordpressUserId
    = WordpressUserId { wordpressUserId :: Integer }
    deriving (Show, Eq)

-- | The @user_pass@ field from the @users@ table of a Wordpress site.
newtype WordpressUserPass
    = WordpressUserPass { wordpressUserPass :: Text }
    deriving (Show, Eq)

-- | Determine if a `WPCookie`'s hash matches the hashed password & token.
--
-- A secret is generated by hashing the user, password, expiration, & token.
-- This secret is then used to hash the user, expiration, & token. The
-- resulting hash should match the `hmac` hash in the `WPCookie`.
validateCookieHash :: AuthScheme -> WPCookie -> WordpressUserPass -> Bool
validateCookieHash scheme cookie userPass =
    let
        passwordFragment = T.take 4 $ T.drop 8 $ wordpressUserPass userPass
        user             = username cookie
        tok              = cookieToken $ token cookie
        secret           = wordpressHash scheme $ joinHashParts
            [user, passwordFragment, posixText $ expiration cookie, tok]
        hash =
            hmacText SHA256.hmac (HashSecret secret)
                $ HashMessage
                $ joinHashParts [user, posixText $ expiration cookie, tok]
    in
        hash == hmac cookie
  where
    posixText :: POSIXTime -> Text
    posixText t = T.pack $ show (floor t :: Integer)

-- | Validate a Wordpress Authentication Cookie by verifying that the hash
-- & token in the cookie are valid and the expiration time is in the
-- future.
validateCookie
    :: AuthScheme -- ^ They @_KEY@ & @_SALT@ constants for a WP auth scheme.
    -> POSIXTime -- ^ The current time.
    -> WPCookie -- ^ The cookie to validate.
    -> WordpressUserPass -- ^ The @user_pass@ field for the cookie's user.
    -> [SessionToken] -- ^ The @session_tokens@ meta for the cookie's user.
    -> Either CookieValidationError ()
validateCookie scheme currentTime cookie userPass sessionTokens =
    let validHash = validateCookieHash scheme cookie userPass
        validSessionToken =
                validateSessionToken currentTime (token cookie) sessionTokens
    in  if currentTime > expiration cookie
            then Left CookieExpired
            else case (validHash, validSessionToken) of
                (False, _    ) -> Left InvalidHash
                (_    , False) -> Left InvalidToken
                (True , True ) -> Right ()

data CookieValidationError
    = CookieExpired
    | InvalidHash
    | InvalidToken




-- Hashing / Salting

-- | A port of the `wp_hash` function. This performs an 'MD5.hmac' hash on
-- some text using a secret derived from the authentication scheme's key
-- & salt constants.
wordpressHash :: AuthScheme -> Text -> Text
wordpressHash scheme textToHash =
    let secret = HashSecret $ wordpressSalt scheme
    in  hmacText MD5.hmac secret $ HashMessage textToHash

-- | A port of the `wp_salt` function. Builds a secret key for a hashing
-- function using the auth scheme's key & salt.
wordpressSalt :: AuthScheme -> Text
wordpressSalt AuthScheme { schemeKey, schemeSalt } =
    unKey schemeKey <> unSalt schemeSalt



-- Tokens

-- | A User Session's Token. These can be found in the `usermeta` Wordpress
-- table for rows where @meta_key="session_token"@.
--
-- You'll probably want to use `decodeSessionTokens` to parse the tables's
-- @meta_value@ instead of constructing them yourself.
data SessionToken
    = SessionToken
        { sessionToken :: Text
        , tokenExpiration :: POSIXTime
        }
    deriving (Show, Eq)

-- | Decode a serialized PHP array containing a User's Session Tokens.
-- These are usually stored as the `session_tokens` usermeta.
--
-- It may be an associative array of tokens to expiration times, or tokens
-- to an associative array of sub-fields:
--
-- > array(
-- >   'some-random-hex-text' => 192836504,
-- >   // ...
-- > );
-- > array(
-- >   'deadbeef ' => array(
-- >     'expiration' => 9001,
-- >     // ...
-- >   ),
-- > );
decodeSessionTokens :: Text -> [SessionToken]
decodeSessionTokens serializedText =
    case decodePHPSessionValue (LBS.fromStrict $ encodeUtf8 serializedText) of
        Nothing       -> []
        Just phpValue -> decodeTokenArray phpValue
  where
    decodeTokenArray :: PHPSessionValue -> [SessionToken]
    decodeTokenArray = \case
        PHPSessionValueArray sessionTokens ->
            mapMaybe decodeToken sessionTokens
        _ -> []
    -- Decode a single Token, which can be a (token, expiration) pair, or
    -- an associative array.
    decodeToken :: (PHPSessionValue, PHPSessionValue) -> Maybe SessionToken
    decodeToken = \case
        (PHPSessionValueString token, expirationData) ->
            let decodedExpiration = case expirationData of
                    PHPSessionValueInt posixExpiration ->
                        Just . fromInteger $ fromIntegral posixExpiration
                    PHPSessionValueArray tokenData -> decodeTokenData tokenData
                    _                              -> Nothing
                sessionToken = decodeUtf8 $ LBS.toStrict token
            in  (\tokenExpiration -> SessionToken { .. }) <$> decodedExpiration

        _ -> Nothing
    -- Decode the sub-fields of a Token.
    decodeTokenData :: [(PHPSessionValue, PHPSessionValue)] -> Maybe POSIXTime
    decodeTokenData = \case
        [] -> Nothing
        (PHPSessionValueString "expiration", PHPSessionValueInt expiration) : _
            -> Just $ fromInteger $ fromIntegral expiration
        _ : rest -> decodeTokenData rest


-- | Determine if the SHA256 hash of the token matches one of the unexpired
-- session tokens.
validateSessionToken
    :: POSIXTime -- ^ The current time
    -> CookieToken -- ^ A session token(e.g., from a `WPCookie`)
    -> [SessionToken] -- ^ A list of the User's session tokens
    -> Bool
validateSessionToken currentTime (CookieToken cookieToken) sessionTokens =
    let hashedCookieToken = hashText SHA256.hash $ HashMessage cookieToken
    in  isJust $ L.find ((== hashedCookieToken) . sessionToken) $ filter
            (\tok -> tokenExpiration tok >= currentTime)
            sessionTokens



-- Nonces

-- | The tick number of a Wordpress site - required for Nonce verification.
newtype NonceTick
    = NonceTick
        { tickCount :: Integer
        }
    deriving (Show, Eq)

-- | A port of the @wp_nonce_tick@ function. Calculates the nonce tick
-- number, where each nonce has a lifetime of two ticks.
wordpressNonceTick
    :: NominalDiffTime -- ^ The nonce lifetime. Wordpress's default is 1 day.
    -> POSIXTime -- ^ The current time.
    -> NonceTick
wordpressNonceTick nonceLifetime currentTime =
    let currentTick = toRational currentTime / (toRational nonceLifetime / 2)
    in  NonceTick $ ceiling currentTick

-- | Determine if the tick-dependent hash of the `CookieToken` matches the
-- hash of the current or previous tick.
validateNonce
    :: AuthScheme -- ^ The Wordpress site's @nonce@ scheme constants - @NONCE_KEY@ & @NONCE_SALT@.
    -> Maybe CookieToken -- ^ A token from the `logged_in` cookie.
    -> NonceTick  -- ^ The current tick number.
    -> Maybe WordpressUserId -- ^ The ID of the currently logged in User.
    -> Text  -- ^ The @action@ of the nonce (e.g., @"wp_rest"@ for API requests).
    -> Text -- ^ The nonce to verify.
    -> Bool
validateNonce scheme maybeToken tick maybeUserId action nonce =
    let
        userId        = maybe "" (T.pack . show . wordpressUserId) maybeUserId
        token         = maybe "" cookieToken maybeToken
        thisCycleHash = hashAndTrim $ joinHashParts
            [T.pack $ show $ tickCount tick, action, userId, token]
        lastCycleHash = hashAndTrim $ joinHashParts
            [T.pack $ show $ tickCount tick - 1, action, userId, token]
    in
        nonce /= "" && nonce `elem` [thisCycleHash, lastCycleHash]
  where
    hashAndTrim s =
        let hashed = wordpressHash scheme s
        in  T.take 10 $ T.drop (T.length hashed - 12) hashed



-- Basic Types

-- | This represents one of the @$scheme@s that Wordpress's cookie/nonce
-- functions use to salt their hashes.
--
-- The built-in Wordpress schemes are @auth@/@auth_sec@ for HTTP/HTTPS
-- requests to @/wp-admin/@, @logged_in@ for authenticated front-end
-- requests, & @nonce@ for form submissions & API requests.
--
-- The secret keys & salts are constants found in your @wp-config.php@
-- file, defined as @LOGGED_IN_SALT@, @LOGGED_IN_KEY@, etc.
--
data AuthScheme
    = AuthScheme
        { schemeKey :: WordpressKey
        , schemeSalt :: WordpressSalt
        }
    deriving (Show, Eq)

-- | An auth scheme's `_KEY` constant, usually defined in your Wordpress
-- site's @wp-config.php@. E.g., `LOGGED_IN_KEY`
newtype WordpressKey
    = WordpressKey { unKey :: Text }
    deriving (Show, Eq)
-- | An auth scheme's `_SALT` constant, usually defined in your Wordpress
-- site's @wp-config.php@. E.g., `LOGGED_IN_SALT`
newtype WordpressSalt
    = WordpressSalt { unSalt :: Text }
    deriving (Show, Eq)

-- | Build the `_KEY` value for an authentiation scheme.
wpConfigKey :: Text -> WordpressKey
wpConfigKey = WordpressKey

-- | Build the `_SALT` value for an authentiation scheme.
wpConfigSalt :: Text -> WordpressSalt
wpConfigSalt = WordpressSalt



-- Helpers

newtype HashSecret = HashSecret Text
newtype HashMessage = HashMessage { hashMessage :: Text }
-- Apply an HMAC hashing function, converting the output to
-- a hex-representation.
hmacText
    :: (B.ByteString -> B.ByteString -> B.ByteString)
    -> HashSecret
    -> HashMessage
    -> Text
hmacText hasher (HashSecret secret) =
    decodeUtf8
        . Base16.encode
        . hasher (encodeUtf8 secret)
        . encodeUtf8
        . hashMessage

-- Apply a hashing function to Text values, converting the output to
-- a hex-representation.
hashText :: (B.ByteString -> B.ByteString) -> HashMessage -> Text
hashText hasher =
    decodeUtf8 . Base16.encode . hasher . encodeUtf8 . hashMessage

-- Join the different text to hash together by `|` like Wordpress expects.
joinHashParts :: [Text] -> Text
joinHashParts = T.intercalate "|"
