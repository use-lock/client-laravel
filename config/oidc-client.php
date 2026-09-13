<?php

declare(strict_types=1);

return [
    /*
    |--------------------------------------------------------------------------
    | OIDC client
    |--------------------------------------------------------------------------
    |
    | This package turns a Laravel app into an OpenID Connect client: it
    | drives the Authorization-Code + PKCE flow against any OIDC provider,
    | validates the returned id_token against the provider's JWKS, and logs the
    | resolved user into the configured guard. For self-SSO, point `issuer` at
    | your own use-lock/server provider.
    |
    */

    'enabled' => env('OIDC_ENABLED', false),

    'issuer' => env('OIDC_ISSUER'),

    'client_id' => env('OIDC_CLIENT_ID'),

    'client_secret' => env('OIDC_CLIENT_SECRET'),

    // Unset, the app's own login.callback route.
    'redirect_uri' => env('OIDC_REDIRECT_URI'),

    'scopes' => ['openid', 'profile', 'email'],

    'login_guard' => env('OIDC_LOGIN_GUARD', 'web'),

    'redirect_after_login' => env('OIDC_HOME', '/dashboard'),

    'post_logout_redirect_uri' => env('OIDC_POST_LOGOUT_REDIRECT_URI'),

    /*
    |--------------------------------------------------------------------------
    | Discovery cache
    |--------------------------------------------------------------------------
    |
    | The provider's discovery document and JWKS are cached for this many
    | seconds to avoid an HTTP round-trip on every authentication request.
    |
    */

    'discovery_cache_ttl' => (int) env('OIDC_DISCOVERY_TTL', 3600),

    /*
    |--------------------------------------------------------------------------
    | Clock skew
    |--------------------------------------------------------------------------
    |
    | Allowed leeway, in seconds, when validating the id_token `exp`/`nbf`/`iat`
    | claims.
    |
    */

    'leeway' => (int) env('OIDC_LEEWAY', 60),

    /*
    |--------------------------------------------------------------------------
    | Back-channel logout
    |--------------------------------------------------------------------------
    |
    | When enabled, the package registers an endpoint that accepts OIDC
    | back-channel logout tokens from the provider and terminates the
    | matching local session(s).
    |
    */

    'backchannel_logout' => [
        'enabled' => env('OIDC_BACKCHANNEL_LOGOUT_ENABLED', false),
        'auto_middleware' => true,
        'middleware_group' => 'web',
        'retention_minutes' => (int) env('OIDC_BACKCHANNEL_LOGOUT_RETENTION', (int) env('SESSION_LIFETIME', 120)),
    ],
];
