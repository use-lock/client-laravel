<?php

declare(strict_types=1);

return [
    /*
    |--------------------------------------------------------------------------
    | Lock client
    |--------------------------------------------------------------------------
    |
    | Signs users in through a Lock realm with the authorization code flow and
    | PKCE, and logs the resolved user into the configured guard. `issuer` is
    | the realm URL. For self-SSO, point it at the app's own realm.
    |
    */

    'enabled' => env('OIDC_ENABLED', false),

    'issuer' => env('OIDC_ISSUER'),

    'client_id' => env('OIDC_CLIENT_ID'),

    'client_secret' => env('OIDC_CLIENT_SECRET'),

    // client_secret_post or client_secret_basic, as registered for the client.
    'token_endpoint_auth_method' => env('OIDC_TOKEN_ENDPOINT_AUTH_METHOD', 'client_secret_post'),

    // Unset, the app's own login.callback route.
    'redirect_uri' => env('OIDC_REDIRECT_URI'),

    'scopes' => ['openid', 'profile', 'email'],

    'login_guard' => env('OIDC_LOGIN_GUARD', 'web'),

    'redirect_after_login' => env('OIDC_HOME', '/dashboard'),

    'post_logout_redirect_uri' => env('OIDC_POST_LOGOUT_REDIRECT_URI'),

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
