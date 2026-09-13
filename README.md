# use-lock/client-laravel

OpenID Connect authentication for Laravel 13 and PHP 8.5. This package is the
client companion to [use-lock/server](https://github.com/use-lock/server).
It runs independently and uses discovery to connect to an OIDC provider.

## Features

- Authorization Code login with S256 PKCE, single-use state and nonce.
- ID token validation: RS256/ES256 signatures, issuer, audience, authorized party,
  nonce and timestamps; cached discovery and JWKS with key rotation support.
- Custom local user resolution and a configurable session guard.
- Local and provider logout, including Inertia external redirects.
- Optional back-channel logout with replay detection and session enforcement.
- API token exchange, refresh tokens and client-credentials grants.
- A fake OIDC provider for application tests.

## Installation

```bash
composer require use-lock/client-laravel
php artisan vendor:publish --tag=oidc-client-config
```

Before a release is available, add a Composer path repository to your consuming
application (adjust the path to this checkout):

```json
{
    "repositories": [{"type": "path", "url": "../client"}]
}
```

Then run `composer require use-lock/client-laravel:@dev`. The service provider is discovered
automatically. No package migrations or server dependency are required.

## Connect to use-lock/server

Register a client on the provider with the exact callback URL of your application,
for example `https://app.example.com/login/callback`. Configure any post-logout
redirect URL on the provider too. Copy the resulting client ID and secret into the
client application's environment:

```dotenv
OIDC_ENABLED=true
OIDC_ISSUER=https://id.example.com
OIDC_CLIENT_ID=your-client-id
OIDC_CLIENT_SECRET=your-client-secret
OIDC_REDIRECT_URI=https://app.example.com/login/callback
OIDC_HOME=/dashboard
OIDC_POST_LOGOUT_REDIRECT_URI=https://app.example.com
```

The issuer must match the provider's configured issuer and discovery document.
A public client can omit the secret. The default scopes are `openid profile email`;
add `offline_access` to `oidc-client.scopes` if your provider requires it to issue
refresh tokens. Clear your application's configuration cache after changing setup.

When enabled, these routes are registered:

| Method | Path | Name |
| --- | --- | --- |
| GET | `/login` | `login` |
| GET | `/login/callback` | `login.callback` |
| POST | `/logout` | `logout` |
| POST | `/oidc/backchannel-logout` | `oidc.backchannel-logout` (opt-in) |

Login, callback and logout use the `web` middleware group. Send a CSRF token with
logout requests. Remove conflicting application routes, or leave `OIDC_ENABLED`
false and register the package controllers on your own routes. With custom callback
routes, set `OIDC_REDIRECT_URI` explicitly.

## Resolve local users

By default, the configured guard's user provider looks up the local user by the
ID token's `sub` claim. For separate user databases, register a resolver in your
application service provider's `boot()` method:

```php
use App\Models\User;
use Lock\Laravel\Support\Facades\OidcClient;

OidcClient::resolveUsersUsing(
    fn (string $subject, array $claims): ?User => User::query()
        ->where('oidc_subject', $subject)
        ->first(),
);
```

This example assumes your application stores the provider subject in its own
`oidc_subject` column. Return an `Authenticatable` user or `null` to reject login.
If you support multiple issuers, bind the mapping to the issuer as well as the
subject. Account creation and linking belong in your application's resolver.

`OIDC_LOGIN_GUARD` defaults to `web` and must select a session-based guard.
Successful login returns to the intended URL or `OIDC_HOME` (default `/dashboard`).

## Back-channel logout

Set `OIDC_BACKCHANNEL_LOGOUT_ENABLED=true` and register
`https://app.example.com/oidc/backchannel-logout` on the provider. This endpoint is
outside the `web` group and accepts signed logout tokens without a browser CSRF
token. The provider must supply a `sid` and `exp`, and use the `logout+jwt` token type.

The package destroys the recorded server-side session and automatically appends
logout enforcement to `web`. Other matching sessions and cookie sessions are
logged out on their next request. Use a persistent cache shared by your application
instances. Set `OIDC_BACKCHANNEL_LOGOUT_RETENTION` at least as high as your maximum
session lifetime (minutes). If you disable `backchannel_logout.auto_middleware`,
add `oidc-client.enforce-logout` to your authenticated session routes yourself.

## API tokens

Resolve `Lock\Laravel\Tokens\ApiTokenBroker` from the container:

```php
use Lock\Laravel\Tokens\ApiTokenBroker;

$broker = app(ApiTokenBroker::class);

// Exchange the logged-in user's access token for an API audience.
$token = $broker->accessToken(audience: 'https://api.example.com', scopes: ['profile']);

// Obtain a machine token without a login session.
$machineToken = $broker->machineToken(audience: 'https://api.example.com');
```

These grants require provider support and client permissions. User token exchange
refreshes expiring session tokens when a refresh token is available. The broker
caches issued tokens until shortly before expiry. Use `exchangedToken()` or
`machineExchangedToken()` for an `ExchangedToken` containing the access token,
expiry and granted scopes. `forget()` clears the current session's exchanged tokens.

## Testing your application

```php
use Lock\Laravel\Support\Facades\OidcClient;

$fake = OidcClient::fake();
$user = User::factory()->create();

$this->withSession($fake->callbackContext())
    ->get($fake->loginAs($user))
    ->assertRedirect('/dashboard');

$this->assertAuthenticatedAs($user);
```

The fake signs real test JWTs and stubs the provider's HTTP endpoints. Unexpected
outbound requests fail. Enable the package routes in your application's test config.

## Namespace layout

Runtime code is grouped by domain, matching the server's architecture. The primary
application entry points are:

- `Lock\Laravel\Support\Facades\OidcClient`
- `Lock\Laravel\Tokens\ApiTokenBroker`
- `Lock\Laravel\Shared\Tokens\ExchangedToken`
- `Lock\Laravel\Shared\Protocol\OidcClientException`
- `Lock\Laravel\Support\Testing\OidcClientFake`

This Laravel package uses the `Lock\Laravel` namespace. Update Composer requirements
and PHP imports in applications using an earlier checkout. Controllers live under
`Lock\Laravel\Protocol\Http\Controllers`; the auto-discovered service provider is
`Lock\Laravel\OidcClientServiceProvider`. Configuration keys and route names retain
their existing names. Environment variables use the
`OIDC_` prefix; update your application environment to the names shown above.

See [CONTRIBUTING.md](CONTRIBUTING.md#domain-structure) for domain ownership and
dependency rules.

## Development

```bash
composer install
composer test
composer check
composer fix
```

The package follows the server's Composer, Pint, PHPStan, Rector, Testbench and Pest
layout. Tests use SQLite and an isolated workbench user model; no running server,
PostgreSQL database or external identity provider is needed. CI checks PHP 8.5 /
Testbench 11 with both lowest and latest installable dependencies. Release Please
manages this package's own versions and changelog.

See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

## License

MIT. Based on the client from `bambamboole/laravel-oidc`.
