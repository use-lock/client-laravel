# use-lock/client-laravel

Laravel integration for [Lock](https://github.com/use-lock/lock). It signs users in
through a Lock realm, handles back-channel logout and obtains API tokens. The
protocol work (authorization code flow with PKCE, token grants and token validation)
is done by [use-lock/client-php](https://github.com/use-lock/client-php). The package
works with Lock only, not with other OpenID Connect providers.

Requires PHP 8.5 and Laravel 13.

## Installation

```bash
composer require use-lock/client-laravel
php artisan vendor:publish --tag=oidc-client-config
```

## Configuration

Register a client in your Lock realm with the callback URL of your application, for
example `https://app.example.com/login/callback`, and any post-logout redirect URL.
Then configure the application:

```dotenv
OIDC_ENABLED=true
OIDC_ISSUER=https://id.example.com
OIDC_CLIENT_ID=your-client-id
OIDC_CLIENT_SECRET=your-client-secret
OIDC_TOKEN_ENDPOINT_AUTH_METHOD=client_secret_post
OIDC_REDIRECT_URI=https://app.example.com/login/callback
OIDC_HOME=/dashboard
OIDC_POST_LOGOUT_REDIRECT_URI=https://app.example.com
```

| Key | Env | Default | Purpose |
| --- | --- | --- | --- |
| `enabled` | `OIDC_ENABLED` | `false` | Registers the routes below |
| `issuer` | `OIDC_ISSUER` | | The realm URL |
| `client_id` | `OIDC_CLIENT_ID` | | |
| `client_secret` | `OIDC_CLIENT_SECRET` | | Omit for public clients |
| `token_endpoint_auth_method` | `OIDC_TOKEN_ENDPOINT_AUTH_METHOD` | `client_secret_post` | `client_secret_post` or `client_secret_basic`, as registered for the client |
| `redirect_uri` | `OIDC_REDIRECT_URI` | the `login.callback` route | |
| `scopes` | | `openid profile email` | Add `offline_access` for refresh tokens if the realm requires it |
| `login_guard` | `OIDC_LOGIN_GUARD` | `web` | Must be a session guard |
| `redirect_after_login` | `OIDC_HOME` | `/dashboard` | Used when there is no intended URL |
| `post_logout_redirect_uri` | `OIDC_POST_LOGOUT_REDIRECT_URI` | | |
| `backchannel_logout.*` | `OIDC_BACKCHANNEL_LOGOUT_*` | disabled | See below |

The container binds a `Lock\Client\Realm` built from this configuration. It uses the
default cache store for signing keys and client credentials tokens, and sends its
requests through Laravel's HTTP client, so `Http::fake()` applies to them.

When enabled, these routes are registered:

| Method | Path | Name |
| --- | --- | --- |
| GET | `/login` | `login` |
| GET | `/login/callback` | `login.callback` |
| POST | `/logout` | `logout` |
| POST | `/oidc/backchannel-logout` | `oidc.backchannel-logout` (opt-in) |

Login, callback and logout use the `web` middleware group; send a CSRF token with
logout requests. Login and logout answer Inertia requests with an external redirect.
Every protocol failure throws `Lock\Client\Auth\OidcException`; the callback reports
it and redirects to `login` with an `oidc` error.

## Resolve local users

By default, the guard's user provider looks up the user by the ID token's `sub`
claim. To map users yourself, register a resolver in a service provider's `boot()`
method and return an `Authenticatable` or `null` to reject the login:

```php
use App\Models\User;
use Lock\Laravel\Support\Facades\OidcClient;

OidcClient::resolveUsersUsing(
    fn (string $subject, array $claims): ?User => User::firstWhere('lock_subject', $subject),
);
```

## Back-channel logout

Set `OIDC_BACKCHANNEL_LOGOUT_ENABLED=true` and register
`https://app.example.com/oidc/backchannel-logout` as the client's back-channel logout
URL. The endpoint destroys the session recorded for the token's `sid`, and a
middleware appended to the `web` group logs out other sessions with that `sid` on
their next request. Each logout token `jti` is accepted once.

Use a cache shared by all application instances, and set
`OIDC_BACKCHANNEL_LOGOUT_RETENTION` (minutes) at least as high as the session
lifetime. If you disable `backchannel_logout.auto_middleware`, add
`oidc-client.enforce-logout` to your session routes yourself.

## API tokens

```php
use Lock\Laravel\Tokens\ApiTokenBroker;

$broker = app(ApiTokenBroker::class);

// Exchange the logged-in user's access token for another audience.
$token = $broker->userToken(audience: 'https://api.example.com', scopes: ['profile']);

// A client credentials token, without a login session.
$token = $broker->machineToken(audience: 'https://api.example.com');

$token->accessToken;
```

Both return a `Lock\Client\Auth\TokenSet` with the access token, expiry and granted
scopes. The user token exchange renews expired session tokens with the refresh token
and caches exchanged tokens in the session; `forget()` clears them. Machine tokens
are cached in the application cache.

A failed grant throws `Lock\Client\Auth\ProviderException`. Check `isTransient()`
before discarding the session: it is true when the provider could not be reached,
failed, or throttled the request, and false when it rejected the grant (its `status`
and OAuth `error` tell which).

## Testing your application

```php
use Lock\Laravel\Support\Facades\OidcClient;

$fake = OidcClient::fake();
$user = User::factory()->create();

$this->withSession($fake->callbackContext())
    ->get($fake->loginAs($user))
    ->assertRedirect('/dashboard');

$fake->assertCodeExchanged()->assertLoggedIn($user);
```

The fake signs real test tokens and stubs the realm's JWKS, token and logout
endpoints. Other outbound requests fail. Enable the package routes in your test
configuration.

## Development

```bash
composer check   # Pint, PHPStan, Rector and Pest
composer fix     # Rector and Pint
```

See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

## License

MIT.
