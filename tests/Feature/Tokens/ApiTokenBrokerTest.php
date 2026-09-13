<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Http;
use Lock\Laravel\Shared\Protocol\OidcClientException;
use Lock\Laravel\Tokens\ApiTokenBroker;

beforeEach(function (): void {
    config()->set('oidc-client.issuer', 'https://id.example.com');
    config()->set('oidc-client.client_id', 'client-123');

    Http::fake([
        'https://id.example.com/.well-known/openid-configuration' => Http::response([
            'issuer' => 'https://id.example.com',
            'authorization_endpoint' => 'https://id.example.com/oauth/authorize',
            'token_endpoint' => 'https://id.example.com/oauth/token',
            'jwks_uri' => 'https://id.example.com/jwks.json',
        ]),
    ]);

    session()->put('oidc-client.tokens', [
        'access_token' => 'login-token',
        'refresh_token' => 'refresh-token',
        'id_token' => 'id-token',
        'expires_at' => time() + 3600,
    ]);
});

it('exchanges the login token with extension parameters and the issuer as default audience', function (): void {
    Http::fake(['https://id.example.com/oauth/token' => Http::response(['access_token' => 'api-token', 'expires_in' => 300])]);

    expect(app(ApiTokenBroker::class)->accessToken(['tenant' => 'acme']))->toBe('api-token');

    Http::assertSent(fn ($request): bool => $request->url() === 'https://id.example.com/oauth/token'
        && $request['grant_type'] === 'urn:ietf:params:oauth:grant-type:token-exchange'
        && $request['subject_token'] === 'login-token'
        && $request['subject_token_type'] === 'urn:ietf:params:oauth:token-type:access_token'
        && $request['audience'] === 'https://id.example.com'
        && $request['client_id'] === 'client-123'
        && $request['tenant'] === 'acme');
});

it('strips a trailing slash from the issuer when it is used as the default audience', function (): void {
    config()->set('oidc-client.issuer', 'https://id.example.com/');
    Http::fake(['https://id.example.com/oauth/token' => Http::response(['access_token' => 'api-token', 'expires_in' => 300])]);

    app(ApiTokenBroker::class)->accessToken(['tenant' => 'acme']);

    Http::assertSent(fn ($request): bool => $request->url() === 'https://id.example.com/oauth/token'
        && $request['grant_type'] === 'urn:ietf:params:oauth:grant-type:token-exchange'
        && $request['audience'] === 'https://id.example.com');
});

it('uses an explicit audience and caches it separately', function (): void {
    Http::fake(['https://id.example.com/oauth/token' => Http::sequence()
        ->push(['access_token' => 'issuer-token', 'expires_in' => 300])
        ->push(['access_token' => 'other-token', 'expires_in' => 300])]);
    $broker = app(ApiTokenBroker::class);

    expect($broker->accessToken(['tenant' => 'acme']))->toBe('issuer-token')
        ->and($broker->accessToken(['tenant' => 'acme'], 'https://other.example'))->toBe('other-token');

    Http::assertSent(fn ($request): bool => $request->url() !== 'https://id.example.com/oauth/token'
        || $request['audience'] === 'https://other.example');
});

it('serves a cached token without a second exchange', function (): void {
    Http::fake(['https://id.example.com/oauth/token' => Http::response(['access_token' => 'api-token', 'expires_in' => 300])]);
    $broker = app(ApiTokenBroker::class);

    $broker->accessToken(['tenant' => 'acme']);
    expect($broker->accessToken(['tenant' => 'acme']))->toBe('api-token');

    Http::assertSentCount(2);
});

it('re-exchanges when the cached token is expired', function (): void {
    Http::fake(['https://id.example.com/oauth/token' => Http::sequence()
        ->push(['access_token' => 'api-token', 'expires_in' => 10])
        ->push(['access_token' => 'fresh-token', 'expires_in' => 300])]);
    $broker = app(ApiTokenBroker::class);

    $broker->accessToken(['tenant' => 'acme']);
    expect($broker->accessToken(['tenant' => 'acme']))->toBe('fresh-token');
});

it('caches per parameter set', function (): void {
    Http::fake(['https://id.example.com/oauth/token' => Http::sequence()
        ->push(['access_token' => 'acme-token', 'expires_in' => 300])
        ->push(['access_token' => 'globex-token', 'expires_in' => 300])]);
    $broker = app(ApiTokenBroker::class);

    expect($broker->accessToken(['tenant' => 'acme']))->toBe('acme-token')
        ->and($broker->accessToken(['tenant' => 'globex']))->toBe('globex-token')
        ->and($broker->accessToken(['tenant' => 'acme']))->toBe('acme-token');
});

it('sends requested scopes space-joined', function (): void {
    Http::fake(['https://id.example.com/oauth/token' => Http::response(['access_token' => 'api-token', 'expires_in' => 300])]);

    app(ApiTokenBroker::class)->accessToken(['tenant' => 'acme'], scopes: ['crm:view', 'catalog:view']);

    Http::assertSent(fn ($request): bool => $request->url() === 'https://id.example.com/oauth/token'
        && $request['grant_type'] === 'urn:ietf:params:oauth:grant-type:token-exchange'
        && $request['scope'] === 'crm:view catalog:view');
});

it('omits the scope parameter when no scopes are requested', function (): void {
    Http::fake(['https://id.example.com/oauth/token' => Http::response(['access_token' => 'api-token', 'expires_in' => 300])]);

    app(ApiTokenBroker::class)->accessToken(['tenant' => 'acme'], scopes: []);

    Http::assertSent(fn ($request): bool => $request->url() === 'https://id.example.com/oauth/token'
        && $request['grant_type'] === 'urn:ietf:params:oauth:grant-type:token-exchange'
        && ! isset($request['scope']));
});

it('caches per scope set regardless of scope order', function (): void {
    Http::fake(['https://id.example.com/oauth/token' => Http::sequence()
        ->push(['access_token' => 'narrow-token', 'expires_in' => 300])
        ->push(['access_token' => 'wide-token', 'expires_in' => 300])]);
    $broker = app(ApiTokenBroker::class);

    expect($broker->accessToken(['tenant' => 'acme'], scopes: ['crm:view']))->toBe('narrow-token')
        ->and($broker->accessToken(['tenant' => 'acme'], scopes: ['crm:view', 'crm:manage']))->toBe('wide-token')
        ->and($broker->accessToken(['tenant' => 'acme'], scopes: ['crm:manage', 'crm:view']))->toBe('wide-token');
});

it('returns the exchanged token with its expiry', function (): void {
    Http::fake(['https://id.example.com/oauth/token' => Http::response(['access_token' => 'api-token', 'expires_in' => 300])]);

    $token = app(ApiTokenBroker::class)->exchangedToken(['tenant' => 'acme'], scopes: ['crm:view']);

    expect($token->accessToken)->toBe('api-token')
        ->and($token->expiresAt)->toBeGreaterThan(time() + 290)
        ->and($token->expiresAt)->toBeLessThanOrEqual(time() + 300)
        ->and($token->expiresIn())->toBeGreaterThan(290);
});

it('keeps the cached expiry when serving an exchanged token from the cache', function (): void {
    Http::fake(['https://id.example.com/oauth/token' => Http::response(['access_token' => 'api-token', 'expires_in' => 300])]);
    $broker = app(ApiTokenBroker::class);

    $first = $broker->exchangedToken(['tenant' => 'acme']);
    $second = $broker->exchangedToken(['tenant' => 'acme']);

    expect($second->accessToken)->toBe('api-token')
        ->and($second->expiresAt)->toBe($first->expiresAt);
    Http::assertSentCount(2);
});

it('exchanges again after the cached tokens are forgotten', function (): void {
    Http::fake(['https://id.example.com/oauth/token' => Http::sequence()
        ->push(['access_token' => 'api-token', 'expires_in' => 300])
        ->push(['access_token' => 'fresh-token', 'expires_in' => 300])]);
    $broker = app(ApiTokenBroker::class);

    $broker->accessToken(['tenant' => 'acme']);
    $broker->forget();

    expect($broker->accessToken(['tenant' => 'acme']))->toBe('fresh-token');
});

it('throws when the exchange is rejected', function (): void {
    Http::fake(['https://id.example.com/oauth/token' => Http::response(['error' => 'invalid_grant'], 400)]);

    app(ApiTokenBroker::class)->accessToken(['tenant' => 'acme']);
})->throws(OidcClientException::class);

it('throws when no login token is in the session', function (): void {
    session()->forget('oidc-client.tokens');

    app(ApiTokenBroker::class)->accessToken(['tenant' => 'acme']);
})->throws(OidcClientException::class);

it('refreshes an expired login token before exchanging', function (): void {
    session()->put('oidc-client.tokens.expires_at', time() - 10);
    Http::fake(['https://id.example.com/oauth/token' => Http::sequence()
        ->push(['access_token' => 'renewed-login', 'refresh_token' => 'renewed-refresh', 'expires_in' => 3600])
        ->push(['access_token' => 'api-token', 'expires_in' => 300])]);

    expect(app(ApiTokenBroker::class)->accessToken(['tenant' => 'acme']))->toBe('api-token');

    Http::assertSent(fn ($request): bool => $request->url() === 'https://id.example.com/oauth/token'
        && $request['grant_type'] === 'refresh_token'
        && $request['refresh_token'] === 'refresh-token'
        && $request['client_id'] === 'client-123');
    Http::assertSent(fn ($request): bool => $request->url() === 'https://id.example.com/oauth/token'
        && $request['grant_type'] === 'urn:ietf:params:oauth:grant-type:token-exchange'
        && $request['subject_token'] === 'renewed-login');
    expect(session('oidc-client.tokens.access_token'))->toBe('renewed-login')
        ->and(session('oidc-client.tokens.refresh_token'))->toBe('renewed-refresh')
        ->and(session('oidc-client.tokens.expires_at'))->toBeGreaterThan(time() + 3500);
});

it('keeps the old refresh token when the response omits one', function (): void {
    session()->put('oidc-client.tokens.expires_at', time() - 10);
    Http::fake(['https://id.example.com/oauth/token' => Http::sequence()
        ->push(['access_token' => 'renewed-login', 'expires_in' => 3600])
        ->push(['access_token' => 'api-token', 'expires_in' => 300])]);

    app(ApiTokenBroker::class)->accessToken(['tenant' => 'acme']);

    expect(session('oidc-client.tokens.refresh_token'))->toBe('refresh-token');
});

it('throws when the refresh is rejected', function (): void {
    session()->put('oidc-client.tokens.expires_at', time() - 10);
    Http::fake(['https://id.example.com/oauth/token' => Http::response(['error' => 'invalid_grant'], 400)]);

    app(ApiTokenBroker::class)->accessToken(['tenant' => 'acme']);
})->throws(OidcClientException::class);

it('throws when the login token is expired and no refresh token exists', function (): void {
    session()->put('oidc-client.tokens', ['access_token' => 'login-token', 'expires_at' => time() - 10]);

    app(ApiTokenBroker::class)->accessToken(['tenant' => 'acme']);
})->throws(OidcClientException::class);

it('mints a machine token via client credentials without any login session', function (): void {
    session()->forget('oidc-client.tokens');
    config()->set('oidc-client.client_secret', 'secret-123');
    Http::fake(['https://id.example.com/oauth/token' => Http::response(['access_token' => 'machine-token', 'expires_in' => 3600])]);

    expect(app(ApiTokenBroker::class)->machineToken(audience: 'https://mail.example.com'))->toBe('machine-token');

    Http::assertSent(fn ($request): bool => $request->url() === 'https://id.example.com/oauth/token'
        && $request['grant_type'] === 'client_credentials'
        && $request['client_id'] === 'client-123'
        && $request['client_secret'] === 'secret-123'
        && $request['resource'] === 'https://mail.example.com');
});

it('omits the resource parameter without an audience and sends requested scopes', function (): void {
    config()->set('oidc-client.client_secret', 'secret-123');
    Http::fake(['https://id.example.com/oauth/token' => Http::response(['access_token' => 'machine-token', 'expires_in' => 3600])]);

    app(ApiTokenBroker::class)->machineToken(scopes: ['contacts:write']);

    Http::assertSent(fn ($request): bool => $request->url() === 'https://id.example.com/oauth/token'
        && $request['grant_type'] === 'client_credentials'
        && ! isset($request['resource'])
        && $request['scope'] === 'contacts:write');
});

it('caches machine tokens in the application cache per client and audience', function (): void {
    Http::fake(['https://id.example.com/oauth/token' => Http::sequence()
        ->push(['access_token' => 'first-token', 'expires_in' => 3600])
        ->push(['access_token' => 'other-client-token', 'expires_in' => 3600])]);
    $broker = app(ApiTokenBroker::class);

    expect($broker->machineToken(audience: 'https://mail.example.com'))->toBe('first-token')
        ->and($broker->machineToken(audience: 'https://mail.example.com'))->toBe('first-token')
        ->and($broker->machineToken(audience: 'https://mail.example.com', clientId: 'other-client', clientSecret: 'other-secret'))->toBe('other-client-token');

    Http::assertSentCount(3);
});

it('uses explicit client credentials over the configured ones', function (): void {
    Http::fake(['https://id.example.com/oauth/token' => Http::response(['access_token' => 'machine-token', 'expires_in' => 3600])]);

    app(ApiTokenBroker::class)->machineToken(clientId: 'm2m-client', clientSecret: 'm2m-secret');

    Http::assertSent(fn ($request): bool => $request->url() === 'https://id.example.com/oauth/token'
        && $request['client_id'] === 'm2m-client'
        && $request['client_secret'] === 'm2m-secret');
});

it('throws when the client-credentials request is rejected', function (): void {
    Http::fake(['https://id.example.com/oauth/token' => Http::response(['error' => 'invalid_client'], 401)]);

    app(ApiTokenBroker::class)->machineToken();
})->throws(OidcClientException::class);

it('returns the machine token with its expiry', function (): void {
    Http::fake(['https://id.example.com/oauth/token' => Http::response(['access_token' => 'machine-token', 'expires_in' => 300])]);

    $token = app(ApiTokenBroker::class)->machineExchangedToken();

    expect($token->accessToken)->toBe('machine-token')
        ->and($token->expiresIn())->toBeGreaterThan(250)
        ->and($token->expiresIn())->toBeLessThanOrEqual(300);
});

it('exposes the scopes the token endpoint granted on the exchange', function (): void {
    Http::fake(['https://id.example.com/oauth/token' => Http::response(['access_token' => 'api-token', 'expires_in' => 300, 'scope' => 'crm:view catalog:view'])]);

    $token = app(ApiTokenBroker::class)->exchangedToken(['tenant' => 'acme'], scopes: ['crm:view', 'catalog:view', 'crm:manage']);

    expect($token->scopes)->toBe(['crm:view', 'catalog:view'])
        ->and($token->hasScope('crm:view'))->toBeTrue()
        ->and($token->hasScope('crm:manage'))->toBeFalse();
});

it('serves the granted scopes from the session cache', function (): void {
    Http::fake(['https://id.example.com/oauth/token' => Http::response(['access_token' => 'api-token', 'expires_in' => 300, 'scope' => 'crm:view'])]);
    $broker = app(ApiTokenBroker::class);

    $broker->exchangedToken(['tenant' => 'acme']);
    $cached = $broker->exchangedToken(['tenant' => 'acme']);

    expect($cached->scopes)->toBe(['crm:view']);
    Http::assertSentCount(2);
});

it('leaves the granted scopes unknown when the exchange response omits scope', function (): void {
    Http::fake(['https://id.example.com/oauth/token' => Http::response(['access_token' => 'api-token', 'expires_in' => 300])]);

    $token = app(ApiTokenBroker::class)->exchangedToken(['tenant' => 'acme'], scopes: ['crm:view']);

    expect($token->scopes)->toBeNull()
        ->and($token->hasScope('crm:view'))->toBeFalse();
});

it('exposes the scopes granted to a machine token', function (): void {
    config()->set('oidc-client.client_secret', 'secret-456');
    session()->forget('oidc-client.tokens');
    Http::fake(['https://id.example.com/oauth/token' => Http::response(['access_token' => 'machine-token', 'expires_in' => 300, 'scope' => 'sync:run'])]);

    $token = app(ApiTokenBroker::class)->machineExchangedToken(scopes: ['sync:run', 'sync:admin']);

    expect($token->scopes)->toBe(['sync:run'])
        ->and($token->hasScope('sync:run'))->toBeTrue();
});
