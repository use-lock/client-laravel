<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Http;
use Lock\Client\Auth\OidcException;
use Lock\Laravel\Tokens\ApiTokenBroker;

beforeEach(function (): void {
    config()->set('oidc-client.issuer', 'https://id.example.com/');
    config()->set('oidc-client.client_id', 'client-123');
    config()->set('oidc-client.client_secret', 'secret-123');

    session()->put('oidc-client.tokens', [
        'access_token' => 'login-token',
        'refresh_token' => 'refresh-token',
        'id_token' => 'id-token',
        'expires_at' => time() + 3600,
    ]);
});

/**
 * @param  array<string, mixed>  ...$responses
 */
function fakeTokenEndpoint(array ...$responses): void
{
    Http::fake(['https://id.example.com/oauth/token' => Http::sequence($responses)]);
}

it('exchanges the login token for the issuer by default and caches it in the session', function (): void {
    fakeTokenEndpoint(['access_token' => 'api-token', 'expires_in' => 300, 'scope' => 'crm:view']);
    $broker = app(ApiTokenBroker::class);

    $first = $broker->userToken(scopes: ['crm:view', 'crm:manage']);
    $cached = $broker->userToken(scopes: ['crm:manage', 'crm:view']);

    expect($cached)->toEqual($first)
        ->and($cached->accessToken)->toBe('api-token')
        ->and($cached->hasScope('crm:view'))->toBeTrue();
    Http::assertSentCount(1);
    Http::assertSent(fn ($request): bool => $request['grant_type'] === 'urn:ietf:params:oauth:grant-type:token-exchange'
        && $request['subject_token'] === 'login-token'
        && $request['audience'] === 'https://id.example.com');
});

it('caches per audience and exchanges again once forgotten or expired', function (): void {
    fakeTokenEndpoint(
        ['access_token' => 'issuer-token', 'expires_in' => 300],
        ['access_token' => 'other-token', 'expires_in' => 10],
        ['access_token' => 'fresh-other-token', 'expires_in' => 300],
        ['access_token' => 'fresh-issuer-token', 'expires_in' => 300],
    );
    $broker = app(ApiTokenBroker::class);

    expect($broker->userToken()->accessToken)->toBe('issuer-token')
        ->and($broker->userToken('https://other.example')->accessToken)->toBe('other-token')
        ->and($broker->userToken('https://other.example')->accessToken)->toBe('fresh-other-token');

    $broker->forget();

    expect($broker->userToken()->accessToken)->toBe('fresh-issuer-token');
});

it('refreshes an expired login token before exchanging and keeps the id token', function (): void {
    session()->put('oidc-client.tokens.expires_at', time() - 10);
    fakeTokenEndpoint(
        ['access_token' => 'renewed-login', 'refresh_token' => 'renewed-refresh', 'expires_in' => 3600],
        ['access_token' => 'api-token', 'expires_in' => 300],
    );

    expect(app(ApiTokenBroker::class)->userToken()->accessToken)->toBe('api-token')
        ->and(session('oidc-client.tokens'))->toMatchArray([
            'access_token' => 'renewed-login',
            'refresh_token' => 'renewed-refresh',
            'id_token' => 'id-token',
        ]);
    Http::assertSent(fn ($request): bool => $request['grant_type'] === 'refresh_token' && $request['refresh_token'] === 'refresh-token');
    Http::assertSent(fn ($request): bool => ($request['subject_token'] ?? null) === 'renewed-login');
});

it('throws when the login token is expired and no refresh token exists', function (): void {
    session()->put('oidc-client.tokens', ['access_token' => 'login-token', 'expires_at' => time() - 10]);

    app(ApiTokenBroker::class)->userToken();
})->throws(OidcException::class);

it('throws when the token endpoint rejects the exchange', function (): void {
    Http::fake(['https://id.example.com/oauth/token' => Http::response(['error' => 'invalid_grant'], 400)]);

    app(ApiTokenBroker::class)->userToken();
})->throws(OidcException::class);

it('mints a machine token without a login session and caches it in the application cache', function (): void {
    session()->forget('oidc-client.tokens');
    fakeTokenEndpoint(['access_token' => 'machine-token', 'expires_in' => 3600, 'scope' => 'sync:run']);
    $broker = app(ApiTokenBroker::class);

    $token = $broker->machineToken('https://mail.example.com', ['sync:run']);

    expect($token->hasScope('sync:run'))->toBeTrue()
        ->and($broker->machineToken('https://mail.example.com', ['sync:run'])->accessToken)->toBe('machine-token');
    Http::assertSentCount(1);
    Http::assertSent(fn ($request): bool => $request['grant_type'] === 'client_credentials'
        && $request['client_id'] === 'client-123'
        && $request['client_secret'] === 'secret-123'
        && $request['resource'] === 'https://mail.example.com');
});
