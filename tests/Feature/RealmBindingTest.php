<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Http;
use Lock\Client\Auth\OidcException;
use Lock\Client\Realm;

beforeEach(function (): void {
    config()->set([
        'oidc-client.issuer' => 'https://id.example.com',
        'oidc-client.client_id' => 'client-123',
        'oidc-client.client_secret' => 'secret-123',
    ]);
});

it('sends realm requests through Http fakes registered after the realm was resolved', function (): void {
    $realm = app(Realm::class);

    Http::fake(['https://id.example.com/oauth/token' => Http::response(['access_token' => 'machine-token', 'expires_in' => 300])]);

    expect($realm->tokens()->clientCredentials()->accessToken)->toBe('machine-token');
    Http::assertSent(fn ($request): bool => $request['client_secret'] === 'secret-123' && ! $request->hasHeader('Authorization'));
});

it('authenticates with client_secret_basic when configured', function (): void {
    config()->set('oidc-client.token_endpoint_auth_method', 'client_secret_basic');
    Http::fake(['https://id.example.com/oauth/token' => Http::response(['access_token' => 'machine-token', 'expires_in' => 300])]);

    app(Realm::class)->tokens()->clientCredentials();

    Http::assertSent(fn ($request): bool => $request->hasHeader('Authorization', 'Basic '.base64_encode('client-123:secret-123'))
        && ! isset($request['client_secret']));
});

it('requires a realm URL', function (): void {
    config()->set('oidc-client.issuer');

    app(Realm::class);
})->throws(OidcException::class, 'oidc-client.issuer');
