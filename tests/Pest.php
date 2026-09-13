<?php

declare(strict_types=1);

use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Http;
use Lock\Laravel\Support\Testing\FakeOidcProvider;
use Lock\Laravel\Tests\TestCase;

uses(TestCase::class)->in('Feature');
uses(RefreshDatabase::class)->in('Feature');

/**
 * @param  array<int, array<string, mixed>>|null  $keys  Defaults to the provider's RSA key under kid `key-1`.
 */
function fakeIssuerEndpoints(FakeOidcProvider $provider, ?array $keys = null): void
{
    Http::fake([
        'https://id.example.com/.well-known/openid-configuration' => Http::response([
            'issuer' => 'https://id.example.com',
            'authorization_endpoint' => 'https://id.example.com/oauth/authorize',
            'token_endpoint' => 'https://id.example.com/oauth/token',
            'jwks_uri' => 'https://id.example.com/.well-known/jwks.json',
        ]),
        'https://id.example.com/.well-known/jwks.json' => Http::response([
            'keys' => $keys ?? $provider->rsaJwks('key-1'),
        ]),
    ]);
}

/**
 * @param  array<string, mixed>  $overrides
 * @return array<string, mixed>
 */
function idTokenClaims(array $overrides = []): array
{
    return array_merge([
        'iss' => 'https://id.example.com',
        'aud' => 'client-123',
        'sub' => '42',
        'nonce' => 'the-nonce',
        'iat' => time(),
        'nbf' => time(),
        'exp' => time() + 300,
    ], $overrides);
}

/**
 * @param  array<string, mixed>  $overrides
 * @return array<string, mixed>
 */
function logoutTokenClaims(array $overrides = []): array
{
    return array_merge([
        'iss' => 'https://id.example.com',
        'aud' => 'client-123',
        'sub' => '42',
        'sid' => 'sess-abc',
        'iat' => time(),
        'exp' => time() + 120,
        'jti' => 'jti-1',
        'events' => ['http://schemas.openid.net/event/backchannel-logout' => (object) []],
    ], $overrides);
}
