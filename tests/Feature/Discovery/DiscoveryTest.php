<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Http;
use Lock\Laravel\Discovery\OidcDiscovery;

beforeEach(function (): void {
    config()->set('oidc-client.issuer', 'https://id.example.com');
});

it('fetches and maps the discovery document', function (): void {
    Http::fake([
        'https://id.example.com/.well-known/openid-configuration' => Http::response([
            'issuer' => 'https://id.example.com',
            'authorization_endpoint' => 'https://id.example.com/oauth/authorize',
            'token_endpoint' => 'https://id.example.com/oauth/token',
            'jwks_uri' => 'https://id.example.com/.well-known/jwks.json',
            'end_session_endpoint' => 'https://id.example.com/oauth/logout',
        ]),
    ]);

    $meta = app(OidcDiscovery::class)->metadata();

    expect($meta->issuer)->toBe('https://id.example.com')
        ->and($meta->authorizationEndpoint)->toBe('https://id.example.com/oauth/authorize')
        ->and($meta->tokenEndpoint)->toBe('https://id.example.com/oauth/token')
        ->and($meta->jwksUri)->toBe('https://id.example.com/.well-known/jwks.json')
        ->and($meta->endSessionEndpoint)->toBe('https://id.example.com/oauth/logout');
});

it('caches discovery so the document is fetched once', function (): void {
    Http::fake([
        'https://id.example.com/.well-known/openid-configuration' => Http::response([
            'issuer' => 'https://id.example.com',
            'authorization_endpoint' => 'https://id.example.com/oauth/authorize',
            'token_endpoint' => 'https://id.example.com/oauth/token',
            'jwks_uri' => 'https://id.example.com/.well-known/jwks.json',
        ]),
    ]);

    $discovery = app(OidcDiscovery::class);
    $discovery->metadata();
    $discovery->metadata();

    Http::assertSentCount(1);
});

it('fetches the jwks key set from the discovered jwks_uri', function (): void {
    Http::fake([
        'https://id.example.com/.well-known/openid-configuration' => Http::response([
            'issuer' => 'https://id.example.com',
            'authorization_endpoint' => 'https://id.example.com/oauth/authorize',
            'token_endpoint' => 'https://id.example.com/oauth/token',
            'jwks_uri' => 'https://id.example.com/.well-known/jwks.json',
        ]),
        'https://id.example.com/.well-known/jwks.json' => Http::response([
            'keys' => [['kid' => 'abc', 'kty' => 'RSA', 'n' => 'AQAB', 'e' => 'AQAB']],
        ]),
    ]);

    $keys = app(OidcDiscovery::class)->jwks();

    expect($keys)->toHaveCount(1)
        ->and($keys[0]['kid'])->toBe('abc');
});
