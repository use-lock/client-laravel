<?php

declare(strict_types=1);

use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\Http;
use Lock\Laravel\Discovery\OidcDiscovery;
use Lock\Laravel\Shared\Protocol\OidcClientException;
use Lock\Laravel\Support\Testing\FakeOidcProvider;
use Lock\Laravel\Tokens\Validation\IdTokenValidator;

/**
 * @param  array<int, array<int, array<string, mixed>>>  $jwksResponses  Key lists served in order, one per JWKS fetch.
 */
function fakeIssuerWithRotatingJwks(array $jwksResponses): void
{
    $sequence = Http::sequence();
    foreach ($jwksResponses as $keys) {
        $sequence->push(['keys' => $keys]);
    }

    Http::fake([
        'https://id.example.com/.well-known/openid-configuration' => Http::response([
            'issuer' => 'https://id.example.com',
            'authorization_endpoint' => 'https://id.example.com/oauth/authorize',
            'token_endpoint' => 'https://id.example.com/oauth/token',
            'jwks_uri' => 'https://id.example.com/.well-known/jwks.json',
        ]),
        'https://id.example.com/.well-known/jwks.json' => $sequence,
    ]);
}

function jwksFetchCount(): int
{
    return Http::recorded(fn (Request $request): bool => $request->url() === 'https://id.example.com/.well-known/jwks.json')->count();
}

beforeEach(function (): void {
    config()->set('oidc-client.issuer', 'https://id.example.com');
    config()->set('oidc-client.client_id', 'client-123');
});

it('accepts a token signed with a rotated key by refetching the JWKS on an unknown kid', function (): void {
    $oldProvider = new FakeOidcProvider;
    $newProvider = new FakeOidcProvider;
    fakeIssuerWithRotatingJwks([
        $oldProvider->rsaJwks('key-old'),
        $newProvider->rsaJwks('key-new'),
    ]);
    $validator = app(IdTokenValidator::class);
    $validator->validate($oldProvider->idToken(idTokenClaims(), 'key-old'), 'the-nonce');

    $claims = $validator->validate($newProvider->idToken(idTokenClaims(), 'key-new'), 'the-nonce');

    expect($claims['sub'])->toBe('42')
        ->and(jwksFetchCount())->toBe(2);
});

it('rejects a token whose kid is in neither the cached nor the fresh JWKS', function (): void {
    $provider = new FakeOidcProvider;
    fakeIssuerWithRotatingJwks([
        $provider->rsaJwks('key-old'),
        $provider->rsaJwks('key-old'),
    ]);
    app(OidcDiscovery::class)->jwks();

    expect(fn () => app(IdTokenValidator::class)->validate($provider->idToken(idTokenClaims(), 'key-unknown'), 'the-nonce'))
        ->toThrow(OidcClientException::class, 'No JWKS key matches');

    expect(jwksFetchCount())->toBe(2);
});
