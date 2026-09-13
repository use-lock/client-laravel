<?php

declare(strict_types=1);

use Lock\Laravel\Shared\Protocol\OidcClientException;
use Lock\Laravel\Support\Testing\FakeOidcProvider;
use Lock\Laravel\Tokens\Validation\IdTokenValidator;

function signatureAlgB64Url(string $bytes): string
{
    return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
}

beforeEach(function (): void {
    config()->set('oidc-client.issuer', 'https://id.example.com');
    config()->set('oidc-client.client_id', 'client-123');

    $this->provider = new FakeOidcProvider;

    fakeIssuerEndpoints($this->provider, array_merge(
        $this->provider->rsaJwks('key-1'),
        $this->provider->ecJwks('key-2'),
        array_map(
            fn (array $jwk): array => array_merge($jwk, ['kid' => 'key-3', 'alg' => 'PS256']),
            $this->provider->rsaJwks('key-3'),
        ),
    ));
});

it('accepts an ES256-signed id token', function (): void {
    $jwt = $this->provider->idToken(idTokenClaims(), 'key-2', 'ES256');

    $claims = app(IdTokenValidator::class)->validate($jwt, 'the-nonce');

    expect($claims['sub'])->toBe('42');
});

it('rejects a token whose header claims HS256', function (): void {
    $header = signatureAlgB64Url(json_encode(['typ' => 'JWT', 'alg' => 'HS256', 'kid' => 'key-1'], JSON_THROW_ON_ERROR));
    $payload = signatureAlgB64Url(json_encode(idTokenClaims(), JSON_THROW_ON_ERROR));
    $signature = signatureAlgB64Url(hash_hmac('sha256', $header.'.'.$payload, 'attacker-known-secret', true));

    app(IdTokenValidator::class)->validate($header.'.'.$payload.'.'.$signature, 'the-nonce');
})->throws(OidcClientException::class, 'signature is invalid');

it('rejects an unsigned token with alg none', function (): void {
    $header = signatureAlgB64Url(json_encode(['typ' => 'JWT', 'alg' => 'none', 'kid' => 'key-1'], JSON_THROW_ON_ERROR));
    $payload = signatureAlgB64Url(json_encode(idTokenClaims(), JSON_THROW_ON_ERROR));

    app(IdTokenValidator::class)->validate($header.'.'.$payload.'.', 'the-nonce');
})->throws(OidcClientException::class, 'could not be parsed');

it('rejects a token bound to a JWK with an algorithm outside the allow-list', function (): void {
    $jwt = $this->provider->idToken(idTokenClaims(), 'key-3');

    app(IdTokenValidator::class)->validate($jwt, 'the-nonce');
})->throws(OidcClientException::class, 'not supported');
