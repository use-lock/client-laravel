<?php

declare(strict_types=1);

use Lock\Laravel\Shared\Protocol\OidcClientException;
use Lock\Laravel\Support\Testing\FakeOidcProvider;
use Lock\Laravel\Tokens\Validation\IdTokenValidator;

beforeEach(function (): void {
    config()->set('oidc-client.issuer', 'https://id.example.com');
    config()->set('oidc-client.client_id', 'client-123');

    $this->provider = new FakeOidcProvider;

    fakeIssuerEndpoints($this->provider);
});

it('accepts a well-formed id token and returns its claims', function (): void {
    $jwt = $this->provider->idToken(idTokenClaims(), 'key-1');

    $claims = app(IdTokenValidator::class)->validate($jwt, 'the-nonce');

    expect($claims['sub'])->toBe('42')
        ->and($claims['iss'])->toBe('https://id.example.com');
});

it('rejects a token whose nonce does not match', function (): void {
    $jwt = $this->provider->idToken(idTokenClaims(), 'key-1');

    app(IdTokenValidator::class)->validate($jwt, 'different-nonce');
})->throws(OidcClientException::class, 'nonce does not match');

it('rejects a token with the wrong audience', function (): void {
    $jwt = $this->provider->idToken(idTokenClaims(['aud' => 'someone-else']), 'key-1');

    app(IdTokenValidator::class)->validate($jwt, 'the-nonce');
})->throws(OidcClientException::class, 'audience does not include');

it('rejects a token with the wrong issuer', function (): void {
    $jwt = $this->provider->idToken(idTokenClaims(['iss' => 'https://evil.example.com']), 'key-1');

    app(IdTokenValidator::class)->validate($jwt, 'the-nonce');
})->throws(OidcClientException::class, 'issuer does not match');

it('rejects an expired token', function (): void {
    $jwt = $this->provider->idToken(idTokenClaims(['exp' => time() - 3600]), 'key-1');

    app(IdTokenValidator::class)->validate($jwt, 'the-nonce');
})->throws(OidcClientException::class, 'has expired');

it('rejects a token signed with an unknown kid', function (): void {
    $jwt = $this->provider->idToken(idTokenClaims(), 'unknown-kid');

    app(IdTokenValidator::class)->validate($jwt, 'the-nonce');
})->throws(OidcClientException::class, 'No JWKS key matches');

it('rejects a token missing a subject', function (): void {
    $jwt = $this->provider->idToken(idTokenClaims(['sub' => '']), 'key-1');

    app(IdTokenValidator::class)->validate($jwt, 'the-nonce');
})->throws(OidcClientException::class, 'missing a subject');

it('rejects a token missing exp', function (): void {
    $jwt = $this->provider->idToken(array_diff_key(idTokenClaims(), ['exp' => true]), 'key-1');

    app(IdTokenValidator::class)->validate($jwt, 'the-nonce');
})->throws(OidcClientException::class, 'missing or invalid exp');

it('rejects a token missing iat', function (): void {
    $jwt = $this->provider->idToken(array_diff_key(idTokenClaims(), ['iat' => true]), 'key-1');

    app(IdTokenValidator::class)->validate($jwt, 'the-nonce');
})->throws(OidcClientException::class, 'missing or invalid iat');

it('rejects invalid timestamp claim shapes', function (string $claim): void {
    $jwt = $this->provider->rawIdToken(idTokenClaims([$claim => 'not-a-timestamp']), 'key-1');

    app(IdTokenValidator::class)->validate($jwt, 'the-nonce');
})->with(['exp', 'iat', 'nbf'])->throws(OidcClientException::class);

it('rejects a token issued in the future outside leeway', function (): void {
    config()->set('oidc-client.leeway', 60);
    $jwt = $this->provider->idToken(idTokenClaims(['iat' => time() + 300]), 'key-1');

    app(IdTokenValidator::class)->validate($jwt, 'the-nonce');
})->throws(OidcClientException::class, 'issued in the future');
