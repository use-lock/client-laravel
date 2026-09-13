<?php

declare(strict_types=1);

use Lock\Laravel\Shared\Protocol\OidcClientException;
use Lock\Laravel\Support\Testing\FakeOidcProvider;
use Lock\Laravel\Tokens\Validation\LogoutTokenValidator;

beforeEach(function (): void {
    config()->set('oidc-client.issuer', 'https://id.example.com');
    config()->set('oidc-client.client_id', 'client-123');
    $this->provider = new FakeOidcProvider;
    fakeIssuerEndpoints($this->provider);
});

it('accepts a well-formed logout token and returns sid + sub', function (): void {
    $jwt = $this->provider->logoutToken(logoutTokenClaims(), 'key-1');

    $result = app(LogoutTokenValidator::class)->validate($jwt);

    expect($result['sid'])->toBe('sess-abc')->and($result['sub'])->toBe('42');
});

it('rejects a logout token that carries a nonce', function (): void {
    $jwt = $this->provider->logoutToken(logoutTokenClaims(['nonce' => 'x']), 'key-1');
    app(LogoutTokenValidator::class)->validate($jwt);
})->throws(OidcClientException::class, 'nonce');

it('rejects a token without the backchannel-logout event', function (): void {
    $jwt = $this->provider->logoutToken(logoutTokenClaims(['events' => ['other' => (object) []]]), 'key-1');
    app(LogoutTokenValidator::class)->validate($jwt);
})->throws(OidcClientException::class);

it('rejects a token without a sid', function (): void {
    $claims = logoutTokenClaims();
    unset($claims['sid']);
    app(LogoutTokenValidator::class)->validate($this->provider->logoutToken($claims, 'key-1'));
})->throws(OidcClientException::class);

it('rejects a token with the wrong audience', function (): void {
    $jwt = $this->provider->logoutToken(logoutTokenClaims(['aud' => 'someone-else']), 'key-1');
    app(LogoutTokenValidator::class)->validate($jwt);
})->throws(OidcClientException::class);

it('rejects an expired token', function (): void {
    $jwt = $this->provider->logoutToken(logoutTokenClaims(['exp' => time() - 3600, 'iat' => time() - 3700]), 'key-1');
    app(LogoutTokenValidator::class)->validate($jwt);
})->throws(OidcClientException::class);

it('rejects a token that is missing the logout+jwt typ header', function (): void {
    $jwt = $this->provider->idToken(logoutTokenClaims(), 'key-1');
    app(LogoutTokenValidator::class)->validate($jwt);
})->throws(OidcClientException::class, 'typ');

it('rejects a logout token issued implausibly far in the past', function (): void {
    $jwt = $this->provider->logoutToken(logoutTokenClaims(['iat' => time() - 3600, 'exp' => time() + 3600]), 'key-1');
    app(LogoutTokenValidator::class)->validate($jwt);
})->throws(OidcClientException::class);

it('rejects a token signed with an untrusted key', function (): void {
    $otherProvider = new FakeOidcProvider;
    $jwt = $otherProvider->logoutToken(logoutTokenClaims(), 'key-1');
    app(LogoutTokenValidator::class)->validate($jwt);
})->throws(OidcClientException::class);

it('rejects a token with the wrong issuer', function (): void {
    $jwt = $this->provider->logoutToken(logoutTokenClaims(['iss' => 'https://someone-else.example.com']), 'key-1');
    app(LogoutTokenValidator::class)->validate($jwt);
})->throws(OidcClientException::class, 'issuer');
