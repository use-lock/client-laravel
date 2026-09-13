<?php

declare(strict_types=1);

use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Http;
use Lock\Laravel\Discovery\OidcDiscovery;
use Lock\Laravel\Support\Facades\OidcClient;
use Lock\Laravel\Support\Testing\OidcClientFake;
use Lock\Laravel\Tokens\Validation\IdTokenValidator;
use Lock\Laravel\Tokens\Validation\LogoutTokenValidator;
use Workbench\App\Models\User;

it('blocks unstubbed requests from reaching the network', function (): void {
    Http::allowStrayRequests();

    OidcClient::fake();

    expect(fn () => Http::get('https://unrelated.example/api'))
        ->toThrow(RuntimeException::class, 'unrelated.example');
});

it('mints an id_token the real validator accepts', function (): void {
    $fake = OidcClient::fake();

    $claims = app(IdTokenValidator::class)->validate($fake->idToken(['sub' => '42']), OidcClientFake::NONCE);

    expect($claims['sub'])->toBe('42')
        ->and($claims['iss'])->toBe('https://oidc.test');
});

it('mints a logout_token the real validator accepts', function (): void {
    $fake = OidcClient::fake();

    $result = app(LogoutTokenValidator::class)->validate($fake->logoutToken(['sub' => '42', 'sid' => 's1']));

    expect($result['sid'])->toBe('s1')
        ->and($result['sub'])->toBe('42');
});

it('honors an issuer configured before fake() even when discovery was already resolved', function (): void {
    config()->set('oidc-client.issuer', 'https://custom.test');
    app(OidcDiscovery::class);

    $fake = OidcClient::fake();

    $claims = app(IdTokenValidator::class)->validate($fake->idToken(), OidcClientFake::NONCE);
    expect($claims['iss'])->toBe('https://custom.test');
});

it('mints tokens at the frozen Carbon test time', function (): void {
    Carbon::setTestNow('2026-01-01 12:00:00');
    $frozen = Carbon::now()->getTimestamp();
    $fake = OidcClient::fake();

    $decode = fn (string $jwt): array => json_decode(
        base64_decode(strtr(explode('.', $jwt)[1], '-_', '+/')),
        true,
    );

    expect((int) $decode($fake->idToken())['iat'])->toBe($frozen)
        ->and((int) $decode($fake->logoutToken())['iat'])->toBe($frozen);
});

it('asserts a user is logged in on the configured guard', function (): void {
    $fake = OidcClient::fake();
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'secret']);

    $this->withSession($fake->callbackContext())->get($fake->loginAs($user));

    $fake->assertLoggedIn($user);
});

it('asserts the code exchange fired after a successful callback', function (): void {
    $fake = OidcClient::fake();
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'secret']);

    $this->withSession($fake->callbackContext())->get($fake->loginAs($user));

    $fake->assertCodeExchanged();
});

it('keeps assertCodeExchanged bound to the request history when a customizer is applied after the exchange', function (): void {
    $fake = OidcClient::fake();
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'secret']);
    $this->withSession($fake->callbackContext())->get($fake->loginAs($user));

    $fake->withoutEndSessionEndpoint();

    $fake->assertCodeExchanged();
});
