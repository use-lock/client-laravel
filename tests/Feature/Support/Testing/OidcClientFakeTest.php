<?php

declare(strict_types=1);

use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Http;
use Lock\Client\Realm;
use Lock\Laravel\Support\Facades\OidcClient;
use Lock\Laravel\Support\Testing\OidcClientFake;
use Workbench\App\Models\User;

it('blocks unstubbed requests from reaching the network', function (): void {
    Http::allowStrayRequests();

    OidcClient::fake();

    expect(fn () => Http::get('https://unrelated.example/api'))
        ->toThrow(RuntimeException::class, 'unrelated.example');
});

it('mints id and logout tokens the realm accepts', function (): void {
    $fake = OidcClient::fake();
    $realm = app(Realm::class);

    expect($realm->idTokens()->validate($fake->idToken(['sub' => '42']), OidcClientFake::NONCE))
        ->toMatchArray(['sub' => '42', 'iss' => 'https://oidc.test'])
        ->and($realm->logoutTokens()->validate($fake->logoutToken(['sub' => '42', 'sid' => 's1'])))
        ->toMatchArray(['sub' => '42', 'sid' => 's1']);
});

it('honors an issuer configured before fake() even when the realm was already resolved', function (): void {
    config()->set('oidc-client.issuer', 'https://custom.test');
    app(Realm::class);

    $fake = OidcClient::fake();

    $claims = app(Realm::class)->idTokens()->validate($fake->idToken(), OidcClientFake::NONCE);
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

it('asserts the login and the code exchange after a successful callback', function (): void {
    $fake = OidcClient::fake();
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'secret']);

    $this->withSession($fake->callbackContext())->get($fake->loginAs($user));

    $fake->assertLoggedIn($user)->assertCodeExchanged();
});
