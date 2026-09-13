<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Route;
use Lock\Laravel\Support\Facades\OidcClient;
use Workbench\App\Models\User;

beforeEach(function (): void {
    $this->fake = OidcClient::fake();
});

it('logs out and redirects to the provider end-session endpoint', function (): void {
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'secret']);

    $response = $this->actingAs($user)
        ->withSession(['oidc-client.tokens' => ['id_token' => 'the-id-token']])
        ->post(route('logout'));

    $response->assertRedirectContains(config('oidc-client.issuer').'/oauth/logout');
    $response->assertRedirectContains('id_token_hint=the-id-token');
    $this->assertGuest();
});

it('answers an Inertia logout request with a 409 + X-Inertia-Location instead of a redirect', function (): void {
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'secret']);

    $response = $this->actingAs($user)
        ->withSession(['oidc-client.tokens' => ['id_token' => 'the-id-token']])
        ->post(route('logout'), [], ['X-Inertia' => 'true']);

    $response->assertStatus(409);
    expect($response->headers->get('X-Inertia-Location'))
        ->toStartWith(config('oidc-client.issuer').'/oauth/logout');
    $this->assertGuest();
});

it('redirects home when the provider has no end-session endpoint', function (): void {
    $this->fake->withoutEndSessionEndpoint();

    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'secret']);

    $response = $this->actingAs($user)->post(route('logout'));

    $response->assertRedirect('/');
    $this->assertGuest();
});

it('omits id_token_hint when no id_token was stored in the session', function (): void {
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'secret']);

    $response = $this->actingAs($user)->post(route('logout'));

    $response->assertRedirectContains(config('oidc-client.issuer').'/oauth/logout');
    $location = $response->headers->get('Location');
    expect($location)->not->toContain('id_token_hint');
});

it('persists local logout when provider discovery fails', function (): void {
    // OidcClient::fake() only models success responses, so the failing issuer is stubbed raw.
    config()->set('oidc-client.issuer', 'https://unavailable.example.com');

    Http::fake([
        'https://unavailable.example.com/.well-known/openid-configuration' => Http::response([], 503),
    ]);

    Route::get('/session-status', fn (): string => auth()->check() ? 'authenticated' : 'guest');

    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'secret']);

    $this->actingAs($user)
        ->withSession(['oidc-client.tokens' => ['id_token' => 'the-id-token']])
        ->post(route('logout'))
        ->assertRedirect('/');

    $this->get('/session-status')->assertSeeText('guest');
    $this->assertGuest();
});
