<?php

declare(strict_types=1);

use Lock\Laravel\Support\Facades\OidcClient;
use Workbench\App\Models\User;

beforeEach(function (): void {
    OidcClient::fake();
    $this->user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'secret']);
});

it('logs out and redirects to the provider logout endpoint', function (): void {
    config()->set('oidc-client.post_logout_redirect_uri', 'https://app.test/bye');

    $response = $this->actingAs($this->user)
        ->withSession(['oidc-client.tokens' => ['id_token' => 'the-id-token']])
        ->post(route('logout'));

    $response->assertRedirectContains(config('oidc-client.issuer').'/oauth/logout?');
    $response->assertRedirectContains('id_token_hint=the-id-token');
    $response->assertRedirectContains('post_logout_redirect_uri='.rawurlencode('https://app.test/bye'));
    $this->assertGuest();
});

it('answers an Inertia logout request with a 409 + X-Inertia-Location instead of a redirect', function (): void {
    $response = $this->actingAs($this->user)
        ->withSession(['oidc-client.tokens' => ['id_token' => 'the-id-token']])
        ->post(route('logout'), [], ['X-Inertia' => 'true']);

    $response->assertStatus(409);
    expect($response->headers->get('X-Inertia-Location'))
        ->toStartWith(config('oidc-client.issuer').'/oauth/logout');
    $this->assertGuest();
});

it('omits id_token_hint when no id_token was stored in the session', function (): void {
    $response = $this->actingAs($this->user)->post(route('logout'));

    $response->assertRedirectContains(config('oidc-client.issuer').'/oauth/logout');
    expect($response->headers->get('Location'))->not->toContain('id_token_hint');
    $this->assertGuest();
});
