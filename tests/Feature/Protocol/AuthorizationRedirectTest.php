<?php

declare(strict_types=1);

use Lock\Laravel\Support\Facades\OidcClient;
use Workbench\App\Models\User;

beforeEach(function (): void {
    $this->fake = OidcClient::fake()->clientId('client-123');
});

it('redirects to the provider authorization endpoint with pkce', function (): void {
    $this->fake->assertRedirectedToProvider($this->get(route('login')));

    $this->assertNotNull(session('oidc-client.state'));
    $this->assertNotNull(session('oidc-client.nonce'));
    $this->assertNotNull(session('oidc-client.code_verifier'));
});

it('asks the provider to come back to the app\'s own callback unless told otherwise', function (?string $configured, string $expected): void {
    config()->set('oidc-client.redirect_uri', $configured);

    parse_str((string) parse_url((string) $this->get(route('login'))->headers->get('Location'), PHP_URL_QUERY), $query);

    expect($query['redirect_uri'])->toBe($expected);
})->with([
    'default' => [null, 'http://localhost/login/callback'],
    'configured' => ['https://app.test/sso/callback', 'https://app.test/sso/callback'],
]);

it('answers an Inertia login request with a 409 + X-Inertia-Location instead of a redirect', function (): void {
    $response = $this->get(route('login'), ['X-Inertia' => 'true']);

    $response->assertStatus(409);
    expect($response->headers->get('X-Inertia-Location'))
        ->toStartWith(config('oidc-client.issuer').'/oauth/authorize?');
});

it('sends an authenticated user straight home', function (): void {
    config()->set('oidc-client.redirect_after_login', '/dashboard');

    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'secret']);

    $this->actingAs($user)->get(route('login'))->assertRedirect('/dashboard');
});
