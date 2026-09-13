<?php

declare(strict_types=1);

use Illuminate\Auth\Events\Login;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Exceptions;
use Illuminate\Support\Facades\Http;
use Lock\Laravel\Sessions\BackchannelLogoutStore;
use Lock\Laravel\Shared\Protocol\OidcClientException;
use Lock\Laravel\Support\Facades\OidcClient;
use Lock\Laravel\Support\Testing\OidcClientFake;
use Workbench\App\Models\User;

beforeEach(function (): void {
    config()->set('oidc-client.client_secret', 'secret-xyz');
    config()->set('oidc-client.redirect_after_login', '/dashboard');

    $this->fake = OidcClient::fake()->clientId('client-123');
    $this->user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'secret']);
});

it('completes the callback and logs the user into the web guard', function (): void {
    $this->withSession($this->fake->callbackContext())
        ->get($this->fake->loginAs($this->user))
        ->assertRedirect('/dashboard');

    $this->assertAuthenticatedAs($this->user);

    Http::assertSent(fn ($request): bool => $request->url() === config('oidc-client.issuer').'/oauth/token'
        && $request['grant_type'] === 'authorization_code'
        && $request['code_verifier'] === OidcClientFake::VERIFIER
        && $request['client_secret'] === 'secret-xyz');
});

it('records the sid and a session pointer when backchannel logout is enabled', function (): void {
    config()->set('oidc-client.backchannel_logout.enabled', true);

    $this->withSession($this->fake->callbackContext())
        ->get($this->fake->loginAs($this->user, ['sid' => 'the-sid']))
        ->assertRedirect('/dashboard');

    $this->assertAuthenticatedAs($this->user);
    expect(session('oidc-client.sid'))->toBe('the-sid');
    expect(app(BackchannelLogoutStore::class)->pullSessionId('the-sid'))->toBe(session()->getId());
});

it('rejects a tampered state and does not log in', function (): void {
    $this->withSession($this->fake->callbackContext())
        ->get($this->fake->callbackUrl(['state' => 'WRONG-state']))
        ->assertRedirect(route('login'));

    $this->assertGuest();

    $this->fake->assertCodeNotExchanged();
});

it('rejects missing or empty callback session context before discovery or token exchange', function (array $context): void {
    $this->withSession($context)
        ->get($this->fake->callbackUrl())
        ->assertRedirect(route('login'));

    $this->assertGuest();
    $this->fake->assertCodeNotExchanged();
})->with([
    'missing context' => [[]],
    'missing state' => [[
        'oidc-client.nonce' => OidcClientFake::NONCE,
        'oidc-client.code_verifier' => OidcClientFake::VERIFIER,
    ]],
    'empty state' => [[
        'oidc-client.state' => '',
        'oidc-client.nonce' => OidcClientFake::NONCE,
        'oidc-client.code_verifier' => OidcClientFake::VERIFIER,
    ]],
    'missing nonce' => [[
        'oidc-client.state' => OidcClientFake::STATE,
        'oidc-client.code_verifier' => OidcClientFake::VERIFIER,
    ]],
    'empty nonce' => [[
        'oidc-client.state' => OidcClientFake::STATE,
        'oidc-client.nonce' => '',
        'oidc-client.code_verifier' => OidcClientFake::VERIFIER,
    ]],
    'missing verifier' => [[
        'oidc-client.state' => OidcClientFake::STATE,
        'oidc-client.nonce' => OidcClientFake::NONCE,
    ]],
    'empty verifier' => [[
        'oidc-client.state' => OidcClientFake::STATE,
        'oidc-client.nonce' => OidcClientFake::NONCE,
        'oidc-client.code_verifier' => '',
    ]],
]);

it('rejects replayed callback session context before discovery or token exchange', function (): void {
    $this->withSession($this->fake->callbackContext())
        ->get($this->fake->callbackUrl(['state' => 'WRONG-state']))
        ->assertRedirect(route('login'));

    $this->get($this->fake->callbackUrl())
        ->assertRedirect(route('login'));

    $this->assertGuest();
    $this->fake->assertCodeNotExchanged();
});

it('reports the callback failure before redirecting back to login', function (): void {
    Exceptions::fake();

    $this->withSession($this->fake->callbackContext())
        ->get($this->fake->callbackUrl(['state' => 'WRONG-state']))
        ->assertRedirect(route('login'));

    Exceptions::assertReported(OidcClientException::class);
});

it('rejects a failed token exchange and does not log in', function (): void {
    $this->fake->failTokenExchange(400);

    $this->withSession($this->fake->callbackContext())
        ->get($this->fake->callbackUrl())
        ->assertRedirect(route('login'));

    $this->assertGuest();
});

it('rejects an id token whose subject has no local user and does not log in', function (): void {
    $this->withSession($this->fake->callbackContext())
        ->get($this->fake->callbackUrl())
        ->assertRedirect(route('login'))
        ->assertSessionHasErrors('oidc');

    $this->assertGuest();
});

it('rejects an id token with a tampered signature and does not log in', function (): void {
    $this->fake->withInvalidSignature();

    $this->withSession($this->fake->callbackContext())
        ->get($this->fake->callbackUrl())
        ->assertRedirect(route('login'));

    $this->assertGuest();
});

it('stores the access token expiry alongside the tokens', function (): void {
    $this->withSession($this->fake->callbackContext())->get($this->fake->loginAs($this->user));

    expect(session('oidc-client.tokens.expires_at'))
        ->toBeInt()
        ->toBeGreaterThanOrEqual(time() + 3590)
        ->toBeLessThanOrEqual(time() + 3610);
});

it('keeps the session id the guard established, so a self-SSO provider keeps pointing at it', function (): void {
    $atLogin = null;

    Event::listen(Login::class, function () use (&$atLogin): void {
        $atLogin = session()->getId();
    });

    $this->withSession($this->fake->callbackContext())
        ->get($this->fake->loginAs($this->user))
        ->assertRedirect('/dashboard');

    expect($atLogin)->not->toBeNull()
        ->and(session()->getId())->toBe($atLogin);
});
