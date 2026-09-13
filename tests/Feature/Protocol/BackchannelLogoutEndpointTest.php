<?php

declare(strict_types=1);

namespace Lock\Laravel\Tests\Feature\Protocol;

use Illuminate\Support\Facades\Exceptions;
use Illuminate\Support\Facades\Session;
use Lock\Laravel\Sessions\BackchannelLogoutStore;
use Lock\Laravel\Shared\Protocol\OidcClientException;
use Lock\Laravel\Support\Testing\FakeOidcProvider;
use Lock\Laravel\Tests\Support\BackchannelLogoutEnabledTestCase;

class BackchannelLogoutEndpointTest extends BackchannelLogoutEnabledTestCase
{
    private FakeOidcProvider $provider;

    private BackchannelLogoutStore $store;

    protected function setUp(): void
    {
        parent::setUp();

        config()->set('oidc-client.issuer', 'https://id.example.com');
        config()->set('oidc-client.client_id', 'client-123');
        $this->provider = new FakeOidcProvider;
        $this->store = app(BackchannelLogoutStore::class);
        fakeIssuerEndpoints($this->provider);
    }

    /**
     * @param  array<string, mixed>  $overrides
     */
    private function validLogoutToken(array $overrides = []): string
    {
        return $this->provider->logoutToken(logoutTokenClaims($overrides), 'key-1');
    }

    public function test_it_accepts_a_valid_logout_token_marks_the_sid_and_returns_200_no_store(): void
    {
        $response = $this->post('/oidc/backchannel-logout', ['logout_token' => $this->validLogoutToken()]);

        $response->assertOk()->assertHeader('Cache-Control', 'no-store, private');
        $this->assertTrue($this->store->isRevoked('sess-abc'));
    }

    public function test_it_destroys_the_session_registered_for_the_sid_and_drops_the_pointer(): void
    {
        Session::getHandler()->write('the-session-id', 'session-payload');
        $this->store->registerSession('sess-abc', 'the-session-id');

        $this->post('/oidc/backchannel-logout', ['logout_token' => $this->validLogoutToken()])->assertOk();

        $this->assertSame('', Session::getHandler()->read('the-session-id'));
        $this->assertNull($this->store->pullSessionId('sess-abc'));
    }

    public function test_it_rejects_a_replayed_logout_token_jti_with_400(): void
    {
        $token = $this->validLogoutToken(['jti' => 'jti-replayed']);

        $this->post('/oidc/backchannel-logout', ['logout_token' => $token])->assertOk();

        $this->post('/oidc/backchannel-logout', ['logout_token' => $token])
            ->assertStatus(400)->assertJson(['error' => 'invalid_request']);
    }

    public function test_it_rejects_an_invalid_logout_token_with_400_and_revokes_nothing(): void
    {
        $this->post('/oidc/backchannel-logout', ['logout_token' => 'not-a-jwt'])
            ->assertStatus(400)->assertJson(['error' => 'invalid_request']);
        $this->assertFalse($this->store->isRevoked('sess-abc'));
    }

    public function test_it_reports_the_rejected_logout_token_before_responding(): void
    {
        Exceptions::fake();

        $this->post('/oidc/backchannel-logout', ['logout_token' => 'not-a-jwt'])->assertStatus(400);

        Exceptions::assertReported(OidcClientException::class);
    }
}
