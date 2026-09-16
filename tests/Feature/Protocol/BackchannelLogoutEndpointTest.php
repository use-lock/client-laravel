<?php

declare(strict_types=1);

namespace Lock\Laravel\Tests\Feature\Protocol;

use Illuminate\Support\Facades\Exceptions;
use Illuminate\Support\Facades\Session;
use Lock\Client\Auth\OidcException;
use Lock\Laravel\Sessions\BackchannelLogoutStore;
use Lock\Laravel\Support\Facades\OidcClient;
use Lock\Laravel\Support\Testing\OidcClientFake;
use Lock\Laravel\Tests\Support\BackchannelLogoutEnabledTestCase;

class BackchannelLogoutEndpointTest extends BackchannelLogoutEnabledTestCase
{
    private OidcClientFake $fake;

    private BackchannelLogoutStore $store;

    protected function setUp(): void
    {
        parent::setUp();

        $this->fake = OidcClient::fake();
        $this->store = app(BackchannelLogoutStore::class);
    }

    public function test_it_accepts_a_valid_logout_token_marks_the_sid_and_returns_200_no_store(): void
    {
        $response = $this->post('/oidc/backchannel-logout', ['logout_token' => $this->fake->logoutToken(['sid' => 'sess-abc'])]);

        $response->assertOk()->assertHeader('Cache-Control', 'no-store, private');
        $this->assertTrue($this->store->isRevoked('sess-abc'));
    }

    public function test_it_destroys_the_session_registered_for_the_sid_and_drops_the_pointer(): void
    {
        Session::getHandler()->write('the-session-id', 'session-payload');
        $this->store->registerSession('sess-abc', 'the-session-id');

        $this->post('/oidc/backchannel-logout', ['logout_token' => $this->fake->logoutToken(['sid' => 'sess-abc'])])->assertOk();

        $this->assertSame('', Session::getHandler()->read('the-session-id'));
        $this->assertNull($this->store->pullSessionId('sess-abc'));
    }

    public function test_it_rejects_a_replayed_logout_token_jti_with_400(): void
    {
        $token = $this->fake->logoutToken(['jti' => 'jti-replayed']);

        $this->post('/oidc/backchannel-logout', ['logout_token' => $token])->assertOk();

        $this->post('/oidc/backchannel-logout', ['logout_token' => $token])
            ->assertStatus(400)->assertJson(['error' => 'invalid_request']);
    }

    public function test_it_reports_an_invalid_logout_token_answers_400_and_revokes_nothing(): void
    {
        Exceptions::fake();

        $this->post('/oidc/backchannel-logout', ['logout_token' => 'not-a-jwt'])
            ->assertStatus(400)->assertJson(['error' => 'invalid_request']);

        Exceptions::assertReported(OidcException::class);
        $this->assertFalse($this->store->isRevoked(OidcClientFake::SID));
    }
}
