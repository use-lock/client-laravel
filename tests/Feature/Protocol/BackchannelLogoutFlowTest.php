<?php

declare(strict_types=1);

namespace Lock\Laravel\Tests\Feature\Protocol;

use Illuminate\Support\Facades\Route;
use Lock\Laravel\Support\Facades\OidcClient;
use Lock\Laravel\Tests\Support\BackchannelLogoutEnabledTestCase;
use Workbench\App\Models\User;

class BackchannelLogoutFlowTest extends BackchannelLogoutEnabledTestCase
{
    public function test_a_provider_logout_token_logs_the_session_out_on_its_next_request_through_the_web_group(): void
    {
        $fake = OidcClient::fake()->clientId('client-123');
        Route::get('/session-status', fn (): string => auth()->check() ? 'authenticated' : 'guest')
            ->middleware('web');
        $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'secret']);
        $fake->loginAs($user);

        $this->actingAs($user)->withSession(['oidc-client.sid' => 'sess-e2e']);
        $this->get('/session-status')->assertSeeText('authenticated');

        $this->post('/oidc/backchannel-logout', ['logout_token' => $fake->logoutToken(['sid' => 'sess-e2e'])])->assertOk();

        $this->actingAs($user)->withSession(['oidc-client.sid' => 'sess-e2e']);
        $this->get('/session-status')->assertSeeText('guest');

        $fake->assertBackchannelLogoutProcessed('sess-e2e');
        $this->assertGuest();
    }
}
