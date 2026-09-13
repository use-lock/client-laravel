<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Route;
use Lock\Laravel\Sessions\BackchannelLogoutStore;
use Workbench\App\Models\User;

it('answers the back-channel logout endpoint with 404 while back-channel logout is disabled', function (): void {
    $this->post('/oidc/backchannel-logout', ['logout_token' => 'any'])->assertNotFound();
});

it('keeps a session with a revoked sid authenticated while back-channel logout is disabled', function (): void {
    Route::get('/session-status', fn (): string => auth()->check() ? 'authenticated' : 'guest')->middleware('web');
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'secret']);
    app(BackchannelLogoutStore::class)->markRevoked('sess-x');

    $this->actingAs($user)
        ->withSession(['oidc-client.sid' => 'sess-x'])
        ->get('/session-status')
        ->assertSeeText('authenticated');
});
