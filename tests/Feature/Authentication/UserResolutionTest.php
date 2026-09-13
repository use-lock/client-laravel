<?php

declare(strict_types=1);

use Illuminate\Contracts\Auth\Authenticatable;
use Lock\Laravel\Support\Facades\OidcClient;
use Workbench\App\Models\User;

it('logs in the user returned by the resolveUsersUsing seam instead of the primary-key fallback', function (): void {
    $fake = OidcClient::fake();
    OidcClient::resolveUsersUsing(fn (string $sub, array $claims): ?Authenticatable => User::where('email', $claims['email'])->first());
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'secret']);

    $this->withSession($fake->callbackContext())
        ->get($fake->loginAs($user, ['sub' => 'external-subject', 'email' => 'm@example.com']))
        ->assertRedirect('/dashboard');

    $this->assertAuthenticatedAs($user);
});
