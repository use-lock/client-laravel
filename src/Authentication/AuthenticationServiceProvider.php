<?php
declare(strict_types=1);

namespace Lock\Laravel\Authentication;

use Illuminate\Support\ServiceProvider;
use Lock\Laravel\Shared\Authentication\UserAuthentication;

class AuthenticationServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->singleton(OidcClientManager::class);
        $this->app->bind(UserAuthentication::class, OidcClientManager::class);
    }
}
