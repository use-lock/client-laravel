<?php
declare(strict_types=1);

namespace Lock\Laravel\Protocol;

use Illuminate\Support\ServiceProvider;

class ProtocolServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->singleton(AuthorizationFlow::class);
    }
}
