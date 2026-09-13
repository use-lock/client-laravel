<?php
declare(strict_types=1);

namespace Lock\Laravel\Discovery;

use Illuminate\Support\ServiceProvider;
use Lock\Laravel\Shared\Discovery\ProviderDiscovery;

class DiscoveryServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->singleton(OidcDiscovery::class);
        $this->app->bind(ProviderDiscovery::class, OidcDiscovery::class);
    }
}
