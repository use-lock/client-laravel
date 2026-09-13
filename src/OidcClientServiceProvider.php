<?php
declare(strict_types=1);

namespace Lock\Laravel;

use Illuminate\Support\ServiceProvider;
use Lock\Laravel\Authentication\AuthenticationServiceProvider;
use Lock\Laravel\Discovery\DiscoveryServiceProvider;
use Lock\Laravel\Protocol\ProtocolServiceProvider;
use Lock\Laravel\Sessions\SessionsServiceProvider;
use Lock\Laravel\Tokens\TokensServiceProvider;

class OidcClientServiceProvider extends ServiceProvider
{
    /**
     * Domains own their bindings and middleware. The package provider owns
     * configuration, routes and publishing.
     *
     * @var list<class-string<ServiceProvider>>
     */
    private const array DOMAIN_PROVIDERS = [
        AuthenticationServiceProvider::class,
        DiscoveryServiceProvider::class,
        TokensServiceProvider::class,
        SessionsServiceProvider::class,
        ProtocolServiceProvider::class,
    ];

    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/oidc-client.php', 'oidc-client');

        foreach (self::DOMAIN_PROVIDERS as $provider) {
            $this->app->register($provider);
        }
    }

    public function boot(): void
    {
        if (config('oidc-client.enabled', false)) {
            $this->loadRoutesFrom(__DIR__.'/../routes/oidc-client.php');
        }

        $this->publishes([
            __DIR__.'/../config/oidc-client.php' => config_path('oidc-client.php'),
        ], 'oidc-client-config');
    }
}
