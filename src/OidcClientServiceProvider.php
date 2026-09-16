<?php
declare(strict_types=1);

namespace Lock\Laravel;

use GuzzleHttp\Client;
use GuzzleHttp\Promise\PromiseInterface;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Http\Client\Factory as Http;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\ServiceProvider;
use Lock\Client\Auth\OidcException;
use Lock\Client\Realm;
use Lock\Laravel\Authentication\AuthenticationServiceProvider;
use Lock\Laravel\Sessions\SessionsServiceProvider;
use Psr\Http\Message\RequestInterface;

class OidcClientServiceProvider extends ServiceProvider
{
    /**
     * Domains own their bindings and middleware. The package provider owns
     * configuration, the realm, routes and publishing.
     *
     * @var list<class-string<ServiceProvider>>
     */
    private const array DOMAIN_PROVIDERS = [
        AuthenticationServiceProvider::class,
        SessionsServiceProvider::class,
    ];

    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/oidc-client.php', 'oidc-client');

        foreach (self::DOMAIN_PROVIDERS as $provider) {
            $this->app->register($provider);
        }

        $this->app->singleton(Realm::class, fn (Application $app): Realm => new Realm(
            url: config('oidc-client.issuer') ?: throw new OidcException('No Lock realm URL has been configured (oidc-client.issuer).'),
            clientId: (string) config('oidc-client.client_id'),
            clientSecret: config('oidc-client.client_secret') ?: null,
            redirectUri: config('oidc-client.redirect_uri') ?: (Route::has('login.callback') ? route('login.callback') : null),
            basicAuth: config('oidc-client.token_endpoint_auth_method') === 'client_secret_basic',
            cache: $app->make('cache.store'),
            // Laravel builds a pending request's handler stack from the stubs and
            // stray-request setting of that moment, so build one per request:
            // Http::fake() calls made after the realm was resolved still apply.
            http: new Client(['handler' => fn (RequestInterface $request, array $options): PromiseInterface => $app->make(Http::class)
                ->createPendingRequest()
                ->buildHandlerStack()($request, $options)]),
        ));
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
