<?php
declare(strict_types=1);

namespace Lock\Laravel\Sessions;

use Illuminate\Contracts\Http\Kernel;
use Illuminate\Support\ServiceProvider;
use Lock\Laravel\Sessions\Http\Middleware\EnforceBackchannelLogout;
use Lock\Laravel\Shared\Sessions\BackchannelSessions;

class SessionsServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->bind(BackchannelSessions::class, BackchannelLogoutStore::class);
    }

    public function boot(): void
    {
        if (config('oidc-client.backchannel_logout.enabled', false)) {
            $router = $this->app['router'];
            $router->aliasMiddleware('oidc-client.enforce-logout', EnforceBackchannelLogout::class);

            if (config('oidc-client.backchannel_logout.auto_middleware', true)) {
                // Appending through the Kernel (rather than pushing directly onto the
                // Router) is required: the HTTP Kernel's constructor overwrites the
                // Router's middleware groups from its own $middlewareGroups property
                // the first time it is resolved, which would silently wipe a push made
                // straight against the Router before that first resolution.
                $this->app->make(Kernel::class)->appendMiddlewareToGroup(
                    (string) config('oidc-client.backchannel_logout.middleware_group', 'web'),
                    EnforceBackchannelLogout::class,
                );
            }
        }
    }
}
