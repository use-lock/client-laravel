<?php

declare(strict_types=1);

namespace Lock\Laravel\Support\Facades;

use Illuminate\Support\Facades\Facade;
use Lock\Laravel\Authentication\OidcClientManager;
use Lock\Laravel\Support\Testing\OidcClientFake;

/**
 * @method static void resolveUsersUsing(\Closure $callback)
 * @method static \Illuminate\Contracts\Auth\StatefulGuard guard()
 * @method static \Illuminate\Http\RedirectResponse redirectAfterLogin()
 * @method static void terminateLocalSession(\Illuminate\Http\Request $request)
 * @method static \Lock\Laravel\Support\Testing\OidcClientFake fake()
 *
 * @see OidcClientManager
 */
class OidcClient extends Facade
{
    public static function fake(): OidcClientFake
    {
        return OidcClientFake::start();
    }

    protected static function getFacadeAccessor(): string
    {
        return OidcClientManager::class;
    }
}
