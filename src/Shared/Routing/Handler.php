<?php

declare(strict_types=1);

namespace Lock\Laravel\Shared\Routing;

/**
 * The registry of the package's route names. Each case's value is the name the
 * route is registered under in `routes/oidc-client.php`; `login` and `logout`
 * are Laravel's conventional names so the framework resolves them by default.
 */
enum Handler: string
{
    case Login = 'login';
    case Callback = 'login.callback';
    case Logout = 'logout';
    case BackchannelLogout = 'oidc.backchannel-logout';
}
