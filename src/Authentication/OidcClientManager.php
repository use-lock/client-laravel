<?php

declare(strict_types=1);

namespace Lock\Laravel\Authentication;

use Closure;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\StatefulGuard;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Lock\Laravel\Shared\Authentication\UserAuthentication;

class OidcClientManager implements UserAuthentication
{
    /**
     * @var (Closure(string, array<string, mixed>): (Authenticatable|null))|null
     */
    private ?Closure $resolveUsersUsing = null;

    /**
     * The guard resolved users are logged into (`oidc-client.login_guard`).
     */
    public function guard(): StatefulGuard
    {
        /** @var StatefulGuard $guard The login guard must be session-based. */
        $guard = Auth::guard($this->guardName());

        return $guard;
    }

    public function redirectAfterLogin(): RedirectResponse
    {
        return redirect()->intended((string) config('oidc-client.redirect_after_login', '/dashboard'));
    }

    public function terminateLocalSession(Request $request): void
    {
        $this->guard()->logout();
        $request->session()->invalidate();
        $request->session()->regenerateToken();
    }

    /**
     * @param  Closure(string, array<string, mixed>): (Authenticatable|null)  $callback
     */
    public function resolveUsersUsing(Closure $callback): void
    {
        $this->resolveUsersUsing = $callback;
    }

    /**
     * @param  array<string, mixed>  $claims
     */
    public function resolveUser(string $sub, array $claims): ?Authenticatable
    {
        if ($this->resolveUsersUsing instanceof Closure) {
            return ($this->resolveUsersUsing)($sub, $claims);
        }

        $provider = Auth::createUserProvider(config('auth.guards.'.$this->guardName().'.provider'));

        return $provider?->retrieveById($sub);
    }

    private function guardName(): string
    {
        return (string) config('oidc-client.login_guard', 'web');
    }
}
