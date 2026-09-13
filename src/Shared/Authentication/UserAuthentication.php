<?php
declare(strict_types=1);

namespace Lock\Laravel\Shared\Authentication;

use Closure;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\StatefulGuard;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;

interface UserAuthentication
{
    public function guard(): StatefulGuard;

    /** @param Closure(string, array<string, mixed>): (Authenticatable|null) $callback */
    public function resolveUsersUsing(Closure $callback): void;

    /** @param array<string, mixed> $claims */
    public function resolveUser(string $sub, array $claims): ?Authenticatable;

    public function redirectAfterLogin(): RedirectResponse;

    public function terminateLocalSession(Request $request): void;
}
