<?php
declare(strict_types=1);

namespace Lock\Laravel\Shared\Tokens;

interface LogoutTokens
{
    /** @return array{sid: string, sub: string, jti: string|null, exp: int} */
    public function validate(string $logoutToken): array;
}
