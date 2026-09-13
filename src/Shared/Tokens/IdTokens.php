<?php
declare(strict_types=1);

namespace Lock\Laravel\Shared\Tokens;

interface IdTokens
{
    /** @return array<string, mixed> */
    public function validate(string $idToken, string $expectedNonce): array;
}
