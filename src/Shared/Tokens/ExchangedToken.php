<?php

declare(strict_types=1);

namespace Lock\Laravel\Shared\Tokens;

final readonly class ExchangedToken
{
    /**
     * @param  list<string>|null  $scopes  Scopes the token endpoint granted, null when the response did not say.
     */
    public function __construct(
        public string $accessToken,
        public int $expiresAt,
        public ?array $scopes = null,
    ) {}

    public function expiresIn(): int
    {
        return max(0, $this->expiresAt - time());
    }

    /**
     * False while the granted scopes are unknown.
     */
    public function hasScope(string $scope): bool
    {
        return $this->scopes !== null && in_array($scope, $this->scopes, true);
    }
}
