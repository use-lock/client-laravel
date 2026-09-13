<?php
declare(strict_types=1);

namespace Lock\Laravel\Shared\Sessions;

interface BackchannelSessions
{
    public function registerSession(string $sid, string $sessionId): void;

    public function pullSessionId(string $sid): ?string;

    public function markRevoked(string $sid): void;

    public function isRevoked(string $sid): bool;

    public function rememberJti(string $jti, int $expiresAt): bool;
}
