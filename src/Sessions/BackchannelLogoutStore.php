<?php

declare(strict_types=1);

namespace Lock\Laravel\Sessions;

use DateTimeInterface;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Cache;
use Lock\Laravel\Shared\Sessions\BackchannelSessions;

/**
 * Owns the back-channel logout bookkeeping: which local session belongs to a
 * provider sid, and which sids have been revoked. The cache key formats and
 * the retention window live here and nowhere else.
 */
class BackchannelLogoutStore implements BackchannelSessions
{
    public function registerSession(string $sid, string $sessionId): void
    {
        Cache::put($this->sessionKey($sid), $sessionId, $this->retention());
    }

    public function pullSessionId(string $sid): ?string
    {
        $sessionId = Cache::pull($this->sessionKey($sid));

        return is_string($sessionId) && $sessionId !== '' ? $sessionId : null;
    }

    public function markRevoked(string $sid): void
    {
        Cache::put($this->revokedKey($sid), true, $this->retention());
    }

    public function isRevoked(string $sid): bool
    {
        return Cache::has($this->revokedKey($sid));
    }

    /**
     * Remember a consumed logout-token jti; false means it was already
     * consumed (a replay, Back-Channel Logout §2.6). Kept until the later of
     * the token's exp and the retention window, which outlives the exp+leeway
     * span in which the token itself would still be accepted.
     */
    public function rememberJti(string $jti, int $expiresAt): bool
    {
        $retention = $this->retention();
        $until = max($expiresAt, $retention->getTimestamp());

        return Cache::add("oidc-client:logout-jti:{$jti}", true, Carbon::createFromTimestamp($until));
    }

    private function sessionKey(string $sid): string
    {
        return "oidc-client:bclo:session:{$sid}";
    }

    private function revokedKey(string $sid): string
    {
        return "oidc-client:bclo:revoked:{$sid}";
    }

    private function retention(): DateTimeInterface
    {
        return now()->addMinutes((int) config('oidc-client.backchannel_logout.retention_minutes', 120));
    }
}
