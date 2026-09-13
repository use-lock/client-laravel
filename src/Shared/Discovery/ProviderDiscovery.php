<?php
declare(strict_types=1);

namespace Lock\Laravel\Shared\Discovery;

interface ProviderDiscovery
{
    public function metadata(): ProviderMetadata;

    /** @return array<int, array<string, mixed>> */
    public function jwks(bool $fresh = false): array;
}
