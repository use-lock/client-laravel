<?php

declare(strict_types=1);

namespace Lock\Laravel\Discovery;

use Illuminate\Contracts\Cache\Repository as Cache;
use Illuminate\Http\Client\Factory as Http;
use Lock\Laravel\Shared\Discovery\ProviderDiscovery;
use Lock\Laravel\Shared\Discovery\ProviderMetadata;
use Lock\Laravel\Shared\Protocol\OidcClientException;

class OidcDiscovery implements ProviderDiscovery
{
    private ?ProviderMetadata $metadata = null;

    public function __construct(
        private readonly Http $http,
        private readonly Cache $cache,
    ) {}

    public function metadata(): ProviderMetadata
    {
        if ($this->metadata instanceof ProviderMetadata) {
            return $this->metadata;
        }

        $issuer = $this->issuer();

        $doc = $this->cache->remember(
            'oidc-client:discovery:'.$issuer,
            $this->ttl(),
            function () use ($issuer): array {
                $doc = $this->http->get($issuer.'/.well-known/openid-configuration')->throw()->json();

                if (! is_array($doc)) {
                    throw new OidcClientException('The OIDC discovery document response was not a JSON object.');
                }

                return $doc;
            },
        );

        $metadata = ProviderMetadata::fromArray($doc);

        if (rtrim($metadata->issuer, '/') !== $issuer) {
            throw new OidcClientException('The discovery document issuer does not match the configured issuer.');
        }

        return $this->metadata = $metadata;
    }

    /**
     * @return array<int, array<string, mixed>>
     */
    public function jwks(bool $fresh = false): array
    {
        $key = 'oidc-client:jwks:'.$this->issuer();

        if ($fresh) {
            $this->cache->forget($key);
        }

        return $this->cache->remember(
            $key,
            $this->ttl(),
            function (): array {
                $keys = $this->http->get($this->metadata()->jwksUri)->throw()->json('keys', []);

                if (! is_array($keys)) {
                    throw new OidcClientException('The OIDC JWKS response was not a JSON object.');
                }

                return $keys;
            },
        );
    }

    private function issuer(): string
    {
        $issuer = config('oidc-client.issuer');

        if (! is_string($issuer) || $issuer === '') {
            throw new OidcClientException('No OIDC issuer has been configured (oidc-client.issuer).');
        }

        return rtrim($issuer, '/');
    }

    private function ttl(): int
    {
        return (int) config('oidc-client.discovery_cache_ttl', 3600);
    }
}
