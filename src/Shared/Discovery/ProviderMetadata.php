<?php

declare(strict_types=1);

namespace Lock\Laravel\Shared\Discovery;

use Lock\Laravel\Shared\Protocol\OidcClientException;

final readonly class ProviderMetadata
{
    public function __construct(
        public string $issuer,
        public string $authorizationEndpoint,
        public string $tokenEndpoint,
        public string $jwksUri,
        public ?string $endSessionEndpoint,
    ) {}

    /**
     * @param  array<string, mixed>  $doc
     */
    public static function fromArray(array $doc): self
    {
        foreach (['issuer', 'authorization_endpoint', 'token_endpoint', 'jwks_uri'] as $required) {
            if (! isset($doc[$required]) || ! is_string($doc[$required])) {
                throw new OidcClientException("The OIDC discovery document is missing [{$required}].");
            }
        }

        $endSession = $doc['end_session_endpoint'] ?? null;

        return new self(
            $doc['issuer'],
            $doc['authorization_endpoint'],
            $doc['token_endpoint'],
            $doc['jwks_uri'],
            is_string($endSession) ? $endSession : null,
        );
    }
}
