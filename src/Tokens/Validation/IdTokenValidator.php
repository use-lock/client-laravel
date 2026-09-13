<?php

declare(strict_types=1);

namespace Lock\Laravel\Tokens\Validation;

use Lcobucci\JWT\UnencryptedToken;
use Lock\Laravel\Shared\Protocol\OidcClientException;
use Lock\Laravel\Shared\Tokens\IdTokens;

class IdTokenValidator extends TokenValidator implements IdTokens
{
    /**
     * @return array<string, mixed>
     */
    public function validate(string $idToken, string $expectedNonce): array
    {
        $token = $this->parseAndVerifySignature($idToken);

        $this->assertClaims($token, $expectedNonce);

        return $token->claims()->all();
    }

    protected function tokenName(): string
    {
        return 'id_token';
    }

    private function assertClaims(UnencryptedToken $token, string $expectedNonce): void
    {
        $claims = $token->claims();
        $leeway = (int) config('oidc-client.leeway', 60);
        $now = time();

        $this->assertIssuer($token);

        $sub = $claims->get('sub');
        if (! is_string($sub) || $sub === '') {
            throw new OidcClientException('The id_token is missing a subject.');
        }

        $audience = $this->assertAudience($token);
        $clientId = (string) config('oidc-client.client_id');

        $azp = $claims->get('azp');
        if (count($audience) > 1) {
            if (! is_string($azp) || $azp !== $clientId) {
                throw new OidcClientException('The id_token azp does not match this client.');
            }
        } elseif (is_string($azp) && $azp !== $clientId) {
            throw new OidcClientException('The id_token azp does not match this client.');
        }

        if ($claims->get('nonce') !== $expectedNonce) {
            throw new OidcClientException('The id_token nonce does not match.');
        }

        $exp = $this->timestamp($claims->get('exp'), 'exp', required: true);
        if ($now > $exp + $leeway) {
            throw new OidcClientException('The id_token has expired.');
        }

        $nbf = $this->timestamp($claims->get('nbf'), 'nbf');
        if ($nbf !== null && $now + $leeway < $nbf) {
            throw new OidcClientException('The id_token is not yet valid.');
        }

        $iat = $this->timestamp($claims->get('iat'), 'iat', required: true);
        if ($now + $leeway < $iat) {
            throw new OidcClientException('The id_token was issued in the future.');
        }
    }
}
