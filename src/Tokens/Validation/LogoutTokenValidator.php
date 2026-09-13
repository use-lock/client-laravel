<?php

declare(strict_types=1);

namespace Lock\Laravel\Tokens\Validation;

use Lcobucci\JWT\UnencryptedToken;
use Lock\Laravel\Shared\Protocol\OidcClientException;
use Lock\Laravel\Shared\Tokens\LogoutTokens;

class LogoutTokenValidator extends TokenValidator implements LogoutTokens
{
    private const string EVENT = 'http://schemas.openid.net/event/backchannel-logout';

    /**
     * @return array{sid: string, sub: string, jti: string|null, exp: int}
     */
    public function validate(string $logoutToken): array
    {
        $token = $this->parseAndVerifySignature($logoutToken);

        $claims = $token->claims();
        $leeway = (int) config('oidc-client.leeway', 60);
        $now = time();

        $this->assertIssuer($token);
        $this->assertAudience($token);

        if ($claims->has('nonce')) {
            throw new OidcClientException('A logout token must not contain a nonce.');
        }

        $events = $claims->get('events');
        $events = is_object($events) ? (array) $events : $events;
        if (! is_array($events) || ! array_key_exists(self::EVENT, $events)) {
            throw new OidcClientException('The logout token is missing the back-channel logout event.');
        }

        $exp = $this->timestamp($claims->get('exp'), 'exp', required: true);
        if ($now > $exp + $leeway) {
            throw new OidcClientException('The logout token has expired.');
        }

        $iat = $this->timestamp($claims->get('iat'), 'iat', required: true);
        if ($now - $iat > $leeway + 300) {
            throw new OidcClientException('The logout token was issued too long ago.');
        }

        $sid = $claims->get('sid');
        if (! is_string($sid) || $sid === '') {
            throw new OidcClientException('The logout token is missing a sid.');
        }

        $sub = $claims->get('sub');
        $jti = $claims->get('jti');

        return [
            'sid' => $sid,
            'sub' => is_string($sub) ? $sub : '',
            'jti' => is_string($jti) && $jti !== '' ? $jti : null,
            'exp' => (int) $exp,
        ];
    }

    protected function tokenName(): string
    {
        return 'logout token';
    }

    protected function assertHeaders(UnencryptedToken $token): void
    {
        if ($token->headers()->get('typ') !== 'logout+jwt') {
            throw new OidcClientException('The logout token has an invalid typ header.');
        }
    }
}
