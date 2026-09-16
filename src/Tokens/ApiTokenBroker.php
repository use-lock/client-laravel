<?php

declare(strict_types=1);

namespace Lock\Laravel\Tokens;

use Lock\Client\Auth\OidcException;
use Lock\Client\Auth\TokenSet;
use Lock\Client\Realm;

class ApiTokenBroker
{
    public function __construct(private readonly Realm $realm) {}

    /**
     * Exchanges the logged-in user's access token for one aimed at $audience
     * (the issuer by default), cached in the session until shortly before it expires.
     *
     * @param  list<string>|null  $scopes
     */
    public function userToken(?string $audience = null, ?array $scopes = null): TokenSet
    {
        $audience ??= rtrim((string) config('oidc-client.issuer'), '/');
        $sorted = array_unique((array) $scopes);
        sort($sorted);

        $key = 'oidc-client.exchanged.'.hash('sha256', json_encode([$audience, $sorted], JSON_THROW_ON_ERROR));
        $cached = session($key);

        if (is_array($cached) && ! ($token = new TokenSet(...$cached))->isExpired()) {
            return $token;
        }

        $token = $this->realm->tokens()->exchange($this->sessionAccessToken(), $audience, $scopes ?: null);
        session()->put($key, get_object_vars($token));

        return $token;
    }

    /**
     * A client credentials token that needs no login session, so it also works
     * in queue workers and commands. The audience becomes the RFC 8707 resource;
     * the application cache holds the token until shortly before it expires.
     *
     * @param  list<string>|null  $scopes
     */
    public function machineToken(?string $audience = null, ?array $scopes = null): TokenSet
    {
        return $this->realm->tokens()->clientCredentials($audience, $scopes ?: null);
    }

    public function forget(): void
    {
        session()->forget('oidc-client.exchanged');
    }

    /**
     * The session's access token, renewed with the refresh token once it expires.
     */
    private function sessionAccessToken(): string
    {
        $tokens = (array) session('oidc-client.tokens', []);
        $accessToken = $tokens['access_token'] ?? null;

        if (is_string($accessToken) && $accessToken !== '' && (int) ($tokens['expires_at'] ?? 0) > time() + 30) {
            return $accessToken;
        }

        $refreshToken = $tokens['refresh_token'] ?? null;

        if (! is_string($refreshToken) || $refreshToken === '') {
            throw new OidcException('The OIDC access token is missing or expired and no refresh token is available.');
        }

        $renewed = $this->realm->tokens()->refresh($refreshToken);

        session()->put('oidc-client.tokens', [
            'access_token' => $renewed->accessToken,
            'refresh_token' => $renewed->refreshToken,
            'id_token' => $renewed->idToken ?? $tokens['id_token'] ?? null,
            'expires_at' => $renewed->expiresAt,
        ]);

        return $renewed->accessToken;
    }
}
