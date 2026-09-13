<?php

declare(strict_types=1);

namespace Lock\Laravel\Tokens;

use Illuminate\Contracts\Cache\Repository as Cache;
use Illuminate\Http\Client\Factory as Http;
use Lock\Laravel\Shared\Discovery\ProviderDiscovery;
use Lock\Laravel\Shared\Protocol\OidcClientException;
use Lock\Laravel\Shared\Tokens\ExchangedToken;
use SensitiveParameter;

class ApiTokenBroker
{
    private const string EXCHANGE_GRANT = 'urn:ietf:params:oauth:grant-type:token-exchange';

    private const string ACCESS_TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:access_token';

    private const int EXPIRY_SKEW = 30;

    public function __construct(
        private readonly ProviderDiscovery $discovery,
        private readonly Http $http,
        private readonly Cache $cache,
    ) {}

    /**
     * @param  array<string, string>  $parameters
     * @param  list<string>|null  $scopes
     */
    public function accessToken(array $parameters = [], ?string $audience = null, ?array $scopes = null): string
    {
        return $this->exchangedToken($parameters, $audience, $scopes)->accessToken;
    }

    /**
     * @param  array<string, string>  $parameters
     * @param  list<string>|null  $scopes
     */
    public function exchangedToken(array $parameters = [], ?string $audience = null, ?array $scopes = null): ExchangedToken
    {
        $scopes = $scopes === [] ? null : $scopes;
        $audience ??= rtrim((string) config('oidc-client.issuer'), '/');
        $key = $this->cacheKey($audience, $parameters, $scopes);
        $cached = session('oidc-client.exchanged.'.$key);

        if (is_array($cached) && is_string($cached['access_token'] ?? null) && (int) ($cached['expires_at'] ?? 0) > time() + self::EXPIRY_SKEW) {
            return $this->exchangedTokenFrom($cached);
        }

        $issued = $this->exchange($this->subjectToken(), $audience, $parameters, $scopes);
        session()->put('oidc-client.exchanged.'.$key, $issued);

        return $this->exchangedTokenFrom($issued);
    }

    /**
     * Machine token for server-to-server calls: a client_credentials grant
     * that needs no login session, so it also works in queue workers and
     * commands. An audience becomes the RFC 8707 `resource` parameter (the
     * client's allowed audience list on the provider governs it); client
     * credentials default to this app's own oidc-client configuration.
     *
     * @param  list<string>|null  $scopes
     */
    public function machineToken(?string $audience = null, ?array $scopes = null, ?string $clientId = null, #[SensitiveParameter] ?string $clientSecret = null): string
    {
        return $this->machineExchangedToken($audience, $scopes, $clientId, $clientSecret)->accessToken;
    }

    /**
     * @param  list<string>|null  $scopes
     */
    public function machineExchangedToken(?string $audience = null, ?array $scopes = null, ?string $clientId = null, #[SensitiveParameter] ?string $clientSecret = null): ExchangedToken
    {
        $scopes = $scopes === [] ? null : $scopes;
        $clientId ??= (string) config('oidc-client.client_id');
        $clientSecret ??= (string) config('oidc-client.client_secret');
        $key = 'oidc-client:machine:'.$this->cacheKey($audience ?? '', ['client_id' => $clientId], $scopes);
        $cached = $this->cache->get($key);

        if (is_array($cached) && is_string($cached['access_token'] ?? null) && (int) ($cached['expires_at'] ?? 0) > time() + self::EXPIRY_SKEW) {
            return $this->exchangedTokenFrom($cached);
        }

        $issued = $this->clientCredentials($clientId, $clientSecret, $audience, $scopes);
        $ttl = max($issued['expires_at'] - time() - self::EXPIRY_SKEW, 0);
        $this->cache->put($key, $issued, $ttl);

        return $this->exchangedTokenFrom($issued);
    }

    public function forget(): void
    {
        session()->forget('oidc-client.exchanged');
    }

    /**
     * @param  list<string>|null  $scopes
     * @return array{access_token: string, expires_at: int}
     */
    private function clientCredentials(string $clientId, #[SensitiveParameter] string $clientSecret, ?string $audience, ?array $scopes): array
    {
        $payload = [
            'grant_type' => 'client_credentials',
            'client_id' => $clientId,
            'client_secret' => $clientSecret,
        ];

        if ($audience !== null && $audience !== '') {
            $payload['resource'] = $audience;
        }

        if ($scopes !== null && $scopes !== []) {
            $payload['scope'] = implode(' ', $scopes);
        }

        $response = $this->http->asForm()->post($this->discovery->metadata()->tokenEndpoint, $payload);

        $accessToken = $response->json('access_token');

        if ($response->failed() || ! is_string($accessToken) || $accessToken === '') {
            throw new OidcClientException('The token endpoint rejected the client-credentials request.');
        }

        $expiresIn = is_numeric($response->json('expires_in')) ? (int) $response->json('expires_in') : 60;

        return [
            'access_token' => $accessToken,
            'expires_at' => time() + $expiresIn,
            'scopes' => $this->grantedScopes($response->json('scope')),
        ];
    }

    private function subjectToken(): string
    {
        $tokens = (array) session('oidc-client.tokens', []);
        $expiresAt = $tokens['expires_at'] ?? null;

        if (! is_int($expiresAt) || $expiresAt <= time() + self::EXPIRY_SKEW) {
            $tokens = $this->refresh($tokens);
        }

        $accessToken = $tokens['access_token'] ?? null;

        if (! is_string($accessToken) || $accessToken === '') {
            throw new OidcClientException('The OIDC access token is missing or expired.');
        }

        return $accessToken;
    }

    /**
     * @param  array<string, mixed>  $tokens
     * @return array<string, mixed>
     */
    private function refresh(array $tokens): array
    {
        $refreshToken = $tokens['refresh_token'] ?? null;

        if (! is_string($refreshToken) || $refreshToken === '') {
            throw new OidcClientException('No refresh token is available to renew the session tokens.');
        }

        $payload = [
            'grant_type' => 'refresh_token',
            'refresh_token' => $refreshToken,
            'client_id' => (string) config('oidc-client.client_id'),
        ];

        $clientSecret = config('oidc-client.client_secret');

        if (is_string($clientSecret) && $clientSecret !== '') {
            $payload['client_secret'] = $clientSecret;
        }

        $response = $this->http->asForm()->post($this->discovery->metadata()->tokenEndpoint, $payload);

        $accessToken = $response->json('access_token');

        if ($response->failed() || ! is_string($accessToken) || $accessToken === '') {
            throw new OidcClientException('The token endpoint rejected the refresh.');
        }

        $renewed = [
            'access_token' => $accessToken,
            'refresh_token' => is_string($response->json('refresh_token')) ? $response->json('refresh_token') : $refreshToken,
            'id_token' => is_string($response->json('id_token')) ? $response->json('id_token') : ($tokens['id_token'] ?? null),
            'expires_at' => is_numeric($response->json('expires_in')) ? time() + (int) $response->json('expires_in') : null,
        ];

        session()->put('oidc-client.tokens', $renewed);

        return $renewed;
    }

    /**
     * @param  array<string, string>  $parameters
     * @param  list<string>|null  $scopes
     * @return array{access_token: string, expires_at: int}
     */
    private function exchange(string $subjectToken, string $audience, array $parameters, ?array $scopes): array
    {
        $payload = [
            ...$parameters,
            'grant_type' => self::EXCHANGE_GRANT,
            'client_id' => (string) config('oidc-client.client_id'),
            'subject_token' => $subjectToken,
            'subject_token_type' => self::ACCESS_TOKEN_TYPE,
            'audience' => $audience,
        ];

        if ($scopes !== null && $scopes !== []) {
            $payload['scope'] = implode(' ', $scopes);
        }

        $response = $this->http->asForm()->post($this->discovery->metadata()->tokenEndpoint, $payload);

        $accessToken = $response->json('access_token');

        if ($response->failed() || ! is_string($accessToken) || $accessToken === '') {
            throw new OidcClientException('The token endpoint rejected the token exchange.');
        }

        $expiresIn = is_numeric($response->json('expires_in')) ? (int) $response->json('expires_in') : 60;

        return [
            'access_token' => $accessToken,
            'expires_at' => time() + $expiresIn,
            'scopes' => $this->grantedScopes($response->json('scope')),
        ];
    }

    /**
     * @param  array{access_token: string, expires_at: int, scopes?: list<string>|null}  $issued
     */
    private function exchangedTokenFrom(array $issued): ExchangedToken
    {
        $scopes = $issued['scopes'] ?? null;

        return new ExchangedToken(
            $issued['access_token'],
            (int) $issued['expires_at'],
            is_array($scopes) ? array_values(array_filter($scopes, is_string(...))) : null,
        );
    }

    /**
     * The space-delimited `scope` response parameter (RFC 6749 §5.1, RFC 8693 §2.2.1)
     * as a list, or null when the token endpoint did not report granted scopes.
     *
     * @return list<string>|null
     */
    private function grantedScopes(mixed $scope): ?array
    {
        if (! is_string($scope)) {
            return null;
        }

        return array_values(array_filter(explode(' ', $scope), fn (string $value): bool => $value !== ''));
    }

    /**
     * @param  array<string, string>  $parameters
     * @param  list<string>|null  $scopes
     */
    private function cacheKey(string $audience, array $parameters, ?array $scopes): string
    {
        ksort($parameters);

        if ($scopes !== null) {
            sort($scopes);
        }

        return hash('sha256', json_encode([$audience, $parameters, $scopes], JSON_THROW_ON_ERROR));
    }
}
