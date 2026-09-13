<?php

declare(strict_types=1);

namespace Lock\Laravel\Protocol;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Client\Factory as Http;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Str;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lock\Laravel\Protocol\Http\Concerns\RespondsToInertiaExternalRedirects;
use Lock\Laravel\Shared\Authentication\UserAuthentication;
use Lock\Laravel\Shared\Discovery\ProviderDiscovery;
use Lock\Laravel\Shared\Protocol\OidcClientException;
use Lock\Laravel\Shared\Sessions\BackchannelSessions;
use Lock\Laravel\Shared\Tokens\IdTokens;
use Symfony\Component\HttpFoundation\Response;

class AuthorizationFlow
{
    use RespondsToInertiaExternalRedirects;

    public function __construct(
        private readonly ProviderDiscovery $discovery,
        private readonly Http $http,
        private readonly IdTokens $validator,
        private readonly UserAuthentication $manager,
        private readonly BackchannelSessions $backchannelLogout,
    ) {}

    public function redirect(Request $request): Response
    {
        $metadata = $this->discovery->metadata();

        $state = Str::random(40);
        $nonce = Str::random(40);
        $verifier = Str::random(64);
        $challenge = (new JoseEncoder)->base64UrlEncode(hash('sha256', $verifier, true));

        session()->put([
            'oidc-client.state' => $state,
            'oidc-client.nonce' => $nonce,
            'oidc-client.code_verifier' => $verifier,
        ]);

        $query = http_build_query([
            'response_type' => 'code',
            'client_id' => (string) config('oidc-client.client_id'),
            'redirect_uri' => $this->redirectUri(),
            'scope' => implode(' ', (array) config('oidc-client.scopes', ['openid'])),
            'state' => $state,
            'nonce' => $nonce,
            'code_challenge' => $challenge,
            'code_challenge_method' => 'S256',
        ]);

        return $this->respondToInertia($request, redirect()->away($metadata->authorizationEndpoint.'?'.$query));
    }

    public function handleCallback(Request $request): RedirectResponse
    {
        $state = session()->pull('oidc-client.state');
        $nonce = session()->pull('oidc-client.nonce');
        $verifier = session()->pull('oidc-client.code_verifier');

        if (! is_string($state) || $state === '' || ! is_string($nonce) || $nonce === '' || ! is_string($verifier) || $verifier === '') {
            throw new OidcClientException('The OIDC callback session context is missing or has already been used.');
        }

        if ($request->query('error') !== null) {
            throw new OidcClientException('The provider returned an authorization error.');
        }

        if (! is_string($request->query('state')) || ! hash_equals($state, $request->query('state'))) {
            throw new OidcClientException('The OIDC state parameter did not match.');
        }

        $code = $request->query('code');

        if (! is_string($code) || $code === '') {
            throw new OidcClientException('The provider did not return an authorization code.');
        }

        $metadata = $this->discovery->metadata();

        $payload = [
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => $this->redirectUri(),
            'client_id' => (string) config('oidc-client.client_id'),
            'code_verifier' => $verifier,
        ];

        $clientSecret = config('oidc-client.client_secret');

        if (is_string($clientSecret) && $clientSecret !== '') {
            $payload['client_secret'] = $clientSecret;
        }

        $response = $this->http->asForm()->post($metadata->tokenEndpoint, $payload);

        if ($response->failed()) {
            throw new OidcClientException('The token endpoint rejected the code exchange.');
        }

        $idToken = $response->json('id_token');

        if (! is_string($idToken)) {
            throw new OidcClientException('The token response did not include an id_token.');
        }

        $claims = $this->validator->validate($idToken, $nonce);

        $user = $this->manager->resolveUser((string) $claims['sub'], $claims);

        if (! $user instanceof Authenticatable) {
            throw new OidcClientException('No local user matched the id_token subject.');
        }

        // The guard regenerates the session on login; doing it again here would
        // detach the provider's OIDC session from the browser session it
        // recorded, which matters when the app is also its own OIDC provider.
        $this->manager->guard()->login($user);

        session()->put('oidc-client.tokens', [
            'access_token' => $response->json('access_token'),
            'refresh_token' => $response->json('refresh_token'),
            'id_token' => $idToken,
            'expires_at' => is_numeric($response->json('expires_in')) ? time() + (int) $response->json('expires_in') : null,
        ]);

        if (config('oidc-client.backchannel_logout.enabled', false)) {
            $sid = $claims['sid'] ?? null;

            if (is_string($sid) && $sid !== '') {
                $request->session()->put('oidc-client.sid', $sid);
                $this->backchannelLogout->registerSession($sid, $request->session()->getId());
            }
        }

        return $this->manager->redirectAfterLogin();
    }

    private function redirectUri(): string
    {
        $configured = config('oidc-client.redirect_uri');

        return is_string($configured) && $configured !== '' ? $configured : route('login.callback');
    }
}
