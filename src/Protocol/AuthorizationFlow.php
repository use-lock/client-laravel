<?php

declare(strict_types=1);

namespace Lock\Laravel\Protocol;

use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Lock\Client\Auth\AuthorizationRequest;
use Lock\Client\Auth\OidcException;
use Lock\Client\Realm;
use Lock\Laravel\Protocol\Http\Concerns\RespondsToInertiaExternalRedirects;
use Lock\Laravel\Shared\Authentication\UserAuthentication;
use Lock\Laravel\Shared\Sessions\BackchannelSessions;
use Symfony\Component\HttpFoundation\Response;

class AuthorizationFlow
{
    use RespondsToInertiaExternalRedirects;

    public function __construct(
        private readonly Realm $realm,
        private readonly UserAuthentication $manager,
        private readonly BackchannelSessions $backchannelLogout,
    ) {}

    public function redirect(Request $request): Response
    {
        /** @var list<string> $scopes */
        $scopes = (array) config('oidc-client.scopes', ['openid']);
        $authorization = $this->realm->authorization()->begin($scopes);

        $request->session()->put([
            'oidc-client.state' => $authorization->state,
            'oidc-client.nonce' => $authorization->nonce,
            'oidc-client.code_verifier' => $authorization->codeVerifier,
        ]);

        return $this->respondToInertia($request, redirect()->away($authorization->url));
    }

    public function handleCallback(Request $request): RedirectResponse
    {
        $state = $request->session()->pull('oidc-client.state');
        $nonce = $request->session()->pull('oidc-client.nonce');
        $verifier = $request->session()->pull('oidc-client.code_verifier');

        if (! is_string($state) || ! is_string($nonce) || ! is_string($verifier) || in_array('', [$state, $nonce, $verifier], true)) {
            throw new OidcException('The OIDC callback session context is missing or has already been used.');
        }

        $tokens = $this->realm->authorization()->complete(new AuthorizationRequest('', $state, $nonce, $verifier), $request->query());
        $claims = (array) $tokens->claims;

        $user = $this->manager->resolveUser((string) $claims['sub'], $claims)
            ?? throw new OidcException('No local user matched the id_token subject.');

        // The guard regenerates the session on login; doing it again here would
        // detach the provider's OIDC session from the browser session it
        // recorded, which matters when the app is also its own OIDC provider.
        $this->manager->guard()->login($user);

        $request->session()->put('oidc-client.tokens', [
            'access_token' => $tokens->accessToken,
            'refresh_token' => $tokens->refreshToken,
            'id_token' => $tokens->idToken,
            'expires_at' => $tokens->expiresAt,
        ]);

        $sid = $claims['sid'] ?? null;

        if (config('oidc-client.backchannel_logout.enabled', false) && is_string($sid) && $sid !== '') {
            $request->session()->put('oidc-client.sid', $sid);
            $this->backchannelLogout->registerSession($sid, $request->session()->getId());
        }

        return $this->manager->redirectAfterLogin();
    }
}
