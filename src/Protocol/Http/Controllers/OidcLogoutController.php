<?php

declare(strict_types=1);

namespace Lock\Laravel\Protocol\Http\Controllers;

use Illuminate\Http\Client\ConnectionException;
use Illuminate\Http\Client\RequestException;
use Illuminate\Http\Request;
use Lock\Laravel\Protocol\Http\Concerns\RespondsToInertiaExternalRedirects;
use Lock\Laravel\Shared\Authentication\UserAuthentication;
use Lock\Laravel\Shared\Discovery\ProviderDiscovery;
use Lock\Laravel\Shared\Protocol\OidcClientException;
use Symfony\Component\HttpFoundation\Response;

class OidcLogoutController
{
    use RespondsToInertiaExternalRedirects;

    public function __invoke(Request $request, ProviderDiscovery $discovery, UserAuthentication $manager): Response
    {
        $idToken = $request->session()->get('oidc-client.tokens.id_token');

        $manager->terminateLocalSession($request);

        try {
            $endSession = $discovery->metadata()->endSessionEndpoint;
        } catch (ConnectionException|RequestException|OidcClientException) {
            $endSession = null;
        }

        if ($endSession === null) {
            return redirect('/');
        }

        $postLogoutRedirectUri = config('oidc-client.post_logout_redirect_uri');

        $query = http_build_query(array_filter([
            'id_token_hint' => is_string($idToken) ? $idToken : null,
            'post_logout_redirect_uri' => is_string($postLogoutRedirectUri) && $postLogoutRedirectUri !== '' ? $postLogoutRedirectUri : null,
        ]));

        $separator = str_contains($endSession, '?') ? '&' : '?';

        return $this->respondToInertia($request, redirect()->away($endSession.$separator.$query));
    }
}
