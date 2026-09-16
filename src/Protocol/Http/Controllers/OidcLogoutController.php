<?php

declare(strict_types=1);

namespace Lock\Laravel\Protocol\Http\Controllers;

use Illuminate\Http\Request;
use Lock\Client\Realm;
use Lock\Laravel\Protocol\Http\Concerns\RespondsToInertiaExternalRedirects;
use Lock\Laravel\Shared\Authentication\UserAuthentication;
use Symfony\Component\HttpFoundation\Response;

class OidcLogoutController
{
    use RespondsToInertiaExternalRedirects;

    public function __invoke(Request $request, Realm $realm, UserAuthentication $manager): Response
    {
        $idToken = $request->session()->get('oidc-client.tokens.id_token');

        $manager->terminateLocalSession($request);

        $url = $realm->authorization()->logoutUrl(
            is_string($idToken) ? $idToken : null,
            config('oidc-client.post_logout_redirect_uri') ?: null,
        );

        return $this->respondToInertia($request, redirect()->away($url));
    }
}
