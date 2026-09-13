<?php

declare(strict_types=1);

namespace Lock\Laravel\Protocol\Http\Controllers;

use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Lock\Laravel\Protocol\AuthorizationFlow;
use Lock\Laravel\Shared\Protocol\OidcClientException;
use Lock\Laravel\Shared\Routing\Handler;

class OidcCallbackController
{
    public function __invoke(Request $request, AuthorizationFlow $authorizationFlow): RedirectResponse
    {
        try {
            return $authorizationFlow->handleCallback($request);
        } catch (OidcClientException $e) {
            report($e);

            return redirect()->route(Handler::Login->value)->withErrors([
                'oidc' => 'Sign-in failed. Please try again.',
            ]);
        }
    }
}
