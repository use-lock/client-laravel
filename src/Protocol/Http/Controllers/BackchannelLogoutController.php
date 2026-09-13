<?php

declare(strict_types=1);

namespace Lock\Laravel\Protocol\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Session;
use Lock\Laravel\Shared\Protocol\OidcClientException;
use Lock\Laravel\Shared\Sessions\BackchannelSessions;
use Lock\Laravel\Shared\Tokens\LogoutTokens;
use Symfony\Component\HttpFoundation\Response;

class BackchannelLogoutController
{
    public function __invoke(Request $request, LogoutTokens $validator, BackchannelSessions $store): Response
    {
        try {
            ['sid' => $sid, 'jti' => $jti, 'exp' => $exp] = $validator->validate((string) $request->input('logout_token'));

            if ($jti !== null && ! $store->rememberJti($jti, $exp)) {
                throw new OidcClientException("The logout token jti [{$jti}] has already been consumed.");
            }
        } catch (OidcClientException $e) {
            report($e);

            return response()->json(['error' => 'invalid_request'], 400)->header('Cache-Control', 'no-store, private');
        }

        // Destroying the session is a no-op for the cookie driver, so the revoked
        // marker below is what the enforcement middleware falls back on.
        $sessionId = $store->pullSessionId($sid);
        if ($sessionId !== null) {
            Session::getHandler()->destroy($sessionId);
        }

        $store->markRevoked($sid);

        return response('', 200)->header('Cache-Control', 'no-store, private');
    }
}
