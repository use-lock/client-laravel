<?php

declare(strict_types=1);

namespace Lock\Laravel\Protocol\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Session;
use Lock\Client\Auth\OidcException;
use Lock\Client\Realm;
use Lock\Laravel\Shared\Sessions\BackchannelSessions;
use Symfony\Component\HttpFoundation\Response;

class BackchannelLogoutController
{
    public function __invoke(Request $request, Realm $realm, BackchannelSessions $store): Response
    {
        try {
            ['sid' => $sid, 'jti' => $jti, 'exp' => $exp] = $realm->logoutTokens()->validate((string) $request->input('logout_token'));

            if ($jti !== null && ! $store->rememberJti($jti, $exp)) {
                throw new OidcException("The logout token jti [{$jti}] has already been consumed.");
            }
        } catch (OidcException $e) {
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
