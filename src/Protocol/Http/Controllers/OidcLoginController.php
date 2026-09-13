<?php

declare(strict_types=1);

namespace Lock\Laravel\Protocol\Http\Controllers;

use Illuminate\Http\Request;
use Lock\Laravel\Protocol\AuthorizationFlow;
use Lock\Laravel\Shared\Authentication\UserAuthentication;
use Symfony\Component\HttpFoundation\Response;

class OidcLoginController
{
    public function __invoke(Request $request, AuthorizationFlow $authorizationFlow, UserAuthentication $manager): Response
    {
        if ($manager->guard()->check()) {
            return $manager->redirectAfterLogin();
        }

        return $authorizationFlow->redirect($request);
    }
}
