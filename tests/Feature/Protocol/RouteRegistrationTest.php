<?php

declare(strict_types=1);

namespace Lock\Laravel\Tests\Feature\Protocol;

use Lock\Laravel\Tests\Support\DisabledRoutesTestCase;

class RouteRegistrationTest extends DisabledRoutesTestCase
{
    public function test_the_login_callback_and_logout_endpoints_answer_404_while_the_client_is_disabled(): void
    {
        $this->get('/login')->assertNotFound();
        $this->get('/login/callback')->assertNotFound();
        $this->post('/logout')->assertNotFound();
    }
}
