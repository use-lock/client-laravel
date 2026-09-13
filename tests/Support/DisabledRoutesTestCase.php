<?php

declare(strict_types=1);

namespace Lock\Laravel\Tests\Support;

use Lock\Laravel\Tests\TestCase;

abstract class DisabledRoutesTestCase extends TestCase
{
    protected function getEnvironmentSetUp($app): void
    {
        parent::getEnvironmentSetUp($app);

        $app['config']->set('oidc-client.enabled', false);
    }
}
