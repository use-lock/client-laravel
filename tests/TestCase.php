<?php
declare(strict_types=1);

namespace Lock\Laravel\Tests;

use Illuminate\Support\Facades\File;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\ParallelTesting;
use Lock\Laravel\OidcClientServiceProvider;
use Orchestra\Testbench\Concerns\WithLaravelMigrations;
use Orchestra\Testbench\Concerns\WithWorkbench;
use Orchestra\Testbench\TestCase as BaseTestCase;
use Workbench\App\Models\User;

abstract class TestCase extends BaseTestCase
{
    use WithLaravelMigrations;
    use WithWorkbench;

    protected $enablesPackageDiscoveries = false;

    /**
     * Only this package's provider: the suite must prove the client works without the
     * server or ui packages that share this monorepo's vendor directory.
     */
    protected function getPackageProviders($app): array
    {
        return [OidcClientServiceProvider::class];
    }

    protected function setUp(): void
    {
        parent::setUp();

        Http::preventStrayRequests();
    }

    protected function getEnvironmentSetUp($app): void
    {
        $token = ParallelTesting::token();
        $workspace = sys_get_temp_dir().'/use-lock-client-laravel-tests';
        $database = $token
            ? $workspace.'/test_'.$token.'.sqlite'
            : $workspace.'/database-'.getmypid().'.sqlite';

        File::makeDirectory(dirname($database), 0755, true, true);

        if (! file_exists($database)) {
            touch($database);
        }

        $app['config']->set('app.key', 'base64:'.base64_encode(random_bytes(32)));
        $app['config']->set('database.default', 'sqlite');
        $app['config']->set('database.connections.sqlite.database', $database);
        $app['config']->set('auth.providers.users.model', User::class);
        $app['config']->set('session.driver', 'array');
        $app['config']->set('oidc-client.enabled', true);
    }

    protected function defineDatabaseMigrations(): void
    {
        $this->loadMigrationsFrom(dirname(__DIR__).'/workbench/database/migrations');
    }
}
