<?php
declare(strict_types=1);
use Lock\Laravel\OidcClientServiceProvider;

$domains = ['Authentication', 'Protocol', 'Sessions', 'Shared', 'Support', 'Tokens'];

it('names every domain the package ships', function () use ($domains): void {
    $directories = array_map(basename(...), glob(__DIR__.'/../../src/*', GLOB_ONLYDIR) ?: []);
    sort($directories);

    expect($directories)->toBe($domains);
});

foreach (array_diff($domains, ['Support']) as $domain) {
    $forbidden = array_values(array_diff($domains, [$domain, 'Shared']));

    arch("{$domain} only depends on its own domain and Shared")
        ->expect("Lock\\Laravel\\{$domain}")
        ->not->toUse(array_map(fn (string $other): string => "Lock\\Laravel\\{$other}", $forbidden));
}

arch('the client does not depend on the server')
    ->expect('Lock\Laravel')
    ->not->toUse('Lock\Server');

it('keeps only the package service provider at the source root', function (): void {
    $files = array_map(basename(...), glob(__DIR__.'/../../src/*.php') ?: []);

    expect($files)->toBe(['OidcClientServiceProvider.php']);
});

arch('domain classes do not depend on the package composition root')
    ->expect(array_map(fn (string $domain): string => "Lock\\Laravel\\{$domain}", $domains))
    ->not->toUse(OidcClientServiceProvider::class);
