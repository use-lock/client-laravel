<?php
declare(strict_types=1);

use Illuminate\Support\Facades\Http;
use Lock\Laravel\Shared\Discovery\ProviderDiscovery;
use Lock\Laravel\Shared\Discovery\ProviderMetadata;

it('uses the application discovery binding to initiate login', function (): void {
    $discovery = Mockery::mock(ProviderDiscovery::class);
    $discovery->shouldReceive('metadata')->once()->andReturn(new ProviderMetadata(
        issuer: 'https://custom.example.com',
        authorizationEndpoint: 'https://custom.example.com/authorize',
        tokenEndpoint: 'https://custom.example.com/token',
        jwksUri: 'https://custom.example.com/keys',
        endSessionEndpoint: null,
    ));
    $this->app->instance(ProviderDiscovery::class, $discovery);
    Http::fake();

    $response = $this->get('/login');

    $response->assertRedirect();
    expect($response->headers->get('Location'))->toStartWith('https://custom.example.com/authorize?');
    Http::assertNothingSent();
});
