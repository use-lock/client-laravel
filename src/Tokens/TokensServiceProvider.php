<?php
declare(strict_types=1);

namespace Lock\Laravel\Tokens;

use Illuminate\Support\ServiceProvider;
use Lock\Laravel\Shared\Tokens\IdTokens;
use Lock\Laravel\Shared\Tokens\LogoutTokens;
use Lock\Laravel\Tokens\Validation\IdTokenValidator;
use Lock\Laravel\Tokens\Validation\JwksKeyResolver;
use Lock\Laravel\Tokens\Validation\LogoutTokenValidator;

class TokensServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->singleton(JwksKeyResolver::class);
        $this->app->singleton(IdTokenValidator::class);
        $this->app->singleton(LogoutTokenValidator::class);
        $this->app->singleton(ApiTokenBroker::class);
        $this->app->bind(IdTokens::class, IdTokenValidator::class);
        $this->app->bind(LogoutTokens::class, LogoutTokenValidator::class);
    }
}
