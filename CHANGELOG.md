# Changelog

## [0.2.0](https://github.com/use-lock/client-laravel/compare/0.1.0...0.2.0) (2026-09-16)


### ⚠ BREAKING CHANGES

* errors throw Lock\Client\Auth\OidcException. ApiTokenBroker exposes userToken() and machineToken(), both returning a TokenSet, without extension parameters or per-call client credentials. The discovery_cache_ttl and leeway options are gone, token_endpoint_auth_method is new, and only RS256 tokens are accepted. OidcClientFake drops withoutEndSessionEndpoint().

### Features

* build on use-lock/client-php ([736cb32](https://github.com/use-lock/client-laravel/commit/736cb32a89258c3cefbabcfe814c3ebde47a77c7))

## 0.1.0 (2026-09-13)


### Initial release

* initial commit ([3bc698b](https://github.com/use-lock/client-laravel/commit/3bc698b1d83e468df63ff032484f5296377ed9e8))
