# Contributing

Use PHP 8.5, Composer and the SQLite extension. Run `composer install` from this
package directory. The test suite runs through Orchestra Testbench with an isolated
workbench and fake provider HTTP responses.

Run `composer check` before submitting changes. It checks Pint formatting, PHPStan
level 6 for source and tests, Rector rules, and parallel Pest tests. `composer fix`
applies Rector and Pint changes; review the result before committing.

Add behavior tests under `tests/Feature/<Domain>`. Architecture tests live under
`tests/Unit` and run without Testbench. Keep the client independent of the server
package and application-specific user models. Test helpers shipped to consumers
belong in `src/Support/Testing`; the workbench model is only a local test fixture.

Use Conventional Commits (`feat:`, `fix:`, `docs:`, `refactor:`) for Release Please.
Do not commit `vendor/`, generated caches or `composer.lock`. GitHub Actions tests
both lowest and latest installable dependencies for PHP 8.5 and Testbench 11.

## Domain structure

| Directory | Responsibility |
| --- | --- |
| `Authentication` | Local user resolution, guard access and local login/logout behavior |
| `Discovery` | Provider discovery and cached JWKS retrieval |
| `Tokens` | Signature/claim validation, API token exchange and refresh |
| `Sessions` | Back-channel session tracking, revocation and enforcement middleware |
| `Protocol` | Authorization flow, HTTP controllers and provider redirects |
| `Shared` | Cross-domain contracts, value objects, exceptions and route names |
| `Support` | Consumer facade and testing helpers |

Each functional domain registers its bindings in its own service provider.
`OidcClientServiceProvider` composes those providers and owns config, routes and
publishing, following the server package's structure.

Domain code may depend only on its own domain and `Shared`. `Shared` must not
reference domain implementations. `Support` integrates the domains for consuming
applications and tests; runtime domains must not depend on it. Keep new cross-domain
contracts small and bind them to implementations in the owning domain's provider.
`tests/Unit/ArchitectureTest.php` enforces these boundaries and the list of domains.

The singleton implementations are registered separately from their contract bindings
so the facade, protocol handlers and test helpers share the same resolver and cached
provider state. Use the contracts under `Shared` when replacing behavior in an app.
