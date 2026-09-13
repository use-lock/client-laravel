<?php

declare(strict_types=1);

namespace Lock\Laravel\Support\Testing;

use GuzzleHttp\Promise\PromiseInterface;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Illuminate\Testing\TestResponse;
use Lock\Laravel\Discovery\OidcDiscovery;
use Lock\Laravel\Protocol\AuthorizationFlow;
use Lock\Laravel\Sessions\BackchannelLogoutStore;
use Lock\Laravel\Shared\Routing\Handler;
use Lock\Laravel\Support\Facades\OidcClient;
use Lock\Laravel\Tokens\Validation\IdTokenValidator;
use Lock\Laravel\Tokens\Validation\JwksKeyResolver;
use Lock\Laravel\Tokens\Validation\LogoutTokenValidator;
use PHPUnit\Framework\Assert;
use Symfony\Component\HttpFoundation\Response;

/**
 * A fake OpenID provider for client tests. Install with
 * {@see OidcClient::fake()}: it stubs the
 * issuer's discovery, JWKS, token, and end-session endpoints against a test RSA
 * keypair and returns this object for token minting, callback seeding, and flow
 * assertions.
 */
class OidcClientFake
{
    public const string STATE = 'oidc-fake-state';

    public const string NONCE = 'oidc-fake-nonce';

    public const string VERIFIER = 'oidc-fake-verifier';

    public const string SID = 'oidc-fake-sid';

    public const string KID = 'oidc-fake-key';

    private readonly string $issuer;

    private string $clientId;

    private string $subject = 'oidc-fake-subject';

    private bool $endSessionEnabled = true;

    private ?int $failTokenStatus = null;

    private ?FakeOidcProvider $rogueProvider = null;

    /** @var array<string, mixed> */
    private array $defaultClaims = [];

    public function __construct(private readonly FakeOidcProvider $provider)
    {
        $this->issuer = rtrim((string) (config('oidc-client.issuer') ?: 'https://oidc.test'), '/');
        $this->clientId = (string) (config('oidc-client.client_id') ?: 'oidc-client-test');
    }

    public static function start(): self
    {
        $fake = new self(new FakeOidcProvider);
        $fake->reset();
        $fake->installStub();

        // The stub returns null for URLs it does not own, which would send
        // the request over the real network. Fail loudly instead; tests that
        // need other endpoints can Http::fake() them, and real network access
        // can be restored with Http::allowStrayRequests().
        Http::preventStrayRequests();

        app()->instance(self::class, $fake);

        return $fake;
    }

    public function clientId(string $clientId): static
    {
        $this->clientId = $clientId;
        config()->set('oidc-client.client_id', $clientId);

        return $this;
    }

    public function withoutEndSessionEndpoint(): static
    {
        $this->endSessionEnabled = false;

        return $this;
    }

    public function failTokenExchange(int $status = 400): static
    {
        $this->failTokenStatus = $status;

        return $this;
    }

    public function withInvalidSignature(): static
    {
        $this->rogueProvider = new FakeOidcProvider;

        return $this;
    }

    /**
     * Seed values for the callback session triplet. Pass the result to the
     * test's withSession(): the facade fake cannot inject request session state.
     *
     * @param  array<string, string>  $overrides
     * @return array<string, string>
     */
    public function callbackContext(array $overrides = []): array
    {
        return array_merge([
            'oidc-client.state' => self::STATE,
            'oidc-client.nonce' => self::NONCE,
            'oidc-client.code_verifier' => self::VERIFIER,
        ], $overrides);
    }

    /**
     * @param  array<string, string>  $query
     */
    public function callbackUrl(array $query = []): string
    {
        return route(Handler::Callback->value, array_merge([
            'code' => 'oidc-fake-code',
            'state' => self::STATE,
        ], $query));
    }

    /**
     * Point the token endpoint's id_token at $user and return the callback URL.
     * Seed the session with callbackContext() in the same chain. Each call
     * replaces the prior claims rather than accumulating them.
     *
     * @param  array<string, mixed>  $claims
     */
    public function loginAs(Authenticatable $user, array $claims = []): string
    {
        $this->subject = (string) $user->getAuthIdentifier();
        $this->defaultClaims = $claims;

        return $this->callbackUrl();
    }

    /**
     * @param  array<string, mixed>  $claims
     */
    public function idToken(array $claims = []): string
    {
        $signer = $this->rogueProvider ?? $this->provider;

        return $signer->idToken(array_merge($this->defaultIdTokenClaims(), $this->defaultClaims, $claims), self::KID);
    }

    /**
     * @param  array<string, mixed>  $claims
     */
    public function logoutToken(array $claims = []): string
    {
        return $this->provider->logoutToken(array_merge([
            'iss' => $this->issuer,
            'aud' => $this->clientId,
            'sub' => $this->subject,
            'sid' => self::SID,
            'iat' => Carbon::now()->getTimestamp(),
            'exp' => Carbon::now()->getTimestamp() + 300,
            'jti' => 'oidc-fake-jti',
            'events' => ['http://schemas.openid.net/event/backchannel-logout' => (object) []],
        ], $claims), self::KID);
    }

    /**
     * @return array<string, mixed>
     */
    private function defaultIdTokenClaims(): array
    {
        return [
            'iss' => $this->issuer,
            'aud' => $this->clientId,
            'sub' => $this->subject,
            'nonce' => self::NONCE,
            'iat' => Carbon::now()->getTimestamp(),
            'nbf' => Carbon::now()->getTimestamp(),
            'exp' => Carbon::now()->getTimestamp() + 300,
        ];
    }

    private function reset(): void
    {
        config()->set('oidc-client.issuer', $this->issuer);
        config()->set('oidc-client.client_id', $this->clientId);

        foreach ([OidcDiscovery::class, JwksKeyResolver::class, AuthorizationFlow::class, IdTokenValidator::class, LogoutTokenValidator::class] as $abstract) {
            app()->forgetInstance($abstract);
        }

        Cache::forget('oidc-client:discovery:'.$this->issuer);
        Cache::forget('oidc-client:jwks:'.$this->issuer);
    }

    /**
     * Register a single closure stub that reads live state from $this at
     * request time. Unlike Http::fake([...]) with a fixed URL map, this
     * survives customizers called after a request has already resolved the
     * HTTP factory (AuthorizationFlow and OidcDiscovery constructor-inject it),
     * so a customizer applied between two requests in the same test still
     * takes effect on the second request.
     */
    private function installStub(): void
    {
        Http::fake(fn (Request $request): ?PromiseInterface => $this->respondTo($request));
    }

    private function respondTo(Request $request): ?PromiseInterface
    {
        return match ($request->url()) {
            $this->issuer.'/.well-known/openid-configuration' => Http::response($this->discoveryDocument()),
            $this->issuer.'/.well-known/jwks.json' => Http::response(['keys' => $this->provider->rsaJwks(self::KID)]),
            $this->issuer.'/oauth/token' => $this->tokenResponse(),
            $this->issuer.'/oauth/logout' => Http::response('', 200),
            default => null,
        };
    }

    /**
     * @return array<string, mixed>
     */
    private function discoveryDocument(): array
    {
        $discovery = [
            'issuer' => $this->issuer,
            'authorization_endpoint' => $this->issuer.'/oauth/authorize',
            'token_endpoint' => $this->issuer.'/oauth/token',
            'jwks_uri' => $this->issuer.'/.well-known/jwks.json',
        ];

        if ($this->endSessionEnabled) {
            $discovery['end_session_endpoint'] = $this->issuer.'/oauth/logout';
        }

        return $discovery;
    }

    private function tokenResponse(): PromiseInterface
    {
        if ($this->failTokenStatus !== null) {
            return Http::response([], $this->failTokenStatus);
        }

        return Http::response([
            'access_token' => 'oidc-fake-access-token',
            'refresh_token' => 'oidc-fake-refresh-token',
            'id_token' => $this->idToken(),
            'token_type' => 'Bearer',
            'expires_in' => 3600,
        ]);
    }

    /**
     * @param  TestResponse<Response>  $response
     */
    public function assertRedirectedToProvider(TestResponse $response): static
    {
        $location = (string) $response->headers->get('Location');

        Assert::assertStringStartsWith($this->issuer.'/oauth/authorize', $location);
        Assert::assertStringContainsString('response_type=code', $location);
        Assert::assertStringContainsString('code_challenge_method=S256', $location);
        Assert::assertStringContainsString('client_id='.rawurlencode($this->clientId), $location);

        return $this;
    }

    public function assertLoggedIn(Authenticatable $user): static
    {
        $guard = Auth::guard((string) config('oidc-client.login_guard', 'web'));

        Assert::assertTrue($guard->check(), 'The login guard is not authenticated.');
        Assert::assertSame((string) $user->getAuthIdentifier(), (string) $guard->id());

        return $this;
    }

    public function assertBackchannelLogoutProcessed(string $sid): static
    {
        Assert::assertTrue(
            app(BackchannelLogoutStore::class)->isRevoked($sid),
            "No back-channel logout was processed for sid [{$sid}].",
        );

        return $this;
    }

    public function assertCodeExchanged(): static
    {
        Http::assertSent(fn (Request $request): bool => $request->url() === $this->issuer.'/oauth/token');

        return $this;
    }

    public function assertCodeNotExchanged(): static
    {
        Http::assertNotSent(fn (Request $request): bool => $request->url() === $this->issuer.'/oauth/token');

        return $this;
    }
}
