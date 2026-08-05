<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Tests\Feature;

use Apkk\LaravelSecurityGuard\Contracts\CrawlerRangeFetcherContract;
use Apkk\LaravelSecurityGuard\Crawlers\CrawlerProvider;
use Apkk\LaravelSecurityGuard\Crawlers\CrawlerRangeStore;
use Apkk\LaravelSecurityGuard\Crawlers\CrawlerVerifierRegistry;
use Apkk\LaravelSecurityGuard\Data\BlockReason;
use Apkk\LaravelSecurityGuard\Data\CrawlerVerificationResult;
use Apkk\LaravelSecurityGuard\Http\Middleware\GuardPublicRequests;
use Apkk\LaravelSecurityGuard\SecurityGuardServiceProvider;
use Apkk\LaravelSecurityGuard\Services\CrawlerRateLimiter;
use Apkk\LaravelSecurityGuard\Services\IpBlockService;
use Apkk\LaravelSecurityGuard\Services\PublicRateLimiter;
use Apkk\LaravelSecurityGuard\Support\CacheKeyFactory;
use Apkk\LaravelSecurityGuard\Support\FailureLogger;
use Apkk\LaravelSecurityGuard\Tests\Fixtures\FakeCrawlerRangeFetcher;
use Apkk\LaravelSecurityGuard\Tests\Fixtures\SpyCrawlerVerifier;
use Apkk\LaravelSecurityGuard\Tests\TestCase;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Http\Kernel;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Route;
use RuntimeException;

/**
 * The crawler policy wired into the public request gate.
 *
 * The one rule everything below defends: verification swaps the rate limit
 * and nothing else. A verified crawler keeps every defence; an unverified
 * claimant loses nothing but the crawler budget; and no failure inside the
 * crawler subsystem may either widen access for impostors or permanently
 * block a genuine crawler.
 */
class CrawlerGuardIntegrationTest extends TestCase
{
    use RefreshDatabase;

    private const GOOGLEBOT_UA = 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)';

    private const BINGBOT_UA = 'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)';

    private const BROWSER_UA = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/126.0.0.0';

    /** Inside the seeded google range 66.249.64.0/27. */
    private const GOOGLE_IP = '66.249.64.5';

    /** A different address inside the same google range. */
    private const GOOGLE_IP_2 = '66.249.64.20';

    /** Inside the seeded bing range 157.55.39.0/24. */
    private const BING_IP = '157.55.39.7';

    /** Outside every seeded range. */
    private const OUTSIDE_IP = '203.0.113.10';

    private FakeCrawlerRangeFetcher $fetcher;

    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);

        $app->make(Kernel::class)->prependMiddleware(GuardPublicRequests::class);

        $app->make(Repository::class)->set([
            'security-guard.crawler_access.enabled' => true,
            'security-guard.crawler_access.rate_limit.requests_per_minute' => 2,
        ]);
    }

    protected function setUp(): void
    {
        parent::setUp();

        // The fake holds no responses, so any fetch attempted during request
        // handling throws — and fetchedUrls() records the attempt either way.
        $this->fetcher = new FakeCrawlerRangeFetcher;
        $this->app->instance(CrawlerRangeFetcherContract::class, $this->fetcher);
    }

    protected function tearDown(): void
    {
        Carbon::setTestNow();

        parent::tearDown();
    }

    protected function defineRoutes($router): void
    {
        Route::get('/', fn (): string => 'home');
        Route::post('/api/payment/webhook', fn (): string => 'webhook accepted');
    }

    /**
     * Store validated range data directly, as the refresh command would.
     *
     * @param  array<int, string>  $v4
     * @param  array<int, string>  $v6
     */
    private function seedRanges(string $provider, array $v4, array $v6 = []): void
    {
        $this->app->make(CrawlerRangeStore::class)->store($provider, [
            'creation_time' => '2026-08-01T00:00:00Z',
            'v4' => $v4,
            'v6' => $v6,
        ], "https://ranges.example.test/{$provider}.json", sha1($provider.serialize([$v4, $v6])));
    }

    private function seedBothProviders(): void
    {
        $this->seedRanges(CrawlerProvider::GOOGLE, ['66.249.64.0/27'], ['2001:4860:4801:10::/64']);
        $this->seedRanges(CrawlerProvider::BING, ['157.55.39.0/24']);
    }

    private function crawlerAttempts(string $provider, string $ipAddress): int
    {
        return $this->app->make(CrawlerRateLimiter::class)->status($provider, $ipAddress)['attempts'];
    }

    private function publicAttempts(string $ipAddress): int
    {
        return $this->app->make(PublicRateLimiter::class)->status($ipAddress)['attempts'];
    }

    // -----------------------------------------------------------------
    // Backwards compatibility: crawler_access off means v0.2.0 behaviour
    // -----------------------------------------------------------------

    public function test_the_verifier_is_never_consulted_while_crawler_access_is_off(): void
    {
        config()->set('security-guard.crawler_access.enabled', false);

        $spy = new SpyCrawlerVerifier;
        $this->app->make(CrawlerVerifierRegistry::class)->register($spy);

        $this->fromIp(self::GOOGLE_IP)->get('/', ['User-Agent' => self::GOOGLEBOT_UA])->assertOk();

        $this->assertSame(0, $spy->claimCalls, 'Classification must not run at all while the module is off.');
        $this->assertSame(0, $spy->ownsCalls);
    }

    public function test_the_public_rate_limit_behaves_as_before_while_crawler_access_is_off(): void
    {
        config()->set('security-guard.crawler_access.enabled', false);
        config()->set('security-guard.public_rate_limit.enabled', true);
        config()->set('security-guard.public_rate_limit.requests_per_minute', 2);

        // A Googlebot UA earns nothing: same counter, same default
        // permanent_block on the third request, exactly as in v0.2.0.
        $this->fromIp(self::GOOGLE_IP)->get('/', ['User-Agent' => self::GOOGLEBOT_UA])->assertOk();
        $this->fromIp(self::GOOGLE_IP)->get('/', ['User-Agent' => self::GOOGLEBOT_UA])->assertOk();
        $this->fromIp(self::GOOGLE_IP)->get('/', ['User-Agent' => self::GOOGLEBOT_UA])->assertForbidden();

        $this->assertDatabaseHas('security_guard_blocked_ips', [
            'ip_address' => self::GOOGLE_IP,
            'reason_code' => BlockReason::RATE_LIMIT,
        ]);
    }

    public function test_an_ignored_address_still_passes_early(): void
    {
        $this->seedBothProviders();
        config()->set('security-guard.permanent_block.ignored_ips', [self::GOOGLE_IP]);
        config()->set('security-guard.public_rate_limit.enabled', true);
        config()->set('security-guard.public_rate_limit.requests_per_minute', 1);

        for ($i = 0; $i < 4; $i++) {
            $this->fromIp(self::GOOGLE_IP)->get('/', ['User-Agent' => self::GOOGLEBOT_UA])->assertOk();
        }

        // The ignore list answers before classification, so neither budget
        // was ever touched.
        $this->assertSame(0, $this->crawlerAttempts(CrawlerProvider::GOOGLE, self::GOOGLE_IP));
        $this->assertSame(0, $this->publicAttempts(self::GOOGLE_IP));
    }

    public function test_an_existing_block_answers_before_crawler_classification(): void
    {
        $this->seedBothProviders();

        $this->app->make(IpBlockService::class)
            ->block(self::GOOGLE_IP, BlockReason::KNOWN_ATTACK_PATH, 'wordpress_probe');

        $this->fromIp(self::GOOGLE_IP)->get('/', ['User-Agent' => self::GOOGLEBOT_UA])->assertForbidden();

        // Verification is not an appeal process for blocked addresses.
        $this->assertSame(0, $this->crawlerAttempts(CrawlerProvider::GOOGLE, self::GOOGLE_IP));
    }

    public function test_an_attack_path_from_a_verified_crawler_address_is_still_blocked(): void
    {
        $this->seedBothProviders();

        $this->fromIp(self::GOOGLE_IP)->get('/wp-admin', ['User-Agent' => self::GOOGLEBOT_UA])->assertForbidden();

        $this->assertDatabaseHas('security_guard_blocked_ips', [
            'ip_address' => self::GOOGLE_IP,
            'reason_code' => BlockReason::KNOWN_ATTACK_PATH,
            'matched_pattern' => 'wordpress_probe',
        ]);
        $this->assertSame(0, $this->crawlerAttempts(CrawlerProvider::GOOGLE, self::GOOGLE_IP));
    }

    // -----------------------------------------------------------------
    // Verified crawlers
    // -----------------------------------------------------------------

    public function test_a_verified_crawler_reaches_the_application_within_its_budget(): void
    {
        $this->seedBothProviders();

        $this->fromIp(self::GOOGLE_IP)->get('/', ['User-Agent' => self::GOOGLEBOT_UA])->assertOk()->assertSee('home');
        $this->fromIp(self::GOOGLE_IP)->get('/', ['User-Agent' => self::GOOGLEBOT_UA])->assertOk();

        $this->assertSame(2, $this->crawlerAttempts(CrawlerProvider::GOOGLE, self::GOOGLE_IP));
    }

    public function test_a_verified_crawler_does_not_spend_the_public_budget(): void
    {
        $this->seedBothProviders();
        config()->set('security-guard.public_rate_limit.enabled', true);
        config()->set('security-guard.public_rate_limit.requests_per_minute', 1);

        $this->fromIp(self::GOOGLE_IP)->get('/', ['User-Agent' => self::GOOGLEBOT_UA])->assertOk();
        $this->fromIp(self::GOOGLE_IP)->get('/', ['User-Agent' => self::GOOGLEBOT_UA])->assertOk();

        $this->assertSame(0, $this->publicAttempts(self::GOOGLE_IP));
    }

    public function test_crawler_budgets_are_per_provider(): void
    {
        $this->seedBothProviders();

        $this->fromIp(self::GOOGLE_IP)->get('/', ['User-Agent' => self::GOOGLEBOT_UA])->assertOk();
        $this->fromIp(self::GOOGLE_IP)->get('/', ['User-Agent' => self::GOOGLEBOT_UA])->assertOk();
        $this->fromIp(self::GOOGLE_IP)->get('/', ['User-Agent' => self::GOOGLEBOT_UA])->assertStatus(429);

        // Googlebot exhausting its budget says nothing about Bingbot's.
        $this->fromIp(self::BING_IP)->get('/', ['User-Agent' => self::BINGBOT_UA])->assertOk();

        $this->assertSame(3, $this->crawlerAttempts(CrawlerProvider::GOOGLE, self::GOOGLE_IP));
        $this->assertSame(1, $this->crawlerAttempts(CrawlerProvider::BING, self::BING_IP));
    }

    public function test_crawler_budgets_are_per_address(): void
    {
        $this->seedBothProviders();

        $this->fromIp(self::GOOGLE_IP)->get('/', ['User-Agent' => self::GOOGLEBOT_UA])->assertOk();
        $this->fromIp(self::GOOGLE_IP)->get('/', ['User-Agent' => self::GOOGLEBOT_UA])->assertOk();
        $this->fromIp(self::GOOGLE_IP)->get('/', ['User-Agent' => self::GOOGLEBOT_UA])->assertStatus(429);

        $this->fromIp(self::GOOGLE_IP_2)->get('/', ['User-Agent' => self::GOOGLEBOT_UA])->assertOk();
    }

    public function test_exceeding_the_crawler_budget_answers_429_with_retry_after(): void
    {
        $this->seedBothProviders();

        $this->fromIp(self::GOOGLE_IP)->get('/', ['User-Agent' => self::GOOGLEBOT_UA])->assertOk();
        $this->fromIp(self::GOOGLE_IP)->get('/', ['User-Agent' => self::GOOGLEBOT_UA])->assertOk();

        $response = $this->fromIp(self::GOOGLE_IP)->get('/', ['User-Agent' => self::GOOGLEBOT_UA]);

        $response->assertStatus(429);
        $this->assertGreaterThanOrEqual(1, (int) $response->headers->get('Retry-After'));

        $this->assertDatabaseCount('security_guard_blocked_ips', 0);
    }

    public function test_the_service_unavailable_action_answers_503_with_retry_after(): void
    {
        $this->seedBothProviders();
        config()->set('security-guard.crawler_access.rate_limit.action', 'service_unavailable');

        $this->fromIp(self::GOOGLE_IP)->get('/', ['User-Agent' => self::GOOGLEBOT_UA])->assertOk();
        $this->fromIp(self::GOOGLE_IP)->get('/', ['User-Agent' => self::GOOGLEBOT_UA])->assertOk();

        $response = $this->fromIp(self::GOOGLE_IP)->get('/', ['User-Agent' => self::GOOGLEBOT_UA]);

        $response->assertStatus(503);
        $this->assertGreaterThanOrEqual(1, (int) $response->headers->get('Retry-After'));

        $this->assertDatabaseCount('security_guard_blocked_ips', 0);
    }

    public function test_no_block_row_is_ever_created_for_a_verified_crawler(): void
    {
        $this->seedBothProviders();

        // Well past the budget: every rejection is a rejection and nothing
        // more. No row, so nothing to release and nothing to notify about.
        for ($i = 0; $i < 6; $i++) {
            $this->fromIp(self::GOOGLE_IP)->get('/', ['User-Agent' => self::GOOGLEBOT_UA]);
        }

        $this->assertDatabaseCount('security_guard_blocked_ips', 0);
        $this->fromIp(self::GOOGLE_IP)->get('/', ['User-Agent' => self::GOOGLEBOT_UA])->assertStatus(429);
    }

    public function test_crawler_limits_work_with_the_public_rate_limit_disabled(): void
    {
        $this->seedBothProviders();
        config()->set('security-guard.public_rate_limit.enabled', false);

        $this->fromIp(self::GOOGLE_IP)->get('/', ['User-Agent' => self::GOOGLEBOT_UA])->assertOk();
        $this->fromIp(self::GOOGLE_IP)->get('/', ['User-Agent' => self::GOOGLEBOT_UA])->assertOk();
        $this->fromIp(self::GOOGLE_IP)->get('/', ['User-Agent' => self::GOOGLEBOT_UA])->assertStatus(429);
    }

    // -----------------------------------------------------------------
    // Unverified and unknown requests
    // -----------------------------------------------------------------

    public function test_an_unverified_claimant_falls_back_to_the_public_policy(): void
    {
        $this->seedBothProviders();
        config()->set('security-guard.public_rate_limit.enabled', true);
        config()->set('security-guard.public_rate_limit.requests_per_minute', 2);
        config()->set('security-guard.public_rate_limit.action', 'reject_only');

        // A Googlebot UA from outside the published ranges: normal policy,
        // no crawler budget, no punishment either.
        $this->fromIp(self::OUTSIDE_IP)->get('/', ['User-Agent' => self::GOOGLEBOT_UA])->assertOk();
        $this->fromIp(self::OUTSIDE_IP)->get('/', ['User-Agent' => self::GOOGLEBOT_UA])->assertOk();
        $this->fromIp(self::OUTSIDE_IP)->get('/', ['User-Agent' => self::GOOGLEBOT_UA])->assertStatus(429);

        $this->assertSame(0, $this->crawlerAttempts(CrawlerProvider::GOOGLE, self::OUTSIDE_IP));
        $this->assertSame(3, $this->publicAttempts(self::OUTSIDE_IP));
    }

    public function test_an_unknown_user_agent_falls_back_to_the_public_policy(): void
    {
        $this->seedBothProviders();
        config()->set('security-guard.public_rate_limit.enabled', true);
        config()->set('security-guard.public_rate_limit.requests_per_minute', 2);
        config()->set('security-guard.public_rate_limit.action', 'reject_only');

        $this->fromIp(self::OUTSIDE_IP)->get('/', ['User-Agent' => self::BROWSER_UA])->assertOk();
        $this->fromIp(self::OUTSIDE_IP)->get('/', ['User-Agent' => self::BROWSER_UA])->assertOk();
        $this->fromIp(self::OUTSIDE_IP)->get('/', ['User-Agent' => self::BROWSER_UA])->assertStatus(429);

        $this->assertSame(3, $this->publicAttempts(self::OUTSIDE_IP));
    }

    public function test_unverified_and_unknown_pass_through_when_the_public_limit_is_off(): void
    {
        $this->seedBothProviders();
        config()->set('security-guard.public_rate_limit.enabled', false);

        for ($i = 0; $i < 5; $i++) {
            $this->fromIp(self::OUTSIDE_IP)->get('/', ['User-Agent' => self::GOOGLEBOT_UA])->assertOk();
            $this->fromIp(self::OUTSIDE_IP)->get('/', ['User-Agent' => self::BROWSER_UA])->assertOk();
        }

        $this->assertSame(0, $this->crawlerAttempts(CrawlerProvider::GOOGLE, self::OUTSIDE_IP));
    }

    public function test_missing_range_data_denies_crawler_treatment(): void
    {
        // Nothing seeded: the UA claims Googlebot from a real Google address,
        // but with no data there is no verification and no crawler budget.
        config()->set('security-guard.public_rate_limit.enabled', true);
        config()->set('security-guard.public_rate_limit.requests_per_minute', 100);

        $this->fromIp(self::GOOGLE_IP)->get('/', ['User-Agent' => self::GOOGLEBOT_UA])->assertOk();

        $this->assertSame(0, $this->crawlerAttempts(CrawlerProvider::GOOGLE, self::GOOGLE_IP));
        $this->assertSame(1, $this->publicAttempts(self::GOOGLE_IP));
    }

    public function test_stale_range_data_denies_crawler_treatment(): void
    {
        Carbon::setTestNow('2026-08-04 12:00:00');
        $this->seedBothProviders();

        // A week and a second later the data is retained but trusts nobody.
        Carbon::setTestNow('2026-08-11 12:00:01');

        config()->set('security-guard.public_rate_limit.enabled', true);
        config()->set('security-guard.public_rate_limit.requests_per_minute', 100);

        $this->fromIp(self::GOOGLE_IP)->get('/', ['User-Agent' => self::GOOGLEBOT_UA])->assertOk();

        $this->assertSame(0, $this->crawlerAttempts(CrawlerProvider::GOOGLE, self::GOOGLE_IP));
        $this->assertSame(1, $this->publicAttempts(self::GOOGLE_IP));
    }

    // -----------------------------------------------------------------
    // Failure paths
    // -----------------------------------------------------------------

    public function test_a_throwing_verifier_degrades_to_the_public_policy(): void
    {
        config()->set('security-guard.public_rate_limit.enabled', true);
        config()->set('security-guard.public_rate_limit.requests_per_minute', 100);

        $this->app->make(CrawlerVerifierRegistry::class)->register(new SpyCrawlerVerifier(
            owns: static fn (): bool => throw new RuntimeException('range cache exploded'),
        ));

        $this->fromIp(self::OUTSIDE_IP)->get('/', ['User-Agent' => 'SpyBot/1.0'])->assertOk();

        $this->assertSame(1, $this->publicAttempts(self::OUTSIDE_IP));
    }

    public function test_a_throwing_registry_degrades_to_the_public_policy(): void
    {
        $this->seedBothProviders();
        config()->set('security-guard.public_rate_limit.enabled', true);
        config()->set('security-guard.public_rate_limit.requests_per_minute', 100);

        $this->app->instance(
            CrawlerVerifierRegistry::class,
            new class($this->app->make(FailureLogger::class)) extends CrawlerVerifierRegistry
            {
                public function classify(?string $userAgent, ?string $normalizedIp): CrawlerVerificationResult
                {
                    throw new RuntimeException('registry exploded');
                }
            },
        );

        // Even a genuine Googlebot address gets the normal policy while
        // classification is broken: failure never widens access.
        $this->fromIp(self::GOOGLE_IP)->get('/', ['User-Agent' => self::GOOGLEBOT_UA])->assertOk();

        $this->assertSame(0, $this->crawlerAttempts(CrawlerProvider::GOOGLE, self::GOOGLE_IP));
        $this->assertSame(1, $this->publicAttempts(self::GOOGLE_IP));
    }

    public function test_a_failing_crawler_limiter_fails_open(): void
    {
        $this->seedBothProviders();
        config()->set('security-guard.public_rate_limit.enabled', true);
        config()->set('security-guard.public_rate_limit.requests_per_minute', 1);

        $this->app->instance(CrawlerRateLimiter::class, new class($this->app->make(SecurityGuardServiceProvider::RATE_LIMITER), $this->app->make(CacheKeyFactory::class), $this->app->make(Repository::class)) extends CrawlerRateLimiter
        {
            public function consume(string $provider, string $normalizedIp): array
            {
                throw new RuntimeException('counter store down');
            }
        });

        // Four requests, public limit of one: every request passes, because a
        // verified crawler with a broken counter is let through — never handed
        // to the public limiter, whose default action would permanently block
        // the very crawler this module exists to protect.
        for ($i = 0; $i < 4; $i++) {
            $this->fromIp(self::GOOGLE_IP)->get('/', ['User-Agent' => self::GOOGLEBOT_UA])->assertOk();
        }

        $this->assertSame(0, $this->publicAttempts(self::GOOGLE_IP));
        $this->assertDatabaseCount('security_guard_blocked_ips', 0);
    }

    public function test_request_handling_never_reaches_the_network(): void
    {
        $this->seedBothProviders();
        config()->set('security-guard.public_rate_limit.enabled', true);

        // Verified, unverified and unknown paths alike. The fetcher is the
        // package's only outbound boundary — there is no DNS code path at
        // all — and it must stay untouched outside the refresh command.
        $this->fromIp(self::GOOGLE_IP)->get('/', ['User-Agent' => self::GOOGLEBOT_UA])->assertOk();
        $this->fromIp(self::OUTSIDE_IP)->get('/', ['User-Agent' => self::GOOGLEBOT_UA])->assertOk();
        $this->fromIp(self::OUTSIDE_IP)->get('/', ['User-Agent' => self::BROWSER_UA])->assertOk();

        $this->assertSame([], $this->fetcher->fetchedUrls());
    }

    public function test_a_malformed_user_agent_never_errors(): void
    {
        $this->seedBothProviders();
        config()->set('security-guard.public_rate_limit.enabled', true);

        $malformed = "Googlebot\x7f ".str_repeat('A', 5000).' "\'<>%00{}';

        $this->fromIp(self::OUTSIDE_IP)->get('/', ['User-Agent' => $malformed])->assertOk();
    }

    public function test_an_empty_user_agent_is_unknown(): void
    {
        $this->seedBothProviders();
        config()->set('security-guard.public_rate_limit.enabled', true);
        config()->set('security-guard.public_rate_limit.requests_per_minute', 100);

        $this->fromIp(self::GOOGLE_IP)->get('/', ['User-Agent' => ''])->assertOk();

        // No claim, no classification — a Google address without the UA is
        // just a visitor.
        $this->assertSame(0, $this->crawlerAttempts(CrawlerProvider::GOOGLE, self::GOOGLE_IP));
        $this->assertSame(1, $this->publicAttempts(self::GOOGLE_IP));
    }

    // -----------------------------------------------------------------
    // Excluded paths
    // -----------------------------------------------------------------

    public function test_excluded_paths_spend_neither_budget(): void
    {
        $this->seedBothProviders();
        config()->set('security-guard.public_rate_limit.enabled', true);
        config()->set('security-guard.public_rate_limit.requests_per_minute', 1);
        config()->set('security-guard.public_rate_limit.excluded_paths', ['api/*']);

        for ($i = 0; $i < 3; $i++) {
            $this->fromIp(self::GOOGLE_IP)->post('/api/payment/webhook', [], ['User-Agent' => self::GOOGLEBOT_UA])->assertOk();
            $this->fromIp(self::OUTSIDE_IP)->post('/api/payment/webhook', [], ['User-Agent' => self::BROWSER_UA])->assertOk();
        }

        $this->assertSame(0, $this->crawlerAttempts(CrawlerProvider::GOOGLE, self::GOOGLE_IP));
        $this->assertSame(0, $this->publicAttempts(self::GOOGLE_IP));
        $this->assertSame(0, $this->publicAttempts(self::OUTSIDE_IP));
    }

    public function test_an_excluded_path_still_serves_403_to_a_blocked_crawler_address(): void
    {
        $this->seedBothProviders();
        config()->set('security-guard.public_rate_limit.enabled', true);
        config()->set('security-guard.public_rate_limit.excluded_paths', ['api/*']);

        $this->app->make(IpBlockService::class)
            ->block(self::GOOGLE_IP, BlockReason::KNOWN_ATTACK_PATH, 'wordpress_probe');

        $this->fromIp(self::GOOGLE_IP)
            ->post('/api/payment/webhook', [], ['User-Agent' => self::GOOGLEBOT_UA])
            ->assertForbidden();
    }

    public function test_an_excluded_path_still_detects_attack_paths(): void
    {
        $this->seedBothProviders();
        config()->set('security-guard.public_rate_limit.enabled', true);
        config()->set('security-guard.public_rate_limit.excluded_paths', ['wp-admin']);

        $this->fromIp(self::GOOGLE_IP)->get('/wp-admin', ['User-Agent' => self::GOOGLEBOT_UA])->assertForbidden();

        $this->assertDatabaseHas('security_guard_blocked_ips', [
            'ip_address' => self::GOOGLE_IP,
            'matched_pattern' => 'wordpress_probe',
        ]);
    }
}
