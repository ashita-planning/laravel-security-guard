<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Tests\Feature;

use Apkk\LaravelSecurityGuard\Crawlers\CrawlerProvider;
use Apkk\LaravelSecurityGuard\Services\BlockResponseFactory;
use Apkk\LaravelSecurityGuard\Services\CrawlerRateLimiter;
use Apkk\LaravelSecurityGuard\Services\PublicRateLimiter;
use Apkk\LaravelSecurityGuard\Support\CacheKeyFactory;
use Apkk\LaravelSecurityGuard\Tests\TestCase;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Foundation\Testing\RefreshDatabase;

/**
 * The crawler budget, as a service. Middleware integration is the next stage.
 *
 * Two properties carry the whole design: the counter is nowhere near the
 * public one, and exceeding it never persists a block. A search crawler that
 * trips a permanent block keeps receiving 403s until a human releases it,
 * which costs crawling, index refresh and search presence — much worse than
 * the burst that caused it.
 */
class CrawlerRateLimitTest extends TestCase
{
    use RefreshDatabase;

    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);

        $app->make(Repository::class)->set([
            'security-guard.crawler_access.enabled' => true,
            'security-guard.crawler_access.rate_limit.requests_per_minute' => 3,
        ]);
    }

    private function limiter(): CrawlerRateLimiter
    {
        return $this->app->make(CrawlerRateLimiter::class);
    }

    // -----------------------------------------------------------------
    // Counting
    // -----------------------------------------------------------------

    public function test_it_allows_up_to_the_limit_then_rejects(): void
    {
        $limiter = $this->limiter();

        for ($i = 1; $i <= 3; $i++) {
            $result = $limiter->consume(CrawlerProvider::GOOGLE, '66.249.64.5');
            $this->assertTrue($result['allowed'], "Request {$i} should be allowed.");
            $this->assertSame(0, $result['retry_after']);
        }

        $result = $limiter->consume(CrawlerProvider::GOOGLE, '66.249.64.5');

        $this->assertFalse($result['allowed']);
        $this->assertSame(4, $result['attempts']);
    }

    public function test_a_rejection_always_carries_a_usable_retry_interval(): void
    {
        $limiter = $this->limiter();

        for ($i = 0; $i < 4; $i++) {
            $result = $limiter->consume(CrawlerProvider::GOOGLE, '66.249.64.5');
        }

        // Telling a crawler to back off without saying for how long tells it
        // nothing it can act on.
        $this->assertFalse($result['allowed']);
        $this->assertGreaterThan(0, $result['retry_after']);
    }

    public function test_each_provider_gets_its_own_budget(): void
    {
        $limiter = $this->limiter();

        for ($i = 0; $i < 4; $i++) {
            $limiter->consume(CrawlerProvider::GOOGLE, '203.0.113.10');
        }

        $this->assertFalse($limiter->consume(CrawlerProvider::GOOGLE, '203.0.113.10')['allowed']);
        // Bingbot must not be throttled by Googlebot's traffic.
        $this->assertTrue($limiter->consume(CrawlerProvider::BING, '203.0.113.10')['allowed']);
    }

    public function test_each_address_gets_its_own_budget(): void
    {
        $limiter = $this->limiter();

        for ($i = 0; $i < 4; $i++) {
            $limiter->consume(CrawlerProvider::GOOGLE, '66.249.64.5');
        }

        $this->assertFalse($limiter->consume(CrawlerProvider::GOOGLE, '66.249.64.5')['allowed']);
        $this->assertTrue($limiter->consume(CrawlerProvider::GOOGLE, '66.249.64.6')['allowed']);
    }

    // -----------------------------------------------------------------
    // The counters never touch
    // -----------------------------------------------------------------

    public function test_the_crawler_counter_is_a_different_key_space(): void
    {
        $keys = $this->app->make(CacheKeyFactory::class);

        $this->assertNotSame(
            $keys->publicRequests('66.249.64.5'),
            $keys->crawlerRequests(CrawlerProvider::GOOGLE, '66.249.64.5'),
        );
        $this->assertNotSame(
            $keys->crawlerRequests(CrawlerProvider::GOOGLE, '66.249.64.5'),
            $keys->crawlerRequests(CrawlerProvider::BING, '66.249.64.5'),
        );
        // The raw address never appears in a key.
        $this->assertStringNotContainsString(
            '66.249.64.5',
            $keys->crawlerRequests(CrawlerProvider::GOOGLE, '66.249.64.5'),
        );
    }

    public function test_crawler_traffic_does_not_spend_the_public_budget(): void
    {
        config()->set('security-guard.public_rate_limit.enabled', true);
        config()->set('security-guard.public_rate_limit.requests_per_minute', 2);

        $crawler = $this->limiter();
        $public = $this->app->make(PublicRateLimiter::class);

        // A crawler hammering one address must not push the humans behind
        // that address over the public limit.
        for ($i = 0; $i < 10; $i++) {
            $crawler->consume(CrawlerProvider::GOOGLE, '203.0.113.10');
        }

        $this->assertSame(0, $public->status('203.0.113.10')['attempts']);
        $this->assertTrue($public->consume('203.0.113.10')['allowed']);
    }

    public function test_public_traffic_does_not_spend_the_crawler_budget(): void
    {
        config()->set('security-guard.public_rate_limit.enabled', true);
        config()->set('security-guard.public_rate_limit.requests_per_minute', 2);

        $public = $this->app->make(PublicRateLimiter::class);

        for ($i = 0; $i < 5; $i++) {
            $public->consume('203.0.113.10');
        }

        $this->assertSame(0, $this->limiter()->status(CrawlerProvider::GOOGLE, '203.0.113.10')['attempts']);
        $this->assertTrue($this->limiter()->consume(CrawlerProvider::GOOGLE, '203.0.113.10')['allowed']);
    }

    // -----------------------------------------------------------------
    // Exceeding the limit never persists a block
    // -----------------------------------------------------------------

    public function test_exceeding_the_crawler_limit_stores_no_block(): void
    {
        $limiter = $this->limiter();

        for ($i = 0; $i < 50; $i++) {
            $limiter->consume(CrawlerProvider::GOOGLE, '66.249.64.5');
        }

        // The whole point: a crawler burst must not leave a row that keeps
        // returning 403 until a human notices.
        $this->assertDatabaseCount('security_guard_blocked_ips', 0);
    }

    public function test_permanent_block_is_not_an_available_action(): void
    {
        config()->set('security-guard.crawler_access.rate_limit.action', 'permanent_block');

        $limiter = $this->limiter();

        // Downgraded rather than obeyed — and reported, so the correction is
        // visible rather than hidden.
        $this->assertSame(CrawlerRateLimiter::ACTION_REJECT_ONLY, $limiter->action());
        $this->assertTrue($limiter->actionWasDowngraded());

        for ($i = 0; $i < 20; $i++) {
            $limiter->consume(CrawlerProvider::GOOGLE, '66.249.64.5');
        }

        $this->assertDatabaseCount('security_guard_blocked_ips', 0);
    }

    public function test_an_unrecognised_action_falls_back_to_rejecting(): void
    {
        config()->set('security-guard.crawler_access.rate_limit.action', 'temporary_block');

        $this->assertSame(CrawlerRateLimiter::ACTION_REJECT_ONLY, $this->limiter()->action());
        $this->assertTrue($this->limiter()->actionWasDowngraded());
    }

    public function test_the_two_supported_actions_are_honoured(): void
    {
        config()->set('security-guard.crawler_access.rate_limit.action', 'service_unavailable');
        $this->assertSame(CrawlerRateLimiter::ACTION_SERVICE_UNAVAILABLE, $this->limiter()->action());
        $this->assertFalse($this->limiter()->actionWasDowngraded());

        config()->set('security-guard.crawler_access.rate_limit.action', 'reject_only');
        $this->assertSame(CrawlerRateLimiter::ACTION_REJECT_ONLY, $this->limiter()->action());
        $this->assertFalse($this->limiter()->actionWasDowngraded());
    }

    // -----------------------------------------------------------------
    // Responses
    // -----------------------------------------------------------------

    public function test_the_reject_response_is_429_with_a_retry_interval(): void
    {
        $response = $this->app->make(BlockResponseFactory::class)->tooManyRequests(42);

        $this->assertSame(429, $response->getStatusCode());
        $this->assertSame('42', $response->headers->get('Retry-After'));
    }

    public function test_the_overload_response_is_503_and_always_names_an_interval(): void
    {
        $factory = $this->app->make(BlockResponseFactory::class);

        $response = $factory->serviceUnavailable(30);
        $this->assertSame(503, $response->getStatusCode());
        $this->assertSame('30', $response->headers->get('Retry-After'));

        // Even a zero or negative interval yields something actionable.
        $this->assertSame('1', $factory->serviceUnavailable(0)->headers->get('Retry-After'));
    }

    // -----------------------------------------------------------------
    // Configuration
    // -----------------------------------------------------------------

    public function test_it_is_disabled_by_default(): void
    {
        config()->set('security-guard.crawler_access.enabled', false);
        $this->assertFalse($this->limiter()->enabled());

        config()->set('security-guard.crawler_access.enabled', true);
        $this->assertTrue($this->limiter()->enabled());

        // The package-wide switch still wins.
        config()->set('security-guard.enabled', false);
        $this->assertFalse($this->limiter()->enabled());
    }

    public function test_the_shipped_default_limit_is_generous_and_non_blocking(): void
    {
        $defaults = require __DIR__.'/../../config/security-guard.php';
        $rateLimit = $defaults['crawler_access']['rate_limit'];

        $this->assertSame(300, $rateLimit['requests_per_minute']);
        $this->assertSame('reject_only', $rateLimit['action']);
        $this->assertFalse($defaults['crawler_access']['enabled']);
    }

    public function test_a_nonsensical_limit_is_normalised_upward(): void
    {
        config()->set('security-guard.crawler_access.rate_limit.requests_per_minute', 0);

        $this->assertSame(1, $this->limiter()->limit());
    }

    public function test_a_provider_can_be_switched_off(): void
    {
        config()->set('security-guard.crawler_access.verified_crawlers.bing', false);

        $this->assertTrue($this->limiter()->providerEnabled(CrawlerProvider::GOOGLE));
        $this->assertFalse($this->limiter()->providerEnabled(CrawlerProvider::BING));
    }

    public function test_a_counter_can_be_cleared(): void
    {
        $limiter = $this->limiter();

        for ($i = 0; $i < 4; $i++) {
            $limiter->consume(CrawlerProvider::GOOGLE, '66.249.64.5');
        }
        $this->assertFalse($limiter->consume(CrawlerProvider::GOOGLE, '66.249.64.5')['allowed']);

        $limiter->forget(CrawlerProvider::GOOGLE, '66.249.64.5');

        $this->assertTrue($limiter->consume(CrawlerProvider::GOOGLE, '66.249.64.5')['allowed']);
    }
}
