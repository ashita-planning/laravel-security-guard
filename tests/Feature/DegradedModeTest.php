<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Tests\Feature;

use Apkk\LaravelSecurityGuard\Data\AdminSubjectData;
use Apkk\LaravelSecurityGuard\Data\BlockReason;
use Apkk\LaravelSecurityGuard\Http\Middleware\GuardPublicRequests;
use Apkk\LaravelSecurityGuard\SecurityGuardServiceProvider;
use Apkk\LaravelSecurityGuard\Services\AdminIpAccessService;
use Apkk\LaravelSecurityGuard\Services\IpBlockService;
use Apkk\LaravelSecurityGuard\Services\PublicRateLimiter;
use Apkk\LaravelSecurityGuard\Tests\Fixtures\BrokenCacheStore;
use Apkk\LaravelSecurityGuard\Tests\TestCase;
use Illuminate\Cache\Repository as CacheRepository;
use Illuminate\Contracts\Http\Kernel;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Route;

/**
 * The failure matrix: which way each module falls when its infrastructure is
 * unavailable. Public surfaces fail open so an outage cannot lock out every
 * visitor; the administrative surface fails closed.
 */
class DegradedModeTest extends TestCase
{
    use RefreshDatabase;

    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);

        $app->make(Kernel::class)->prependMiddleware(GuardPublicRequests::class);
    }

    protected function defineRoutes($router): void
    {
        Route::get('/', fn (): string => 'home');
    }

    private function breakTheCache(): void
    {
        $this->app->instance(
            SecurityGuardServiceProvider::CACHE,
            new CacheRepository(new BrokenCacheStore),
        );

        $this->app->forgetInstance(IpBlockService::class);
        $this->app->forgetInstance(PublicRateLimiter::class);
    }

    private function breakTheDatabase(): void
    {
        // Point the model at a table that does not exist.
        config()->set('security-guard.database.tables.blocked_ips', 'security_guard_missing_table');
    }

    public function test_a_broken_cache_falls_back_to_the_database_for_block_state(): void
    {
        $this->app->make(IpBlockService::class)->block(
            '203.0.113.10',
            BlockReason::KNOWN_ATTACK_PATH,
            'wordpress_probe',
        );

        $this->breakTheCache();

        // The cached answer is gone, but the stored block still holds.
        $this->fromIp('203.0.113.10')->get('/')->assertForbidden();
    }

    public function test_a_broken_cache_does_not_reject_ordinary_visitors(): void
    {
        $this->breakTheCache();

        $this->fromIp('203.0.113.99')->get('/')->assertOk();
    }

    public function test_a_broken_cache_leaves_the_rate_limiter_open(): void
    {
        config()->set('security-guard.public_rate_limit.enabled', true);
        config()->set('security-guard.public_rate_limit.requests_per_minute', 1);

        $this->breakTheCache();

        // A counter that cannot be read must not turn into a blanket refusal.
        $this->fromIp('203.0.113.98')->get('/')->assertOk();
        $this->fromIp('203.0.113.98')->get('/')->assertOk();
    }

    public function test_a_broken_database_lets_ordinary_requests_through(): void
    {
        $this->breakTheDatabase();

        $this->fromIp('203.0.113.97')->get('/')->assertOk();
    }

    public function test_a_known_attack_path_is_still_refused_when_the_block_cannot_be_stored(): void
    {
        $this->breakTheDatabase();

        // Failing closed here is the one exception: the request is an
        // unmistakable probe, so losing the audit row is not a reason to serve it.
        $this->fromIp('203.0.113.96')->get('/wp-admin')->assertForbidden();
    }

    public function test_the_admin_allowlist_fails_closed_when_its_table_is_unreachable(): void
    {
        config()->set('security-guard.admin_ip.enabled', true);
        config()->set('security-guard.database.tables.admin_allowed_ips', 'security_guard_missing_table');

        $decision = $this->app->make(AdminIpAccessService::class)
            ->check(new AdminSubjectData('admin', '1'), '203.0.113.10');

        $this->assertFalse($decision['allowed']);
        $this->assertSame(AdminIpAccessService::REASON_LOOKUP_FAILED, $decision['reason']);
    }

    public function test_releasing_still_succeeds_while_the_cache_is_down(): void
    {
        $service = $this->app->make(IpBlockService::class);
        $service->block('203.0.113.95', BlockReason::RATE_LIMIT);

        $this->breakTheCache();

        $this->assertTrue($this->app->make(IpBlockService::class)->release('203.0.113.95'));
        $this->assertDatabaseMissing('security_guard_blocked_ips', [
            'ip_address' => '203.0.113.95',
            'released_at' => null,
        ]);
    }
}
