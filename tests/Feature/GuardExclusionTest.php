<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Tests\Feature;

use Apkk\LaravelSecurityGuard\Data\BlockReason;
use Apkk\LaravelSecurityGuard\Http\Middleware\GuardPublicRequests;
use Apkk\LaravelSecurityGuard\Services\IpBlockService;
use Apkk\LaravelSecurityGuard\Tests\TestCase;
use Illuminate\Contracts\Http\Kernel;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Route;

/**
 * The exclusion lists are per-module.
 *
 * Excusing a webhook from request counting used to switch off the whole guard
 * for that path: a permanently blocked address was served normally there, and
 * attack path detection stopped running. Rate limiting is a capacity control;
 * blocking is a security control, and they must be waivable independently.
 */
class GuardExclusionTest extends TestCase
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
        Route::post('/api/payment/webhook', fn (): string => 'webhook accepted');
    }

    private function excludeWebhookFromRateLimiting(): void
    {
        config()->set('security-guard.public_rate_limit.enabled', true);
        config()->set('security-guard.public_rate_limit.requests_per_minute', 2);
        config()->set('security-guard.public_rate_limit.excluded_paths', ['api/*']);
    }

    public function test_a_rate_limit_exclusion_does_not_lift_an_existing_block(): void
    {
        $this->excludeWebhookFromRateLimiting();

        $this->app->make(IpBlockService::class)
            ->block('203.0.113.10', BlockReason::KNOWN_ATTACK_PATH, 'wordpress_probe');

        // The address is blocked, so it stays blocked on the excluded path too.
        $this->fromIp('203.0.113.10')->post('/api/payment/webhook')->assertForbidden();
    }

    public function test_a_rate_limit_exclusion_does_not_disable_attack_path_detection(): void
    {
        $this->excludeWebhookFromRateLimiting();

        $this->fromIp('203.0.113.11')->get('/api/../.env')->assertForbidden();

        $this->assertDatabaseHas('security_guard_blocked_ips', [
            'ip_address' => '203.0.113.11',
            'matched_pattern' => 'secret_file_probe',
        ]);
    }

    public function test_a_rate_limit_exclusion_still_exempts_the_path_from_counting(): void
    {
        $this->excludeWebhookFromRateLimiting();

        for ($i = 0; $i < 6; $i++) {
            $this->fromIp('203.0.113.12')->post('/api/payment/webhook')->assertOk();
        }

        $this->assertDatabaseCount('security_guard_blocked_ips', 0);
    }

    public function test_the_permanent_block_exclusion_waives_blocking_for_that_path_only(): void
    {
        config()->set('security-guard.permanent_block.excluded_paths', ['api/*']);

        $this->app->make(IpBlockService::class)
            ->block('203.0.113.13', BlockReason::KNOWN_ATTACK_PATH, 'wordpress_probe');

        $this->fromIp('203.0.113.13')->post('/api/payment/webhook')->assertOk();
        // Everywhere else the block still applies.
        $this->fromIp('203.0.113.13')->get('/')->assertForbidden();
    }

    public function test_blocking_is_enforced_everywhere_by_default(): void
    {
        $this->app->make(IpBlockService::class)
            ->block('203.0.113.14', BlockReason::RATE_LIMIT);

        // The permanent block exclusion list ships empty on purpose.
        $this->fromIp('203.0.113.14')->post('/api/payment/webhook')->assertForbidden();
        $this->fromIp('203.0.113.14')->get('/')->assertForbidden();
    }
}
