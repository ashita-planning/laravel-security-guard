<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Tests\Feature;

use Apkk\LaravelSecurityGuard\Data\BlockReason;
use Apkk\LaravelSecurityGuard\Http\Middleware\GuardPublicRequests;
use Apkk\LaravelSecurityGuard\Models\BlockedIp;
use Apkk\LaravelSecurityGuard\Services\IpBlockService;
use Apkk\LaravelSecurityGuard\Tests\TestCase;
use Illuminate\Contracts\Http\Kernel;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Route;

class PublicGuardTest extends TestCase
{
    use RefreshDatabase;

    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);

        // Registered globally, exactly as the installation guide instructs, so
        // that probes for paths the application does not route are still seen.
        $app->make(Kernel::class)->prependMiddleware(GuardPublicRequests::class);
    }

    protected function defineRoutes($router): void
    {
        Route::get('/', fn (): string => 'home');
        Route::get('/products/{id}', fn (string $id): string => 'product');
        Route::get('/admin-panel/dashboard', fn (): string => 'admin');
    }

    public function test_a_normal_request_passes_through(): void
    {
        $this->fromIp('203.0.113.10')->get('/')->assertOk()->assertSee('home');

        $this->assertDatabaseCount('security_guard_blocked_ips', 0);
    }

    public function test_a_known_attack_path_is_blocked_on_the_first_request(): void
    {
        $this->fromIp('203.0.113.10')->get('/wp-admin')->assertForbidden();

        $this->assertDatabaseHas('security_guard_blocked_ips', [
            'ip_address' => '203.0.113.10',
            'reason_code' => BlockReason::KNOWN_ATTACK_PATH,
            'matched_pattern' => 'wordpress_probe',
        ]);
    }

    public function test_an_attack_path_that_has_no_route_is_still_blocked(): void
    {
        // The guard runs before routing, so a probe for a path the application
        // does not serve is blocked rather than merely 404'd.
        $this->fromIp('203.0.113.11')->get('/.env')->assertForbidden();

        $this->assertDatabaseHas('security_guard_blocked_ips', [
            'ip_address' => '203.0.113.11',
            'matched_pattern' => 'secret_file_probe',
        ]);
    }

    public function test_the_response_body_never_reflects_the_request(): void
    {
        $response = $this->fromIp('203.0.113.10')->get('/wp-admin/%3Cscript%3Ealert(1)%3C/script%3E');

        $response->assertForbidden();
        $this->assertSame('Forbidden', $response->getContent());
    }

    public function test_a_block_persists_across_later_requests(): void
    {
        $this->fromIp('203.0.113.10')->get('/wp-admin')->assertForbidden();

        $this->fromIp('203.0.113.10')->get('/')->assertForbidden();
        // Only the offending address is affected.
        $this->fromIp('203.0.113.99')->get('/')->assertOk();
    }

    public function test_an_ignored_address_is_never_blocked(): void
    {
        config()->set('security-guard.permanent_block.ignored_ips', ['203.0.113.10']);

        $this->fromIp('203.0.113.10')->get('/wp-admin')->assertNotFound();

        $this->assertDatabaseCount('security_guard_blocked_ips', 0);
    }

    public function test_an_ignored_ipv6_address_matches_in_any_notation(): void
    {
        config()->set('security-guard.permanent_block.ignored_ips', ['0:0:0:0:0:0:0:1']);

        $this->fromIp('::1')->get('/')->assertOk();
        $this->fromIp('::1')->get('/wp-admin')->assertNotFound();
    }

    public function test_an_ipv6_client_can_be_blocked_and_released(): void
    {
        $this->fromIp('2001:db8::1')->get('/wp-admin')->assertForbidden();

        $this->assertDatabaseHas('security_guard_blocked_ips', ['ip_address' => '2001:db8::1']);

        // Released using the long notation of the same address.
        $this->app->make(IpBlockService::class)->release('2001:0db8:0000:0000:0000:0000:0000:0001');

        $this->fromIp('2001:db8::1')->get('/')->assertOk();
    }

    public function test_an_excluded_path_is_neither_counted_nor_blocked(): void
    {
        config()->set('security-guard.public_rate_limit.enabled', true);
        config()->set('security-guard.public_rate_limit.requests_per_minute', 2);
        config()->set('security-guard.public_rate_limit.excluded_paths', ['admin-panel/*']);

        for ($i = 0; $i < 5; $i++) {
            $this->fromIp('203.0.113.10')->get('/admin-panel/dashboard')->assertOk();
        }

        $this->assertDatabaseCount('security_guard_blocked_ips', 0);
    }

    public function test_the_rate_limit_allows_the_configured_number_and_blocks_the_next_request(): void
    {
        config()->set('security-guard.public_rate_limit.enabled', true);
        config()->set('security-guard.public_rate_limit.requests_per_minute', 3);

        for ($i = 1; $i <= 3; $i++) {
            $this->fromIp('203.0.113.20')->get('/')->assertOk();
        }

        $this->fromIp('203.0.113.20')->get('/')->assertForbidden();

        $this->assertDatabaseHas('security_guard_blocked_ips', [
            'ip_address' => '203.0.113.20',
            'reason_code' => BlockReason::RATE_LIMIT,
        ]);
    }

    public function test_reject_only_returns_429_without_persisting_a_block(): void
    {
        config()->set('security-guard.public_rate_limit.enabled', true);
        config()->set('security-guard.public_rate_limit.requests_per_minute', 1);
        config()->set('security-guard.public_rate_limit.action', 'reject_only');

        $this->fromIp('203.0.113.21')->get('/')->assertOk();

        $this->fromIp('203.0.113.21')->get('/')
            ->assertStatus(429)
            ->assertHeader('Retry-After');

        $this->assertDatabaseCount('security_guard_blocked_ips', 0);
    }

    public function test_temporary_block_rejects_without_a_database_row(): void
    {
        config()->set('security-guard.public_rate_limit.enabled', true);
        config()->set('security-guard.public_rate_limit.requests_per_minute', 1);
        config()->set('security-guard.public_rate_limit.action', 'temporary_block');

        $this->fromIp('203.0.113.22')->get('/')->assertOk();
        $this->fromIp('203.0.113.22')->get('/')->assertForbidden();

        // The following request is refused straight from cache.
        $this->fromIp('203.0.113.22')->get('/')->assertForbidden();
        $this->assertDatabaseCount('security_guard_blocked_ips', 0);
    }

    public function test_releasing_clears_the_request_counter_as_well(): void
    {
        config()->set('security-guard.public_rate_limit.enabled', true);
        config()->set('security-guard.public_rate_limit.requests_per_minute', 2);

        $this->fromIp('203.0.113.30')->get('/');
        $this->fromIp('203.0.113.30')->get('/');
        $this->fromIp('203.0.113.30')->get('/')->assertForbidden();

        $this->app->make(IpBlockService::class)->release('203.0.113.30');

        // A surviving counter would re-block the address immediately.
        $this->fromIp('203.0.113.30')->get('/')->assertOk();
        $this->fromIp('203.0.113.30')->get('/')->assertOk();
    }

    public function test_re_blocking_reactivates_the_same_row(): void
    {
        $service = $this->app->make(IpBlockService::class);

        $this->fromIp('203.0.113.40')->get('/wp-admin')->assertForbidden();
        $service->release('203.0.113.40');

        $this->fromIp('203.0.113.40')->get('/')->assertOk();
        $this->fromIp('203.0.113.40')->get('/.env')->assertForbidden();

        // One address, one row, whatever its block and release history is.
        $this->assertDatabaseCount('security_guard_blocked_ips', 1);

        $record = $service->findActive('203.0.113.40');
        $this->assertNotNull($record);
        $this->assertSame('secret_file_probe', $record->matchedPattern);
        $this->assertNull($record->releasedAt);
    }

    public function test_concurrent_blocks_of_one_address_do_not_create_duplicate_rows(): void
    {
        $service = $this->app->make(IpBlockService::class);

        // Stands in for several workers racing on the same address: the unique
        // index rejects the losers, which then update the winning row.
        for ($i = 0; $i < 5; $i++) {
            $service->block('203.0.113.50', BlockReason::KNOWN_ATTACK_PATH, 'wordpress_probe', $i + 1);
        }

        $this->assertSame(1, BlockedIp::query()->where('ip_address', '203.0.113.50')->count());
        $this->assertSame(5, (int) BlockedIp::query()->where('ip_address', '203.0.113.50')->value('request_count'));
    }

    public function test_the_whole_guard_can_be_switched_off(): void
    {
        config()->set('security-guard.enabled', false);

        $this->fromIp('203.0.113.10')->get('/wp-admin')->assertNotFound();
        $this->assertDatabaseCount('security_guard_blocked_ips', 0);
    }

    public function test_an_unresolvable_client_address_is_allowed_through(): void
    {
        // Failing open is deliberate: a proxy that hides the client must never
        // make every visitor look like one blocked address.
        $this->withServerVariables(['REMOTE_ADDR' => 'unknown'])->get('/')->assertOk();
    }

    public function test_the_response_status_and_body_are_configurable(): void
    {
        config()->set('security-guard.permanent_block.response_status', 404);
        config()->set('security-guard.permanent_block.response_body', 'Not Found');

        $response = $this->fromIp('203.0.113.60')->get('/wp-admin');

        $response->assertNotFound();
        $this->assertSame('Not Found', $response->getContent());
    }
}
