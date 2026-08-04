<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Tests\Feature;

use Apkk\LaravelSecurityGuard\Services\DailyLimiter;
use Apkk\LaravelSecurityGuard\Support\CacheKeyFactory;
use Apkk\LaravelSecurityGuard\Support\FailureLogger;
use Apkk\LaravelSecurityGuard\Tests\TestCase;
use Illuminate\Contracts\Cache\Repository;

/**
 * `cache.prefix` has to actually reach the keys.
 *
 * Several applications commonly share one Redis server. With a hard-coded
 * prefix, staging and production collide: staging exhausting its daily
 * notification allowance silences production's alerts, and releasing an
 * address in one clears the other's cached block state.
 */
class CacheNamespaceTest extends TestCase
{
    public function test_the_configured_prefix_is_applied_to_keys(): void
    {
        config()->set('security-guard.cache.prefix', 'acme-production');

        $keys = $this->app->make(CacheKeyFactory::class);

        $this->assertStringStartsWith('acme-production:', $keys->block('203.0.113.10'));
        $this->assertStringStartsWith('acme-production:', $keys->dailyCounter('security-events', '20260804'));
        $this->assertStringStartsWith('acme-production:', $keys->publicRequests('203.0.113.10'));
    }

    public function test_two_prefixes_produce_different_keys_for_the_same_input(): void
    {
        $staging = new CacheKeyFactory('acme-staging');
        $production = new CacheKeyFactory('acme-production');

        $this->assertNotSame(
            $staging->block('203.0.113.10'),
            $production->block('203.0.113.10'),
        );
        $this->assertNotSame(
            $staging->dailyCounter('security-events', '20260804'),
            $production->dailyCounter('security-events', '20260804'),
        );
    }

    public function test_daily_allowances_are_independent_per_prefix(): void
    {
        $cache = $this->app->make(Repository::class);
        $logger = $this->app->make(FailureLogger::class);

        $staging = new DailyLimiter($cache, new CacheKeyFactory('acme-staging'), $logger);
        $production = new DailyLimiter($cache, new CacheKeyFactory('acme-production'), $logger);

        $this->assertTrue($staging->consume('security-events', 1));
        $this->assertFalse($staging->consume('security-events', 1));

        // Production must still have its full allowance.
        $this->assertTrue($production->consume('security-events', 1));
    }

    public function test_an_empty_prefix_falls_back_to_the_package_default(): void
    {
        foreach ([null, '', '   '] as $prefix) {
            $this->assertSame(CacheKeyFactory::DEFAULT_PREFIX, (new CacheKeyFactory($prefix))->prefix());
        }
    }

    public function test_a_trailing_separator_does_not_double_up(): void
    {
        $this->assertStringStartsWith('acme:block:', (new CacheKeyFactory('acme:'))->block('203.0.113.10'));
    }

    public function test_raw_addresses_never_appear_in_a_key(): void
    {
        $keys = $this->app->make(CacheKeyFactory::class);

        $this->assertStringNotContainsString('203.0.113.10', $keys->block('203.0.113.10'));
        $this->assertStringNotContainsString(
            'user@example.test',
            $keys->sensitive('customer_login', 'email', 'user@example.test'),
        );
    }
}
