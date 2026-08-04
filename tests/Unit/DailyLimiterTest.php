<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Tests\Unit;

use Apkk\LaravelSecurityGuard\Services\DailyLimiter;
use Apkk\LaravelSecurityGuard\Tests\TestCase;

class DailyLimiterTest extends TestCase
{
    private function limiter(): DailyLimiter
    {
        return $this->app->make(DailyLimiter::class);
    }

    public function test_a_limit_of_zero_never_allows_a_send(): void
    {
        $this->assertFalse($this->limiter()->consume('security-events', 0));
    }

    public function test_a_negative_limit_never_allows_a_send(): void
    {
        $this->assertFalse($this->limiter()->consume('security-events', -1));
    }

    public function test_a_limit_of_one_allows_exactly_one_send(): void
    {
        $limiter = $this->limiter();

        $this->assertTrue($limiter->consume('security-events', 1));
        $this->assertFalse($limiter->consume('security-events', 1));
    }

    public function test_it_allows_up_to_the_limit_and_then_stops(): void
    {
        $limiter = $this->limiter();

        for ($i = 1; $i <= 4; $i++) {
            $this->assertTrue($limiter->consume('error-events:mail', 4), "Send {$i} should be allowed.");
        }

        $this->assertFalse($limiter->consume('error-events:mail', 4));
        $this->assertSame(4, $limiter->used('error-events:mail'));
    }

    public function test_scopes_are_counted_independently(): void
    {
        $limiter = $this->limiter();

        $this->assertTrue($limiter->consume('error-events:line', 1));
        // Exhausting one channel must not silence the others.
        $this->assertTrue($limiter->consume('error-events:mail', 1));
    }
}
