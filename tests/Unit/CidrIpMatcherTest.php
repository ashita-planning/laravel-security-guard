<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Tests\Unit;

use Apkk\LaravelSecurityGuard\Services\CidrIpMatcher;
use Apkk\LaravelSecurityGuard\Services\ExactIpMatcher;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The v0.2.0 matcher must be a strict superset of the v0.1.x one.
 *
 * Every allowlist written against v0.1.x has to keep matching exactly what it
 * matched before the upgrade. A range that widens on upgrade would admit
 * addresses the operator never approved; one that narrows would lock out
 * whoever was relying on it.
 */
class CidrIpMatcherTest extends TestCase
{
    private function matcher(): CidrIpMatcher
    {
        return new CidrIpMatcher;
    }

    // -----------------------------------------------------------------
    // Backwards compatibility with v0.1.x entries
    // -----------------------------------------------------------------

    /**
     * @param  array<int, string>  $entries
     */
    #[DataProvider('legacyEntries')]
    public function test_it_agrees_with_the_exact_matcher_on_plain_addresses(
        array $entries,
        string $candidate,
    ): void {
        $legacy = (new ExactIpMatcher)->matches($candidate, $entries);
        $current = $this->matcher()->matches($candidate, $entries);

        $this->assertSame(
            $legacy,
            $current,
            sprintf('Behaviour changed for %s against %s', $candidate, implode(',', $entries)),
        );
    }

    /**
     * @return array<string, array{array<int, string>, string}>
     */
    public static function legacyEntries(): array
    {
        return [
            'exact ipv4 hit' => [['203.0.113.10'], '203.0.113.10'],
            'exact ipv4 miss' => [['203.0.113.10'], '203.0.113.11'],
            'adjacent address still misses' => [['203.0.113.10'], '203.0.113.9'],
            'exact ipv6 hit' => [['2001:db8::1'], '2001:db8::1'],
            'exact ipv6 miss' => [['2001:db8::1'], '2001:db8::2'],
            'ipv6 written long' => [['0:0:0:0:0:0:0:1'], '::1'],
            'several entries, one hit' => [['198.51.100.1', '203.0.113.10'], '203.0.113.10'],
            'several entries, no hit' => [['198.51.100.1', '203.0.113.10'], '192.0.2.1'],
            'empty allowlist' => [[], '203.0.113.10'],
            'invalid entry is not a wildcard' => [['not-an-ip'], '203.0.113.10'],
            'families do not cross' => [['203.0.113.10'], '::ffff:203.0.113.10'],
        ];
    }

    public function test_it_tolerates_a_candidate_the_caller_forgot_to_normalise(): void
    {
        // The contract names the parameter $normalizedIp and every caller in
        // this package normalises first, so this is defence in depth rather
        // than a behaviour change. ExactIpMatcher answers false here, which is
        // semantically wrong: 0:0:0:0:0:0:0:1 IS ::1.
        $this->assertTrue($this->matcher()->matches('0:0:0:0:0:0:0:1', ['::1']));
        $this->assertFalse((new ExactIpMatcher)->matches('0:0:0:0:0:0:0:1', ['::1']));
    }

    // -----------------------------------------------------------------
    // What v0.2.0 adds
    // -----------------------------------------------------------------

    public function test_it_admits_an_address_inside_a_cidr_entry(): void
    {
        $this->assertTrue($this->matcher()->matches('203.0.113.10', ['203.0.113.0/24']));
        $this->assertTrue($this->matcher()->matches('2001:db8::dead', ['2001:db8::/32']));
    }

    public function test_it_refuses_an_address_outside_a_cidr_entry(): void
    {
        $this->assertFalse($this->matcher()->matches('203.0.114.10', ['203.0.113.0/24']));
        $this->assertFalse($this->matcher()->matches('2001:db9::1', ['2001:db8::/32']));
    }

    public function test_exact_and_cidr_entries_coexist(): void
    {
        $entries = ['198.51.100.7', '203.0.113.0/24', '2001:db8::/48'];

        $this->assertTrue($this->matcher()->matches('198.51.100.7', $entries));
        $this->assertTrue($this->matcher()->matches('203.0.113.200', $entries));
        $this->assertTrue($this->matcher()->matches('2001:db8:0:1::9', $entries));
        $this->assertFalse($this->matcher()->matches('198.51.100.8', $entries));
    }

    public function test_a_slash_32_entry_matches_only_that_address(): void
    {
        $this->assertTrue($this->matcher()->matches('203.0.113.10', ['203.0.113.10/32']));
        $this->assertFalse($this->matcher()->matches('203.0.113.11', ['203.0.113.10/32']));
    }

    // -----------------------------------------------------------------
    // Failing closed
    // -----------------------------------------------------------------

    /**
     * @param  array<int, string>  $entries
     */
    #[DataProvider('malformedEntries')]
    public function test_a_malformed_entry_never_becomes_a_wildcard(array $entries): void
    {
        // A typo in an allowlist has to fail closed. The alternative is a
        // malformed line quietly admitting everyone.
        $this->assertFalse($this->matcher()->matches('203.0.113.10', $entries));
        $this->assertFalse($this->matcher()->matches('2001:db8::1', $entries));
    }

    /**
     * @return array<string, array{array<int, string>}>
     */
    public static function malformedEntries(): array
    {
        return [
            'nonsense' => [['nonsense']],
            'prefix out of range' => [['203.0.113.0/33']],
            'empty string' => [['']],
            'bare slash' => [['/']],
            'wildcard notation is not supported' => [['203.0.113.*']],
            'range notation is not supported' => [['203.0.113.1-203.0.113.50']],
            'hostname' => [['example.test']],
        ];
    }

    public function test_a_malformed_entry_does_not_stop_later_entries_matching(): void
    {
        $entries = ['203.0.113.*', '203.0.113.0/24'];

        $this->assertTrue($this->matcher()->matches('203.0.113.10', $entries));
    }

    public function test_an_unresolvable_candidate_matches_nothing(): void
    {
        $this->assertFalse($this->matcher()->matches('nonsense', ['0.0.0.0/0']));
        $this->assertFalse($this->matcher()->matches('', ['0.0.0.0/0']));
    }

    public function test_non_string_entries_are_ignored(): void
    {
        /** @var array<int, string> $entries */
        $entries = [null, 123, ['nested'], '203.0.113.0/24'];

        $this->assertTrue($this->matcher()->matches('203.0.113.10', $entries));
        $this->assertFalse($this->matcher()->matches('198.51.100.1', $entries));
    }

    // -----------------------------------------------------------------
    // The widest rules, which are the easiest to get wrong
    // -----------------------------------------------------------------

    public function test_the_ipv4_default_route_admits_every_ipv4_address(): void
    {
        $matcher = $this->matcher();

        foreach (['0.0.0.0', '203.0.113.10', '255.255.255.255'] as $ip) {
            $this->assertTrue($matcher->matches($ip, ['0.0.0.0/0']));
        }

        // Still bounded by family.
        $this->assertFalse($matcher->matches('2001:db8::1', ['0.0.0.0/0']));
    }

    public function test_repeated_lookups_stay_consistent(): void
    {
        $matcher = $this->matcher();
        $entries = ['203.0.113.0/24'];

        // The matcher memoises parsed entries; the cache must not change answers.
        for ($i = 0; $i < 5; $i++) {
            $this->assertTrue($matcher->matches('203.0.113.10', $entries));
            $this->assertFalse($matcher->matches('203.0.114.10', $entries));
        }
    }
}
