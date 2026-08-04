<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Tests\Unit;

use Apkk\LaravelSecurityGuard\Support\IpRange;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Boundary behaviour of the CIDR value object.
 *
 * An off-by-one here is not a cosmetic bug: it either admits an address the
 * operator did not allowlist, or locks out one they did. Every prefix boundary
 * is pinned with the addresses immediately inside and immediately outside it.
 */
class IpRangeTest extends TestCase
{
    // -----------------------------------------------------------------
    // Parsing and canonical storage form
    // -----------------------------------------------------------------

    #[DataProvider('canonicalForms')]
    public function test_it_stores_a_canonical_form(string $input, string $expected): void
    {
        $range = IpRange::parse($input);

        $this->assertNotNull($range, "Expected {$input} to parse.");
        $this->assertSame($expected, $range->toString());
    }

    /**
     * @return array<string, array{string, string}>
     */
    public static function canonicalForms(): array
    {
        return [
            'ipv4 host' => ['203.0.113.10', '203.0.113.10'],
            // /32 and /128 mean "this one address", so the suffix is dropped
            // and a v0.1.x row stays byte-identical to the new form.
            'ipv4 /32 loses its suffix' => ['203.0.113.10/32', '203.0.113.10'],
            'ipv6 /128 loses its suffix' => ['2001:db8::1/128', '2001:db8::1'],
            'ipv6 host is compressed' => ['2001:0db8:0000:0000:0000:0000:0000:0001', '2001:db8::1'],
            'ipv4 network' => ['203.0.113.0/24', '203.0.113.0/24'],
            'ipv6 network' => ['2001:db8::/48', '2001:db8::/48'],
            'ipv4 default route' => ['0.0.0.0/0', '0.0.0.0/0'],
            'ipv6 default route' => ['::/0', '::/0'],
            'surrounding whitespace' => ['  203.0.113.0/24  ', '203.0.113.0/24'],
            'ipv6 case is folded' => ['2001:DB8::/32', '2001:db8::/32'],
        ];
    }

    public function test_the_longest_possible_value_fits_the_existing_column(): void
    {
        $range = IpRange::parse('ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128');

        $this->assertNotNull($range);

        // The whole no-migration decision rests on this: the widest canonical
        // form must still fit ip_address varchar(45).
        $widest = (string) IpRange::parse('ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/127')?->toString();
        $this->assertLessThanOrEqual(45, strlen($widest));
        $this->assertLessThanOrEqual(45, strlen($range->toString()));
    }

    #[DataProvider('unparseableEntries')]
    public function test_it_rejects_unusable_entries(string $input): void
    {
        $this->assertNull(IpRange::parse($input), "Expected {$input} to be rejected.");
    }

    /**
     * @return array<string, array{string}>
     */
    public static function unparseableEntries(): array
    {
        return [
            'empty' => [''],
            'blank' => ['   '],
            'not an address' => ['nonsense'],
            'hostname' => ['example.test'],
            'ipv4 prefix above 32' => ['203.0.113.0/33'],
            'ipv6 prefix above 128' => ['2001:db8::/129'],
            'negative prefix' => ['203.0.113.0/-1'],
            'non numeric prefix' => ['203.0.113.0/abc'],
            'empty prefix' => ['203.0.113.0/'],
            // A silently reinterpreted prefix is worse than a rejected one.
            'leading zero prefix' => ['203.0.113.0/08'],
            'spaced prefix' => ['203.0.113.0/ 24'],
            'double slash' => ['203.0.113.0/24/24'],
            'prefix without address' => ['/24'],
            'ipv4 with port' => ['203.0.113.10:8080'],
            'sql fragment' => ["203.0.113.10' OR '1'='1"],
            'out of range octet' => ['203.0.113.999/24'],
        ];
    }

    // -----------------------------------------------------------------
    // Prefix boundaries
    // -----------------------------------------------------------------

    #[DataProvider('ipv4Boundaries')]
    public function test_ipv4_prefix_boundaries(string $cidr, string $candidate, bool $expected): void
    {
        $range = IpRange::parse($cidr);

        $this->assertNotNull($range);
        $this->assertSame(
            $expected,
            $range->contains($candidate),
            sprintf('%s should %scontain %s', $cidr, $expected ? '' : 'not ', $candidate),
        );
    }

    /**
     * @return array<string, array{string, string, bool}>
     */
    public static function ipv4Boundaries(): array
    {
        return [
            '/0 admits anything v4' => ['0.0.0.0/0', '203.0.113.10', true],
            '/0 admits the lowest' => ['0.0.0.0/0', '0.0.0.0', true],
            '/0 admits the highest' => ['0.0.0.0/0', '255.255.255.255', true],

            '/24 first address' => ['203.0.113.0/24', '203.0.113.0', true],
            '/24 last address' => ['203.0.113.0/24', '203.0.113.255', true],
            '/24 one below' => ['203.0.113.0/24', '203.0.112.255', false],
            '/24 one above' => ['203.0.113.0/24', '203.0.114.0', false],

            '/31 lower half' => ['203.0.113.0/31', '203.0.113.0', true],
            '/31 upper half' => ['203.0.113.0/31', '203.0.113.1', true],
            '/31 just outside' => ['203.0.113.0/31', '203.0.113.2', false],

            '/32 exact match' => ['203.0.113.10/32', '203.0.113.10', true],
            '/32 neighbour' => ['203.0.113.10/32', '203.0.113.11', false],

            '/23 spans two /24s' => ['203.0.112.0/23', '203.0.113.255', true],
            '/23 stops at the third' => ['203.0.112.0/23', '203.0.114.0', false],

            '/1 lower half' => ['0.0.0.0/1', '127.255.255.255', true],
            '/1 upper half excluded' => ['0.0.0.0/1', '128.0.0.0', false],
        ];
    }

    #[DataProvider('ipv6Boundaries')]
    public function test_ipv6_prefix_boundaries(string $cidr, string $candidate, bool $expected): void
    {
        $range = IpRange::parse($cidr);

        $this->assertNotNull($range);
        $this->assertSame(
            $expected,
            $range->contains($candidate),
            sprintf('%s should %scontain %s', $cidr, $expected ? '' : 'not ', $candidate),
        );
    }

    /**
     * @return array<string, array{string, string, bool}>
     */
    public static function ipv6Boundaries(): array
    {
        return [
            '/0 admits anything v6' => ['::/0', '2001:db8::1', true],
            '/0 admits the lowest' => ['::/0', '::', true],
            '/0 admits the highest' => ['::/0', 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff', true],

            '/48 first address' => ['2001:db8::/48', '2001:db8::', true],
            '/48 last address' => ['2001:db8::/48', '2001:db8:0:ffff:ffff:ffff:ffff:ffff', true],
            '/48 one above' => ['2001:db8::/48', '2001:db8:1::', false],

            '/64 inside' => ['2001:db8:0:1::/64', '2001:db8:0:1:ffff:ffff:ffff:ffff', true],
            '/64 outside' => ['2001:db8:0:1::/64', '2001:db8:0:2::', false],

            '/127 lower half' => ['2001:db8::/127', '2001:db8::', true],
            '/127 upper half' => ['2001:db8::/127', '2001:db8::1', true],
            '/127 just outside' => ['2001:db8::/127', '2001:db8::2', false],

            '/128 exact match' => ['2001:db8::1/128', '2001:db8::1', true],
            '/128 neighbour' => ['2001:db8::1/128', '2001:db8::2', false],

            // Prefix boundaries that fall inside a byte rather than on one.
            '/33 inside' => ['2001:db8::/33', '2001:db8:7fff::', true],
            '/33 outside' => ['2001:db8::/33', '2001:db8:8000::', false],
        ];
    }

    // -----------------------------------------------------------------
    // Families never cross
    // -----------------------------------------------------------------

    public function test_an_ipv4_rule_never_admits_an_ipv6_address(): void
    {
        $range = IpRange::parse('203.0.113.0/24');

        $this->assertNotNull($range);
        $this->assertFalse($range->contains('2001:db8::1'));
        $this->assertFalse($range->contains('::1'));
    }

    public function test_an_ipv6_rule_never_admits_an_ipv4_address(): void
    {
        $range = IpRange::parse('2001:db8::/32');

        $this->assertNotNull($range);
        $this->assertFalse($range->contains('203.0.113.10'));
    }

    public function test_an_ipv4_mapped_address_is_not_admitted_by_an_ipv4_rule(): void
    {
        $range = IpRange::parse('203.0.113.0/24');
        $this->assertNotNull($range);

        // Allowlisting a v4 network is not consent to admit a v6 client that
        // encodes the same digits.
        $this->assertFalse($range->contains('::ffff:203.0.113.10'));
    }

    public function test_the_ipv6_default_route_does_not_admit_ipv4(): void
    {
        $range = IpRange::parse('::/0');

        $this->assertNotNull($range);
        $this->assertTrue($range->contains('2001:db8::1'));
        $this->assertFalse($range->contains('203.0.113.10'));
    }

    // -----------------------------------------------------------------
    // Host bits
    // -----------------------------------------------------------------

    public function test_host_bits_are_masked_and_reported(): void
    {
        $range = IpRange::parse('203.0.113.10/24');

        $this->assertNotNull($range);
        $this->assertSame('203.0.113.0/24', $range->toString());
        // Parsed, but the written form was wider than it looked, which the
        // doctor surfaces rather than the matcher silently accepting.
        $this->assertFalse($range->wasCanonical());
    }

    public function test_a_network_written_correctly_is_canonical(): void
    {
        $range = IpRange::parse('203.0.113.0/24');

        $this->assertNotNull($range);
        $this->assertTrue($range->wasCanonical());
    }

    public function test_a_single_host_is_always_canonical(): void
    {
        foreach (['203.0.113.10', '203.0.113.10/32', '2001:db8::1/128'] as $entry) {
            $range = IpRange::parse($entry);

            $this->assertNotNull($range);
            $this->assertTrue($range->wasCanonical(), "{$entry} should be canonical.");
            $this->assertTrue($range->isSingleHost());
        }
    }

    // -----------------------------------------------------------------
    // Metadata used by the doctor and the UI
    // -----------------------------------------------------------------

    public function test_it_reports_family_and_prefix_length(): void
    {
        $v4 = IpRange::parse('203.0.113.0/24');
        $v6 = IpRange::parse('2001:db8::/48');

        $this->assertNotNull($v4);
        $this->assertNotNull($v6);

        $this->assertSame(IpRange::FAMILY_V4, $v4->family());
        $this->assertSame(24, $v4->prefixLength());
        $this->assertSame(IpRange::FAMILY_V6, $v6->family());
        $this->assertSame(48, $v6->prefixLength());
    }

    public function test_a_bare_address_reports_the_widest_prefix_for_its_family(): void
    {
        $this->assertSame(32, IpRange::parse('203.0.113.10')?->prefixLength());
        $this->assertSame(128, IpRange::parse('2001:db8::1')?->prefixLength());
    }

    #[DataProvider('rangeSizes')]
    public function test_it_reports_how_many_addresses_it_admits(string $cidr, float $expected): void
    {
        $this->assertSame($expected, IpRange::parse($cidr)?->size());
    }

    /**
     * @return array<string, array{string, float}>
     */
    public static function rangeSizes(): array
    {
        return [
            'ipv4 host' => ['203.0.113.10', 1.0],
            'ipv4 /24' => ['203.0.113.0/24', 256.0],
            'ipv4 /0' => ['0.0.0.0/0', 4294967296.0],
            'ipv6 host' => ['2001:db8::1', 1.0],
            'ipv6 /112' => ['2001:db8::/112', 65536.0],
        ];
    }

    public function test_equivalent_entries_are_equal(): void
    {
        $a = IpRange::parse('203.0.113.10');
        $b = IpRange::parse('203.0.113.10/32');
        $c = IpRange::parse('203.0.113.11');

        $this->assertNotNull($a);
        $this->assertNotNull($b);
        $this->assertNotNull($c);

        $this->assertTrue($a->equals($b), 'A bare address and its /32 are one rule.');
        $this->assertFalse($a->equals($c));
    }

    public function test_differently_written_ipv6_entries_are_equal(): void
    {
        $a = IpRange::parse('2001:0db8:0000::/48');
        $b = IpRange::parse('2001:db8::/48');

        $this->assertNotNull($a);
        $this->assertNotNull($b);
        $this->assertTrue($a->equals($b));
    }

    public function test_parsing_its_own_output_is_stable(): void
    {
        foreach ([
            '203.0.113.10/32',
            '203.0.113.0/24',
            '2001:db8::1/128',
            '2001:db8::/48',
            '0.0.0.0/0',
            '::/0',
        ] as $entry) {
            $once = IpRange::parse($entry);
            $this->assertNotNull($once);

            $twice = IpRange::parse($once->toString());
            $this->assertNotNull($twice);

            $this->assertSame($once->toString(), $twice->toString(), "{$entry} did not round-trip.");
        }
    }

    public function test_containment_rejects_an_unparseable_candidate(): void
    {
        $range = IpRange::parse('0.0.0.0/0');

        $this->assertNotNull($range);
        $this->assertFalse($range->contains('nonsense'));
        $this->assertFalse($range->contains(''));
    }
}
