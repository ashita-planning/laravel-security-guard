<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Tests\Unit;

use Apkk\LaravelSecurityGuard\Support\Ip;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

class IpTest extends TestCase
{
    #[DataProvider('normalizableAddresses')]
    public function test_it_normalizes_valid_addresses(string $input, string $expected): void
    {
        $this->assertSame($expected, Ip::normalize($input));
    }

    /**
     * @return array<string, array{string, string}>
     */
    public static function normalizableAddresses(): array
    {
        return [
            'ipv4' => ['203.0.113.10', '203.0.113.10'],
            'ipv4 with surrounding space' => ['  203.0.113.10  ', '203.0.113.10'],
            'ipv6 loopback long form' => ['0:0:0:0:0:0:0:1', '::1'],
            'ipv6 loopback short form' => ['::1', '::1'],
            'ipv6 mixed case is folded' => ['2001:DB8::AB', '2001:db8::ab'],
            'ipv6 with leading zeros' => ['2001:0db8:0000:0000:0000:0000:0000:0001', '2001:db8::1'],
        ];
    }

    #[DataProvider('invalidAddresses')]
    public function test_it_rejects_invalid_addresses(?string $input): void
    {
        $this->assertNull(Ip::normalize($input));
    }

    /**
     * @return array<string, array{string|null}>
     */
    public static function invalidAddresses(): array
    {
        return [
            'null' => [null],
            'empty' => [''],
            'text' => ['not-an-ip'],
            'out of range octet' => ['999.0.0.1'],
            'hostname' => ['localhost'],
            'ipv4 with port' => ['203.0.113.10:8080'],
            'sql fragment' => ["1' OR '1'='1"],
        ];
    }

    public function test_it_masks_the_host_portion(): void
    {
        $this->assertSame('203.0.113.0/24', Ip::mask('203.0.113.10'));
        $this->assertSame('2001:db8:1::/48', Ip::mask('2001:db8:1:2::3'));
    }

    #[DataProvider('maskableAddresses')]
    public function test_a_masked_address_is_always_a_valid_network(string $input): void
    {
        // Text-splitting masks used to emit things like `::1::` for compressed
        // notation. Whatever goes in, the network part must parse back.
        [$network, $prefix] = explode('/', Ip::mask($input));

        $this->assertNotFalse(filter_var($network, FILTER_VALIDATE_IP), "{$input} produced {$network}");
        $this->assertContains($prefix, ['24', '48']);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function maskableAddresses(): array
    {
        return [
            'ipv6 loopback' => ['::1'],
            'ipv6 unspecified' => ['::'],
            'ipv6 compressed' => ['2001:db8::1'],
            'ipv6 link local' => ['fe80::'],
            'ipv6 full' => ['2001:0db8:1234:5678:9abc:def0:1234:5678'],
            'ipv4' => ['203.0.113.10'],
            'ipv4 private' => ['10.1.2.3'],
        ];
    }

    public function test_an_unparseable_address_masks_to_a_constant(): void
    {
        $this->assertSame('unknown', Ip::mask('not-an-ip'));
    }
}
