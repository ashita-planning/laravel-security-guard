<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Tests\Unit;

use Apkk\LaravelSecurityGuard\Support\IpRange;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Pins the official range-file format the refresh stage will consume.
 *
 * Google's crawler IP file and Bing's bingbot.json share one shape: a
 * `creationTime` string and a `prefixes` array whose entries carry exactly one
 * of `ipv4Prefix` / `ipv6Prefix`. These fixtures are what every later test
 * parses instead of the network, so their shape being right is itself a test —
 * a drifted fixture would let the whole verification suite pass against data
 * that no longer looks like what the providers actually publish.
 */
class CrawlerRangeFixtureTest extends TestCase
{
    private const FIXTURES = __DIR__.'/../Fixtures/crawler-ranges';

    /**
     * @return array<string, array{string}>
     */
    public static function fixtureFiles(): array
    {
        return [
            'google' => [self::FIXTURES.'/google.json'],
            'bing' => [self::FIXTURES.'/bing.json'],
        ];
    }

    /**
     * @return array<string, mixed>
     */
    private function decode(string $path): array
    {
        $this->assertFileExists($path);

        $decoded = json_decode((string) file_get_contents($path), true, 8, JSON_THROW_ON_ERROR);
        $this->assertIsArray($decoded);

        return $decoded;
    }

    #[DataProvider('fixtureFiles')]
    public function test_the_fixture_carries_the_published_format(string $path): void
    {
        $document = $this->decode($path);

        $this->assertArrayHasKey('creationTime', $document);
        $this->assertIsString($document['creationTime']);
        $this->assertNotSame('', $document['creationTime']);

        $this->assertArrayHasKey('prefixes', $document);
        $this->assertIsArray($document['prefixes']);
        $this->assertNotEmpty($document['prefixes']);
    }

    #[DataProvider('fixtureFiles')]
    public function test_every_prefix_entry_names_exactly_one_family(string $path): void
    {
        foreach ($this->decode($path)['prefixes'] as $index => $entry) {
            $this->assertIsArray($entry);

            $keys = array_intersect(array_keys($entry), ['ipv4Prefix', 'ipv6Prefix']);

            $this->assertCount(1, $keys, "Entry {$index} in {$path} must carry exactly one prefix key.");
        }
    }

    #[DataProvider('fixtureFiles')]
    public function test_every_prefix_parses_canonically_in_the_declared_family(string $path): void
    {
        foreach ($this->decode($path)['prefixes'] as $index => $entry) {
            $isV4 = array_key_exists('ipv4Prefix', $entry);
            $value = (string) ($entry['ipv4Prefix'] ?? $entry['ipv6Prefix']);

            $range = IpRange::parse($value);

            // The refresh stage validates fetched data through IpRange; a
            // fixture it cannot parse would be testing nothing.
            $this->assertNotNull($range, "Entry {$index} ({$value}) in {$path} does not parse.");
            $this->assertTrue($range->wasCanonical(), "Entry {$index} ({$value}) carries host bits.");
            $this->assertSame($value, $range->toString(), "Entry {$index} ({$value}) is not in canonical form.");
            $this->assertSame(
                $isV4 ? IpRange::FAMILY_V4 : IpRange::FAMILY_V6,
                $range->family(),
                "Entry {$index} ({$value}) sits under the wrong prefix key.",
            );
        }
    }

    public function test_the_fixtures_cover_both_families_for_both_providers(): void
    {
        foreach (self::fixtureFiles() as $name => [$path]) {
            $families = [];

            foreach ($this->decode($path)['prefixes'] as $entry) {
                $families[array_key_exists('ipv4Prefix', $entry) ? 'v4' : 'v6'] = true;
            }

            // The acceptance criteria require verifying both families, so the
            // offline data has to exercise both.
            $this->assertSame(['v4' => true, 'v6' => true], array_replace(['v4' => false, 'v6' => false], $families),
                "The {$name} fixture must contain both IPv4 and IPv6 prefixes.");
        }
    }
}
