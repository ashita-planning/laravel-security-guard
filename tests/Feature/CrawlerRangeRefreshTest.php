<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Tests\Feature;

use Apkk\LaravelSecurityGuard\Contracts\CrawlerRangeFetcherContract;
use Apkk\LaravelSecurityGuard\Crawlers\CrawlerRangeStore;
use Apkk\LaravelSecurityGuard\SecurityGuardServiceProvider;
use Apkk\LaravelSecurityGuard\Support\CacheKeyFactory;
use Apkk\LaravelSecurityGuard\Tests\Fixtures\FakeCrawlerRangeFetcher;
use Apkk\LaravelSecurityGuard\Tests\TestCase;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Support\Carbon;
use PHPUnit\Framework\Attributes\DataProvider;
use RuntimeException;

/**
 * The refresh pipeline: fetch → validate → stage → readback → swap.
 *
 * The property under test throughout: a refresh either stores a fully
 * validated document or changes nothing. There is no code path that stores a
 * partial document, and no failure that erases yesterday's known-good data.
 */
class CrawlerRangeRefreshTest extends TestCase
{
    private const FIXTURES = __DIR__.'/../Fixtures/crawler-ranges';

    private FakeCrawlerRangeFetcher $fetcher;

    private string $googleBody = '';

    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);

        $app->make(Repository::class)->set('security-guard.crawler_access.ranges.sources', [
            'google' => 'https://ranges.example.test/google.json',
            'bing' => 'https://ranges.example.test/bing.json',
        ]);
    }

    protected function setUp(): void
    {
        parent::setUp();

        $this->googleBody = (string) file_get_contents(self::FIXTURES.'/google.json');

        $this->fetcher = new FakeCrawlerRangeFetcher;
        $this->fetcher->respond('https://ranges.example.test/google.json', $this->googleBody);
        $this->fetcher->respond(
            'https://ranges.example.test/bing.json',
            (string) file_get_contents(self::FIXTURES.'/bing.json'),
        );

        $this->app->instance(CrawlerRangeFetcherContract::class, $this->fetcher);
    }

    protected function tearDown(): void
    {
        Carbon::setTestNow();

        parent::tearDown();
    }

    private function store(): CrawlerRangeStore
    {
        return $this->app->make(CrawlerRangeStore::class);
    }

    // -----------------------------------------------------------------
    // The happy path
    // -----------------------------------------------------------------

    public function test_a_refresh_stores_the_validated_document(): void
    {
        $this->artisan('security-guard:crawler-ranges:refresh')->assertExitCode(0);

        $payload = $this->store()->current('google');

        $this->assertNotNull($payload);
        $this->assertSame('https://ranges.example.test/google.json', $payload['source']);
        $this->assertSame(hash('sha256', $this->googleBody), $payload['content_hash']);
        $this->assertSame('2026-07-30T23:00:14.000000', $payload['creation_time']);
        $this->assertNotSame('', $payload['fetched_at']);
        $this->assertNotSame('', $payload['fresh_until']);
        $this->assertContains('66.249.64.0/27', $payload['v4']);
        $this->assertContains('2001:4860:4801:10::/64', $payload['v6']);

        $this->assertNotNull($this->store()->current('bing'));
    }

    public function test_fresh_ranges_are_served_until_the_freshness_window_closes(): void
    {
        config()->set('security-guard.crawler_access.ranges.fresh_for_hours', 24);

        Carbon::setTestNow('2026-08-04 12:00:00');
        $this->artisan('security-guard:crawler-ranges:refresh')->assertExitCode(0);

        $this->assertNotNull($this->store()->freshRanges('google'));

        // One hour before expiry: still trusted.
        Carbon::setTestNow('2026-08-05 11:00:00');
        $this->assertNotNull($this->store()->freshRanges('google'));

        // Past expiry: verifies nobody, but stays inspectable. "Your ranges
        // are old" and "you have no ranges" are different problems.
        Carbon::setTestNow('2026-08-05 13:00:00');
        $this->assertNull($this->store()->freshRanges('google'));
        $this->assertNotNull($this->store()->current('google'));
    }

    public function test_an_unchanged_document_renews_freshness_and_says_so(): void
    {
        Carbon::setTestNow('2026-08-04 12:00:00');
        $this->artisan('security-guard:crawler-ranges:refresh')->assertExitCode(0);
        $first = $this->store()->current('google');

        Carbon::setTestNow('2026-08-06 12:00:00');
        $this->artisan('security-guard:crawler-ranges:refresh')
            ->expectsOutputToContain('unchanged')
            ->assertExitCode(0);

        $second = $this->store()->current('google');

        $this->assertNotNull($first);
        $this->assertNotNull($second);
        $this->assertSame($first['content_hash'], $second['content_hash']);
        // A cron that keeps fetching identical data must keep the data
        // trusted; only a failing fetch lets freshness lapse.
        $this->assertGreaterThan($first['fresh_until'], $second['fresh_until']);
    }

    public function test_the_provider_option_refreshes_only_the_named_provider(): void
    {
        $this->artisan('security-guard:crawler-ranges:refresh', ['--provider' => ['google']])
            ->assertExitCode(0);

        $this->assertNotNull($this->store()->current('google'));
        $this->assertNull($this->store()->current('bing'));
        $this->assertSame(['https://ranges.example.test/google.json'], $this->fetcher->fetchedUrls());
    }

    public function test_the_staging_key_does_not_outlive_a_successful_refresh(): void
    {
        $this->artisan('security-guard:crawler-ranges:refresh')->assertExitCode(0);

        $cache = $this->app->make(SecurityGuardServiceProvider::CACHE);
        $keys = $this->app->make(CacheKeyFactory::class);

        $this->assertNull($cache->get($keys->crawlerRangesStaging('google')));
        $this->assertNotNull($cache->get($keys->crawlerRanges('google')));
    }

    // -----------------------------------------------------------------
    // Nothing broken ever overwrites something good
    // -----------------------------------------------------------------

    /**
     * @return array<string, array{string}>
     */
    public static function brokenDocuments(): array
    {
        $entries = static fn (string $inner): string => '{"creationTime":"2026-08-04T00:00:00Z","prefixes":['.$inner.']}';

        return [
            'not json' => ['{"creationTime": "x", "prefixes": [broken'],
            'no prefixes key' => ['{"creationTime": "2026-08-04T00:00:00Z"}'],
            'empty prefixes' => [$entries('')],
            'invalid cidr' => [$entries('{"ipv4Prefix":"66.249.64.0/27"},{"ipv4Prefix":"999.0.0.0/8"}')],
            'host bits' => [$entries('{"ipv4Prefix":"66.249.64.5/27"}')],
            'wrong family key' => [$entries('{"ipv4Prefix":"2001:db8::/48"}')],
            'both keys on one entry' => [$entries('{"ipv4Prefix":"66.249.64.0/27","ipv6Prefix":"2001:db8::/48"}')],
            'non-string prefix' => [$entries('{"ipv4Prefix":12345}')],
        ];
    }

    #[DataProvider('brokenDocuments')]
    public function test_a_broken_document_keeps_the_previous_data(string $brokenBody): void
    {
        // Seed known-good data first.
        $this->artisan('security-guard:crawler-ranges:refresh')->assertExitCode(0);
        $before = $this->store()->current('google');
        $this->assertNotNull($before);

        // The next fetch returns the broken document.
        $this->fetcher->respond('https://ranges.example.test/google.json', $brokenBody);

        $this->artisan('security-guard:crawler-ranges:refresh', ['--provider' => ['google']])
            ->expectsOutputToContain('previously stored data was kept')
            ->assertExitCode(1);

        // One valid entry inside a broken document must not survive either:
        // storage is all-or-nothing.
        $this->assertSame($before, $this->store()->current('google'));
    }

    public function test_a_transport_failure_keeps_the_previous_data(): void
    {
        $this->artisan('security-guard:crawler-ranges:refresh')->assertExitCode(0);
        $before = $this->store()->current('google');

        $this->fetcher->respond('https://ranges.example.test/google.json', new RuntimeException('connection refused'));

        $this->artisan('security-guard:crawler-ranges:refresh')->assertExitCode(1);

        $this->assertSame($before, $this->store()->current('google'));
        // The other provider still refreshed; one broken endpoint does not
        // abort the run.
        $this->assertNotNull($this->store()->current('bing'));
    }

    public function test_an_oversized_document_is_rejected(): void
    {
        $this->fetcher->respond('https://ranges.example.test/google.json', str_repeat('a', 5_000_001));

        $this->artisan('security-guard:crawler-ranges:refresh', ['--provider' => ['google']])
            ->assertExitCode(1);

        $this->assertNull($this->store()->current('google'));
    }

    public function test_an_implausibly_long_prefix_list_is_rejected(): void
    {
        $prefixes = implode(',', array_map(
            static fn (int $i): string => sprintf('{"ipv4Prefix":"10.%d.%d.0/24"}', intdiv($i, 256) % 256, $i % 256),
            range(1, 5001),
        ));
        $this->fetcher->respond(
            'https://ranges.example.test/google.json',
            '{"creationTime":"2026-08-04T00:00:00Z","prefixes":['.$prefixes.']}',
        );

        $this->artisan('security-guard:crawler-ranges:refresh', ['--provider' => ['google']])
            ->assertExitCode(1);

        $this->assertNull($this->store()->current('google'));
    }

    // -----------------------------------------------------------------
    // Invocation errors are loud
    // -----------------------------------------------------------------

    public function test_an_unknown_provider_option_fails_without_fetching(): void
    {
        $this->artisan('security-guard:crawler-ranges:refresh', ['--provider' => ['yandex']])
            ->expectsOutputToContain('Unknown provider')
            ->assertExitCode(1);

        $this->assertSame([], $this->fetcher->fetchedUrls());
    }

    public function test_an_empty_source_list_fails_loudly(): void
    {
        // A cron job pointing at nothing must page someone, not report
        // success forever.
        config()->set('security-guard.crawler_access.ranges.sources', []);

        $this->artisan('security-guard:crawler-ranges:refresh')
            ->expectsOutputToContain('No crawler range sources are configured')
            ->assertExitCode(1);
    }

    public function test_the_default_sources_point_at_both_providers(): void
    {
        $app = $this->app;
        $app['config']->offsetUnset('security-guard');
        $defaults = require __DIR__.'/../../config/security-guard.php';

        $sources = $defaults['crawler_access']['ranges']['sources'];

        $this->assertArrayHasKey('google', $sources);
        $this->assertArrayHasKey('bing', $sources);
        $this->assertStringStartsWith('https://', $sources['google']);
        $this->assertStringStartsWith('https://', $sources['bing']);
    }
}
