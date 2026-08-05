<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Tests\Feature;

use Apkk\LaravelSecurityGuard\Contracts\CrawlerRangeFetcherContract;
use Apkk\LaravelSecurityGuard\Crawlers\CrawlerProvider;
use Apkk\LaravelSecurityGuard\Crawlers\CrawlerRangeStore;
use Apkk\LaravelSecurityGuard\Crawlers\CrawlerVerifierRegistry;
use Apkk\LaravelSecurityGuard\Crawlers\PublishedRangeCrawlerVerifier;
use Apkk\LaravelSecurityGuard\Data\CrawlerVerificationResult;
use Apkk\LaravelSecurityGuard\SecurityGuardServiceProvider;
use Apkk\LaravelSecurityGuard\Support\CacheKeyFactory;
use Apkk\LaravelSecurityGuard\Tests\Fixtures\FakeCrawlerRangeFetcher;
use Apkk\LaravelSecurityGuard\Tests\TestCase;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Support\Carbon;
use PHPUnit\Framework\Attributes\DataProvider;

/**
 * Verification against the published ranges, entirely offline.
 *
 * Addresses come from the committed fixtures, so the boundary cases are the
 * real published networks rather than invented ones. Nothing here reaches the
 * network: the acceptance criteria require the whole suite to run against
 * fixture data.
 */
class CrawlerVerificationTest extends TestCase
{
    private const FIXTURES = __DIR__.'/../Fixtures/crawler-ranges';

    private const GOOGLEBOT_UA = 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)';

    private const BINGBOT_UA = 'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)';

    private const BROWSER_UA = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/126.0.0.0';

    private FakeCrawlerRangeFetcher $fetcher;

    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);

        $app->make(Repository::class)->set([
            'security-guard.crawler_access.enabled' => true,
            'security-guard.crawler_access.ranges.sources' => [
                'google' => 'https://ranges.example.test/google.json',
                'bing' => 'https://ranges.example.test/bing.json',
            ],
        ]);
    }

    protected function setUp(): void
    {
        parent::setUp();

        $this->fetcher = new FakeCrawlerRangeFetcher;
        $this->fetcher->respond(
            'https://ranges.example.test/google.json',
            (string) file_get_contents(self::FIXTURES.'/google.json'),
        );
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

    private function refresh(): void
    {
        $this->artisan('security-guard:crawler-ranges:refresh')->assertExitCode(0);
    }

    private function registry(): CrawlerVerifierRegistry
    {
        return $this->app->make(CrawlerVerifierRegistry::class);
    }

    private function verifier(string $provider = CrawlerProvider::GOOGLE): PublishedRangeCrawlerVerifier
    {
        return new PublishedRangeCrawlerVerifier($provider, $this->app->make(CrawlerRangeStore::class));
    }

    // -----------------------------------------------------------------
    // Address ownership, on the real published boundaries
    // -----------------------------------------------------------------

    #[DataProvider('googleAddresses')]
    public function test_it_decides_google_ownership(string $address, ?bool $expected): void
    {
        $this->refresh();

        $this->assertSame($expected, $this->verifier()->ownsAddress($address));
    }

    /**
     * 66.249.64.0/27 covers .0 through .31; the next published block starts
     * at .32. 2001:4860:4801:10::/64 is one of the published v6 networks.
     *
     * @return array<string, array{string, bool|null}>
     */
    public static function googleAddresses(): array
    {
        return [
            'first address of a published block' => ['66.249.64.0', true],
            'last address of a published block' => ['66.249.64.31', true],
            'inside the adjacent published block' => ['66.249.64.32', true],
            'inside a later published block' => ['66.249.79.230', true],
            'one below the lowest published block' => ['66.249.63.255', false],
            'a gap between published blocks' => ['66.249.65.1', false],
            'unrelated public address' => ['203.0.113.10', false],
            'ipv6 inside a published network' => ['2001:4860:4801:10::dead', true],
            'ipv6 network boundary' => ['2001:4860:4801:10::', true],
            'ipv6 just outside' => ['2001:4860:4801:12::1', false],
            'unrelated ipv6' => ['2001:db8::1', false],
        ];
    }

    public function test_it_decides_bing_ownership_from_bings_own_ranges(): void
    {
        $this->refresh();

        $bing = $this->verifier(CrawlerProvider::BING);

        $this->assertTrue($bing->ownsAddress('157.55.39.9'));
        $this->assertTrue($bing->ownsAddress('2620:1ec:c::5'));
        $this->assertFalse($bing->ownsAddress('203.0.113.10'));
        // Google's address is not Bing's, and vice versa.
        $this->assertFalse($bing->ownsAddress('66.249.64.5'));
        $this->assertFalse($this->verifier()->ownsAddress('157.55.39.9'));
    }

    public function test_families_are_evaluated_separately(): void
    {
        $this->refresh();

        // An IPv4 client is never tested against a v6 network, and an
        // IPv4-mapped v6 address is a v6 address.
        $this->assertFalse($this->verifier()->ownsAddress('::ffff:66.249.64.5'));
    }

    public function test_a_non_host_address_is_not_a_question_it_can_answer(): void
    {
        $this->refresh();

        foreach (['66.249.64.0/27', 'nonsense', ''] as $input) {
            $this->assertNull($this->verifier()->ownsAddress($input));
        }
    }

    // -----------------------------------------------------------------
    // Missing, stale and corrupt data all mean "cannot check"
    // -----------------------------------------------------------------

    public function test_without_any_fetch_it_cannot_check(): void
    {
        // Never refreshed. Not a denial — a denial would claim we looked.
        $this->assertNull($this->verifier()->ownsAddress('66.249.64.5'));
    }

    public function test_stale_data_stops_verifying(): void
    {
        config()->set('security-guard.crawler_access.ranges.fresh_for_hours', 24);

        Carbon::setTestNow('2026-08-04 12:00:00');
        $this->refresh();
        $this->assertTrue($this->verifier()->ownsAddress('66.249.64.5'));

        Carbon::setTestNow('2026-08-05 13:00:00');
        $this->assertNull($this->verifier()->ownsAddress('66.249.64.5'));
    }

    public function test_a_provider_publishing_only_one_family_cannot_answer_for_the_other(): void
    {
        $this->fetcher->respond(
            'https://ranges.example.test/google.json',
            '{"creationTime":"2026-08-04T00:00:00Z","prefixes":[{"ipv4Prefix":"66.249.64.0/27"}]}',
        );
        $this->refresh();

        $this->assertTrue($this->verifier()->ownsAddress('66.249.64.5'));
        // No v6 list means no v6 opinion, rather than a false "not Google".
        $this->assertNull($this->verifier()->ownsAddress('2001:4860:4801:10::1'));
    }

    public function test_an_unparseable_stored_list_fails_closed(): void
    {
        $this->refresh();

        // Corrupt the stored payload behind the store's back, as a damaged
        // cache entry would.
        $cache = $this->app->make(SecurityGuardServiceProvider::CACHE);
        $keys = $this->app->make(CacheKeyFactory::class);
        $payload = $cache->get($keys->crawlerRanges('google'));
        $payload['v4'] = ['not-a-network', '999.0.0.0/8'];
        $cache->put($keys->crawlerRanges('google'), $payload, 3600);

        // A corrupted list must not read as "this address is not Google".
        $this->assertNull($this->verifier()->ownsAddress('66.249.64.5'));
    }

    // -----------------------------------------------------------------
    // Registry composition, end to end
    // -----------------------------------------------------------------

    public function test_a_confirmed_googlebot_verifies(): void
    {
        $this->refresh();

        $result = $this->registry()->classify(self::GOOGLEBOT_UA, '66.249.64.5');

        $this->assertTrue($result->isVerified());
        $this->assertSame(CrawlerProvider::GOOGLE, $result->provider);
    }

    public function test_a_spoofed_googlebot_is_unverified_not_verified(): void
    {
        $this->refresh();

        $result = $this->registry()->classify(self::GOOGLEBOT_UA, '203.0.113.10');

        $this->assertFalse($result->isVerified());
        $this->assertSame(CrawlerVerificationResult::UNVERIFIED, $result->state);
        $this->assertSame(
            CrawlerVerificationResult::REASON_ADDRESS_OUTSIDE_PUBLISHED_RANGES,
            $result->reason,
        );
    }

    public function test_a_googlebot_ua_from_bings_range_does_not_verify(): void
    {
        $this->refresh();

        // Claiming Google while coming from Bing's network is still a
        // failed claim; providers do not vouch for each other.
        $result = $this->registry()->classify(self::GOOGLEBOT_UA, '157.55.39.9');

        $this->assertFalse($result->isVerified());
    }

    public function test_a_confirmed_bingbot_verifies(): void
    {
        $this->refresh();

        $result = $this->registry()->classify(self::BINGBOT_UA, '157.55.39.9');

        $this->assertTrue($result->isVerified());
        $this->assertSame(CrawlerProvider::BING, $result->provider);
    }

    public function test_an_ordinary_browser_is_unknown(): void
    {
        $this->refresh();

        $result = $this->registry()->classify(self::BROWSER_UA, '66.249.64.5');

        // Even from Google's own network: no claim, no crawler treatment.
        $this->assertSame(CrawlerVerificationResult::UNKNOWN, $result->state);
    }

    public function test_a_missing_refresh_never_verifies_anyone(): void
    {
        // The fail-safe that matters most: an outage in the range data must
        // not turn "claims to be Googlebot" into "is Googlebot".
        $result = $this->registry()->classify(self::GOOGLEBOT_UA, '66.249.64.5');

        $this->assertFalse($result->isVerified());
        $this->assertSame(CrawlerVerificationResult::REASON_NO_RANGE_DATA, $result->reason);
    }

    // -----------------------------------------------------------------
    // Registration is configuration-driven
    // -----------------------------------------------------------------

    public function test_both_bundled_providers_are_registered_when_enabled(): void
    {
        $this->assertSame(
            [CrawlerProvider::GOOGLE, CrawlerProvider::BING],
            $this->registry()->providers(),
        );
    }

    public function test_a_disabled_provider_is_not_recognised_at_all(): void
    {
        config()->set('security-guard.crawler_access.verified_crawlers.bing', false);
        $this->app->forgetInstance(CrawlerVerifierRegistry::class);

        $registry = $this->registry();
        $this->assertSame([CrawlerProvider::GOOGLE], $registry->providers());

        $this->refresh();

        // Bing is now just another client: no claim is recognised, so it
        // falls through to whatever the normal policy is.
        $this->assertSame(
            CrawlerVerificationResult::UNKNOWN,
            $registry->classify(self::BINGBOT_UA, '157.55.39.9')->state,
        );
    }

    public function test_verification_performs_no_network_access(): void
    {
        $this->refresh();
        $before = count($this->fetcher->fetchedUrls());

        for ($i = 0; $i < 20; $i++) {
            $this->registry()->classify(self::GOOGLEBOT_UA, '66.249.64.5');
            $this->registry()->classify(self::BINGBOT_UA, '157.55.39.9');
        }

        // Request-path verification must never fetch. Both providers advise
        // caching results rather than resolving per request.
        $this->assertSame($before, count($this->fetcher->fetchedUrls()));
    }

    public function test_repeated_classification_is_stable(): void
    {
        $this->refresh();
        $verifier = $this->verifier();

        // The verifier memoises its parsed networks; the cache must not
        // change answers.
        for ($i = 0; $i < 5; $i++) {
            $this->assertTrue($verifier->ownsAddress('66.249.64.5'));
            $this->assertFalse($verifier->ownsAddress('203.0.113.10'));
        }
    }

    public function test_a_refreshed_document_replaces_the_memoised_parse(): void
    {
        $this->refresh();
        $verifier = $this->verifier();
        $this->assertTrue($verifier->ownsAddress('66.249.64.5'));

        // Google publishes a different set; the same verifier instance must
        // follow it rather than answering from the old parse.
        $this->fetcher->respond(
            'https://ranges.example.test/google.json',
            '{"creationTime":"2026-08-05T00:00:00Z","prefixes":[{"ipv4Prefix":"192.178.5.0/27"}]}',
        );
        $this->refresh();

        $this->assertFalse($verifier->ownsAddress('66.249.64.5'));
        $this->assertTrue($verifier->ownsAddress('192.178.5.5'));
    }
}
