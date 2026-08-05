<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Tests\Unit;

use Apkk\LaravelSecurityGuard\Contracts\CrawlerVerifierContract;
use Apkk\LaravelSecurityGuard\Crawlers\CrawlerProvider;
use Apkk\LaravelSecurityGuard\Crawlers\CrawlerUserAgents;
use Apkk\LaravelSecurityGuard\Crawlers\CrawlerVerifierRegistry;
use Apkk\LaravelSecurityGuard\Data\CrawlerVerificationResult;
use Apkk\LaravelSecurityGuard\Support\FailureLogger;
use Closure;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use RuntimeException;

/**
 * The classification model, ahead of any middleware integration.
 *
 * The property everything else hangs on: `verified` exists only when a
 * verifier positively confirms the address from published data. A User-Agent
 * alone, a missing range list, an unresolved client address or a broken
 * verifier all degrade to `unverified` — normal policy, never privilege.
 */
class CrawlerClassificationTest extends TestCase
{
    private const GOOGLEBOT_UA = 'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; '
        .'Googlebot/2.1; +http://www.google.com/bot.html) Chrome/125.0.0.0 Safari/537.36';

    private const BINGBOT_UA = 'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; '
        .'bingbot/2.0; +http://www.bing.com/bingbot.htm) Chrome/116.0.1938.76 Safari/537.36';

    private const BROWSER_UA = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 '
        .'(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36';

    private function registry(): CrawlerVerifierRegistry
    {
        return new CrawlerVerifierRegistry(new FailureLogger(new NullLogger));
    }

    /**
     * @param  bool|null|Closure(): (bool|null)  $owns
     */
    private function verifier(string $provider, bool|null|Closure $owns): CrawlerVerifierContract
    {
        return new class($provider, $owns) implements CrawlerVerifierContract
        {
            public function __construct(
                private readonly string $providerId,
                private readonly mixed $owns,
            ) {}

            public function provider(): string
            {
                return $this->providerId;
            }

            public function claimsUserAgent(string $userAgent): bool
            {
                return CrawlerUserAgents::claimedProvider($userAgent) === $this->providerId;
            }

            public function ownsAddress(string $normalizedIp): ?bool
            {
                return $this->owns instanceof Closure ? ($this->owns)() : $this->owns;
            }
        };
    }

    // -----------------------------------------------------------------
    // User-Agent candidate extraction
    // -----------------------------------------------------------------

    #[DataProvider('userAgentClaims')]
    public function test_it_extracts_the_claimed_provider(?string $userAgent, ?string $expected): void
    {
        $this->assertSame($expected, CrawlerUserAgents::claimedProvider($userAgent));
    }

    /**
     * @return array<string, array{string|null, string|null}>
     */
    public static function userAgentClaims(): array
    {
        return [
            'googlebot desktop' => [self::GOOGLEBOT_UA, CrawlerProvider::GOOGLE],
            'googlebot image variant' => ['Googlebot-Image/1.0', CrawlerProvider::GOOGLE],
            'case-insensitive' => ['GOOGLEBOT/2.1', CrawlerProvider::GOOGLE],
            'bingbot' => [self::BINGBOT_UA, CrawlerProvider::BING],
            'ordinary browser' => [self::BROWSER_UA, null],
            'generic scraper' => ['python-requests/2.32', null],
            'null' => [null, null],
            'empty' => ['', null],
        ];
    }

    public function test_a_hostile_ua_containing_the_needle_is_only_ever_a_candidate(): void
    {
        // Extraction is allowed to be loose because a claim grants nothing:
        // this UA becomes a candidate, fails verification, and lands on the
        // normal public policy.
        $this->assertSame(
            CrawlerProvider::GOOGLE,
            CrawlerUserAgents::claimedProvider('definitely-not-googlebot-honest'),
        );
    }

    public function test_an_oversized_ua_header_is_truncated_before_inspection(): void
    {
        // The needle sits beyond the inspected window, so a megabyte header
        // cannot force a scan of itself.
        $oversized = str_repeat('a', 2048).'googlebot';

        $this->assertNull(CrawlerUserAgents::claimedProvider($oversized));
    }

    // -----------------------------------------------------------------
    // Classification composition
    // -----------------------------------------------------------------

    public function test_everything_is_unknown_while_no_verifier_is_registered(): void
    {
        $registry = $this->registry();

        foreach ([self::GOOGLEBOT_UA, self::BINGBOT_UA, self::BROWSER_UA] as $ua) {
            $this->assertSame(
                CrawlerVerificationResult::UNKNOWN,
                $registry->classify($ua, '203.0.113.10')->state,
            );
        }
    }

    public function test_a_browser_is_unknown_even_with_verifiers_registered(): void
    {
        $registry = $this->registry();
        $registry->register($this->verifier(CrawlerProvider::GOOGLE, true));

        $result = $registry->classify(self::BROWSER_UA, '203.0.113.10');

        $this->assertSame(CrawlerVerificationResult::UNKNOWN, $result->state);
        $this->assertNull($result->provider);
        $this->assertFalse($result->claimsToBeACrawler());
    }

    public function test_a_confirmed_address_verifies(): void
    {
        $registry = $this->registry();
        $registry->register($this->verifier(CrawlerProvider::GOOGLE, true));

        $result = $registry->classify(self::GOOGLEBOT_UA, '66.249.64.5');

        $this->assertTrue($result->isVerified());
        $this->assertSame(CrawlerProvider::GOOGLE, $result->provider);
        $this->assertSame(CrawlerVerificationResult::REASON_ADDRESS_IN_PUBLISHED_RANGE, $result->reason);
    }

    public function test_an_address_outside_the_ranges_is_unverified(): void
    {
        $registry = $this->registry();
        $registry->register($this->verifier(CrawlerProvider::GOOGLE, false));

        $result = $registry->classify(self::GOOGLEBOT_UA, '203.0.113.10');

        $this->assertSame(CrawlerVerificationResult::UNVERIFIED, $result->state);
        $this->assertSame(CrawlerVerificationResult::REASON_ADDRESS_OUTSIDE_PUBLISHED_RANGES, $result->reason);
        $this->assertTrue($result->claimsToBeACrawler());
        $this->assertFalse($result->isVerified());
    }

    public function test_missing_range_data_never_verifies(): void
    {
        // The fail-safe that matters most: an outage in the range data must
        // not turn "claims to be Googlebot" into "is Googlebot".
        $registry = $this->registry();
        $registry->register($this->verifier(CrawlerProvider::GOOGLE, null));

        $result = $registry->classify(self::GOOGLEBOT_UA, '203.0.113.10');

        $this->assertSame(CrawlerVerificationResult::UNVERIFIED, $result->state);
        $this->assertSame(CrawlerVerificationResult::REASON_NO_RANGE_DATA, $result->reason);
    }

    public function test_an_unresolved_client_address_is_unverified_without_consulting_the_verifier(): void
    {
        $registry = $this->registry();
        $registry->register($this->verifier(CrawlerProvider::GOOGLE, function (): bool {
            throw new RuntimeException('ownsAddress must not be called without an address.');
        }));

        foreach ([null, ''] as $ip) {
            $result = $registry->classify(self::GOOGLEBOT_UA, $ip);

            $this->assertSame(CrawlerVerificationResult::UNVERIFIED, $result->state);
            $this->assertSame(CrawlerVerificationResult::REASON_UNRESOLVED_CLIENT_ADDRESS, $result->reason);
        }
    }

    public function test_a_throwing_verifier_degrades_to_unverified_instead_of_raising(): void
    {
        $registry = $this->registry();
        $registry->register($this->verifier(CrawlerProvider::GOOGLE, function (): bool {
            throw new RuntimeException('range cache exploded');
        }));

        // This will run inside request handling later; it must neither 500
        // nor verify.
        $result = $registry->classify(self::GOOGLEBOT_UA, '203.0.113.10');

        $this->assertSame(CrawlerVerificationResult::UNVERIFIED, $result->state);
        $this->assertSame(CrawlerVerificationResult::REASON_NO_RANGE_DATA, $result->reason);
    }

    public function test_a_broken_claim_check_does_not_mask_other_providers(): void
    {
        $registry = $this->registry();
        $registry->register(new class implements CrawlerVerifierContract
        {
            public function provider(): string
            {
                return 'broken';
            }

            public function claimsUserAgent(string $userAgent): bool
            {
                throw new RuntimeException('claim matcher exploded');
            }

            public function ownsAddress(string $normalizedIp): ?bool
            {
                return null;
            }
        });
        $registry->register($this->verifier(CrawlerProvider::BING, true));

        $result = $registry->classify(self::BINGBOT_UA, '157.55.39.9');

        $this->assertTrue($result->isVerified());
        $this->assertSame(CrawlerProvider::BING, $result->provider);
    }

    public function test_providers_are_listed_and_resolvable(): void
    {
        $registry = $this->registry();
        $google = $this->verifier(CrawlerProvider::GOOGLE, true);
        $registry->register($google);
        $registry->register($this->verifier(CrawlerProvider::BING, true));

        $this->assertSame([CrawlerProvider::GOOGLE, CrawlerProvider::BING], $registry->providers());
        $this->assertSame($google, $registry->verifierFor(CrawlerProvider::GOOGLE));
        $this->assertNull($registry->verifierFor('yandex'));
    }

    public function test_each_provider_only_answers_for_its_own_claim(): void
    {
        $registry = $this->registry();
        $registry->register($this->verifier(CrawlerProvider::GOOGLE, function (): bool {
            throw new RuntimeException('google verifier must not see a bingbot claim');
        }));
        $registry->register($this->verifier(CrawlerProvider::BING, true));

        $this->assertSame(CrawlerProvider::BING, $registry->classify(self::BINGBOT_UA, '157.55.39.9')->provider);
    }
}
