<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Crawlers;

/**
 * User-Agent needles for candidate extraction.
 *
 * A match here means "this request claims to be that crawler" and nothing
 * else. The needles are deliberately loose substrings: `googlebot` catches
 * Googlebot-Image and friends, and a hostile UA containing the word costs
 * nothing, because an unconfirmed claim falls back to the normal public
 * policy rather than gaining anything.
 */
final class CrawlerUserAgents
{
    /**
     * A UA header is attacker-controlled; cap what we inspect so a
     * megabyte-long header cannot buy CPU time in candidate extraction.
     */
    private const MAX_INSPECTED_LENGTH = 1024;

    /**
     * Lower-case substrings per provider, matched in declaration order.
     *
     * @var array<string, array<int, string>>
     */
    private const CLAIMS = [
        CrawlerProvider::GOOGLE => ['googlebot'],
        CrawlerProvider::BING => ['bingbot'],
    ];

    /**
     * Which bundled provider, if any, this User-Agent claims to be.
     */
    public static function claimedProvider(?string $userAgent): ?string
    {
        if ($userAgent === null || $userAgent === '') {
            return null;
        }

        $haystack = strtolower(substr($userAgent, 0, self::MAX_INSPECTED_LENGTH));

        foreach (self::CLAIMS as $provider => $needles) {
            foreach ($needles as $needle) {
                if (str_contains($haystack, $needle)) {
                    return $provider;
                }
            }
        }

        return null;
    }

    /**
     * @return array<int, string>
     */
    public static function needlesFor(string $provider): array
    {
        return self::CLAIMS[$provider] ?? [];
    }
}
