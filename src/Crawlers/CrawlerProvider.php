<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Crawlers;

/**
 * Identifiers of the crawler providers this package ships knowledge of.
 *
 * These strings appear in configuration, cache keys and log context, so they
 * are fixed here rather than typed inline. Hosts can register additional
 * providers on the registry under their own identifiers; nothing below is a
 * closed list.
 */
final class CrawlerProvider
{
    public const GOOGLE = 'google';

    public const BING = 'bing';

    /**
     * @return array<int, string>
     */
    public static function bundled(): array
    {
        return [self::GOOGLE, self::BING];
    }
}
