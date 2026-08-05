<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Tests\Fixtures;

use Apkk\LaravelSecurityGuard\Contracts\CrawlerRangeFetcherContract;
use RuntimeException;
use Throwable;

/**
 * Deterministic fetcher for refresh-pipeline tests: canned body or throwable
 * per URL, and a record of every URL asked for. Keeps every crawler test
 * offline, which the acceptance criteria require.
 */
final class FakeCrawlerRangeFetcher implements CrawlerRangeFetcherContract
{
    /** @var array<string, string|Throwable> */
    private array $responses = [];

    /** @var array<int, string> */
    private array $fetched = [];

    public function respond(string $url, string|Throwable $response): void
    {
        $this->responses[$url] = $response;
    }

    public function fetch(string $url): string
    {
        $this->fetched[] = $url;

        $response = $this->responses[$url] ?? new RuntimeException('unexpected url');

        if ($response instanceof Throwable) {
            throw $response;
        }

        return $response;
    }

    /**
     * @return array<int, string>
     */
    public function fetchedUrls(): array
    {
        return $this->fetched;
    }
}
