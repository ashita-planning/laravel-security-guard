<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Crawlers;

use Apkk\LaravelSecurityGuard\Contracts\CrawlerRangeFetcherContract;
use Illuminate\Http\Client\Factory as HttpFactory;

/**
 * Fetches a published range document over HTTPS.
 *
 * Runs only inside the refresh command. Timeouts are short and retries are
 * few on purpose: this is a background maintenance fetch, and a hanging
 * provider endpoint must cost a failed refresh — which keeps the previous
 * data — rather than a stuck worker.
 */
class HttpCrawlerRangeFetcher implements CrawlerRangeFetcherContract
{
    public function __construct(private readonly HttpFactory $http) {}

    public function fetch(string $url): string
    {
        $response = $this->http
            ->connectTimeout(5)
            ->timeout(15)
            ->retry(2, 500, throw: false)
            ->accept('application/json')
            ->get($url);

        // A non-2xx answer throws; the caller must never see an error page
        // body as if it were a range document.
        $response->throw();

        return $response->body();
    }
}
