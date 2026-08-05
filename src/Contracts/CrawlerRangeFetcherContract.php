<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Contracts;

interface CrawlerRangeFetcherContract
{
    /**
     * Fetch the raw body of a published crawler range document.
     *
     * This is the only place in the package that talks to the network for
     * crawler data, and it is reached exclusively from the
     * `security-guard:crawler-ranges:refresh` command — never from request
     * handling. Implementations should keep timeouts short and may retry;
     * they must throw on any transport failure rather than return a partial
     * or empty body, because the caller treats a returned string as a
     * complete document worth validating.
     *
     * @throws \Throwable on any transport failure
     */
    public function fetch(string $url): string;
}
