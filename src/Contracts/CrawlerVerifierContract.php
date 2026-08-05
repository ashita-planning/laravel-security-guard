<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Contracts;

interface CrawlerVerifierContract
{
    /**
     * Stable provider identifier, e.g. `google`. Used in configuration,
     * cache keys and log context, so it must be identifier-shaped and must
     * not change between releases.
     */
    public function provider(): string;

    /**
     * Does this User-Agent claim to be this provider's crawler?
     *
     * Candidate extraction only. A match here must never grant anything by
     * itself — both Google and Bing document their User-Agent strings as
     * spoofable. The registry uses this to decide which verifier to consult,
     * nothing more.
     */
    public function claimsUserAgent(string $userAgent): bool;

    /**
     * Does the address belong to this provider, according to already-cached
     * published data?
     *
     *  - true   the address is inside the provider's published ranges
     *  - false  the address is provably outside them
     *  - null   no usable data: never fetched, expired, or unreadable
     *
     * Implementations must answer from cached data only. No DNS lookup and no
     * HTTP fetch may happen here — this runs inside request handling, and both
     * providers themselves advise caching verification results rather than
     * resolving per request. Refreshing the data belongs to the
     * `security-guard:crawler-ranges:refresh` command.
     */
    public function ownsAddress(string $normalizedIp): ?bool;
}
