<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Services;

use Apkk\LaravelSecurityGuard\Contracts\IpMatcherContract;
use Apkk\LaravelSecurityGuard\Support\Ip;

/**
 * Exact matching after normalisation, so `::1` matches `0:0:0:0:0:0:0:1`.
 *
 * Entries that are not valid addresses are ignored rather than treated as
 * wildcards.
 *
 * This was the default through v0.1.x. CidrIpMatcher replaced it in v0.2.0 and
 * is a superset — a bare address behaves identically under both. Bind this one
 * explicitly only to refuse CIDR entries outright:
 *
 *     $this->app->singleton(IpMatcherContract::class, ExactIpMatcher::class);
 *
 * Note that doing so makes a CIDR entry match nothing at all, silently.
 */
class ExactIpMatcher implements IpMatcherContract
{
    public function matches(string $normalizedIp, array $entries): bool
    {
        foreach ($entries as $entry) {
            if (! is_string($entry)) {
                continue;
            }

            if (Ip::normalize($entry) === $normalizedIp) {
                return true;
            }
        }

        return false;
    }
}
