<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Services;

use Apkk\LaravelSecurityGuard\Contracts\IpMatcherContract;
use Apkk\LaravelSecurityGuard\Support\Ip;
use Apkk\LaravelSecurityGuard\Support\IpRange;

/**
 * Matches an address against exact entries and CIDR networks alike.
 *
 * Replaces ExactIpMatcher as the default in v0.2.0. Exact behaviour is
 * unchanged: a bare address is simply a rule with the widest prefix for its
 * family, so every v0.1.x entry keeps matching exactly what it matched before.
 *
 * An unparseable entry is skipped rather than treated as a wildcard. A typo in
 * an allowlist must fail closed — the alternative is a malformed line quietly
 * admitting everyone.
 */
class CidrIpMatcher implements IpMatcherContract
{
    /** @var array<string, IpRange|false> */
    private array $parsed = [];

    public function matches(string $normalizedIp, array $entries): bool
    {
        $candidate = Ip::normalize($normalizedIp);

        if ($candidate === null) {
            return false;
        }

        foreach ($entries as $entry) {
            if (! is_string($entry)) {
                continue;
            }

            $range = $this->range($entry);

            if ($range !== null && $range->contains($candidate)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Parsing happens on every request through the middleware, so results are
     * memoised per entry string for the life of the process.
     */
    private function range(string $entry): ?IpRange
    {
        if (! array_key_exists($entry, $this->parsed)) {
            $this->parsed[$entry] = IpRange::parse($entry) ?? false;
        }

        $range = $this->parsed[$entry];

        return $range === false ? null : $range;
    }
}
