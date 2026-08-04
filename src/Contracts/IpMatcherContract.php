<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Contracts;

interface IpMatcherContract
{
    /**
     * Decide whether a normalised address matches one of the given entries.
     *
     * v1 ships exact matching only. CIDR ranges, IPv6 subnets and trusted
     * internal networks can be added behind this contract without a breaking
     * change to callers.
     *
     * @param  array<int, string>  $entries
     */
    public function matches(string $normalizedIp, array $entries): bool;
}
