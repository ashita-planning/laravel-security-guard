<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Tests\Fixtures;

use Apkk\LaravelSecurityGuard\Contracts\CrawlerVerifierContract;
use Closure;

/**
 * A verifier that counts how it is used.
 *
 * `$owns` decides what ownsAddress() answers: a fixed bool or null, or a
 * Closure for behaviour like throwing — which is how the failure-path tests
 * simulate a verifier whose data source is down.
 */
final class SpyCrawlerVerifier implements CrawlerVerifierContract
{
    public int $claimCalls = 0;

    public int $ownsCalls = 0;

    public function __construct(
        private readonly string $provider = 'spy',
        private readonly string $claimToken = 'SpyBot',
        private readonly Closure|bool|null $owns = null,
    ) {}

    public function provider(): string
    {
        return $this->provider;
    }

    public function claimsUserAgent(string $userAgent): bool
    {
        $this->claimCalls++;

        return str_contains($userAgent, $this->claimToken);
    }

    public function ownsAddress(string $normalizedIp): ?bool
    {
        $this->ownsCalls++;

        if ($this->owns instanceof Closure) {
            return ($this->owns)($normalizedIp);
        }

        return $this->owns;
    }
}
