<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Crawlers;

use Apkk\LaravelSecurityGuard\Contracts\CrawlerVerifierContract;
use Apkk\LaravelSecurityGuard\Data\CrawlerVerificationResult;
use Apkk\LaravelSecurityGuard\Support\FailureLogger;
use Throwable;

/**
 * Provider name to verifier resolution, and the one place classification
 * composes.
 *
 * The composition rule is fixed: `verified` exists only when a verifier
 * positively confirms the address from its cached published data. Every
 * failure mode — an unresolved client address, missing range data, a verifier
 * throwing — degrades to `unverified`, which downstream means the normal
 * public policy. No failure path may widen access.
 *
 * Bundled verifiers (Google, Bing) register themselves in a later stage;
 * hosts can register their own providers the same way.
 */
class CrawlerVerifierRegistry
{
    /** @var array<string, CrawlerVerifierContract> keyed by provider id */
    private array $verifiers = [];

    public function __construct(private readonly FailureLogger $failureLogger) {}

    public function register(CrawlerVerifierContract $verifier): void
    {
        $this->verifiers[$verifier->provider()] = $verifier;
    }

    /**
     * @return array<int, string>
     */
    public function providers(): array
    {
        return array_keys($this->verifiers);
    }

    public function verifierFor(string $provider): ?CrawlerVerifierContract
    {
        return $this->verifiers[$provider] ?? null;
    }

    /**
     * Classify one request.
     *
     * With no verifiers registered every request is `unknown`, which is what
     * makes shipping this class ahead of the middleware integration safe: it
     * exists, it resolves, and it changes nothing.
     */
    public function classify(?string $userAgent, ?string $normalizedIp): CrawlerVerificationResult
    {
        $claimant = $this->claimant($userAgent);

        if ($claimant === null) {
            return CrawlerVerificationResult::unknown();
        }

        $provider = $claimant->provider();

        if ($normalizedIp === null || $normalizedIp === '') {
            // No address to check means no confirmation is possible. The
            // verifier is deliberately not consulted.
            return CrawlerVerificationResult::unverified(
                $provider,
                CrawlerVerificationResult::REASON_UNRESOLVED_CLIENT_ADDRESS,
            );
        }

        try {
            $owns = $claimant->ownsAddress($normalizedIp);
        } catch (Throwable $exception) {
            // A broken verifier must not 500 the request it runs inside of,
            // and it must not verify anyone either.
            $this->failureLogger->once('Crawler verifier failed while checking an address.', $exception, [
                'provider' => $provider,
            ]);

            return CrawlerVerificationResult::unverified(
                $provider,
                CrawlerVerificationResult::REASON_NO_RANGE_DATA,
            );
        }

        return match ($owns) {
            true => CrawlerVerificationResult::verified($provider),
            false => CrawlerVerificationResult::unverified(
                $provider,
                CrawlerVerificationResult::REASON_ADDRESS_OUTSIDE_PUBLISHED_RANGES,
            ),
            default => CrawlerVerificationResult::unverified(
                $provider,
                CrawlerVerificationResult::REASON_NO_RANGE_DATA,
            ),
        };
    }

    /**
     * The first registered verifier whose User-Agent claim matches.
     */
    private function claimant(?string $userAgent): ?CrawlerVerifierContract
    {
        if ($userAgent === null || $userAgent === '') {
            return null;
        }

        foreach ($this->verifiers as $verifier) {
            try {
                if ($verifier->claimsUserAgent($userAgent)) {
                    return $verifier;
                }
            } catch (Throwable $exception) {
                // Treat a throwing claim check as "does not claim" and keep
                // going: one broken provider must not mask the others.
                $this->failureLogger->once('Crawler verifier failed while matching a User-Agent.', $exception, [
                    'provider' => $verifier->provider(),
                ]);
            }
        }

        return null;
    }
}
