<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Crawlers;

use Apkk\LaravelSecurityGuard\Contracts\CrawlerVerifierContract;
use Apkk\LaravelSecurityGuard\Support\IpRange;

/**
 * Verifies a crawler against the provider's published IP ranges.
 *
 * Both Google and Bing publish their crawler ranges as a document of CIDR
 * networks, so both bundled verifiers are this one class with a different
 * provider id. Reverse/forward DNS is the alternative both providers also
 * document, but it cannot happen here — this runs inside request handling,
 * and both vendors advise against resolving per request. Range data is
 * refreshed out of band by `security-guard:crawler-ranges:refresh`.
 *
 * Three answers, and the difference between the last two matters:
 *
 *  - `true`   the address is inside a published network
 *  - `false`  the address is provably outside every published network
 *  - `null`   there is nothing trustworthy to compare against
 *
 * `null` is not "no", because the caller turns it into `unverified` with a
 * reason that distinguishes "we checked and it wasn't Google" from "we could
 * not check". Both deny crawler treatment; only one of them means someone
 * should go look at the refresh job.
 */
class PublishedRangeCrawlerVerifier implements CrawlerVerifierContract
{
    /** @var array<string, array<int, IpRange>>|null parsed ranges, per family */
    private ?array $parsed = null;

    private ?string $parsedFingerprint = null;

    public function __construct(
        private readonly string $provider,
        private readonly CrawlerRangeStore $store,
    ) {}

    public function provider(): string
    {
        return $this->provider;
    }

    public function claimsUserAgent(string $userAgent): bool
    {
        return CrawlerUserAgents::claimedProvider($userAgent) === $this->provider;
    }

    public function ownsAddress(string $normalizedIp): ?bool
    {
        $candidate = IpRange::parse($normalizedIp);

        if ($candidate === null || ! $candidate->isSingleHost()) {
            // A client address is one host. Anything else is not a question
            // this verifier can answer.
            return null;
        }

        $ranges = $this->store->freshRanges($this->provider);

        if ($ranges === null) {
            // Never fetched, or past its freshness window. Not a denial.
            return null;
        }

        // Only the candidate's own family is consulted: an IPv4 address is
        // never tested against an IPv6 network, and a provider publishing
        // only v6 answers `null` for a v4 client rather than a false `no`.
        $family = $candidate->family() === IpRange::FAMILY_V4 ? 'v4' : 'v6';
        $networks = $this->networksFor($ranges, $family);

        if ($networks === null) {
            return null;
        }

        foreach ($networks as $network) {
            if ($network->contains($normalizedIp)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Parsed networks for one family, memoised for the life of the process.
     *
     * Returns null when the stored list for that family is empty or entirely
     * unparseable — fail closed: a corrupted list must not read as "this
     * address is not Google", which would be a claim we cannot support.
     *
     * @param  array{v4: array<int, string>, v6: array<int, string>}  $ranges
     * @return array<int, IpRange>|null
     */
    private function networksFor(array $ranges, string $family): ?array
    {
        // The refresh command replaces the stored document wholesale, so the
        // cached parse is keyed on the content it came from.
        $fingerprint = hash('sha256', implode(',', $ranges['v4']).'|'.implode(',', $ranges['v6']));

        if ($this->parsedFingerprint !== $fingerprint) {
            $this->parsed = null;
            $this->parsedFingerprint = $fingerprint;
        }

        if (! isset($this->parsed[$family])) {
            $this->parsed[$family] = array_values(array_filter(array_map(
                static fn (string $entry): ?IpRange => IpRange::parse($entry),
                $ranges[$family],
            )));
        }

        return $this->parsed[$family] === [] ? null : $this->parsed[$family];
    }
}
