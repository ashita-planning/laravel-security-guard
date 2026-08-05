<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Crawlers;

use Apkk\LaravelSecurityGuard\Support\CacheKeyFactory;
use Apkk\LaravelSecurityGuard\Support\FailureLogger;
use Illuminate\Contracts\Cache\Repository as CacheRepository;
use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Support\Carbon;
use RuntimeException;
use Throwable;

/**
 * Holds the validated range data the verifiers answer from.
 *
 * Two clocks govern an entry. Data is *fresh* for `fresh_for_hours` — only
 * fresh data may verify a crawler. It is then *retained* for
 * `retain_for_days`: stale data verifies nobody, but stays readable so the
 * doctor can say "your ranges are three weeks old" instead of "you have no
 * ranges", which are different problems with different fixes.
 *
 * Writes go through a staging key first. The payload is written to staging,
 * read back, and only a byte-identical readback is promoted to the live key.
 * A store that mangles the payload — serialization limits, a proxy cache, a
 * flaky driver — therefore fails the refresh and keeps yesterday's data,
 * rather than replacing known-good ranges with something that came back
 * different from what was written.
 */
class CrawlerRangeStore
{
    public const OUTCOME_STORED = 'stored';

    public const OUTCOME_UNCHANGED = 'unchanged';

    private const STAGING_TTL_SECONDS = 600;

    public function __construct(
        private readonly CacheRepository $cache,
        private readonly CacheKeyFactory $cacheKeys,
        private readonly ConfigRepository $config,
        private readonly FailureLogger $failureLogger,
    ) {}

    /**
     * Persist a validated document for a provider.
     *
     * @param  array{creation_time: string|null, v4: array<int, string>, v6: array<int, string>}  $parsed
     * @return self::OUTCOME_STORED|self::OUTCOME_UNCHANGED
     *
     * @throws Throwable when the write cannot be confirmed; the previous
     *                   data is left in place in that case
     */
    public function store(string $provider, array $parsed, string $sourceUrl, string $contentHash): string
    {
        $current = $this->current($provider);
        $unchanged = $current !== null && $current['content_hash'] === $contentHash;

        $now = Carbon::now();

        $payload = [
            'provider' => $provider,
            'source' => $sourceUrl,
            'fetched_at' => $now->toIso8601String(),
            'fresh_until' => $now->copy()->addHours($this->freshForHours())->toIso8601String(),
            'content_hash' => $contentHash,
            'creation_time' => $parsed['creation_time'],
            'v4' => $parsed['v4'],
            'v6' => $parsed['v6'],
        ];

        $stagingKey = $this->cacheKeys->crawlerRangesStaging($provider);

        $this->cache->put($stagingKey, $payload, self::STAGING_TTL_SECONDS);

        $readback = $this->cache->get($stagingKey);

        if (! is_array($readback) || ($readback['content_hash'] ?? null) !== $contentHash) {
            $this->cache->forget($stagingKey);

            throw new RuntimeException(
                'The staged range payload did not read back intact; the previous data was kept.',
            );
        }

        // Promotion is a single put on the live key — atomic per key on every
        // shared store — so a reader sees either the old document or the new
        // one, never a mixture.
        $this->cache->put(
            $this->cacheKeys->crawlerRanges($provider),
            $readback,
            $this->retainForDays() * 86_400,
        );

        $this->cache->forget($stagingKey);

        return $unchanged ? self::OUTCOME_UNCHANGED : self::OUTCOME_STORED;
    }

    /**
     * The stored payload, fresh or stale. For the doctor and the CLI.
     *
     * @return array{provider: string, source: string, fetched_at: string, fresh_until: string, content_hash: string, creation_time: string|null, v4: array<int, string>, v6: array<int, string>}|null
     */
    public function current(string $provider): ?array
    {
        try {
            $raw = $this->cache->get($this->cacheKeys->crawlerRanges($provider));
        } catch (Throwable $exception) {
            $this->failureLogger->once('Crawler range data could not be read.', $exception, [
                'provider' => $provider,
            ]);

            return null;
        }

        return $this->normalize($raw);
    }

    /**
     * The ranges a verifier may trust, or null when there is nothing fresh.
     *
     * Stale data returns null on purpose: expired ranges must stop verifying
     * crawlers, and the resulting `unverified` means normal policy — the
     * failure of this subsystem never widens access.
     *
     * @return array{v4: array<int, string>, v6: array<int, string>}|null
     */
    public function freshRanges(string $provider): ?array
    {
        $payload = $this->current($provider);

        if ($payload === null) {
            return null;
        }

        try {
            $freshUntil = new Carbon($payload['fresh_until']);
        } catch (Throwable) {
            return null;
        }

        if (Carbon::now()->greaterThan($freshUntil)) {
            return null;
        }

        return ['v4' => $payload['v4'], 'v6' => $payload['v6']];
    }

    /**
     * Reject anything that does not look like a payload this class wrote.
     *
     * @return array{provider: string, source: string, fetched_at: string, fresh_until: string, content_hash: string, creation_time: string|null, v4: array<int, string>, v6: array<int, string>}|null
     */
    private function normalize(mixed $raw): ?array
    {
        if (! is_array($raw)) {
            return null;
        }

        foreach (['provider', 'source', 'fetched_at', 'fresh_until', 'content_hash'] as $key) {
            if (! isset($raw[$key]) || ! is_string($raw[$key])) {
                return null;
            }
        }

        foreach (['v4', 'v6'] as $key) {
            if (! isset($raw[$key]) || ! is_array($raw[$key])) {
                return null;
            }
        }

        return [
            'provider' => $raw['provider'],
            'source' => $raw['source'],
            'fetched_at' => $raw['fetched_at'],
            'fresh_until' => $raw['fresh_until'],
            'content_hash' => $raw['content_hash'],
            'creation_time' => isset($raw['creation_time']) && is_string($raw['creation_time'])
                ? $raw['creation_time']
                : null,
            'v4' => array_values(array_filter($raw['v4'], 'is_string')),
            'v6' => array_values(array_filter($raw['v6'], 'is_string')),
        ];
    }

    private function freshForHours(): int
    {
        return max(1, (int) $this->config->get('security-guard.crawler_access.ranges.fresh_for_hours', 168));
    }

    private function retainForDays(): int
    {
        return max(1, (int) $this->config->get('security-guard.crawler_access.ranges.retain_for_days', 30));
    }
}
