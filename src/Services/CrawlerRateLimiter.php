<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Services;

use Apkk\LaravelSecurityGuard\Support\CacheKeyFactory;
use Illuminate\Cache\RateLimiter;
use Illuminate\Contracts\Config\Repository as ConfigRepository;

/**
 * Request counting for crawlers that verified.
 *
 * Separate from PublicRateLimiter in two ways that both matter.
 *
 * The counter is its own key space, so a crawler's traffic never consumes the
 * budget of the humans behind the same address, and a crawler reaching its own
 * ceiling never pushes a visitor over the public one. It is also keyed per
 * provider: Googlebot and Bingbot get a budget each rather than sharing one.
 *
 * Exceeding the limit does not persist a block. A search crawler that trips a
 * permanent block keeps getting 403s until someone notices and releases it,
 * which degrades crawling, index refresh and search presence — a far worse
 * outcome than the burst that caused it. The answer is 429 with Retry-After,
 * which is what the crawler is built to back off on. `permanent_block` is
 * therefore not an accepted action here, and a host that configures it gets
 * `reject_only` plus a doctor failure rather than silent obedience.
 */
class CrawlerRateLimiter
{
    /** 429 with Retry-After: the crawler backs off and returns. */
    public const ACTION_REJECT_ONLY = 'reject_only';

    /** 503 with Retry-After, for hosts that prefer it during overload. */
    public const ACTION_SERVICE_UNAVAILABLE = 'service_unavailable';

    public function __construct(
        private readonly RateLimiter $rateLimiter,
        private readonly CacheKeyFactory $cacheKeys,
        private readonly ConfigRepository $config,
    ) {}

    /**
     * Count one request from a verified crawler.
     *
     * @return array{allowed: bool, attempts: int, action: string, retry_after: int}
     */
    public function consume(string $provider, string $normalizedIp): array
    {
        $key = $this->cacheKeys->crawlerRequests($provider, $normalizedIp);
        $attempts = $this->rateLimiter->hit($key, 60);
        $limit = $this->limit();

        if ($attempts <= $limit) {
            return [
                'allowed' => true,
                'attempts' => $attempts,
                'action' => $this->action(),
                'retry_after' => 0,
            ];
        }

        return [
            'allowed' => false,
            'attempts' => $attempts,
            'action' => $this->action(),
            // Always present when rejecting: a crawler told to back off with
            // no interval has been told nothing useful.
            'retry_after' => max(1, $this->rateLimiter->availableIn($key)),
        ];
    }

    /**
     * @return array{attempts: int}
     */
    public function status(string $provider, string $normalizedIp): array
    {
        return [
            'attempts' => $this->rateLimiter->attempts(
                $this->cacheKeys->crawlerRequests($provider, $normalizedIp),
            ),
        ];
    }

    public function enabled(): bool
    {
        return (bool) $this->config->get('security-guard.enabled', true)
            && (bool) $this->config->get('security-guard.crawler_access.enabled', false);
    }

    public function limit(): int
    {
        return max(1, (int) $this->config->get(
            'security-guard.crawler_access.rate_limit.requests_per_minute',
            300,
        ));
    }

    /**
     * The configured action, with anything that would persist a block
     * downgraded to `reject_only`.
     *
     * Silently correcting a dangerous setting would hide it, so the doctor
     * reports the same condition as a failure. The correction exists so that
     * a misconfiguration cannot de-index a site while it goes unnoticed.
     */
    public function action(): string
    {
        $configured = (string) $this->config->get(
            'security-guard.crawler_access.rate_limit.action',
            self::ACTION_REJECT_ONLY,
        );

        return $configured === self::ACTION_SERVICE_UNAVAILABLE
            ? self::ACTION_SERVICE_UNAVAILABLE
            : self::ACTION_REJECT_ONLY;
    }

    /**
     * Is the configured action one this limiter refuses to honour?
     * Used by the doctor to report the misconfiguration.
     */
    public function actionWasDowngraded(): bool
    {
        $configured = (string) $this->config->get(
            'security-guard.crawler_access.rate_limit.action',
            self::ACTION_REJECT_ONLY,
        );

        return ! in_array($configured, [self::ACTION_REJECT_ONLY, self::ACTION_SERVICE_UNAVAILABLE], true);
    }

    /**
     * Is this provider one the host wants treated as a crawler?
     */
    public function providerEnabled(string $provider): bool
    {
        return (bool) $this->config->get(
            "security-guard.crawler_access.verified_crawlers.{$provider}",
            true,
        );
    }

    public function forget(string $provider, string $normalizedIp): void
    {
        $this->rateLimiter->clear($this->cacheKeys->crawlerRequests($provider, $normalizedIp));
    }
}
