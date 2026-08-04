<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Services;

use Apkk\LaravelSecurityGuard\Contracts\BlockedIpRepositoryContract;
use Apkk\LaravelSecurityGuard\Contracts\IpMatcherContract;
use Apkk\LaravelSecurityGuard\Contracts\SecurityEventDispatcherContract;
use Apkk\LaravelSecurityGuard\Data\ActorData;
use Apkk\LaravelSecurityGuard\Data\BlockedIpRecord;
use Apkk\LaravelSecurityGuard\Data\BlockIpData;
use Apkk\LaravelSecurityGuard\Data\BlockOperationResult;
use Apkk\LaravelSecurityGuard\Data\SecurityEventData;
use Apkk\LaravelSecurityGuard\Events\IpBlocked;
use Apkk\LaravelSecurityGuard\Events\IpReleased;
use Apkk\LaravelSecurityGuard\Support\CacheKeyFactory;
use Apkk\LaravelSecurityGuard\Support\FailureLogger;
use Apkk\LaravelSecurityGuard\Support\Ip;
use Illuminate\Cache\RateLimiter;
use Illuminate\Contracts\Cache\Repository as CacheRepository;
use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Events\Dispatcher as EventDispatcher;
use Throwable;

/**
 * Persistent IP blocking: the decision layer between the middleware and the
 * repository.
 *
 * Read paths fail open, because a cache or database outage must not take the
 * whole site down. Write paths surface their failure to the caller, which is
 * what lets the middleware still return a fixed 403 for an unmistakable attack
 * path even when the row cannot be stored.
 */
class IpBlockService
{
    public function __construct(
        private readonly BlockedIpRepositoryContract $repository,
        private readonly CacheRepository $cache,
        private readonly ConfigRepository $config,
        private readonly EventDispatcher $events,
        private readonly SecurityEventDispatcherContract $securityEvents,
        private readonly IpMatcherContract $ipMatcher,
        private readonly RateLimiter $rateLimiter,
        private readonly CacheKeyFactory $cacheKeys,
        private readonly FailureLogger $failureLogger,
    ) {}

    public function isIgnored(?string $ipAddress): bool
    {
        $normalized = Ip::normalize($ipAddress);

        if ($normalized === null) {
            // An unresolvable address is never blocked, so treat it as ignored.
            return true;
        }

        return $this->ipMatcher->matches(
            $normalized,
            array_values((array) $this->config->get('security-guard.permanent_block.ignored_ips', [])),
        );
    }

    public function isBlocked(string $ipAddress): bool
    {
        $normalized = Ip::normalize($ipAddress);

        if ($normalized === null || $this->isIgnored($normalized)) {
            return false;
        }

        if ($this->hasTemporaryBlock($normalized)) {
            return true;
        }

        $lookup = fn (): bool => $this->repository->findActive($normalized) !== null;

        try {
            return (bool) $this->cache->remember(
                $this->cacheKeys->block($normalized),
                $this->cacheSeconds(),
                $lookup,
            );
        } catch (Throwable $exception) {
            $this->failureLogger->once('Block cache read failed, falling back to the database.', $exception);
        }

        try {
            return $lookup();
        } catch (Throwable $exception) {
            // Fail open: a database outage must not reject every visitor.
            $this->failureLogger->once('Block lookup failed, allowing the request.', $exception);

            return false;
        }
    }

    /**
     * Persist a block. Returns null when the address is ignored or invalid.
     *
     * The repository, not this method, decides whether the call newly blocked
     * the address; a read here followed by a write would let two concurrent
     * probes both announce the same block.
     *
     * @throws Throwable when the record cannot be stored
     */
    public function block(
        string $ipAddress,
        string $reasonCode,
        ?string $matchedPattern = null,
        int $requestCount = 1,
    ): ?BlockOperationResult {
        $normalized = Ip::normalize($ipAddress);

        if ($normalized === null || $this->isIgnored($normalized)) {
            return null;
        }

        $result = $this->repository->block(new BlockIpData(
            ipAddress: $normalized,
            reasonCode: $reasonCode,
            matchedPattern: $matchedPattern,
            requestCount: $requestCount,
        ));

        $this->rememberBlocked($normalized);

        $this->events->dispatch(new IpBlocked($result->record, $result->isNewBlock));

        if ($result->isNewBlock) {
            // Notification failure must never undo a successful block.
            try {
                $this->securityEvents->dispatch(SecurityEventData::ipBlocked($result->record));
            } catch (Throwable $exception) {
                $this->failureLogger->once('Security event dispatch failed.', $exception);
            }
        }

        return $result;
    }

    /**
     * Reject the current request without persisting anything, for
     * `action = temporary_block`.
     */
    public function blockTemporarily(string $ipAddress, int $minutes): bool
    {
        $normalized = Ip::normalize($ipAddress);

        if ($normalized === null || $this->isIgnored($normalized)) {
            return false;
        }

        try {
            $this->cache->put($this->cacheKeys->temporaryBlock($normalized), true, max(1, $minutes) * 60);

            return true;
        } catch (Throwable $exception) {
            $this->failureLogger->once('Temporary block write failed.', $exception);

            return false;
        }
    }

    public function release(string $ipAddress, ?ActorData $actor = null): bool
    {
        $normalized = Ip::normalize($ipAddress);

        if ($normalized === null) {
            return false;
        }

        $released = $this->repository->release($normalized, $actor);

        // Clear the caches even when no row was active: a stale positive cache
        // entry or leftover counter would keep the address locked out.
        $this->forgetCaches($normalized);

        if ($released) {
            $this->events->dispatch(new IpReleased($normalized, $actor));
        }

        return $released;
    }

    public function findActive(string $ipAddress): ?BlockedIpRecord
    {
        $normalized = Ip::normalize($ipAddress);

        return $normalized === null ? null : $this->repository->findActive($normalized);
    }

    public function find(string $ipAddress): ?BlockedIpRecord
    {
        $normalized = Ip::normalize($ipAddress);

        return $normalized === null ? null : $this->repository->find($normalized);
    }

    /**
     * @param  array{active?: bool, ip_address?: string|null}  $filters
     * @return array{items: array<int, BlockedIpRecord>, total: int, page: int, per_page: int}
     */
    public function paginate(array $filters = [], int $perPage = 50, int $page = 1): array
    {
        return $this->repository->paginate($filters, $perPage, $page);
    }

    public function forgetCaches(string $normalizedIp): void
    {
        try {
            $this->cache->forget($this->cacheKeys->block($normalizedIp));
            $this->cache->forget($this->cacheKeys->temporaryBlock($normalizedIp));
        } catch (Throwable $exception) {
            $this->failureLogger->once('Block cache clear failed.', $exception);
        }

        try {
            $this->rateLimiter->clear($this->cacheKeys->publicRequests($normalizedIp));
        } catch (Throwable $exception) {
            $this->failureLogger->once('Public request counter clear failed.', $exception);
        }
    }

    private function hasTemporaryBlock(string $normalizedIp): bool
    {
        try {
            return (bool) $this->cache->get($this->cacheKeys->temporaryBlock($normalizedIp), false);
        } catch (Throwable $exception) {
            $this->failureLogger->once('Temporary block read failed.', $exception);

            return false;
        }
    }

    private function rememberBlocked(string $normalizedIp): void
    {
        try {
            $this->cache->put($this->cacheKeys->block($normalizedIp), true, $this->cacheSeconds());
        } catch (Throwable $exception) {
            $this->failureLogger->once('Block cache write failed.', $exception);
        }
    }

    private function cacheSeconds(): int
    {
        return max(1, (int) $this->config->get('security-guard.permanent_block.cache_minutes', 5)) * 60;
    }
}
