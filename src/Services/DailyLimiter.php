<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Services;

use Apkk\LaravelSecurityGuard\Support\CacheKeys;
use Apkk\LaravelSecurityGuard\Support\FailureLogger;
use Illuminate\Contracts\Cache\LockProvider;
use Illuminate\Contracts\Cache\Repository as CacheRepository;
use Illuminate\Support\Carbon;
use Throwable;

/**
 * Daily send allowance, counted per event rather than per recipient.
 *
 * A burst of blocks is exactly when the notification path is most likely to be
 * hammered, so the counter is guarded by an atomic lock. If the lock cannot be
 * taken the answer is "do not send": under contention, silence beats a flood.
 */
class DailyLimiter
{
    public function __construct(
        private readonly CacheRepository $cache,
        private readonly FailureLogger $failureLogger,
    ) {}

    public function consume(string $scope, int $limit): bool
    {
        if ($limit < 1) {
            return false;
        }

        $key = CacheKeys::dailyCounter($scope, Carbon::now()->format('Ymd'));
        $store = $this->cache->getStore();

        if (! $store instanceof LockProvider) {
            $this->failureLogger->once(
                'Cache store does not support atomic locks; daily notification limits are approximate.',
            );

            return $this->increment($key, $limit);
        }

        try {
            return $this->cache->lock($key.':lock', 5)->block(3, fn (): bool => $this->increment($key, $limit));
        } catch (Throwable $exception) {
            $this->failureLogger->once('Daily notification limit lock failed; skipping the notification.', $exception);

            return false;
        }
    }

    public function used(string $scope): int
    {
        try {
            return (int) $this->cache->get(CacheKeys::dailyCounter($scope, Carbon::now()->format('Ymd')), 0);
        } catch (Throwable) {
            return 0;
        }
    }

    private function increment(string $key, int $limit): bool
    {
        $used = (int) $this->cache->get($key, 0);

        if ($used >= $limit) {
            return false;
        }

        $this->cache->put($key, $used + 1, Carbon::now()->endOfDay());

        return true;
    }
}
