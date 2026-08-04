<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Services;

use Apkk\LaravelSecurityGuard\Support\CacheKeys;
use Illuminate\Contracts\Cache\Repository as CacheRepository;
use Illuminate\Support\Carbon;
use Throwable;

/**
 * Remembers that an external provider has cut us off.
 *
 * When a provider reports its monthly quota is exhausted there is no value in
 * retrying for the rest of the month, so the channel is parked until the month
 * rolls over.
 */
class NotificationSuspension
{
    public function __construct(private readonly CacheRepository $cache) {}

    public function isSuspended(string $scope, string $channel): bool
    {
        try {
            return (bool) $this->cache->get(CacheKeys::suspendedChannel($scope, $channel), false);
        } catch (Throwable) {
            return false;
        }
    }

    public function suspendUntilEndOfMonth(string $scope, string $channel): void
    {
        try {
            $this->cache->put(
                CacheKeys::suspendedChannel($scope, $channel),
                true,
                Carbon::now()->endOfMonth(),
            );
        } catch (Throwable) {
            // A missed suspension only costs a retry; never fail the caller.
        }
    }

    public function resume(string $scope, string $channel): void
    {
        try {
            $this->cache->forget(CacheKeys::suspendedChannel($scope, $channel));
        } catch (Throwable) {
            //
        }
    }
}
