<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Services;

use Apkk\LaravelSecurityGuard\Support\CacheKeyFactory;
use Apkk\LaravelSecurityGuard\Support\FailureLogger;
use Illuminate\Contracts\Cache\Repository;
use Throwable;

/**
 * Remembers how far a notification got, so a retry resumes rather than repeats.
 *
 * Without this, a job whose mail channel failed but whose log channel succeeded
 * has only two options on retry: re-send to everyone, or give up on the channel
 * that failed. It also records whether the daily allowance was already spent,
 * because charging one event twice would let a handful of flaky deliveries eat
 * a whole day's quota.
 */
class NotificationDeliveryState
{
    /** Long enough to outlive the job's retry/backoff window. */
    private const TTL_SECONDS = 86400;

    public function __construct(
        private readonly Repository $cache,
        private readonly CacheKeyFactory $cacheKeys,
        private readonly FailureLogger $failureLogger,
    ) {}

    /**
     * @return array{consumed: bool, delivered: array<int, string>}
     */
    public function get(string $scope, string $uniqueId): array
    {
        try {
            $raw = $this->cache->get($this->cacheKeys->deliveryState($scope, $uniqueId));
        } catch (Throwable $exception) {
            $this->failureLogger->once('Notification delivery state could not be read.', $exception);
            $raw = null;
        }

        return $this->normalize($raw);
    }

    public function markConsumed(string $scope, string $uniqueId): void
    {
        $this->mutate($scope, $uniqueId, function (array $state): array {
            $state['consumed'] = true;

            return $state;
        });
    }

    public function markDelivered(string $scope, string $uniqueId, string $channel): void
    {
        $this->mutate($scope, $uniqueId, function (array $state) use ($channel): array {
            if (! in_array($channel, $state['delivered'], true)) {
                $state['delivered'][] = $channel;
            }

            return $state;
        });
    }

    public function forget(string $scope, string $uniqueId): void
    {
        try {
            $this->cache->forget($this->cacheKeys->deliveryState($scope, $uniqueId));
        } catch (Throwable) {
            // A stale entry only suppresses a duplicate send; never fail here.
        }
    }

    /**
     * @param  callable(array{consumed: bool, delivered: array<int, string>}): array{consumed: bool, delivered: array<int, string>}  $callback
     */
    private function mutate(string $scope, string $uniqueId, callable $callback): void
    {
        $key = $this->cacheKeys->deliveryState($scope, $uniqueId);

        try {
            $state = $callback($this->normalize($this->cache->get($key)));
            $this->cache->put($key, $state, self::TTL_SECONDS);
        } catch (Throwable $exception) {
            // Losing this write can only cause a duplicate notification on
            // retry, which is far better than dropping the delivery entirely.
            $this->failureLogger->once('Notification delivery state could not be written.', $exception);
        }
    }

    /**
     * @return array{consumed: bool, delivered: array<int, string>}
     */
    private function normalize(mixed $raw): array
    {
        if (! is_array($raw)) {
            return ['consumed' => false, 'delivered' => []];
        }

        return [
            'consumed' => (bool) ($raw['consumed'] ?? false),
            'delivered' => array_values(array_filter(
                (array) ($raw['delivered'] ?? []),
                'is_string',
            )),
        ];
    }
}
