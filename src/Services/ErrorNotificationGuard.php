<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Services;

use Apkk\LaravelSecurityGuard\Contracts\ErrorNotificationOutcome;
use Apkk\LaravelSecurityGuard\Contracts\ErrorNotificationOutcomeHandlerContract;
use Apkk\LaravelSecurityGuard\Data\ErrorEventBatch;
use Apkk\LaravelSecurityGuard\Data\ErrorEventData;
use Apkk\LaravelSecurityGuard\Jobs\SendAggregatedErrorNotification;
use Apkk\LaravelSecurityGuard\Support\CacheKeyFactory;
use Apkk\LaravelSecurityGuard\Support\FailureLogger;
use Apkk\LaravelSecurityGuard\Support\UrlSanitizer;
use Illuminate\Contracts\Bus\Dispatcher as BusDispatcher;
use Illuminate\Contracts\Cache\LockProvider;
use Illuminate\Contracts\Cache\LockTimeoutException;
use Illuminate\Contracts\Cache\Repository as CacheRepository;
use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Throwable;

/**
 * Turns a storm of application errors into a few readable notifications.
 *
 * An attack that trips the same exception thousands of times must not become
 * thousands of messages: events of one type are buffered for a short window,
 * sent once, then muted for a cooldown period.
 */
class ErrorNotificationGuard
{
    public const BUFFERED = 'buffered';

    public const DISABLED = 'disabled';

    /** Must outlive the delivery job's full retry and backoff window. */
    private const INFLIGHT_TTL_SECONDS = 86400;

    public function __construct(
        private readonly CacheRepository $cache,
        private readonly ConfigRepository $config,
        private readonly BusDispatcher $bus,
        private readonly CacheKeyFactory $cacheKeys,
        private readonly FailureLogger $failureLogger,
        private readonly ?ErrorNotificationOutcomeHandlerContract $outcomeHandler = null,
    ) {}

    public function enabled(): bool
    {
        return (bool) $this->config->get('security-guard.enabled', true)
            && (bool) $this->config->get('security-guard.error_notifications.enabled', false);
    }

    /**
     * Register an error occurrence.
     *
     * @return string One of the ErrorNotificationOutcome constants, self::BUFFERED or self::DISABLED
     */
    public function report(ErrorEventData $event): string
    {
        if (! $this->enabled()) {
            return self::DISABLED;
        }

        try {
            if ($this->inCooldown($event->notificationType)) {
                $this->handleOutcome([$event], ErrorNotificationOutcome::COOLDOWN);

                return ErrorNotificationOutcome::COOLDOWN;
            }

            $isFirst = $this->buffer($event);

            if ($isFirst) {
                $this->scheduleDelivery($event->notificationType);
            }

            return self::BUFFERED;
        } catch (Throwable $exception) {
            $this->failureLogger->once('Error notification could not be buffered.', $exception);

            return ErrorNotificationOutcome::FAILED;
        }
    }

    /**
     * Take ownership of a window for delivery.
     *
     * The buffer is moved into an in-flight slot rather than simply read and
     * deleted. A queue retry rebuilds the job from its original payload, so a
     * batch held on the job instance would not survive one failed attempt;
     * keeping it here means a retry picks up exactly where it left off, and
     * any occurrences reported meanwhile are folded in.
     *
     * Call `releaseClaim()` once the batch has been dealt with.
     */
    public function claim(string $notificationType): ErrorEventBatch
    {
        $inflightKey = $this->cacheKeys->errorInflight($notificationType);
        $bufferKey = $this->cacheKeys->errorAggregation($notificationType);

        try {
            $claim = function () use ($inflightKey, $bufferKey): array {
                $inflight = $this->normalizeBuffer($this->cache->get($inflightKey));
                // pull() is read-and-delete in one step, so two workers racing
                // here cannot both take the same occurrences.
                $pending = $this->normalizeBuffer($this->cache->pull($bufferKey));

                $merged = [
                    'events' => array_slice(
                        array_merge($inflight['events'], $pending['events']),
                        0,
                        $this->maxAggregatedEvents(),
                    ),
                    'total' => $inflight['total'] + $pending['total'],
                ];

                if ($merged['total'] > 0) {
                    $this->cache->put($inflightKey, $merged, self::INFLIGHT_TTL_SECONDS);
                }

                return $merged;
            };

            $store = $this->cache->getStore();

            $buffer = $store instanceof LockProvider
                ? (array) $store->lock($inflightKey.':lock', 5)->block(3, $claim)
                : $claim();
        } catch (Throwable $exception) {
            $this->failureLogger->once('Error notification buffer could not be claimed.', $exception);

            return ErrorEventBatch::empty();
        }

        return new ErrorEventBatch(
            array_map(
                static fn (array $payload): ErrorEventData => ErrorEventData::fromArray($payload),
                $buffer['events'],
            ),
            $buffer['total'],
        );
    }

    /**
     * Drop an in-flight window once it has been delivered or abandoned.
     */
    public function releaseClaim(string $notificationType): void
    {
        try {
            $this->cache->forget($this->cacheKeys->errorInflight($notificationType));
        } catch (Throwable $exception) {
            $this->failureLogger->once('Error notification claim could not be released.', $exception);
        }
    }

    public function startCooldown(string $notificationType): void
    {
        $minutes = max(0, (int) $this->config->get('security-guard.error_notifications.cooldown_minutes', 10));

        if ($minutes === 0) {
            return;
        }

        try {
            $this->cache->put($this->cacheKeys->errorCooldown($notificationType), true, $minutes * 60);
        } catch (Throwable $exception) {
            $this->failureLogger->once('Error notification cooldown could not be stored.', $exception);
        }
    }

    public function inCooldown(string $notificationType): bool
    {
        try {
            return (bool) $this->cache->get($this->cacheKeys->errorCooldown($notificationType), false);
        } catch (Throwable) {
            return false;
        }
    }

    /**
     * @param  array<int, ErrorEventData>  $events
     * @param  ErrorNotificationOutcome::*  $outcome
     */
    public function handleOutcome(array $events, string $outcome): void
    {
        if ($this->outcomeHandler === null || $events === []) {
            return;
        }

        try {
            $this->outcomeHandler->handle($events, $outcome);
        } catch (Throwable $exception) {
            $this->failureLogger->once('Error notification outcome handler failed.', $exception);
        }
    }

    public function onLimitOutcome(): string
    {
        return $this->config->get('security-guard.error_notifications.on_limit', 'mark_handled') === 'hold'
            ? ErrorNotificationOutcome::LIMIT_HELD
            : ErrorNotificationOutcome::LIMIT_MARK_HANDLED;
    }

    /**
     * @return array<string, int>
     */
    public function dailyLimits(): array
    {
        $limits = (array) $this->config->get('security-guard.error_notifications.daily_limits', []);
        $normalized = [];

        foreach ($limits as $channel => $limit) {
            $normalized[(string) $channel] = (int) $limit;
        }

        return $normalized;
    }

    /**
     * Convenience helper for hosts that persist the request URL alongside the
     * report row. The package itself never transmits it.
     */
    public function sanitizeUrl(string $url): string
    {
        return UrlSanitizer::sanitize(
            $url,
            array_map('strval', (array) $this->config->get('security-guard.error_notifications.masked_query_keys', [])),
            max(1, (int) $this->config->get('security-guard.error_notifications.url_max_bytes', 255)),
        );
    }

    /**
     * Append an event to its aggregation window.
     *
     * Two properties matter here, and the naive read-append-write had neither:
     *
     *  - Atomicity. Concurrent reporters read the same buffer and the last
     *    write wins, silently dropping the others' events. The mutation runs
     *    under a lock wherever the store provides one.
     *  - A ceiling. The buffer is what an error storm inflates fastest; without
     *    a cap, a loop tripping one exception fills the cache entry until the
     *    payload itself becomes the outage. Past the cap only the counter moves.
     *
     * @return bool true when this event opened a new aggregation window
     */
    private function buffer(ErrorEventData $event): bool
    {
        $key = $this->cacheKeys->errorAggregation($event->notificationType);
        $ttl = $this->aggregationDelay() + 300;
        $maxEvents = $this->maxAggregatedEvents();

        $mutate = function () use ($key, $ttl, $maxEvents, $event): bool {
            $buffer = $this->normalizeBuffer($this->cache->get($key));
            $wasEmpty = $buffer['total'] === 0;

            $buffer['total']++;

            if (count($buffer['events']) < $maxEvents) {
                $buffer['events'][] = $event->toArray();
            }

            $this->cache->put($key, $buffer, $ttl);

            return $wasEmpty;
        };

        $store = $this->cache->getStore();

        if (! $store instanceof LockProvider) {
            return $mutate();
        }

        try {
            return (bool) $store->lock($key.':lock', 5)->block(3, $mutate);
        } catch (LockTimeoutException $exception) {
            // Losing the race only costs this one occurrence; the window that
            // already exists will still be delivered.
            $this->failureLogger->once('Error notification buffer lock timed out.', $exception);

            return false;
        }
    }

    /**
     * @return array{events: array<int, array<string, string>>, total: int}
     */
    private function normalizeBuffer(mixed $raw): array
    {
        if (! is_array($raw)) {
            return ['events' => [], 'total' => 0];
        }

        $events = array_values(array_filter((array) ($raw['events'] ?? []), 'is_array'));

        return [
            'events' => $events,
            'total' => max((int) ($raw['total'] ?? 0), count($events)),
        ];
    }

    private function maxAggregatedEvents(): int
    {
        return max(1, (int) $this->config->get('security-guard.error_notifications.max_aggregated_events', 50));
    }

    private function scheduleDelivery(string $notificationType): void
    {
        $job = new SendAggregatedErrorNotification($notificationType);

        $connection = $this->config->get('security-guard.error_notifications.connection');
        $queue = $this->config->get('security-guard.error_notifications.queue', 'default');

        if (is_string($connection) && $connection !== '') {
            $job->onConnection($connection);
        }

        if (is_string($queue) && $queue !== '') {
            $job->onQueue($queue);
        }

        $delay = $this->aggregationDelay();

        if ($delay > 0) {
            $job->delay($delay);
        }

        $this->bus->dispatch($job);
    }

    private function aggregationDelay(): int
    {
        return max(0, (int) $this->config->get('security-guard.error_notifications.aggregation_delay_seconds', 60));
    }
}
