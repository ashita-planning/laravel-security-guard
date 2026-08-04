<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Services;

use Apkk\LaravelSecurityGuard\Contracts\ErrorNotificationOutcome;
use Apkk\LaravelSecurityGuard\Contracts\ErrorNotificationOutcomeHandlerContract;
use Apkk\LaravelSecurityGuard\Data\ErrorEventData;
use Apkk\LaravelSecurityGuard\Jobs\SendAggregatedErrorNotification;
use Apkk\LaravelSecurityGuard\Support\CacheKeys;
use Apkk\LaravelSecurityGuard\Support\FailureLogger;
use Apkk\LaravelSecurityGuard\Support\UrlSanitizer;
use Illuminate\Contracts\Bus\Dispatcher as BusDispatcher;
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

    public function __construct(
        private readonly CacheRepository $cache,
        private readonly ConfigRepository $config,
        private readonly BusDispatcher $bus,
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
     * Take everything buffered for a type. Returns an empty array when another
     * worker already drained the window.
     *
     * @return array<int, ErrorEventData>
     */
    public function drain(string $notificationType): array
    {
        $key = CacheKeys::errorAggregation($notificationType);

        try {
            $payloads = (array) $this->cache->pull($key, []);
        } catch (Throwable $exception) {
            $this->failureLogger->once('Error notification buffer could not be read.', $exception);

            return [];
        }

        return array_values(array_map(
            static fn (array $payload): ErrorEventData => ErrorEventData::fromArray($payload),
            array_filter($payloads, 'is_array'),
        ));
    }

    public function startCooldown(string $notificationType): void
    {
        $minutes = max(0, (int) $this->config->get('security-guard.error_notifications.cooldown_minutes', 10));

        if ($minutes === 0) {
            return;
        }

        try {
            $this->cache->put(CacheKeys::errorCooldown($notificationType), true, $minutes * 60);
        } catch (Throwable $exception) {
            $this->failureLogger->once('Error notification cooldown could not be stored.', $exception);
        }
    }

    public function inCooldown(string $notificationType): bool
    {
        try {
            return (bool) $this->cache->get(CacheKeys::errorCooldown($notificationType), false);
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
     * @return bool true when this event opened a new aggregation window
     */
    private function buffer(ErrorEventData $event): bool
    {
        $key = CacheKeys::errorAggregation($event->notificationType);
        $ttl = $this->aggregationDelay() + 300;

        $existing = (array) $this->cache->get($key, []);
        $existing[] = $event->toArray();

        $this->cache->put($key, $existing, $ttl);

        return count($existing) === 1;
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
