<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Jobs;

use Apkk\LaravelSecurityGuard\Contracts\BlockedIpRepositoryContract;
use Apkk\LaravelSecurityGuard\Contracts\SecurityEventNotifierContract;
use Apkk\LaravelSecurityGuard\Data\SecurityEventData;
use Apkk\LaravelSecurityGuard\Exceptions\NotificationDeliveryFailed;
use Apkk\LaravelSecurityGuard\Notifications\NotifierRegistry;
use Apkk\LaravelSecurityGuard\Services\DailyLimiter;
use Apkk\LaravelSecurityGuard\Services\NotificationDeliveryState;
use Apkk\LaravelSecurityGuard\Services\NotificationSuspension;
use Apkk\LaravelSecurityGuard\Support\FailureLogger;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Queue\ShouldBeUnique;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;
use Throwable;

/**
 * Delivers one security event over every configured channel.
 *
 * The payload is the DTO's scalar array, not an Eloquent model: the job stays
 * valid even if the host swaps its storage, and nothing beyond the vetted
 * fields can ride along into the queue.
 *
 * Retries resume rather than restart. Channels that already accepted the event
 * are recorded, so a second attempt targets only what actually failed and the
 * daily allowance is charged once per event, not once per attempt.
 */
class SendSecurityEventNotification implements ShouldBeUnique, ShouldQueue
{
    use Dispatchable, InteractsWithQueue, Queueable, SerializesModels;

    private const SCOPE = 'security-events';

    public int $tries = 3;

    /** Guards against duplicate blocks from concurrent probes fanning out. */
    public int $uniqueFor = 300;

    /**
     * @param  array<string, string>  $payload
     */
    public function __construct(public array $payload) {}

    public function uniqueId(): string
    {
        return SecurityEventData::fromArray($this->payload)->uniqueId();
    }

    /**
     * @return array<int, int>
     */
    public function backoff(): array
    {
        return [30, 120];
    }

    public function handle(
        ConfigRepository $config,
        NotifierRegistry $registry,
        DailyLimiter $dailyLimiter,
        NotificationSuspension $suspension,
        NotificationDeliveryState $deliveryState,
        BlockedIpRepositoryContract $repository,
        FailureLogger $failureLogger,
    ): void {
        if (! $config->get('security-guard.notifications.enabled', false)) {
            return;
        }

        $event = SecurityEventData::fromArray($this->payload);
        $uniqueId = $event->uniqueId();
        $state = $deliveryState->get(self::SCOPE, $uniqueId);

        if (! $this->stillWorthSending($repository, $event, $state['delivered'], $failureLogger)) {
            return;
        }

        // Skip whatever a previous attempt already delivered.
        $channels = array_diff_key(
            $this->channels($config, $registry, $suspension),
            array_flip($state['delivered']),
        );

        if ($channels === []) {
            return;
        }

        // One event consumes one allowance, however many channels, recipients
        // or retry attempts it takes to get there.
        if (! $state['consumed']) {
            if (! $dailyLimiter->consume(self::SCOPE, $this->dailyLimit($config))) {
                $failureLogger->always('Security event notification skipped: daily limit reached.', null, [
                    'block_id' => (string) $event->blockId,
                ]);

                return;
            }

            $deliveryState->markConsumed(self::SCOPE, $uniqueId);
        }

        $delivered = [];
        $failed = [];

        foreach ($channels as $channel => $notifier) {
            $result = $notifier->notify($event);
            $channel = (string) $channel;

            if ($result->sent) {
                $delivered[] = $channel;
                $deliveryState->markDelivered(self::SCOPE, $uniqueId, $channel);

                continue;
            }

            $failureLogger->always('Security event notification was not delivered.', null, [
                'channel' => $channel,
                'reason' => $result->reason ?? 'unknown',
            ]);

            // A misconfiguration (no recipients, unknown channel) is not worth
            // retrying; only a transport failure is.
            if ($result->isRetryable()) {
                $failed[] = $channel;
            }
        }

        if ($delivered !== []) {
            try {
                $repository->markNotified($event->blockId);
            } catch (Throwable $exception) {
                $failureLogger->once('Marking a block as notified failed.', $exception);
            }
        }

        if ($failed !== []) {
            // The only way to reach the queue's retry machinery: notifiers
            // themselves never throw, by design.
            throw NotificationDeliveryFailed::forChannels($failed);
        }
    }

    /**
     * @return array<string, SecurityEventNotifierContract>
     */
    private function channels(
        ConfigRepository $config,
        NotifierRegistry $registry,
        NotificationSuspension $suspension,
    ): array {
        $channels = [];

        foreach ((array) $config->get('security-guard.notifications.channels', ['log']) as $channel) {
            $channel = (string) $channel;

            if ($suspension->isSuspended(self::SCOPE, $channel)) {
                continue;
            }

            $notifier = $registry->securityNotifier($channel);

            if ($notifier !== null) {
                $channels[$channel] = $notifier;
            }
        }

        return $channels;
    }

    /**
     * Skip work that has become pointless: the address was released, or the
     * event was fully announced already.
     *
     * `notified_at` is set as soon as one channel succeeds, so it cannot mean
     * "finished" on a retry; the delivery record is what distinguishes a
     * completed send from a partial one.
     *
     * @param  array<int, string>  $delivered
     */
    private function stillWorthSending(
        BlockedIpRepositoryContract $repository,
        SecurityEventData $event,
        array $delivered,
        FailureLogger $failureLogger,
    ): bool {
        try {
            $record = $repository->findById($event->blockId);
        } catch (Throwable $exception) {
            $failureLogger->once('Block lookup failed while notifying.', $exception);

            return false;
        }

        if ($record === null || ! $record->isActive()) {
            return false;
        }

        return $record->notifiedAt === null || $delivered !== [];
    }

    private function dailyLimit(ConfigRepository $config): int
    {
        return (int) $config->get('security-guard.notifications.daily_limit', 10);
    }
}
