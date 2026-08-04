<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Jobs;

use Apkk\LaravelSecurityGuard\Contracts\ErrorNotificationOutcome;
use Apkk\LaravelSecurityGuard\Data\ErrorEventBatch;
use Apkk\LaravelSecurityGuard\Exceptions\NotificationDeliveryFailed;
use Apkk\LaravelSecurityGuard\Notifications\NotifierRegistry;
use Apkk\LaravelSecurityGuard\Services\DailyLimiter;
use Apkk\LaravelSecurityGuard\Services\ErrorNotificationGuard;
use Apkk\LaravelSecurityGuard\Services\NotificationDeliveryState;
use Apkk\LaravelSecurityGuard\Services\NotificationSuspension;
use Apkk\LaravelSecurityGuard\Support\FailureLogger;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldBeUnique;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;
use Throwable;

/**
 * Sends one aggregated message per notification type per window.
 *
 * Channels are limited independently, so exhausting the LINE allowance does not
 * silence mail. Whatever the result, the host is told through the outcome
 * handler so its report rows never sit in limbo.
 *
 * The window is claimed in the cache rather than held on the job instance. A
 * retry rebuilds the job from its original payload, so an instance property
 * would be empty on the second attempt and the batch would vanish.
 */
class SendAggregatedErrorNotification implements ShouldBeUnique, ShouldQueue
{
    use Dispatchable, InteractsWithQueue, Queueable, SerializesModels;

    private const SCOPE = 'error-events';

    public int $tries = 3;

    public int $uniqueFor = 900;

    public function __construct(public string $notificationType) {}

    public function uniqueId(): string
    {
        return $this->notificationType;
    }

    /**
     * @return array<int, int>
     */
    public function backoff(): array
    {
        return [60, 300];
    }

    public function handle(
        ErrorNotificationGuard $guard,
        NotifierRegistry $registry,
        DailyLimiter $dailyLimiter,
        NotificationSuspension $suspension,
        NotificationDeliveryState $deliveryState,
        FailureLogger $failureLogger,
    ): void {
        if (! $guard->enabled()) {
            return;
        }

        // Held in the cache, not on this instance: a retry re-creates the job
        // from its original payload and would otherwise find nothing to send.
        $batch = $guard->claim($this->notificationType);

        if ($batch->isEmpty()) {
            return;
        }

        $state = $deliveryState->get(self::SCOPE, $this->notificationType);

        $limits = $guard->dailyLimits();
        $delivered = [];
        $failed = [];
        $limited = false;

        foreach ($limits as $channel => $limit) {
            if (in_array($channel, $state['delivered'], true)
                || $suspension->isSuspended(self::SCOPE, $channel)) {
                continue;
            }

            $notifier = $registry->errorNotifier($channel);

            if ($notifier === null) {
                continue;
            }

            if (! $dailyLimiter->consume(self::SCOPE.':'.$channel, $limit)) {
                $limited = true;
                $failureLogger->always('Error notification skipped: daily channel limit reached.', null, [
                    'channel' => $channel,
                    'notification_type' => $this->notificationType,
                ]);

                continue;
            }

            $result = $notifier->notify($batch->events);

            if ($result->sent) {
                $delivered[] = $channel;
                $deliveryState->markDelivered(self::SCOPE, $this->notificationType, $channel);

                continue;
            }

            $failureLogger->always('Error notification was not delivered.', null, [
                'channel' => $channel,
                'reason' => $result->reason ?? 'unknown',
            ]);

            if ($result->isRetryable()) {
                $failed[] = $channel;
            }
        }

        if ($failed !== []) {
            // Keep the claim so the retry still has the batch; the outcome is
            // only reported once the attempt sequence is settled.
            throw NotificationDeliveryFailed::forChannels($failed);
        }

        $guard->releaseClaim($this->notificationType);
        $deliveryState->forget(self::SCOPE, $this->notificationType);
        $this->reportOutcome($guard, $batch, $delivered !== [] || $state['delivered'] !== [], $limited);
    }

    /**
     * Every attempt has now failed. Hand the batch back to the host so its
     * report rows are not left waiting on a notification that will never come.
     */
    public function failed(?Throwable $exception): void
    {
        $guard = app(ErrorNotificationGuard::class);
        $batch = $guard->claim($this->notificationType);

        $guard->releaseClaim($this->notificationType);
        app(NotificationDeliveryState::class)->forget(self::SCOPE, $this->notificationType);

        if (! $batch->isEmpty()) {
            $guard->handleOutcome($batch->events, ErrorNotificationOutcome::FAILED);
        }
    }

    private function reportOutcome(
        ErrorNotificationGuard $guard,
        ErrorEventBatch $batch,
        bool $anySent,
        bool $limited,
    ): void {
        if ($anySent) {
            $guard->startCooldown($this->notificationType);
            $guard->handleOutcome($batch->events, ErrorNotificationOutcome::SENT);

            return;
        }

        $guard->handleOutcome(
            $batch->events,
            $limited ? $guard->onLimitOutcome() : ErrorNotificationOutcome::FAILED,
        );
    }
}
