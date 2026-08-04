<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Jobs;

use Apkk\LaravelSecurityGuard\Contracts\ErrorNotificationOutcome;
use Apkk\LaravelSecurityGuard\Notifications\NotifierRegistry;
use Apkk\LaravelSecurityGuard\Services\DailyLimiter;
use Apkk\LaravelSecurityGuard\Services\ErrorNotificationGuard;
use Apkk\LaravelSecurityGuard\Services\NotificationSuspension;
use Apkk\LaravelSecurityGuard\Support\FailureLogger;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldBeUnique;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;

/**
 * Sends one aggregated message per notification type per window.
 *
 * Channels are limited independently, so exhausting the LINE allowance does
 * not silence mail. Whatever the result, the host is told through the outcome
 * handler so its report rows never sit in limbo.
 */
class SendAggregatedErrorNotification implements ShouldBeUnique, ShouldQueue
{
    use Dispatchable, InteractsWithQueue, Queueable, SerializesModels;

    public int $tries = 3;

    public int $uniqueFor = 900;

    public function __construct(public string $notificationType) {}

    public function uniqueId(): string
    {
        return $this->notificationType;
    }

    public function handle(
        ErrorNotificationGuard $guard,
        NotifierRegistry $registry,
        DailyLimiter $dailyLimiter,
        NotificationSuspension $suspension,
        FailureLogger $failureLogger,
    ): void {
        if (! $guard->enabled()) {
            return;
        }

        $events = $guard->drain($this->notificationType);

        if ($events === []) {
            return;
        }

        $limits = $guard->dailyLimits();
        $anySent = false;
        $anyLimited = false;

        foreach ($limits as $channel => $limit) {
            if ($suspension->isSuspended('error-events', $channel)) {
                continue;
            }

            $notifier = $registry->errorNotifier($channel);

            if ($notifier === null) {
                continue;
            }

            if (! $dailyLimiter->consume('error-events:'.$channel, $limit)) {
                $anyLimited = true;
                $failureLogger->always('Error notification skipped: daily channel limit reached.', null, [
                    'channel' => $channel,
                    'notification_type' => $this->notificationType,
                ]);

                continue;
            }

            $result = $notifier->notify($events);

            if ($result->sent) {
                $anySent = true;

                continue;
            }

            $failureLogger->always('Error notification was not delivered.', null, [
                'channel' => $channel,
                'reason' => $result->reason ?? 'unknown',
            ]);
        }

        if ($anySent) {
            $guard->startCooldown($this->notificationType);
            $guard->handleOutcome($events, ErrorNotificationOutcome::SENT);

            return;
        }

        $guard->handleOutcome(
            $events,
            $anyLimited ? $guard->onLimitOutcome() : ErrorNotificationOutcome::FAILED,
        );
    }
}
