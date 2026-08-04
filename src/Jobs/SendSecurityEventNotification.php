<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Jobs;

use Apkk\LaravelSecurityGuard\Contracts\BlockedIpRepositoryContract;
use Apkk\LaravelSecurityGuard\Contracts\SecurityEventNotifierContract;
use Apkk\LaravelSecurityGuard\Data\SecurityEventData;
use Apkk\LaravelSecurityGuard\Notifications\NotifierRegistry;
use Apkk\LaravelSecurityGuard\Services\DailyLimiter;
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
 */
class SendSecurityEventNotification implements ShouldBeUnique, ShouldQueue
{
    use Dispatchable, InteractsWithQueue, Queueable, SerializesModels;

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

    public function handle(
        ConfigRepository $config,
        NotifierRegistry $registry,
        DailyLimiter $dailyLimiter,
        NotificationSuspension $suspension,
        BlockedIpRepositoryContract $repository,
        FailureLogger $failureLogger,
    ): void {
        if (! $config->get('security-guard.notifications.enabled', false)) {
            return;
        }

        $event = SecurityEventData::fromArray($this->payload);

        if (! $this->stillWorthSending($repository, $event, $failureLogger)) {
            return;
        }

        $channels = $this->channels($config, $registry, $suspension);

        if ($channels === []) {
            return;
        }

        // One event consumes one allowance, no matter how many channels or
        // recipients it fans out to.
        if (! $dailyLimiter->consume('security-events', $this->dailyLimit($config))) {
            $failureLogger->always('Security event notification skipped: daily limit reached.', null, [
                'block_id' => (string) $event->blockId,
            ]);

            return;
        }

        $sent = false;

        foreach ($channels as $channel => $notifier) {
            $result = $notifier->notify($event);

            if ($result->sent) {
                $sent = true;

                continue;
            }

            $failureLogger->always('Security event notification was not delivered.', null, [
                'channel' => (string) $channel,
                'reason' => $result->reason ?? 'unknown',
            ]);
        }

        if ($sent) {
            try {
                $repository->markNotified($event->blockId);
            } catch (Throwable $exception) {
                $failureLogger->once('Marking a block as notified failed.', $exception);
            }
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

            if ($suspension->isSuspended('security-events', $channel)) {
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
     * event was already announced by an earlier attempt.
     */
    private function stillWorthSending(
        BlockedIpRepositoryContract $repository,
        SecurityEventData $event,
        FailureLogger $failureLogger,
    ): bool {
        try {
            $record = $repository->findById($event->blockId);
        } catch (Throwable $exception) {
            $failureLogger->once('Block lookup failed while notifying.', $exception);

            return false;
        }

        return $record !== null && $record->isActive() && $record->notifiedAt === null;
    }

    private function dailyLimit(ConfigRepository $config): int
    {
        return (int) $config->get('security-guard.notifications.daily_limit', 10);
    }
}
