<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Services;

use Apkk\LaravelSecurityGuard\Contracts\SecurityEventDispatcherContract;
use Apkk\LaravelSecurityGuard\Data\SecurityEventData;
use Apkk\LaravelSecurityGuard\Jobs\SendSecurityEventNotification;
use Apkk\LaravelSecurityGuard\Support\FailureLogger;
use Illuminate\Contracts\Bus\Dispatcher as BusDispatcher;
use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Throwable;

/**
 * Hands security events to the queue.
 *
 * Notification is deliberately decoupled from blocking: this method never
 * throws, so a broken queue connection cannot roll back a block that was
 * already written.
 */
class QueuedSecurityEventDispatcher implements SecurityEventDispatcherContract
{
    public function __construct(
        private readonly BusDispatcher $bus,
        private readonly ConfigRepository $config,
        private readonly FailureLogger $failureLogger,
    ) {}

    public function dispatch(SecurityEventData $event): void
    {
        if (! $this->config->get('security-guard.notifications.enabled', false)) {
            return;
        }

        try {
            $job = new SendSecurityEventNotification($event->toArray());

            $connection = $this->config->get('security-guard.notifications.connection');
            $queue = $this->config->get('security-guard.notifications.queue', 'default');

            if (is_string($connection) && $connection !== '') {
                $job->onConnection($connection);
            }

            if (is_string($queue) && $queue !== '') {
                $job->onQueue($queue);
            }

            $this->bus->dispatch($job);
        } catch (Throwable $exception) {
            $this->failureLogger->once('Security event notification could not be queued.', $exception);
        }
    }
}
