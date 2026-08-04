<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Notifications;

use Apkk\LaravelSecurityGuard\Contracts\ErrorEventNotifierContract;
use Apkk\LaravelSecurityGuard\Data\NotificationResult;
use Psr\Log\LoggerInterface;
use Throwable;

class LogErrorEventNotifier implements ErrorEventNotifierContract
{
    public const CHANNEL = 'log';

    public function __construct(
        private readonly LoggerInterface $logger,
        private readonly SecurityMessageBuilder $messages,
    ) {}

    public function notify(array $events): NotificationResult
    {
        if ($events === []) {
            return NotificationResult::skipped(self::CHANNEL, 'no_events');
        }

        try {
            $this->logger->warning($this->messages->forErrorEvents($events), [
                'count' => count($events),
                'notification_type' => $events[0]->notificationType,
            ]);

            return NotificationResult::sent(self::CHANNEL);
        } catch (Throwable) {
            return NotificationResult::failed(self::CHANNEL);
        }
    }
}
