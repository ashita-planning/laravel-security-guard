<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Notifications;

use Apkk\LaravelSecurityGuard\Contracts\SecurityEventNotifierContract;
use Apkk\LaravelSecurityGuard\Data\NotificationResult;
use Apkk\LaravelSecurityGuard\Data\SecurityEventData;
use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Log\LogManager;
use Psr\Log\LoggerInterface;
use Throwable;

/**
 * The always-available channel: writes the event to the application log.
 */
class LogSecurityEventNotifier implements SecurityEventNotifierContract
{
    public const CHANNEL = 'log';

    public function __construct(
        private readonly LoggerInterface $logger,
        private readonly ConfigRepository $config,
        private readonly SecurityMessageBuilder $messages,
    ) {}

    public function notify(SecurityEventData $event): NotificationResult
    {
        try {
            $context = $event->toArray();

            if ($this->messages->maskIp()) {
                $context['ip_address'] = $event->displayIp(true);
            }

            $this->channel()->log(
                (string) $this->config->get('security-guard.notifications.log.level', 'warning'),
                $this->messages->forSecurityEvent($event),
                $context,
            );

            return NotificationResult::sent(self::CHANNEL);
        } catch (Throwable) {
            return NotificationResult::failed(self::CHANNEL);
        }
    }

    private function channel(): LoggerInterface
    {
        $channel = $this->config->get('security-guard.notifications.log.channel');

        if (is_string($channel) && $channel !== '' && $this->logger instanceof LogManager) {
            return $this->logger->channel($channel);
        }

        return $this->logger;
    }
}
