<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Notifications;

use Apkk\LaravelSecurityGuard\Contracts\ErrorEventNotifierContract;
use Apkk\LaravelSecurityGuard\Data\NotificationResult;
use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Mail\Mailer;
use Illuminate\Mail\Message;
use Throwable;

class MailErrorEventNotifier implements ErrorEventNotifierContract
{
    public const CHANNEL = 'mail';

    public function __construct(
        private readonly Mailer $mailer,
        private readonly ConfigRepository $config,
        private readonly SecurityMessageBuilder $messages,
    ) {}

    public function notify(array $events): NotificationResult
    {
        if ($events === []) {
            return NotificationResult::skipped(self::CHANNEL, 'no_events');
        }

        $recipients = $this->recipients();

        if ($recipients === []) {
            return NotificationResult::skipped(self::CHANNEL, 'no_recipients');
        }

        try {
            $this->mailer->raw(
                $this->messages->forErrorEvents($events),
                function (Message $message) use ($recipients): void {
                    $message->to($recipients)->subject('[security-guard] Application error notification');
                },
            );

            return NotificationResult::sent(self::CHANNEL);
        } catch (Throwable) {
            return NotificationResult::failed(self::CHANNEL);
        }
    }

    /**
     * @return array<int, string>
     */
    private function recipients(): array
    {
        $recipients = $this->config->get('security-guard.notifications.mail.to', []);

        if (is_string($recipients)) {
            $recipients = [$recipients];
        }

        return array_values(array_filter(
            array_map('strval', (array) $recipients),
            static fn (string $address): bool => filter_var($address, FILTER_VALIDATE_EMAIL) !== false,
        ));
    }
}
