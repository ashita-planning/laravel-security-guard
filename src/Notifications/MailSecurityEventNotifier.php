<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Notifications;

use Apkk\LaravelSecurityGuard\Contracts\SecurityEventNotifierContract;
use Apkk\LaravelSecurityGuard\Data\NotificationResult;
use Apkk\LaravelSecurityGuard\Data\SecurityEventData;
use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Mail\Mailer;
use Illuminate\Mail\Message;
use Throwable;

/**
 * Plain-text mail channel.
 *
 * The body is built by SecurityMessageBuilder and sent as raw text: no view,
 * no HTML, therefore no place for an injected link to render.
 */
class MailSecurityEventNotifier implements SecurityEventNotifierContract
{
    public const CHANNEL = 'mail';

    public function __construct(
        private readonly Mailer $mailer,
        private readonly ConfigRepository $config,
        private readonly SecurityMessageBuilder $messages,
    ) {}

    public function notify(SecurityEventData $event): NotificationResult
    {
        $recipients = $this->recipients();

        if ($recipients === []) {
            return NotificationResult::skipped(self::CHANNEL, 'no_recipients');
        }

        $subject = (string) $this->config->get(
            'security-guard.notifications.mail.subject',
            '[security-guard] Automatic IP block',
        );

        try {
            $this->mailer->raw(
                $this->messages->forSecurityEvent($event),
                function (Message $message) use ($recipients, $subject): void {
                    $message->to($recipients)->subject($subject);
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
