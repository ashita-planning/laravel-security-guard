<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Notifications;

use Apkk\LaravelSecurityGuard\Data\ErrorEventData;
use Apkk\LaravelSecurityGuard\Data\SecurityEventData;
use Illuminate\Contracts\Config\Repository as ConfigRepository;

/**
 * Composes outbound notification bodies.
 *
 * Every line is assembled from a fixed label plus a value the DTO has already
 * validated. There is no branch that concatenates a URL, a query string, a
 * header, a request body, an exception message or a stack trace, which is what
 * makes "no attacker-controlled text leaves the system" checkable rather than
 * merely intended.
 */
class SecurityMessageBuilder
{
    public function __construct(private readonly ConfigRepository $config) {}

    public function forSecurityEvent(SecurityEventData $event): string
    {
        $lines = [
            '[security-guard] Automatic IP block',
            'Event: '.$event->type,
            'Criteria: '.$event->reasonLabel(),
            'IP address: '.$event->displayIp($this->maskIp()),
        ];

        if ($event->matchedPattern !== null) {
            $lines[] = 'Pattern: '.$event->matchedPattern;
        }

        $lines[] = 'Detected at: '.($event->detectedAt?->format('Y-m-d H:i:s') ?? '-');
        $lines[] = 'Block ID: '.$event->blockId;
        $lines[] = 'Action: public access stays blocked until the address is released.';

        return implode("\n", $lines);
    }

    /**
     * @param  array<int, ErrorEventData>  $events
     * @param  int|null  $totalOccurrences  Real count when the batch was capped
     */
    public function forErrorEvents(array $events, ?int $totalOccurrences = null): string
    {
        $first = $events[0] ?? null;
        $total = $totalOccurrences ?? count($events);

        $lines = [
            '[security-guard] Application error notification',
            'Type: '.($first?->notificationType ?? 'unknown'),
            'Environment: '.($first?->environment ?? 'unknown'),
            'Area: '.($first?->area ?? 'unknown'),
            // The retained sample is capped; the count never is, so an
            // incident is not under-reported just because the buffer filled.
            'Occurrences: '.$total.($total > count($events) ? ' (showing '.count($events).')' : ''),
        ];

        if ($first?->exceptionClass !== null) {
            $lines[] = 'Exception: '.$first->exceptionClass;
        }

        $lines[] = 'First occurred at: '.($first?->occurredAt?->format('Y-m-d H:i:s') ?? '-');
        $lines[] = 'References: '.$this->references($events);
        $lines[] = 'Action: open the error report screen for the details.';

        return implode("\n", $lines);
    }

    /**
     * @param  array<int, ErrorEventData>  $events
     */
    private function references(array $events): string
    {
        $references = array_slice(array_map(
            static fn (ErrorEventData $event): string => (string) $event->reportReference,
            $events,
        ), 0, 10);

        return $references === [] ? '-' : implode(', ', $references);
    }

    public function maskIp(): bool
    {
        return (bool) $this->config->get('security-guard.notifications.mask_ip', false);
    }
}
