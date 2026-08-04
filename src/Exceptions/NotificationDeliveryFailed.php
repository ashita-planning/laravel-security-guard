<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Exceptions;

use RuntimeException;

/**
 * Thrown by a notification job when a channel failed in a way a retry could fix.
 *
 * Notifiers deliberately swallow their own transport errors and report a result
 * instead, which keeps a broken mailer from failing a block. That leaves the
 * job as the only place that can signal the queue, and without this exception
 * `$tries` would never be used: every attempt would "succeed" having delivered
 * nothing.
 *
 * The message carries channel names only. Provider responses are not included,
 * because a failed API call frequently echoes back the request, and this
 * exception is written to the queue's failed_jobs table.
 */
class NotificationDeliveryFailed extends RuntimeException
{
    /**
     * @param  array<int, string>  $channels
     */
    public static function forChannels(array $channels): self
    {
        return new self('Security guard notification delivery failed for: '.implode(', ', $channels));
    }
}
