<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Contracts;

use Apkk\LaravelSecurityGuard\Data\NotificationResult;
use Apkk\LaravelSecurityGuard\Data\SecurityEventData;

interface SecurityEventNotifierContract
{
    /**
     * Deliver a security event to one channel.
     *
     * Implementations must not throw: a failed delivery is reported through
     * the returned result so that blocking never depends on notification.
     */
    public function notify(SecurityEventData $event): NotificationResult;
}
