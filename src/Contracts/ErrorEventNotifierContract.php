<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Contracts;

use Apkk\LaravelSecurityGuard\Data\ErrorEventData;
use Apkk\LaravelSecurityGuard\Data\NotificationResult;

interface ErrorEventNotifierContract
{
    /**
     * Deliver an aggregated batch of error events over one channel.
     *
     * @param  array<int, ErrorEventData>  $events
     */
    public function notify(array $events): NotificationResult;
}
