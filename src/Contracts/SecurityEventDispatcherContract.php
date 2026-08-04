<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Contracts;

use Apkk\LaravelSecurityGuard\Data\SecurityEventData;

interface SecurityEventDispatcherContract
{
    /**
     * Hand a security event to the notification pipeline.
     *
     * Failure here must never fail the block that produced the event.
     */
    public function dispatch(SecurityEventData $event): void;
}
