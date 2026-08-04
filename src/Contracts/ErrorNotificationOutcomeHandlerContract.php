<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Contracts;

use Apkk\LaravelSecurityGuard\Data\ErrorEventData;

interface ErrorNotificationOutcomeHandlerContract
{
    /**
     * Report what happened to a batch of error events so the host can update
     * its own report rows (for example marking them notified or handled).
     *
     * @param  array<int, ErrorEventData>  $events
     * @param  ErrorNotificationOutcome::*  $outcome
     */
    public function handle(array $events, string $outcome): void;
}
