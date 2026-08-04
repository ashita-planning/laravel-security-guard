<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Contracts;

final class ErrorNotificationOutcome
{
    /** Delivered over at least one channel. */
    public const SENT = 'sent';

    /** Suppressed by the cooldown window. */
    public const COOLDOWN = 'cooldown';

    /** Daily channel limit reached and `on_limit` is `mark_handled`. */
    public const LIMIT_MARK_HANDLED = 'limit_mark_handled';

    /** Daily channel limit reached and `on_limit` is `hold`. */
    public const LIMIT_HELD = 'limit_held';

    /** Every configured channel failed to deliver. */
    public const FAILED = 'failed';
}
