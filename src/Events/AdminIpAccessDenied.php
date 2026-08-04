<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Events;

use Apkk\LaravelSecurityGuard\Data\AdminSubjectData;

/**
 * Fired when an authenticated administrator is rejected by the IP allowlist.
 * The response itself stays a fixed message; this event is where the host
 * connects its own audit log.
 */
final class AdminIpAccessDenied
{
    public function __construct(
        public readonly AdminSubjectData $subject,
        public readonly ?string $ipAddress,
        public readonly string $reason,
    ) {}
}
