<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Events;

use Apkk\LaravelSecurityGuard\Data\BlockedIpRecord;

/**
 * Fired after a block row is persisted. Listen for this to write your own
 * audit trail: the package reuses one row per address, so full history is the
 * host's responsibility.
 */
final class IpBlocked
{
    public function __construct(
        public readonly BlockedIpRecord $record,
        public readonly bool $isNewBlock,
    ) {}
}
