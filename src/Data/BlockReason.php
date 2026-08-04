<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Data;

final class BlockReason
{
    public const RATE_LIMIT = 'rate_limit';

    public const KNOWN_ATTACK_PATH = 'known_attack_path';

    public const MANUAL = 'manual';

    /**
     * A short, non-attacker-controlled label safe to place in a notification.
     */
    public static function label(string $reasonCode): string
    {
        return match ($reasonCode) {
            self::RATE_LIMIT => 'Request rate limit exceeded',
            self::KNOWN_ATTACK_PATH => 'Known attack path probed',
            self::MANUAL => 'Manually blocked',
            default => 'Security policy violation',
        };
    }
}
