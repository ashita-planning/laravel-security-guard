<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Data;

final class NotificationResult
{
    private function __construct(
        public readonly bool $sent,
        public readonly string $channel,
        public readonly ?string $reason = null,
    ) {}

    public static function sent(string $channel): self
    {
        return new self(true, $channel);
    }

    /**
     * @param  string  $reason  A fixed reason code, never an exception message.
     */
    public static function skipped(string $channel, string $reason): self
    {
        return new self(false, $channel, $reason);
    }

    public static function failed(string $channel, string $reason = 'delivery_failed'): self
    {
        return new self(false, $channel, $reason);
    }
}
