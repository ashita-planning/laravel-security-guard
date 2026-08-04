<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Data;

final class NotificationResult
{
    private function __construct(
        public readonly bool $sent,
        public readonly string $channel,
        public readonly ?string $reason = null,
        public readonly bool $retryable = false,
    ) {}

    public static function sent(string $channel): self
    {
        return new self(true, $channel);
    }

    /**
     * Not delivered, and retrying will not change that: no recipients are
     * configured, the channel is unknown, or there was nothing to send.
     *
     * @param  string  $reason  A fixed reason code, never an exception message.
     */
    public static function skipped(string $channel, string $reason): self
    {
        return new self(false, $channel, $reason);
    }

    /**
     * Not delivered because the transport failed. Worth another attempt.
     */
    public static function failed(string $channel, string $reason = 'delivery_failed'): self
    {
        return new self(false, $channel, $reason, true);
    }

    /**
     * Should the queue try this channel again?
     */
    public function isRetryable(): bool
    {
        return ! $this->sent && $this->retryable;
    }
}
