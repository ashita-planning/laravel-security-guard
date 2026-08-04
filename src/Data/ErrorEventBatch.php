<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Data;

/**
 * A drained aggregation window.
 *
 * `total` counts every occurrence seen in the window, while `events` holds only
 * the retained sample. During an incident these differ by orders of magnitude,
 * and the message needs the real count even though the buffer refuses to grow
 * without bound.
 */
final class ErrorEventBatch
{
    /**
     * @param  array<int, ErrorEventData>  $events
     */
    public function __construct(
        public readonly array $events,
        public readonly int $total,
    ) {}

    public static function empty(): self
    {
        return new self([], 0);
    }

    public function isEmpty(): bool
    {
        return $this->events === [];
    }

    public function truncated(): bool
    {
        return $this->total > count($this->events);
    }
}
