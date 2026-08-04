<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Data;

use DateTimeImmutable;
use DateTimeInterface;

final class BlockedIpRecord
{
    public function __construct(
        public readonly int|string $id,
        public readonly string $ipAddress,
        public readonly string $reasonCode,
        public readonly ?string $matchedPattern,
        public readonly int $requestCount,
        public readonly ?DateTimeImmutable $blockedAt,
        public readonly ?DateTimeImmutable $lastAttemptedAt = null,
        public readonly ?DateTimeImmutable $notifiedAt = null,
        public readonly ?DateTimeImmutable $releasedAt = null,
        public readonly ?string $releasedByType = null,
        public readonly ?string $releasedById = null,
    ) {}

    public function isActive(): bool
    {
        return $this->releasedAt === null;
    }

    public function reasonLabel(): string
    {
        return BlockReason::label($this->reasonCode);
    }

    /**
     * @param  array<string, mixed>  $attributes
     */
    public static function fromArray(array $attributes): self
    {
        return new self(
            id: $attributes['id'],
            ipAddress: (string) $attributes['ip_address'],
            reasonCode: (string) $attributes['reason_code'],
            matchedPattern: isset($attributes['matched_pattern']) ? (string) $attributes['matched_pattern'] : null,
            requestCount: (int) ($attributes['request_count'] ?? 1),
            blockedAt: self::toDate($attributes['blocked_at'] ?? null),
            lastAttemptedAt: self::toDate($attributes['last_attempted_at'] ?? null),
            notifiedAt: self::toDate($attributes['notified_at'] ?? null),
            releasedAt: self::toDate($attributes['released_at'] ?? null),
            releasedByType: isset($attributes['released_by_type']) ? (string) $attributes['released_by_type'] : null,
            releasedById: isset($attributes['released_by_id']) ? (string) $attributes['released_by_id'] : null,
        );
    }

    private static function toDate(mixed $value): ?DateTimeImmutable
    {
        if ($value === null || $value === '') {
            return null;
        }

        if ($value instanceof DateTimeImmutable) {
            return $value;
        }

        if ($value instanceof DateTimeInterface) {
            return DateTimeImmutable::createFromInterface($value);
        }

        return new DateTimeImmutable((string) $value);
    }
}
