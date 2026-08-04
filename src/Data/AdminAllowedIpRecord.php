<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Data;

use DateTimeImmutable;
use DateTimeInterface;

final class AdminAllowedIpRecord
{
    public function __construct(
        public readonly int|string $id,
        public readonly string $subjectType,
        public readonly string $subjectId,
        public readonly string $ipAddress,
        public readonly ?string $label,
        public readonly bool $enabled,
        public readonly ?DateTimeImmutable $createdAt = null,
        public readonly ?DateTimeImmutable $updatedAt = null,
    ) {}

    /**
     * @param  array<string, mixed>  $attributes
     */
    public static function fromArray(array $attributes): self
    {
        return new self(
            id: $attributes['id'],
            subjectType: (string) $attributes['subject_type'],
            subjectId: (string) $attributes['subject_id'],
            ipAddress: (string) $attributes['ip_address'],
            label: isset($attributes['label']) ? (string) $attributes['label'] : null,
            enabled: (bool) ($attributes['enabled'] ?? true),
            createdAt: self::toDate($attributes['created_at'] ?? null),
            updatedAt: self::toDate($attributes['updated_at'] ?? null),
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
