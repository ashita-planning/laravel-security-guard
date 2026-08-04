<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Data;

final class AdminAllowedIpRecord
{
    public function __construct(
        public readonly int|string $id,
        public readonly string $subjectType,
        public readonly string $subjectId,
        public readonly string $ipAddress,
        public readonly ?string $label,
        public readonly bool $enabled,
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
        );
    }
}
