<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Data;

/**
 * A logical administrative identity: no model class, no primary key type
 * assumptions, so UUID and string keys work unchanged.
 */
final class AdminSubjectData
{
    public function __construct(
        public readonly string $type,
        public readonly string $id,
    ) {}

    public function key(): string
    {
        return $this->type.'|'.$this->id;
    }
}
