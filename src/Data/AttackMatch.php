<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Data;

/**
 * The outcome of a known attack path match.
 *
 * Only the category and the match type are carried; the offending path itself
 * is deliberately absent so it cannot reach storage or a notification body.
 */
final class AttackMatch
{
    public const TYPE_EXACT = 'exact';

    public const TYPE_PREFIX = 'prefix';

    public const TYPE_REGEX = 'regex';

    public function __construct(
        public readonly string $category,
        public readonly string $type,
    ) {}

    public function toArray(): array
    {
        return [
            'category' => $this->category,
            'type' => $this->type,
        ];
    }
}
