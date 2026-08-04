<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Data;

/**
 * Who performed an administrative action, stored as scalars so the package
 * never holds a reference to a host Eloquent model.
 */
final class ActorData
{
    public function __construct(
        public readonly ?string $type = null,
        public readonly ?string $id = null,
    ) {}

    public static function console(?string $identifier = null): self
    {
        return new self('console', $identifier);
    }

    public static function fromAuthenticatable(mixed $user, ?string $type = null): ?self
    {
        if (! is_object($user)) {
            return null;
        }

        $id = method_exists($user, 'getAuthIdentifier') ? $user->getAuthIdentifier() : null;

        if ($id === null) {
            return null;
        }

        return new self($type ?? $user::class, (string) $id);
    }
}
