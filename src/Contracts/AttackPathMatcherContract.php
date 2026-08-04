<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Contracts;

use Apkk\LaravelSecurityGuard\Data\AttackMatch;

interface AttackPathMatcherContract
{
    /**
     * Match a request path against the known attack path catalogue.
     *
     * Only the path is considered; query strings and request bodies are never
     * inspected here.
     */
    public function match(string $path): ?AttackMatch;
}
