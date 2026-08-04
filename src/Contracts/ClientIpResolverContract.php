<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Contracts;

use Illuminate\Http\Request;

interface ClientIpResolverContract
{
    /**
     * Return the normalised client IP, or null when it cannot be trusted.
     *
     * Implementations must never block a request by returning a placeholder:
     * an unresolvable address is null and the caller lets the request through.
     */
    public function resolve(Request $request): ?string;
}
