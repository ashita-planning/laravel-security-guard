<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Contracts;

use Illuminate\Http\Request;

interface IdentifierResolverContract
{
    /**
     * Extract the identifier a sensitive route profile limits on, such as the
     * submitted e-mail address. The raw value never leaves this call: the
     * limiter hashes it before it reaches a cache key or a log line.
     */
    public function resolve(Request $request): ?string;
}
