<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Services;

use Apkk\LaravelSecurityGuard\Contracts\ClientIpResolverContract;
use Apkk\LaravelSecurityGuard\Support\Ip;
use Illuminate\Http\Request;

/**
 * Default resolver: Laravel's own `Request::ip()`.
 *
 * X-Forwarded-For is never read here. Behind a proxy, configure Laravel's
 * TrustProxies middleware; that is the single place where proxy headers become
 * trusted, and this resolver simply follows that decision.
 */
class LaravelRequestIpResolver implements ClientIpResolverContract
{
    public function resolve(Request $request): ?string
    {
        return Ip::normalize($request->ip());
    }
}
