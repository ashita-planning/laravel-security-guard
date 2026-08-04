<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Services;

use Apkk\LaravelSecurityGuard\Contracts\ClientIpResolverContract;
use Apkk\LaravelSecurityGuard\Support\Ip;
use Illuminate\Http\Request;

/**
 * Reads REMOTE_ADDR directly, ignoring trusted proxy configuration.
 *
 * Use this when the application is not behind a proxy and you want the socket
 * peer regardless of what Laravel's trusted proxy settings say.
 */
class RemoteAddrIpResolver implements ClientIpResolverContract
{
    public function resolve(Request $request): ?string
    {
        $ipAddress = $request->server('REMOTE_ADDR');

        return is_string($ipAddress) ? Ip::normalize($ipAddress) : null;
    }
}
