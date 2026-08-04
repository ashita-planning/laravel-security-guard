<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Support;

/**
 * IPv4 / IPv6 normalisation.
 *
 * Every comparison, cache key and stored value in this package must go through
 * `normalize()` first so that `::1` and `0:0:0:0:0:0:0:1` are one address.
 */
final class Ip
{
    public static function normalize(?string $ipAddress): ?string
    {
        if ($ipAddress === null) {
            return null;
        }

        $ipAddress = trim($ipAddress);

        if ($ipAddress === '' || filter_var($ipAddress, FILTER_VALIDATE_IP) === false) {
            return null;
        }

        $packed = @inet_pton($ipAddress);

        if ($packed === false) {
            return null;
        }

        $normalized = @inet_ntop($packed);

        return $normalized === false ? null : $normalized;
    }

    /**
     * Mask the host portion so notifications can reference an address without
     * exposing it in full.
     */
    public static function mask(string $ipAddress): string
    {
        if (str_contains($ipAddress, ':')) {
            $segments = explode(':', $ipAddress);
            $kept = array_slice($segments, 0, 3);

            return implode(':', $kept).'::';
        }

        $segments = explode('.', $ipAddress);

        if (count($segments) !== 4) {
            return $ipAddress;
        }

        return $segments[0].'.'.$segments[1].'.'.$segments[2].'.x';
    }
}
