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

    /** Bits of an IPv4 address kept when masking. */
    private const IPV4_KEEP_BITS = 24;

    /** Bits of an IPv6 address kept when masking. */
    private const IPV6_KEEP_BITS = 48;

    /**
     * Mask the host portion so notifications can reference an address without
     * exposing it in full.
     *
     * The masking is done on the packed bytes and re-rendered by inet_ntop, so
     * the result is always a valid address in CIDR form. Splitting the text on
     * ':' cannot work: `::1` has only three text segments, and keeping the
     * first three of them then appending '::' produces `::1::`, which is not an
     * address at all.
     */
    public static function mask(string $ipAddress): string
    {
        $packed = @inet_pton($ipAddress);

        if ($packed === false) {
            return 'unknown';
        }

        $keepBits = strlen($packed) === 4 ? self::IPV4_KEEP_BITS : self::IPV6_KEEP_BITS;
        $masked = self::zeroAfter($packed, $keepBits);
        $rendered = @inet_ntop($masked);

        return $rendered === false ? 'unknown' : $rendered.'/'.$keepBits;
    }

    /**
     * Zero every bit after the first `$keepBits` of a packed address.
     */
    private static function zeroAfter(string $packed, int $keepBits): string
    {
        $bytes = strlen($packed);

        for ($index = 0; $index < $bytes; $index++) {
            $bitOffset = $index * 8;

            if ($bitOffset >= $keepBits) {
                $packed[$index] = "\0";

                continue;
            }

            $remaining = $keepBits - $bitOffset;

            if ($remaining < 8) {
                // Partial byte: keep the high `$remaining` bits, clear the rest.
                $mask = (0xFF << (8 - $remaining)) & 0xFF;
                $packed[$index] = chr(ord($packed[$index]) & $mask);
            }
        }

        return $packed;
    }
}
