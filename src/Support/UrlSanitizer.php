<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Support;

/**
 * Prepares a URL for storage in the host's own error report table.
 *
 * The package never sends a URL outward; this exists because hosts do store
 * one, and a raw URL carries password reset tokens, signatures and API keys in
 * its query string. Values are replaced before the string is truncated to the
 * column width in bytes, so a multi-byte path cannot overflow the column.
 */
final class UrlSanitizer
{
    public const MASK = '[FILTERED]';

    /**
     * @param  array<int, string>  $maskedKeys
     */
    public static function sanitize(string $url, array $maskedKeys = [], int $maxBytes = 255): string
    {
        $sanitized = self::maskQuery($url, $maskedKeys);

        return self::truncateBytes($sanitized, $maxBytes);
    }

    /**
     * @param  array<int, string>  $maskedKeys
     */
    public static function maskQuery(string $url, array $maskedKeys): string
    {
        $position = strpos($url, '?');

        if ($position === false || $maskedKeys === []) {
            return $url;
        }

        $base = substr($url, 0, $position);
        $queryString = substr($url, $position + 1);
        $fragment = '';

        if (($hashPosition = strpos($queryString, '#')) !== false) {
            $fragment = substr($queryString, $hashPosition);
            $queryString = substr($queryString, 0, $hashPosition);
        }

        $lowerKeys = array_map('strtolower', $maskedKeys);
        $pairs = [];

        foreach (explode('&', $queryString) as $pair) {
            if ($pair === '') {
                continue;
            }

            [$key, $value] = array_pad(explode('=', $pair, 2), 2, '');

            $pairs[] = in_array(strtolower(rawurldecode($key)), $lowerKeys, true)
                ? $key.'='.self::MASK
                : $key.($value === '' && ! str_contains($pair, '=') ? '' : '='.$value);
        }

        return $base.($pairs === [] ? '' : '?'.implode('&', $pairs)).$fragment;
    }

    /**
     * Cut on a byte budget without leaving a broken multi-byte sequence behind.
     */
    public static function truncateBytes(string $value, int $maxBytes): string
    {
        if ($maxBytes < 1 || strlen($value) <= $maxBytes) {
            return $value;
        }

        // mb_strcut works on the byte budget but stops on a character boundary,
        // so a truncated URL is never invalid UTF-8 in the host's column.
        return mb_check_encoding($value, 'UTF-8')
            ? mb_strcut($value, 0, $maxBytes, 'UTF-8')
            : substr($value, 0, $maxBytes);
    }
}
