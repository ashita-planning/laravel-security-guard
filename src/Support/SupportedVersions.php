<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Support;

/**
 * The single source of truth for what this package supports.
 *
 * The floors are not each major's `.0`: they are the oldest releases of each
 * line that Composer's advisory policy accepts. Anything below is installable
 * only by switching that check off, which is not something a security package
 * should ask of its users.
 *
 * SupportMatrixTest asserts these agree with composer.json, so the doctor
 * command and the manifest cannot drift apart.
 */
final class SupportedVersions
{
    /**
     * Laravel major => oldest release free of known advisories.
     *
     * Keys are written as strings but PHP stores them as integers; use
     * majors(), floorFor() and supportEndsFor() rather than indexing directly.
     *
     * @var array<int, string>
     */
    public const FLOORS = [
        '12' => '12.61.1',
        '13' => '13.12.0',
    ];

    /**
     * Laravel major => the date upstream stops shipping security fixes.
     *
     * @var array<int, string>
     */
    public const SECURITY_SUPPORT_ENDS = [
        '12' => '2027-02-24',
        '13' => '2028-03-17',
    ];

    /**
     * PHP silently casts numeric string array keys to integers, so the majors
     * are normalised back to strings rather than leaking that detail to every
     * caller.
     *
     * @return array<int, string>
     */
    public static function majors(): array
    {
        return array_map('strval', array_keys(self::FLOORS));
    }

    public static function floorFor(int|string $major): ?string
    {
        return self::FLOORS[(string) $major] ?? null;
    }

    public static function supportEndsFor(int|string $major): ?string
    {
        return self::SECURITY_SUPPORT_ENDS[(string) $major] ?? null;
    }

    /**
     * Human-readable range, for messages and documentation.
     */
    public static function describe(): string
    {
        $parts = [];

        foreach (self::FLOORS as $major => $floor) {
            $parts[] = "Laravel {$major} (>= {$floor})";
        }

        return implode(', ', $parts);
    }
}
