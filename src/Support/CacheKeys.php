<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Support;

/**
 * Cache and rate limiter key factory.
 *
 * Raw IP addresses and identifiers such as e-mail addresses never appear in a
 * key; they are hashed with SHA-256 first.
 */
final class CacheKeys
{
    public const PREFIX = 'security-guard';

    public static function hash(string $value): string
    {
        return hash('sha256', $value);
    }

    public static function block(string $normalizedIp): string
    {
        return self::PREFIX.':block:'.self::hash($normalizedIp);
    }

    public static function temporaryBlock(string $normalizedIp): string
    {
        return self::PREFIX.':temp-block:'.self::hash($normalizedIp);
    }

    public static function publicRequests(string $normalizedIp): string
    {
        return self::PREFIX.':requests:'.self::hash($normalizedIp);
    }

    public static function sensitive(string $profile, string $dimension, string $value): string
    {
        return self::PREFIX.":sensitive:{$profile}:{$dimension}:".self::hash($value);
    }

    public static function sensitiveLogOnce(string $profile, string $dimension, string $valueHash): string
    {
        return self::PREFIX.":sensitive-log:{$profile}:{$dimension}:{$valueHash}";
    }

    public static function usedSubmissionToken(string $token): string
    {
        return self::PREFIX.':submission-token:used:'.self::hash($token);
    }

    public static function dailyCounter(string $scope, string $day): string
    {
        return self::PREFIX.":daily:{$scope}:{$day}";
    }

    public static function suspendedChannel(string $scope, string $channel): string
    {
        return self::PREFIX.":suspended:{$scope}:{$channel}";
    }

    public static function errorAggregation(string $notificationType): string
    {
        return self::PREFIX.':error-aggregation:'.self::hash($notificationType);
    }

    public static function errorCooldown(string $notificationType): string
    {
        return self::PREFIX.':error-cooldown:'.self::hash($notificationType);
    }
}
