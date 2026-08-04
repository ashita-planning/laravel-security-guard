<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Support;

/**
 * Cache and rate limiter key factory.
 *
 * The prefix is per-instance rather than a constant so that several
 * applications sharing one Redis server keep separate block state, daily
 * counters and submission tokens. With a fixed prefix, staging exhausting its
 * notification allowance would silence production.
 *
 * Raw IP addresses and identifiers such as e-mail addresses never appear in a
 * key; they are hashed with SHA-256 first.
 */
final class CacheKeyFactory
{
    public const DEFAULT_PREFIX = 'security-guard';

    private readonly string $prefix;

    public function __construct(?string $prefix = null)
    {
        $prefix = trim((string) ($prefix ?? ''));

        $this->prefix = $prefix === '' ? self::DEFAULT_PREFIX : rtrim($prefix, ':');
    }

    public function prefix(): string
    {
        return $this->prefix;
    }

    public static function hash(string $value): string
    {
        return hash('sha256', $value);
    }

    public function block(string $normalizedIp): string
    {
        return $this->key('block', self::hash($normalizedIp));
    }

    public function temporaryBlock(string $normalizedIp): string
    {
        return $this->key('temp-block', self::hash($normalizedIp));
    }

    public function publicRequests(string $normalizedIp): string
    {
        return $this->key('requests', self::hash($normalizedIp));
    }

    public function sensitive(string $profile, string $dimension, string $value): string
    {
        return $this->key('sensitive', $profile, $dimension, self::hash($value));
    }

    public function sensitiveLogOnce(string $profile, string $dimension, string $valueHash): string
    {
        return $this->key('sensitive-log', $profile, $dimension, $valueHash);
    }

    public function usedSubmissionToken(string $token): string
    {
        return $this->key('submission-token', 'used', self::hash($token));
    }

    public function dailyCounter(string $scope, string $day): string
    {
        return $this->key('daily', $scope, $day);
    }

    public function suspendedChannel(string $scope, string $channel): string
    {
        return $this->key('suspended', $scope, $channel);
    }

    public function errorAggregation(string $notificationType): string
    {
        return $this->key('error-aggregation', self::hash($notificationType));
    }

    public function errorCooldown(string $notificationType): string
    {
        return $this->key('error-cooldown', self::hash($notificationType));
    }

    /**
     * A drained window held while its delivery job runs.
     *
     * A queue retry restores the job from its original payload, so anything the
     * previous attempt kept on the job instance is gone. The batch has to live
     * here instead, or a single transport failure would discard it.
     */
    public function errorInflight(string $notificationType): string
    {
        return $this->key('error-inflight', self::hash($notificationType));
    }

    /**
     * Tracks which channels an event has already reached, so a queue retry
     * resumes rather than restarting.
     */
    public function deliveryState(string $scope, string $uniqueId): string
    {
        return $this->key('delivery', $scope, self::hash($uniqueId));
    }

    private function key(string ...$segments): string
    {
        return $this->prefix.':'.implode(':', $segments);
    }
}
