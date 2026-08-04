<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Data;

/**
 * The outcome of one configuration check.
 *
 * Two orthogonal things are recorded, because conflating them makes the
 * report ambiguous: whether the check ran at all, and — if it did — how bad
 * the result was.
 *
 * A skipped check has no severity. It was not evaluated, usually because the
 * module it covers is switched off, so calling it "ok" would claim a guarantee
 * nobody verified and calling it a warning would demand action on a feature
 * nobody enabled.
 *
 * Severity itself is three-valued. "Works, but is unsafe in production" and
 * "broken or actively dangerous" are different problems; collapsing them would
 * make `--strict` either useless or unusable.
 */
final class DiagnosticResult
{
    /** The check ran. */
    public const STATE_EXECUTED = 'executed';

    /** The check did not run, so it carries no severity. */
    public const STATE_SKIPPED = 'skipped';

    /** Severity: the check passed. */
    public const OK = 'ok';

    /** Severity: works, but is unsafe or fragile in production. */
    public const WARNING = 'warning';

    /** Severity: broken or actively dangerous as configured. */
    public const FAILURE = 'failure';

    /**
     * @param  self::STATE_*  $state
     * @param  self::OK|self::WARNING|self::FAILURE|null  $severity
     * @param  array<string, string>  $context
     */
    private function __construct(
        public readonly string $check,
        public readonly string $state,
        public readonly ?string $severity,
        public readonly string $message,
        public readonly ?string $remedy = null,
        public readonly array $context = [],
    ) {}

    /**
     * @param  array<string, string>  $context
     */
    public static function ok(string $check, string $message, array $context = []): self
    {
        return new self($check, self::STATE_EXECUTED, self::OK, $message, null, $context);
    }

    /**
     * @param  array<string, string>  $context
     */
    public static function warning(string $check, string $message, string $remedy, array $context = []): self
    {
        return new self($check, self::STATE_EXECUTED, self::WARNING, $message, $remedy, $context);
    }

    /**
     * @param  array<string, string>  $context
     */
    public static function failure(string $check, string $message, string $remedy, array $context = []): self
    {
        return new self($check, self::STATE_EXECUTED, self::FAILURE, $message, $remedy, $context);
    }

    public static function skipped(string $check, string $message): self
    {
        return new self($check, self::STATE_SKIPPED, null, $message);
    }

    public function wasExecuted(): bool
    {
        return $this->state === self::STATE_EXECUTED;
    }

    public function isFailure(): bool
    {
        return $this->severity === self::FAILURE;
    }

    public function isWarning(): bool
    {
        return $this->severity === self::WARNING;
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'check' => $this->check,
            'state' => $this->state,
            'severity' => $this->severity,
            'message' => $this->message,
            'remedy' => $this->remedy,
            'context' => $this->context,
        ];
    }
}
