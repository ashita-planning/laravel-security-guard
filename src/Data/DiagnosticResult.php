<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Data;

/**
 * The outcome of one configuration check.
 *
 * Severity is deliberately three-valued. A misconfiguration that will lock
 * administrators out or silently disable a defence is not the same as one that
 * merely deserves attention before going to production, and collapsing the two
 * would make `--strict` either useless or unusable.
 */
final class DiagnosticResult
{
    /** The check passed. */
    public const OK = 'ok';

    /** Works, but is unsafe or fragile in production. */
    public const WARNING = 'warning';

    /** Broken or actively dangerous; the module cannot be trusted as configured. */
    public const FAILURE = 'failure';

    /** Not applicable, usually because the module is disabled. */
    public const SKIPPED = 'skipped';

    /**
     * @param  self::OK|self::WARNING|self::FAILURE|self::SKIPPED  $status
     * @param  array<string, string>  $context
     */
    private function __construct(
        public readonly string $check,
        public readonly string $status,
        public readonly string $message,
        public readonly ?string $remedy = null,
        public readonly array $context = [],
    ) {}

    /**
     * @param  array<string, string>  $context
     */
    public static function ok(string $check, string $message, array $context = []): self
    {
        return new self($check, self::OK, $message, null, $context);
    }

    /**
     * @param  array<string, string>  $context
     */
    public static function warning(string $check, string $message, string $remedy, array $context = []): self
    {
        return new self($check, self::WARNING, $message, $remedy, $context);
    }

    /**
     * @param  array<string, string>  $context
     */
    public static function failure(string $check, string $message, string $remedy, array $context = []): self
    {
        return new self($check, self::FAILURE, $message, $remedy, $context);
    }

    public static function skipped(string $check, string $message): self
    {
        return new self($check, self::SKIPPED, $message);
    }

    public function isFailure(): bool
    {
        return $this->status === self::FAILURE;
    }

    public function isWarning(): bool
    {
        return $this->status === self::WARNING;
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'check' => $this->check,
            'status' => $this->status,
            'message' => $this->message,
            'remedy' => $this->remedy,
            'context' => $this->context,
        ];
    }
}
