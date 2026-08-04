<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Data;

use DateTimeImmutable;

/**
 * A host error occurrence, reduced to what is safe to send outside.
 *
 * Exception messages, stack traces, URLs and request payloads have no field
 * here on purpose. Store those in your own report table and reference the row
 * through `reportReference`.
 */
final class ErrorEventData
{
    public readonly string $environment;

    public readonly string $area;

    public readonly string $notificationType;

    public readonly ?string $exceptionClass;

    public readonly int|string $reportReference;

    public function __construct(
        string $environment,
        string $area,
        string $notificationType,
        int|string $reportReference,
        ?string $exceptionClass = null,
        public readonly ?DateTimeImmutable $occurredAt = null,
    ) {
        $this->environment = self::safeToken($environment) ?? 'unknown';
        $this->area = self::safeToken($area) ?? 'unknown';
        $this->notificationType = self::safeToken($notificationType) ?? 'unknown';
        $this->exceptionClass = self::safeClassName($exceptionClass);
        // Printed into the notification body, so it is held to an identifier
        // shape even though the host supplies it.
        $this->reportReference = self::safeIdentifier($reportReference);
    }

    /**
     * @return array<string, string>
     */
    public function toArray(): array
    {
        return [
            'environment' => $this->environment,
            'area' => $this->area,
            'notification_type' => $this->notificationType,
            'report_reference' => (string) $this->reportReference,
            'exception_class' => $this->exceptionClass ?? '',
            'occurred_at' => $this->occurredAt?->format('Y-m-d H:i:s') ?? '',
        ];
    }

    /**
     * @param  array<string, mixed>  $payload
     */
    public static function fromArray(array $payload): self
    {
        return new self(
            environment: (string) ($payload['environment'] ?? ''),
            area: (string) ($payload['area'] ?? ''),
            notificationType: (string) ($payload['notification_type'] ?? ''),
            reportReference: $payload['report_reference'] ?? '',
            exceptionClass: isset($payload['exception_class']) && $payload['exception_class'] !== ''
                ? (string) $payload['exception_class']
                : null,
            occurredAt: isset($payload['occurred_at']) && $payload['occurred_at'] !== ''
                ? new DateTimeImmutable((string) $payload['occurred_at'])
                : null,
        );
    }

    private static function safeToken(?string $value): ?string
    {
        if ($value === null) {
            return null;
        }

        $value = trim($value);

        return preg_match('/^[A-Za-z0-9_.\-]{1,100}$/', $value) === 1 ? $value : null;
    }

    /**
     * Report references are integers, UUIDs or ULIDs. Anything else is replaced
     * rather than concatenated into a notification.
     */
    private static function safeIdentifier(int|string $value): int|string
    {
        if (is_int($value)) {
            return $value;
        }

        $value = trim($value);

        return preg_match('/^[A-Za-z0-9_\-]{1,64}$/', $value) === 1 ? $value : 'unknown';
    }

    private static function safeClassName(?string $value): ?string
    {
        if ($value === null) {
            return null;
        }

        $value = trim($value);

        return preg_match('/^[A-Za-z0-9_\\\\]{1,191}$/', $value) === 1 ? $value : null;
    }
}
