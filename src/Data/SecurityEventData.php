<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Data;

use Apkk\LaravelSecurityGuard\Support\Ip;
use DateTimeImmutable;

/**
 * The only shape a security event may take once it leaves the package.
 *
 * Construction is deliberately narrow: there is no field for a URL, a query
 * string, a header, a request body or an exception message, and every value
 * that does exist is re-validated here. An attacker-controlled string cannot
 * reach a notification body because there is nowhere to put it.
 */
final class SecurityEventData
{
    public const TYPE_IP_BLOCKED = 'ip_blocked';

    public readonly string $type;

    public readonly ?string $ipAddress;

    public readonly ?string $matchedPattern;

    public readonly int|string $blockId;

    public readonly string $reasonCode;

    public function __construct(
        string $type,
        int|string $blockId,
        string $reasonCode,
        ?string $ipAddress,
        public readonly ?DateTimeImmutable $detectedAt = null,
        ?string $matchedPattern = null,
        public readonly int $requestCount = 1,
    ) {
        $this->type = self::safeToken($type) ?? 'security_event';
        $this->ipAddress = Ip::normalize($ipAddress);
        $this->matchedPattern = self::safeToken($matchedPattern);
        // The id reaches the notification body and the job's unique key. A
        // custom repository could return anything as a primary key, so it is
        // held to the same identifier shape as every other field here.
        $this->blockId = self::safeIdentifier($blockId);
        $this->reasonCode = self::safeToken($reasonCode) ?? 'unknown';
    }

    public static function ipBlocked(BlockedIpRecord $record): self
    {
        return new self(
            type: self::TYPE_IP_BLOCKED,
            blockId: $record->id,
            reasonCode: $record->reasonCode,
            ipAddress: $record->ipAddress,
            detectedAt: $record->blockedAt,
            matchedPattern: $record->matchedPattern,
            requestCount: $record->requestCount,
        );
    }

    /**
     * @param  array<string, mixed>  $payload
     */
    public static function fromArray(array $payload): self
    {
        $detectedAt = (string) ($payload['detected_at'] ?? '');

        return new self(
            type: (string) ($payload['type'] ?? self::TYPE_IP_BLOCKED),
            blockId: $payload['block_id'] ?? '',
            reasonCode: (string) ($payload['reason_code'] ?? ''),
            ipAddress: ($payload['ip_address'] ?? '') !== '' ? (string) $payload['ip_address'] : null,
            detectedAt: $detectedAt !== '' ? new DateTimeImmutable($detectedAt) : null,
            matchedPattern: ($payload['matched_pattern'] ?? '') !== '' ? (string) $payload['matched_pattern'] : null,
            requestCount: (int) ($payload['request_count'] ?? 1),
        );
    }

    public function reasonLabel(): string
    {
        return BlockReason::label($this->reasonCode);
    }

    public function uniqueId(): string
    {
        return $this->type.':'.$this->blockId;
    }

    /**
     * The presentable address, masked when the host asks for masking.
     */
    public function displayIp(bool $mask = false): string
    {
        if ($this->ipAddress === null) {
            return 'unknown';
        }

        return $mask ? Ip::mask($this->ipAddress) : $this->ipAddress;
    }

    /**
     * @return array<string, string>
     */
    public function toArray(): array
    {
        return [
            'type' => $this->type,
            'block_id' => (string) $this->blockId,
            'reason_code' => $this->reasonCode,
            'matched_pattern' => $this->matchedPattern ?? '',
            'ip_address' => $this->ipAddress ?? '',
            'detected_at' => $this->detectedAt?->format('Y-m-d H:i:s') ?? '',
            'request_count' => (string) $this->requestCount,
        ];
    }

    /**
     * Accept only identifier-shaped values: category names and reason codes,
     * never free text.
     */
    private static function safeToken(?string $value): ?string
    {
        if ($value === null) {
            return null;
        }

        $value = trim($value);

        return preg_match('/^[A-Za-z0-9_.\-]{1,100}$/', $value) === 1 ? $value : null;
    }

    /**
     * Primary keys are integers, UUIDs or ULIDs. Anything else is replaced
     * rather than passed through to a message body or a cache key.
     */
    private static function safeIdentifier(int|string $value): int|string
    {
        if (is_int($value)) {
            return $value;
        }

        $value = trim($value);

        return preg_match('/^[A-Za-z0-9_\-]{1,64}$/', $value) === 1 ? $value : 'unknown';
    }
}
