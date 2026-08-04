<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Tests\Unit;

use Apkk\LaravelSecurityGuard\Data\BlockedIpRecord;
use Apkk\LaravelSecurityGuard\Data\BlockReason;
use Apkk\LaravelSecurityGuard\Data\ErrorEventData;
use Apkk\LaravelSecurityGuard\Data\SecurityEventData;
use DateTimeImmutable;
use PHPUnit\Framework\TestCase;

class SecurityEventDataTest extends TestCase
{
    public function test_it_only_carries_fields_that_are_safe_to_send(): void
    {
        $event = new SecurityEventData(
            type: SecurityEventData::TYPE_IP_BLOCKED,
            blockId: 7,
            reasonCode: BlockReason::KNOWN_ATTACK_PATH,
            ipAddress: '203.0.113.10',
            detectedAt: new DateTimeImmutable('2026-08-03 10:00:00'),
            matchedPattern: 'wordpress_probe',
        );

        // There is nowhere to put a URL, a header, a body or a stack trace,
        // which is what keeps attacker text out of notifications by design.
        $this->assertSame([
            'type',
            'block_id',
            'reason_code',
            'matched_pattern',
            'ip_address',
            'detected_at',
            'request_count',
        ], array_keys($event->toArray()));
    }

    public function test_it_discards_a_pattern_name_that_is_not_identifier_shaped(): void
    {
        $event = new SecurityEventData(
            type: SecurityEventData::TYPE_IP_BLOCKED,
            blockId: 1,
            reasonCode: BlockReason::KNOWN_ATTACK_PATH,
            ipAddress: '203.0.113.10',
            matchedPattern: 'https://evil.example/?<script>alert(1)</script>',
        );

        $this->assertNull($event->matchedPattern);
    }

    public function test_it_discards_an_unparseable_address(): void
    {
        $event = new SecurityEventData(
            type: SecurityEventData::TYPE_IP_BLOCKED,
            blockId: 1,
            reasonCode: BlockReason::RATE_LIMIT,
            ipAddress: "203.0.113.10' OR 1=1",
        );

        $this->assertNull($event->ipAddress);
        $this->assertSame('unknown', $event->displayIp());
    }

    public function test_it_normalizes_the_address_it_keeps(): void
    {
        $event = new SecurityEventData(
            type: SecurityEventData::TYPE_IP_BLOCKED,
            blockId: 1,
            reasonCode: BlockReason::RATE_LIMIT,
            ipAddress: '0:0:0:0:0:0:0:1',
        );

        $this->assertSame('::1', $event->ipAddress);
    }

    public function test_it_survives_a_round_trip_through_the_queue_payload(): void
    {
        $original = SecurityEventData::ipBlocked(new BlockedIpRecord(
            id: 42,
            ipAddress: '203.0.113.10',
            reasonCode: BlockReason::RATE_LIMIT,
            matchedPattern: null,
            requestCount: 121,
            blockedAt: new DateTimeImmutable('2026-08-03 10:00:00'),
        ));

        $restored = SecurityEventData::fromArray($original->toArray());

        $this->assertSame($original->toArray(), $restored->toArray());
        $this->assertSame('ip_blocked:42', $restored->uniqueId());
    }

    public function test_it_rejects_an_identifier_that_is_not_key_shaped(): void
    {
        // A custom repository decides this value, and it lands in the message
        // body and the job's unique key.
        $event = new SecurityEventData(
            type: SecurityEventData::TYPE_IP_BLOCKED,
            blockId: '1; DROP TABLE users--',
            reasonCode: BlockReason::RATE_LIMIT,
            ipAddress: '203.0.113.10',
        );

        $this->assertSame('unknown', $event->blockId);
    }

    public function test_it_accepts_the_key_shapes_hosts_actually_use(): void
    {
        foreach ([42, '42', '01JQZ0X9K5R7YB3H2N8M4T6VWX', 'c7a1f0e2-3b4c-4d5e-8f90-1a2b3c4d5e6f'] as $id) {
            $event = new SecurityEventData(
                type: SecurityEventData::TYPE_IP_BLOCKED,
                blockId: $id,
                reasonCode: BlockReason::RATE_LIMIT,
                ipAddress: '203.0.113.10',
            );

            $this->assertSame($id, $event->blockId);
        }
    }

    public function test_it_replaces_an_unrecognised_reason_code(): void
    {
        $event = new SecurityEventData(
            type: SecurityEventData::TYPE_IP_BLOCKED,
            blockId: 1,
            reasonCode: "rate_limit\nX-Injected: header",
            ipAddress: '203.0.113.10',
        );

        $this->assertSame('unknown', $event->reasonCode);
    }

    public function test_error_events_reject_a_reference_that_is_not_key_shaped(): void
    {
        $event = new ErrorEventData(
            environment: 'production',
            area: 'front',
            notificationType: 'front_error',
            reportReference: 'https://evil.example/leak?token=abc',
        );

        $this->assertSame('unknown', $event->reportReference);
    }

    public function test_error_events_reject_free_text_in_their_identifier_fields(): void
    {
        $event = new ErrorEventData(
            environment: 'production',
            area: "front\nInjected: line",
            notificationType: 'front_error',
            reportReference: 99,
            exceptionClass: 'RuntimeException: password=secret',
        );

        $this->assertSame('production', $event->environment);
        $this->assertSame('unknown', $event->area);
        $this->assertNull($event->exceptionClass);
    }
}
