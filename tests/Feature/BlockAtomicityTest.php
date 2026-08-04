<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Tests\Feature;

use Apkk\LaravelSecurityGuard\Contracts\BlockedIpRepositoryContract;
use Apkk\LaravelSecurityGuard\Data\BlockIpData;
use Apkk\LaravelSecurityGuard\Data\BlockReason;
use Apkk\LaravelSecurityGuard\Events\IpBlocked;
use Apkk\LaravelSecurityGuard\Models\BlockedIp;
use Apkk\LaravelSecurityGuard\Services\IpBlockService;
use Apkk\LaravelSecurityGuard\Tests\TestCase;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Event;

/**
 * Exactly one caller may claim to have blocked an address.
 *
 * The flag decides whether a notification goes out, so getting it wrong means
 * either a duplicate alert for every request of a flood, or none at all.
 */
class BlockAtomicityTest extends TestCase
{
    use RefreshDatabase;

    private function repository(): BlockedIpRepositoryContract
    {
        return $this->app->make(BlockedIpRepositoryContract::class);
    }

    public function test_the_first_block_of_an_address_is_reported_as_new(): void
    {
        $result = $this->repository()->block(
            new BlockIpData('203.0.113.10', BlockReason::KNOWN_ATTACK_PATH, 'wordpress_probe'),
        );

        $this->assertTrue($result->isNewBlock);
        $this->assertSame('203.0.113.10', $result->record->ipAddress);
    }

    public function test_blocking_an_already_blocked_address_is_not_reported_as_new(): void
    {
        $data = new BlockIpData('203.0.113.10', BlockReason::RATE_LIMIT, null, 121);

        $this->assertTrue($this->repository()->block($data)->isNewBlock);

        for ($i = 0; $i < 5; $i++) {
            $this->assertFalse(
                $this->repository()->block($data)->isNewBlock,
                'Only the transition into a blocked state counts as new.',
            );
        }

        $this->assertSame(1, BlockedIp::query()->count());
    }

    public function test_re_blocking_a_released_address_is_reported_as_new_again(): void
    {
        $service = $this->app->make(IpBlockService::class);

        $this->assertTrue($service->block('203.0.113.20', BlockReason::RATE_LIMIT)?->isNewBlock);
        $service->release('203.0.113.20');

        // A fresh incident after a release deserves a fresh notification.
        $this->assertTrue($service->block('203.0.113.20', BlockReason::RATE_LIMIT)?->isNewBlock);
        $this->assertSame(1, BlockedIp::query()->count());
    }

    public function test_re_blocking_resets_the_notification_marker(): void
    {
        $service = $this->app->make(IpBlockService::class);
        $first = $service->block('203.0.113.21', BlockReason::RATE_LIMIT);

        $this->repository()->markNotified($first->record->id);
        $service->release('203.0.113.21');
        $service->block('203.0.113.21', BlockReason::KNOWN_ATTACK_PATH, 'secret_file_probe');

        $record = $service->findActive('203.0.113.21');
        $this->assertNotNull($record);
        $this->assertNull($record->notifiedAt, 'A re-block must be announceable again.');
        $this->assertSame('secret_file_probe', $record->matchedPattern);
    }

    public function test_a_sustained_flood_announces_the_block_once(): void
    {
        Event::fake([IpBlocked::class]);

        $service = $this->app->make(IpBlockService::class);

        for ($i = 1; $i <= 10; $i++) {
            $service->block('203.0.113.30', BlockReason::RATE_LIMIT, requestCount: 120 + $i);
        }

        Event::assertDispatchedTimes(IpBlocked::class, 10);
        Event::assertDispatched(
            IpBlocked::class,
            fn (IpBlocked $event): bool => $event->isNewBlock === true,
        );

        // Ten writes, one transition.
        $newBlocks = 0;
        Event::assertDispatched(IpBlocked::class, function (IpBlocked $event) use (&$newBlocks): bool {
            $newBlocks += $event->isNewBlock ? 1 : 0;

            return true;
        });
        $this->assertSame(1, $newBlocks);
    }

    public function test_the_request_count_only_moves_upward(): void
    {
        $repository = $this->repository();

        $repository->block(new BlockIpData('203.0.113.40', BlockReason::RATE_LIMIT, null, 500));
        $repository->block(new BlockIpData('203.0.113.40', BlockReason::RATE_LIMIT, null, 3));

        $this->assertSame(500, (int) BlockedIp::query()->value('request_count'));
    }

    public function test_an_invalid_address_is_refused_rather_than_stored(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        $this->repository()->block(new BlockIpData("203.0.113.10' OR 1=1", BlockReason::RATE_LIMIT));
    }
}
