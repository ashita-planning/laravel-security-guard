<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Tests\Feature;

use Apkk\LaravelSecurityGuard\Contracts\BlockedIpRepositoryContract;
use Apkk\LaravelSecurityGuard\Data\BlockReason;
use Apkk\LaravelSecurityGuard\Data\SecurityEventData;
use Apkk\LaravelSecurityGuard\Http\Middleware\GuardPublicRequests;
use Apkk\LaravelSecurityGuard\Jobs\SendSecurityEventNotification;
use Apkk\LaravelSecurityGuard\Notifications\NotifierRegistry;
use Apkk\LaravelSecurityGuard\Notifications\SecurityMessageBuilder;
use Apkk\LaravelSecurityGuard\Services\DailyLimiter;
use Apkk\LaravelSecurityGuard\Services\IpBlockService;
use Apkk\LaravelSecurityGuard\Services\NotificationDeliveryState;
use Apkk\LaravelSecurityGuard\Services\NotificationSuspension;
use Apkk\LaravelSecurityGuard\Support\FailureLogger;
use Apkk\LaravelSecurityGuard\Tests\TestCase;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Http\Kernel;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Queue;
use Illuminate\Support\Facades\Route;

class SecurityEventNotificationTest extends TestCase
{
    use RefreshDatabase;

    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);

        $app->make(Kernel::class)->prependMiddleware(GuardPublicRequests::class);

        tap($app->make(Repository::class), function (Repository $config): void {
            $config->set('security-guard.notifications.enabled', true);
            $config->set('security-guard.notifications.channels', ['mail']);
            $config->set('security-guard.notifications.mail.to', ['ops@example.test']);
        });
    }

    protected function defineRoutes($router): void
    {
        Route::get('/', fn (): string => 'home');
    }

    private function block(string $ipAddress = '203.0.113.10'): void
    {
        $this->app->make(IpBlockService::class)->block(
            $ipAddress,
            BlockReason::KNOWN_ATTACK_PATH,
            'wordpress_probe',
        );
    }

    public function test_blocking_queues_one_notification(): void
    {
        Queue::fake();

        $this->block();

        Queue::assertPushed(SendSecurityEventNotification::class, 1);
    }

    public function test_notifications_stay_silent_while_the_module_is_disabled(): void
    {
        config()->set('security-guard.notifications.enabled', false);
        Queue::fake();

        $this->block();

        Queue::assertNothingPushed();
    }

    public function test_re_blocking_an_active_address_does_not_queue_a_second_notification(): void
    {
        Queue::fake();

        $this->block();
        $this->block();

        Queue::assertPushed(SendSecurityEventNotification::class, 1);
    }

    public function test_the_job_is_unique_per_block(): void
    {
        $this->block();

        $record = $this->app->make(BlockedIpRepositoryContract::class)->findActive('203.0.113.10');
        $this->assertNotNull($record);

        $job = new SendSecurityEventNotification(SecurityEventData::ipBlocked($record)->toArray());

        $this->assertSame('ip_blocked:'.$record->id, $job->uniqueId());
    }

    public function test_a_delivered_notification_marks_the_block_as_notified(): void
    {
        $this->block();

        $this->assertCount(1, $this->sentMails());

        $record = $this->app->make(BlockedIpRepositoryContract::class)->findActive('203.0.113.10');
        $this->assertNotNull($record->notifiedAt);
    }

    public function test_an_already_notified_block_is_not_announced_again(): void
    {
        $this->block();
        $this->assertCount(1, $this->sentMails());

        // Re-running the job (a queue retry, for instance) must stay silent.
        $record = $this->app->make(BlockedIpRepositoryContract::class)->findActive('203.0.113.10');
        (new SendSecurityEventNotification(SecurityEventData::ipBlocked($record)->toArray()))
            ->handle(
                $this->app->make(Repository::class),
                $this->app->make(NotifierRegistry::class),
                $this->app->make(DailyLimiter::class),
                $this->app->make(NotificationSuspension::class),
                $this->app->make(NotificationDeliveryState::class),
                $this->app->make(BlockedIpRepositoryContract::class),
                $this->app->make(FailureLogger::class),
            );

        $this->assertCount(1, $this->sentMails());
    }

    public function test_the_daily_limit_caps_the_number_of_events_sent(): void
    {
        config()->set('security-guard.notifications.daily_limit', 2);
        $this->block('203.0.113.1');
        $this->block('203.0.113.2');
        $this->block('203.0.113.3');

        $this->assertCount(2, $this->sentMails());
    }

    public function test_a_daily_limit_of_zero_disables_delivery(): void
    {
        config()->set('security-guard.notifications.daily_limit', 0);
        $this->block();

        $this->assertCount(0, $this->sentMails());
    }

    public function test_the_limit_is_consumed_per_event_not_per_recipient(): void
    {
        config()->set('security-guard.notifications.daily_limit', 1);
        config()->set('security-guard.notifications.mail.to', [
            'ops@example.test',
            'security@example.test',
            'oncall@example.test',
        ]);
        $this->block();

        // Three recipients, one event, one allowance consumed.
        $this->assertCount(1, $this->sentMails());
        $this->assertSame(1, $this->app->make(DailyLimiter::class)
            ->used('security-events'));
    }

    public function test_a_failing_channel_never_undoes_the_block(): void
    {
        // No recipients configured: the mail channel cannot deliver anything.
        config()->set('security-guard.notifications.mail.to', []);

        $this->block();

        $this->assertDatabaseHas('security_guard_blocked_ips', [
            'ip_address' => '203.0.113.10',
            'released_at' => null,
        ]);
    }

    public function test_the_message_body_contains_no_attacker_controlled_text(): void
    {
        $event = new SecurityEventData(
            type: SecurityEventData::TYPE_IP_BLOCKED,
            blockId: 12,
            reasonCode: BlockReason::KNOWN_ATTACK_PATH,
            ipAddress: '203.0.113.10',
            detectedAt: new \DateTimeImmutable('2026-08-03 12:00:00'),
            matchedPattern: 'wordpress_probe',
        );

        $body = $this->app->make(SecurityMessageBuilder::class)->forSecurityEvent($event);

        foreach (['http://', 'https://', '?', '<', 'Stack trace', 'SQLSTATE'] as $forbidden) {
            $this->assertStringNotContainsString($forbidden, $body);
        }

        $this->assertStringContainsString('203.0.113.10', $body);
        $this->assertStringContainsString('wordpress_probe', $body);
        $this->assertStringContainsString('Block ID: 12', $body);
    }

    public function test_the_address_can_be_masked_in_the_message(): void
    {
        config()->set('security-guard.notifications.mask_ip', true);

        $event = new SecurityEventData(
            type: SecurityEventData::TYPE_IP_BLOCKED,
            blockId: 1,
            reasonCode: BlockReason::RATE_LIMIT,
            ipAddress: '203.0.113.10',
        );

        $body = $this->app->make(SecurityMessageBuilder::class)->forSecurityEvent($event);

        $this->assertStringContainsString('203.0.113.0/24', $body);
        $this->assertStringNotContainsString('203.0.113.10', $body);
    }
}
