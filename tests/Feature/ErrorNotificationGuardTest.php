<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Tests\Feature;

use Apkk\LaravelSecurityGuard\Contracts\ErrorNotificationOutcome;
use Apkk\LaravelSecurityGuard\Contracts\ErrorNotificationOutcomeHandlerContract;
use Apkk\LaravelSecurityGuard\Data\ErrorEventData;
use Apkk\LaravelSecurityGuard\Jobs\SendAggregatedErrorNotification;
use Apkk\LaravelSecurityGuard\Services\ErrorNotificationGuard;
use Apkk\LaravelSecurityGuard\Tests\TestCase;
use DateTimeImmutable;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Support\Facades\Queue;

class ErrorNotificationGuardTest extends TestCase
{
    /** @var array<int, array{events: array<int, ErrorEventData>, outcome: string}> */
    public static array $outcomes = [];

    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);

        tap($app->make(Repository::class), function (Repository $config): void {
            $config->set('security-guard.error_notifications.enabled', true);
            $config->set('security-guard.error_notifications.aggregation_delay_seconds', 0);
            $config->set('security-guard.error_notifications.daily_limits', ['mail' => 4]);
            $config->set('security-guard.notifications.mail.to', ['ops@example.test']);
        });

        $app->bind(ErrorNotificationOutcomeHandlerContract::class, fn (): object => new class implements ErrorNotificationOutcomeHandlerContract
        {
            public function handle(array $events, string $outcome): void
            {
                ErrorNotificationGuardTest::$outcomes[] = ['events' => $events, 'outcome' => $outcome];
            }
        });
    }

    protected function setUp(): void
    {
        parent::setUp();

        self::$outcomes = [];
    }

    private function guard(): ErrorNotificationGuard
    {
        return $this->app->make(ErrorNotificationGuard::class);
    }

    private function event(string $type = 'front_error', int $reference = 1): ErrorEventData
    {
        return new ErrorEventData(
            environment: 'production',
            area: 'front',
            notificationType: $type,
            reportReference: $reference,
            exceptionClass: 'RuntimeException',
            occurredAt: new DateTimeImmutable('2026-08-03 12:00:00'),
        );
    }

    public function test_it_stays_inert_while_disabled(): void
    {
        config()->set('security-guard.error_notifications.enabled', false);
        Queue::fake();

        $this->assertSame(ErrorNotificationGuard::DISABLED, $this->guard()->report($this->event()));

        Queue::assertNothingPushed();
    }

    public function test_the_first_event_of_a_window_schedules_one_delivery(): void
    {
        Queue::fake();

        $this->guard()->report($this->event());

        Queue::assertPushed(SendAggregatedErrorNotification::class, 1);
    }

    public function test_later_events_in_the_window_join_the_same_delivery(): void
    {
        Queue::fake();

        $guard = $this->guard();
        $guard->report($this->event(reference: 1));
        $guard->report($this->event(reference: 2));
        $guard->report($this->event(reference: 3));

        // One message for a burst, not one per occurrence.
        Queue::assertPushed(SendAggregatedErrorNotification::class, 1);
        $this->assertCount(3, $guard->drain('front_error'));
    }

    public function test_different_types_are_aggregated_separately(): void
    {
        Queue::fake();

        $guard = $this->guard();
        $guard->report($this->event('front_error'));
        $guard->report($this->event('batch_error'));

        Queue::assertPushed(SendAggregatedErrorNotification::class, 2);
    }

    public function test_a_delivered_batch_covers_every_aggregated_event_and_opens_a_cooldown(): void
    {
        Queue::fake();

        $guard = $this->guard();
        $guard->report($this->event(reference: 1));
        $guard->report($this->event(reference: 2));

        // Run the delayed job the way a worker would once the window closes.
        $this->app->call([new SendAggregatedErrorNotification('front_error'), 'handle']);

        $this->assertCount(1, $this->sentMails());
        $this->assertTrue($guard->inCooldown('front_error'));
        $this->assertSame(ErrorNotificationOutcome::SENT, self::$outcomes[0]['outcome']);
        $this->assertCount(2, self::$outcomes[0]['events']);
    }

    public function test_events_arriving_during_the_cooldown_are_suppressed(): void
    {
        $guard = $this->guard();

        $guard->report($this->event(reference: 1));
        $this->assertCount(1, $this->sentMails());

        $outcome = $guard->report($this->event(reference: 2));

        $this->assertSame(ErrorNotificationOutcome::COOLDOWN, $outcome);
        $this->assertCount(1, $this->sentMails());
    }

    public function test_the_daily_channel_limit_stops_delivery_and_reports_the_configured_outcome(): void
    {
        config()->set('security-guard.error_notifications.cooldown_minutes', 0);
        config()->set('security-guard.error_notifications.daily_limits', ['mail' => 2]);

        $guard = $this->guard();

        $guard->report($this->event('type_a'));
        $guard->report($this->event('type_b'));
        $guard->report($this->event('type_c'));

        $this->assertCount(2, $this->sentMails());

        $last = end(self::$outcomes);
        $this->assertSame(ErrorNotificationOutcome::LIMIT_MARK_HANDLED, $last['outcome']);
    }

    public function test_the_hold_policy_reports_a_different_outcome(): void
    {
        config()->set('security-guard.error_notifications.cooldown_minutes', 0);
        config()->set('security-guard.error_notifications.daily_limits', ['mail' => 1]);
        config()->set('security-guard.error_notifications.on_limit', 'hold');

        $guard = $this->guard();

        $guard->report($this->event('type_a'));
        $guard->report($this->event('type_b'));

        $last = end(self::$outcomes);
        $this->assertSame(ErrorNotificationOutcome::LIMIT_HELD, $last['outcome']);
    }

    public function test_channel_limits_are_independent(): void
    {
        config()->set('security-guard.error_notifications.cooldown_minutes', 0);
        config()->set('security-guard.error_notifications.daily_limits', ['mail' => 1, 'log' => 4]);

        $guard = $this->guard();

        $guard->report($this->event('type_a'));
        $guard->report($this->event('type_b'));

        // Mail is exhausted, but the log channel still records the second batch.
        $this->assertCount(1, $this->sentMails());
        $this->assertSame(ErrorNotificationOutcome::SENT, end(self::$outcomes)['outcome']);
    }

    public function test_the_message_body_carries_no_urls_or_exception_text(): void
    {
        $this->guard()->report($this->event());

        $body = $this->sentMailBodies()[0] ?? '';

        foreach (['http://', 'https://', '?', 'Stack trace', '/var/www'] as $forbidden) {
            $this->assertStringNotContainsString($forbidden, $body);
        }

        $this->assertStringContainsString('front_error', $body);
        $this->assertStringContainsString('RuntimeException', $body);
    }

    public function test_it_sanitizes_a_url_for_the_host_report_table(): void
    {
        $sanitized = $this->guard()->sanitizeUrl(
            'https://example.test/reset?token=secret-value&page=2',
        );

        $this->assertStringNotContainsString('secret-value', $sanitized);
        $this->assertStringContainsString('page=2', $sanitized);
    }
}
