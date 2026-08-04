<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Tests\Feature;

use Apkk\LaravelSecurityGuard\Contracts\ErrorEventNotifierContract;
use Apkk\LaravelSecurityGuard\Data\ErrorEventData;
use Apkk\LaravelSecurityGuard\Data\NotificationResult;
use Apkk\LaravelSecurityGuard\Exceptions\NotificationDeliveryFailed;
use Apkk\LaravelSecurityGuard\Jobs\SendAggregatedErrorNotification;
use Apkk\LaravelSecurityGuard\Notifications\NotifierRegistry;
use Apkk\LaravelSecurityGuard\Notifications\SecurityMessageBuilder;
use Apkk\LaravelSecurityGuard\Services\ErrorNotificationGuard;
use Apkk\LaravelSecurityGuard\Tests\TestCase;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Queue;

/**
 * Delivery has to survive a flaky channel.
 *
 * Notifiers swallow their own transport errors so that a broken mailer cannot
 * fail a block, which leaves the job as the only thing able to signal the
 * queue. If it never throws, `$tries` is decorative and every attempt
 * "succeeds" having sent nothing.
 */
class NotificationResilienceTest extends TestCase
{
    use RefreshDatabase;

    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);

        $app->make(Repository::class)->set([
            'security-guard.error_notifications.enabled' => true,
            'security-guard.error_notifications.aggregation_delay_seconds' => 0,
            'security-guard.error_notifications.daily_limits' => ['mail' => 4],
        ]);
    }

    private function guard(): ErrorNotificationGuard
    {
        return $this->app->make(ErrorNotificationGuard::class);
    }

    private function event(int $reference = 1): ErrorEventData
    {
        return new ErrorEventData('production', 'front', 'front_error', $reference, 'RuntimeException');
    }

    /**
     * Register a mail notifier whose outcome the test controls.
     */
    /**
     * @param-out int $calls
     */
    private function fakeMailChannel(NotificationResult $result, ?int &$calls = null): void
    {
        $calls = 0;

        $this->app->make(NotifierRegistry::class)->registerErrorChannel(
            'mail',
            function () use ($result, &$calls): ErrorEventNotifierContract {
                return new class($result, $calls) implements ErrorEventNotifierContract
                {
                    public function __construct(private NotificationResult $result, private int &$calls) {}

                    public function notify(array $events): NotificationResult
                    {
                        $this->calls++;

                        return $this->result;
                    }
                };
            },
        );
    }

    public function test_a_transport_failure_throws_so_the_queue_retries(): void
    {
        Queue::fake();
        $this->guard()->report($this->event());

        $this->fakeMailChannel(NotificationResult::failed('mail'));

        $this->expectException(NotificationDeliveryFailed::class);

        $this->app->call([new SendAggregatedErrorNotification('front_error'), 'handle']);
    }

    public function test_a_misconfiguration_does_not_trigger_a_retry(): void
    {
        Queue::fake();
        $this->guard()->report($this->event());

        // No recipients configured: retrying cannot fix that.
        $this->fakeMailChannel(NotificationResult::skipped('mail', 'no_recipients'));

        $this->fakeMailChannel(NotificationResult::skipped('mail', 'no_recipients'), $calls);
        $this->app->call([new SendAggregatedErrorNotification('front_error'), 'handle']);

        // Attempted once and not retried: the queue is never signalled.
        $this->assertSame(1, $calls);
    }

    public function test_the_batch_survives_a_failed_attempt(): void
    {
        Queue::fake();
        $this->guard()->report($this->event(1));
        $this->guard()->report($this->event(2));

        $this->fakeMailChannel(NotificationResult::failed('mail'));

        try {
            $this->app->call([new SendAggregatedErrorNotification('front_error'), 'handle']);
        } catch (NotificationDeliveryFailed) {
            // Expected: the first attempt failed.
        }

        // A retry rebuilds the job from its payload, so the events have to be
        // waiting in the cache rather than on the previous job instance.
        $this->fakeMailChannel(NotificationResult::sent('mail'), $calls);
        $this->app->call([new SendAggregatedErrorNotification('front_error'), 'handle']);

        $this->assertSame(1, $calls, 'The retry must deliver the retained batch.');
    }

    public function test_a_delivered_batch_is_not_sent_twice(): void
    {
        Queue::fake();
        $this->guard()->report($this->event());

        $this->fakeMailChannel(NotificationResult::sent('mail'), $calls);

        $this->app->call([new SendAggregatedErrorNotification('front_error'), 'handle']);
        $this->app->call([new SendAggregatedErrorNotification('front_error'), 'handle']);

        $this->assertSame(1, $calls);
    }

    public function test_the_aggregation_buffer_stops_growing_at_the_cap(): void
    {
        Queue::fake();
        config()->set('security-guard.error_notifications.max_aggregated_events', 5);

        for ($i = 1; $i <= 40; $i++) {
            $this->guard()->report($this->event($i));
        }

        $batch = $this->guard()->claim('front_error');

        // The sample is capped; the count is not, so the message can still say
        // how bad it really was.
        $this->assertCount(5, $batch->events);
        $this->assertSame(40, $batch->total);
        $this->assertTrue($batch->truncated());
    }

    public function test_the_message_reports_the_true_occurrence_count(): void
    {
        Queue::fake();
        config()->set('security-guard.error_notifications.max_aggregated_events', 3);

        for ($i = 1; $i <= 12; $i++) {
            $this->guard()->report($this->event($i));
        }

        $batch = $this->guard()->claim('front_error');
        $body = $this->app->make(SecurityMessageBuilder::class)
            ->forErrorEvents($batch->events, $batch->total);

        $this->assertStringContainsString('Occurrences: 12 (showing 3)', $body);
    }

    public function test_only_the_first_event_of_a_window_schedules_delivery(): void
    {
        Queue::fake();

        for ($i = 1; $i <= 10; $i++) {
            $this->guard()->report($this->event($i));
        }

        Queue::assertPushed(SendAggregatedErrorNotification::class, 1);
    }
}
