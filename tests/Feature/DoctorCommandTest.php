<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Tests\Feature;

use Apkk\LaravelSecurityGuard\Console\DoctorCommand;
use Apkk\LaravelSecurityGuard\Contracts\AdminAllowedIpRepositoryContract;
use Apkk\LaravelSecurityGuard\Contracts\CrawlerVerifierContract;
use Apkk\LaravelSecurityGuard\Crawlers\CrawlerRangeStore;
use Apkk\LaravelSecurityGuard\Crawlers\CrawlerVerifierRegistry;
use Apkk\LaravelSecurityGuard\Data\AdminSubjectData;
use Apkk\LaravelSecurityGuard\SecurityGuardServiceProvider;
use Apkk\LaravelSecurityGuard\Support\CacheKeyFactory;
use Apkk\LaravelSecurityGuard\Tests\TestCase;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Artisan;

/**
 * The doctor exists because this package fails quietly.
 *
 * A misconfigured module does not throw; it stops defending, or it locks every
 * administrator out at the moment someone tries to sign in. These tests pin
 * the cases where staying silent would be worst.
 */
class DoctorCommandTest extends TestCase
{
    use RefreshDatabase;

    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);

        // A realistic healthy baseline: a shared, lock-capable store.
        $app->make(Repository::class)->set([
            'cache.default' => 'database',
            'security-guard.cache.store' => 'database',
            'security-guard.cache.prefix' => 'acme-production',
        ]);
    }

    protected function tearDown(): void
    {
        Carbon::setTestNow();

        parent::tearDown();
    }

    /**
     * Store a validated range document the way the refresh command would.
     *
     * @param  array<int, string>  $v4
     * @param  array<int, string>  $v6
     */
    private function seedRanges(string $provider, array $v4, array $v6 = []): void
    {
        $this->app->make(CrawlerRangeStore::class)->store($provider, [
            'creation_time' => '2026-08-01T00:00:00Z',
            'v4' => $v4,
            'v6' => $v6,
        ], "https://ranges.example.test/{$provider}.json", sha1($provider.serialize([$v4, $v6])));
    }

    /**
     * @param  array<string, mixed>  $options
     * @return array<string, mixed>
     */
    private function runJson(array $options = []): array
    {
        $exitCode = Artisan::call('security-guard:doctor', $options + ['--json' => true]);
        $decoded = json_decode(Artisan::output(), true);

        $this->assertIsArray($decoded, 'The --json output must be valid JSON.');
        $this->assertSame($exitCode, $decoded['exit_code']);

        return $decoded;
    }

    /**
     * @param  array<string, mixed>  $report
     * @return array<string, mixed>
     */
    private function check(array $report, string $name): array
    {
        foreach ($report['results'] as $result) {
            if ($result['check'] === $name) {
                return $result;
            }
        }

        $this->fail("The doctor did not report a check named {$name}.");
    }

    public function test_a_healthy_installation_passes(): void
    {
        $report = $this->runJson();

        $this->assertTrue($report['healthy'], 'Baseline should be healthy: '.json_encode($report['results']));
        $this->assertSame(0, $report['exit_code']);
        $this->assertSame(0, $report['summary']['failures']);
    }

    public function test_the_json_document_is_machine_readable(): void
    {
        $report = $this->runJson();

        $this->assertArrayHasKey('summary', $report);
        $this->assertArrayHasKey('results', $report);
        $this->assertNotEmpty($report['results']);

        foreach ($report['results'] as $result) {
            $this->assertArrayHasKey('check', $result);
            $this->assertArrayHasKey('state', $result);
            $this->assertArrayHasKey('severity', $result);
            $this->assertArrayHasKey('message', $result);

            // State and severity are orthogonal: a check that did not run
            // carries no severity at all.
            $this->assertContains($result['state'], ['executed', 'skipped']);

            if ($result['state'] === 'skipped') {
                $this->assertNull($result['severity']);

                continue;
            }

            $this->assertContains($result['severity'], ['ok', 'warning', 'failure']);
        }
    }

    public function test_it_confirms_the_running_laravel_version_is_supported(): void
    {
        $check = $this->check($this->runJson(), 'laravel_version');

        $this->assertSame('ok', $check['severity']);
        $this->assertArrayHasKey('security_support_ends', $check['context']);
    }

    public function test_it_reports_a_missing_table(): void
    {
        $this->app->make('db')->connection()->getSchemaBuilder()->drop('security_guard_blocked_ips');

        $check = $this->check($this->runJson(), 'database_tables');

        $this->assertSame('failure', $check['severity']);
        $this->assertStringContainsString('migrate', (string) $check['remedy']);
    }

    public function test_it_rejects_a_cache_store_that_keeps_nothing(): void
    {
        config()->set('security-guard.cache.store', 'array');

        $check = $this->check($this->runJson(), 'cache_shared');

        $this->assertSame('failure', $check['severity']);
    }

    public function test_it_verifies_add_is_a_test_and_set(): void
    {
        $check = $this->check($this->runJson(), 'cache_atomic_add');

        $this->assertSame('ok', $check['severity']);
    }

    public function test_it_flags_the_default_cache_prefix(): void
    {
        config()->set('security-guard.cache.prefix', null);

        $check = $this->check($this->runJson(), 'cache_prefix');

        $this->assertSame('warning', $check['severity']);
        $this->assertStringContainsString('prefix', (string) $check['remedy']);
    }

    public function test_it_rejects_an_unknown_ip_resolver_driver(): void
    {
        config()->set('security-guard.ip_resolver.driver', 'x_forwarded_for');

        $check = $this->check($this->runJson(), 'ip_resolver');

        $this->assertSame('failure', $check['severity']);
    }

    public function test_it_reports_an_invalid_attack_path_regex(): void
    {
        config()->set('security-guard.permanent_block.attack_patterns', [
            'broken' => ['regex' => ['#(unclosed#']],
        ]);

        $check = $this->check($this->runJson(), 'attack_patterns');

        $this->assertSame('failure', $check['severity']);
        $this->assertStringContainsString('broken', $check['context']['categories']);
    }

    public function test_it_catches_a_rate_limit_that_can_never_take_effect(): void
    {
        config()->set('security-guard.public_rate_limit.enabled', true);
        config()->set('security-guard.public_rate_limit.action', 'permanent_block');
        config()->set('security-guard.permanent_block.enabled', false);

        $check = $this->check($this->runJson(), 'rate_limit_consistency');

        $this->assertSame('failure', $check['severity']);
    }

    public function test_it_warns_about_paths_excluded_from_blocking(): void
    {
        config()->set('security-guard.permanent_block.excluded_paths', ['api/*']);

        $check = $this->check($this->runJson(), 'permanent_block_exclusions');

        $this->assertSame('warning', $check['severity']);
    }

    public function test_it_refuses_an_admin_allowlist_that_locks_everyone_out(): void
    {
        config()->set('security-guard.admin_ip.enabled', true);
        config()->set('security-guard.admin_ip.empty_policy', 'deny');

        $check = $this->check($this->runJson(), 'admin_ip_allowlist');

        $this->assertSame('failure', $check['severity']);
        $this->assertStringContainsString('admin-ip:allow', (string) $check['remedy']);
    }

    public function test_a_populated_admin_allowlist_passes(): void
    {
        config()->set('security-guard.admin_ip.enabled', true);

        $this->app->make(AdminAllowedIpRepositoryContract::class)
            ->allow(new AdminSubjectData('admin', '1'), '203.0.113.10');

        $check = $this->check($this->runJson(), 'admin_ip_allowlist');

        $this->assertSame('ok', $check['severity']);
    }

    public function test_it_warns_when_the_allowlist_lets_empty_subjects_through(): void
    {
        config()->set('security-guard.admin_ip.enabled', true);
        config()->set('security-guard.admin_ip.empty_policy', 'allow_when_empty');

        $check = $this->check($this->runJson(), 'admin_ip_allowlist');

        $this->assertSame('warning', $check['severity']);
    }

    public function test_it_reports_a_mail_channel_without_recipients(): void
    {
        config()->set('security-guard.notifications.enabled', true);
        config()->set('security-guard.notifications.channels', ['mail']);
        config()->set('security-guard.notifications.mail.to', []);

        $check = $this->check($this->runJson(), 'notification_recipients');

        $this->assertSame('failure', $check['severity']);
    }

    public function test_it_reports_an_unresolvable_notification_channel(): void
    {
        config()->set('security-guard.notifications.enabled', true);
        config()->set('security-guard.notifications.channels', ['carrier-pigeon']);

        $check = $this->check($this->runJson(), 'notification_channels');

        $this->assertSame('failure', $check['severity']);
    }

    public function test_it_warns_when_notifications_run_synchronously(): void
    {
        config()->set('security-guard.notifications.enabled', true);
        config()->set('security-guard.notifications.channels', ['log']);
        config()->set('queue.default', 'sync');

        $check = $this->check($this->runJson(), 'queue_connection');

        $this->assertSame('warning', $check['severity']);
    }

    public function test_it_refuses_a_management_ui_without_authorization(): void
    {
        config()->set('security-guard.management_ui.enabled', true);
        config()->set('security-guard.management_ui.middleware', ['web', 'auth']);

        $check = $this->check($this->runJson(), 'management_ui');

        $this->assertSame('failure', $check['severity']);
        $this->assertStringContainsString('authorization', $check['message']);
    }

    public function test_it_refuses_a_management_ui_without_authentication(): void
    {
        config()->set('security-guard.management_ui.enabled', true);
        config()->set('security-guard.management_ui.middleware', ['web']);

        $check = $this->check($this->runJson(), 'management_ui');

        $this->assertSame('failure', $check['severity']);
    }

    public function test_a_guarded_management_ui_passes(): void
    {
        config()->set('security-guard.management_ui.enabled', true);
        config()->set('security-guard.management_ui.middleware', ['web', 'auth', 'can:manage-security']);

        $check = $this->check($this->runJson(), 'management_ui');

        $this->assertSame('ok', $check['severity']);
    }

    public function test_it_refuses_submission_tokens_on_a_per_process_cache(): void
    {
        config()->set('security-guard.submission_token.enabled', true);
        config()->set('security-guard.cache.store', 'array');

        $check = $this->check($this->runJson(), 'submission_token');

        $this->assertSame('failure', $check['severity']);
    }

    public function test_disabled_modules_are_reported_as_skipped(): void
    {
        $report = $this->runJson();

        foreach (['admin_ip_allowlist', 'notifications', 'management_ui', 'submission_token', 'crawler_access'] as $name) {
            $check = $this->check($report, $name);

            $this->assertSame('skipped', $check['state']);
            $this->assertNull($check['severity'], 'A check that did not run must not claim a severity.');
        }

        // Skipped checks are counted separately from executed ones.
        $this->assertSame(
            $report['summary']['total'],
            $report['summary']['executed'] + $report['summary']['skipped'],
        );
    }

    public function test_strict_turns_warnings_into_a_non_zero_exit(): void
    {
        config()->set('security-guard.cache.prefix', null);

        $relaxed = $this->runJson();
        $this->assertSame(0, $relaxed['exit_code']);
        $this->assertGreaterThan(0, $relaxed['summary']['warnings']);

        $strict = $this->runJson(['--strict' => true]);
        $this->assertSame(DoctorCommand::EXIT_WARNINGS, $strict['exit_code']);
        $this->assertFalse($strict['healthy']);
    }

    public function test_a_failure_exits_non_zero_regardless_of_strict(): void
    {
        config()->set('security-guard.cache.store', 'array');

        $this->assertSame(DoctorCommand::FAILURE, $this->runJson()['exit_code']);
    }

    public function test_the_table_output_shows_remedies(): void
    {
        config()->set('security-guard.management_ui.enabled', true);
        config()->set('security-guard.management_ui.middleware', ['web']);

        $this->artisan('security-guard:doctor')
            ->assertExitCode(DoctorCommand::FAILURE)
            ->expectsOutputToContain('management_ui');
    }

    public function test_it_never_prints_a_secret(): void
    {
        config()->set('security-guard.notifications.enabled', true);
        config()->set('security-guard.notifications.channels', ['log', 'mail']);
        config()->set('security-guard.notifications.mail.to', ['ops@example.test']);
        config()->set('app.key', 'base64:c2VjcmV0LWtleS12YWx1ZS1oZXJlLWZvci10ZXN0aW5nIQ==');

        Artisan::call('security-guard:doctor', ['--json' => true]);
        $output = Artisan::output();

        $this->assertStringNotContainsString('base64:', $output);
        $this->assertStringNotContainsString((string) config('app.key'), $output);
    }

    // -----------------------------------------------------------------
    // Verified crawler access
    // -----------------------------------------------------------------

    public function test_it_reports_crawler_access_with_no_providers(): void
    {
        config()->set('security-guard.crawler_access.enabled', true);
        config()->set('security-guard.crawler_access.verified_crawlers', [
            'google' => false,
            'bing' => false,
        ]);

        $check = $this->check($this->runJson(), 'crawler_providers');

        $this->assertSame('failure', $check['severity']);
    }

    public function test_it_requires_range_data_before_crawlers_can_verify(): void
    {
        config()->set('security-guard.crawler_access.enabled', true);

        $report = $this->runJson();

        foreach (['crawler_ranges.google', 'crawler_ranges.bing'] as $name) {
            $check = $this->check($report, $name);

            $this->assertSame('failure', $check['severity'], $name);
            $this->assertStringContainsString('crawler-ranges:refresh', (string) $check['remedy']);
        }
    }

    public function test_a_refreshed_crawler_installation_passes(): void
    {
        config()->set('security-guard.crawler_access.enabled', true);
        $this->seedRanges('google', ['66.249.64.0/27'], ['2001:4860:4801:10::/64']);
        $this->seedRanges('bing', ['157.55.39.0/24'], ['2620:1ec:c::/48']);

        $report = $this->runJson();

        $healthy = [
            'crawler_providers',
            'crawler_cache',
            'crawler_ranges.google',
            'crawler_ranges.bing',
            'crawler_rate_limit',
            'crawler_verification',
        ];

        foreach ($healthy as $name) {
            $this->assertSame('ok', $this->check($report, $name)['severity'], $name);
        }
    }

    public function test_it_reports_stale_crawler_ranges(): void
    {
        Carbon::setTestNow('2026-08-04 12:00:00');

        config()->set('security-guard.crawler_access.enabled', true);
        $this->seedRanges('google', ['66.249.64.0/27']);

        // fresh_for_hours defaults to 168; a week and a second later the
        // data is retained but no longer trusted.
        Carbon::setTestNow('2026-08-11 12:00:01');

        $check = $this->check($this->runJson(), 'crawler_ranges.google');

        $this->assertSame('failure', $check['severity']);
        $this->assertStringContainsString('freshness', $check['message']);
        $this->assertArrayHasKey('fetched_at', $check['context']);
    }

    public function test_it_reports_corrupted_crawler_ranges(): void
    {
        config()->set('security-guard.crawler_access.enabled', true);

        // Written straight to the cache: the refresh validates before storing,
        // so a payload like this can only exist if the document was edited or
        // damaged in the store.
        $this->app->make(SecurityGuardServiceProvider::CACHE)->put(
            $this->app->make(CacheKeyFactory::class)->crawlerRanges('google'),
            [
                'provider' => 'google',
                'source' => 'https://ranges.example.test/google.json',
                'fetched_at' => Carbon::now()->toIso8601String(),
                'fresh_until' => Carbon::now()->addDays(7)->toIso8601String(),
                'content_hash' => 'irrelevant',
                'creation_time' => null,
                'v4' => ['66.249.64.0/27', 'not-a-network'],
                'v6' => [],
            ],
            3600,
        );

        $check = $this->check($this->runJson(), 'crawler_ranges.google');

        $this->assertSame('failure', $check['severity']);
        $this->assertStringContainsString('not-a-network', $check['context']['ranges']);
    }

    public function test_it_refuses_crawler_data_on_a_per_process_cache(): void
    {
        config()->set('security-guard.crawler_access.enabled', true);
        config()->set('security-guard.cache.store', 'array');

        $check = $this->check($this->runJson(), 'crawler_cache');

        $this->assertSame('failure', $check['severity']);
    }

    public function test_it_refuses_a_crawler_action_that_would_persist_a_block(): void
    {
        config()->set('security-guard.crawler_access.enabled', true);
        config()->set('security-guard.crawler_access.rate_limit.action', 'permanent_block');

        $check = $this->check($this->runJson(), 'crawler_rate_limit');

        $this->assertSame('failure', $check['severity']);
        $this->assertStringContainsString('reject_only', $check['message']);
    }

    public function test_it_warns_when_the_crawler_limit_normalises_to_one(): void
    {
        config()->set('security-guard.crawler_access.enabled', true);
        config()->set('security-guard.crawler_access.rate_limit.requests_per_minute', 0);

        $check = $this->check($this->runJson(), 'crawler_rate_limit_threshold');

        $this->assertSame('warning', $check['severity']);
    }

    public function test_it_reports_a_verifier_that_trusts_the_user_agent_alone(): void
    {
        config()->set('security-guard.crawler_access.enabled', true);

        $this->app->make(CrawlerVerifierRegistry::class)->register(new class implements CrawlerVerifierContract
        {
            public function provider(): string
            {
                return 'homegrown';
            }

            public function claimsUserAgent(string $userAgent): bool
            {
                return str_contains($userAgent, 'HomegrownBot');
            }

            public function ownsAddress(string $normalizedIp): ?bool
            {
                // The anti-pattern under test: "the UA said so" as proof.
                return true;
            }
        });

        $check = $this->check($this->runJson(), 'crawler_verification');

        $this->assertSame('failure', $check['severity']);
        $this->assertStringContainsString('homegrown', $check['context']['providers']);
    }

    public function test_it_warns_when_ignore_rules_cover_crawler_ranges(): void
    {
        config()->set('security-guard.crawler_access.enabled', true);
        config()->set('security-guard.permanent_block.ignored_ips', ['66.249.0.0/16']);
        $this->seedRanges('google', ['66.249.64.0/27']);

        $check = $this->check($this->runJson(), 'crawler_guard_exemption');

        $this->assertSame('warning', $check['severity']);
        $this->assertStringContainsString('66.249.0.0/16', $check['context']['rules']);
    }

    public function test_it_warns_about_a_missing_robots_txt(): void
    {
        config()->set('security-guard.crawler_access.enabled', true);

        $check = $this->check($this->runJson(), 'crawler_robots_txt');

        $this->assertSame('warning', $check['severity']);

        // The remedy must keep the boundary honest: robots.txt steers
        // crawlers, it does not protect anything.
        $this->assertStringContainsString('not an access control', (string) $check['remedy']);
    }

    public function test_a_present_robots_txt_passes(): void
    {
        config()->set('security-guard.crawler_access.enabled', true);

        $path = $this->app->publicPath('robots.txt');
        file_put_contents($path, "User-agent: *\nDisallow:\n");

        try {
            $check = $this->check($this->runJson(), 'crawler_robots_txt');

            $this->assertSame('ok', $check['severity']);
        } finally {
            @unlink($path);
        }
    }
}
