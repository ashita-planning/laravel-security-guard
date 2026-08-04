<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Tests\Feature;

use Apkk\LaravelSecurityGuard\Console\DoctorCommand;
use Apkk\LaravelSecurityGuard\Contracts\AdminAllowedIpRepositoryContract;
use Apkk\LaravelSecurityGuard\Data\AdminSubjectData;
use Apkk\LaravelSecurityGuard\Tests\TestCase;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Foundation\Testing\RefreshDatabase;
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

        foreach (['admin_ip_allowlist', 'notifications', 'management_ui', 'submission_token'] as $name) {
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
}
