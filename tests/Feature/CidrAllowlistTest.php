<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Tests\Feature;

use Apkk\LaravelSecurityGuard\Contracts\AdminAllowedIpRepositoryContract;
use Apkk\LaravelSecurityGuard\Contracts\IpMatcherContract;
use Apkk\LaravelSecurityGuard\Data\AdminSubjectData;
use Apkk\LaravelSecurityGuard\Http\Middleware\EnsureAdminIpIsAllowed;
use Apkk\LaravelSecurityGuard\Http\Middleware\GuardPublicRequests;
use Apkk\LaravelSecurityGuard\Models\AdminAllowedIp;
use Apkk\LaravelSecurityGuard\Services\ExactIpMatcher;
use Apkk\LaravelSecurityGuard\Tests\Fixtures\TestUser;
use Apkk\LaravelSecurityGuard\Tests\TestCase;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Http\Kernel;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Route;

/**
 * CIDR support end to end: config ignore list, admin allowlist, CLI, UI.
 *
 * The upgrade guarantee is that every v0.1.x entry keeps behaving identically,
 * so exact rules are asserted alongside the new network ones rather than
 * assumed still to work.
 */
class CidrAllowlistTest extends TestCase
{
    use RefreshDatabase;

    private const SUBJECT_TYPE = 'admin';

    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);

        $app->make(Kernel::class)->prependMiddleware(GuardPublicRequests::class);

        tap($app->make(Repository::class), function (Repository $config): void {
            $config->set('auth.guards.admin', ['driver' => 'session', 'provider' => 'test_users']);
            $config->set('auth.providers.test_users', ['driver' => 'eloquent', 'model' => TestUser::class]);
            $config->set('security-guard.admin_ip.guard', 'admin');
            $config->set('security-guard.admin_ip.subject_type', self::SUBJECT_TYPE);
        });
    }

    protected function defineRoutes($router): void
    {
        Route::get('/', fn (): string => 'home');
        Route::middleware(['web', EnsureAdminIpIsAllowed::class])
            ->get('/admin/dashboard', fn (): string => 'admin dashboard');
    }

    private function admin(): TestUser
    {
        return TestUser::query()->create([
            'name' => 'Administrator',
            'email' => 'admin@example.test',
            'password' => bcrypt('secret'),
        ]);
    }

    private function subjectFor(TestUser $user): AdminSubjectData
    {
        return new AdminSubjectData(self::SUBJECT_TYPE, (string) $user->getKey());
    }

    // -----------------------------------------------------------------
    // Ignore list (config)
    // -----------------------------------------------------------------

    public function test_a_cidr_ignore_entry_exempts_the_whole_network(): void
    {
        config()->set('security-guard.permanent_block.ignored_ips', ['203.0.113.0/24']);

        $this->fromIp('203.0.113.10')->get('/wp-admin')->assertNotFound();
        $this->fromIp('203.0.113.250')->get('/.env')->assertNotFound();

        $this->assertDatabaseCount('security_guard_blocked_ips', 0);
    }

    public function test_an_address_outside_the_ignored_network_is_still_blocked(): void
    {
        config()->set('security-guard.permanent_block.ignored_ips', ['203.0.113.0/24']);

        $this->fromIp('203.0.114.10')->get('/wp-admin')->assertForbidden();

        $this->assertDatabaseHas('security_guard_blocked_ips', ['ip_address' => '203.0.114.10']);
    }

    public function test_an_exact_ignore_entry_still_behaves_as_it_did_in_v0_1(): void
    {
        config()->set('security-guard.permanent_block.ignored_ips', ['203.0.113.10']);

        $this->fromIp('203.0.113.10')->get('/wp-admin')->assertNotFound();
        // The neighbour must not be swept in by the upgrade.
        $this->fromIp('203.0.113.11')->get('/wp-admin')->assertForbidden();
    }

    public function test_an_ipv6_cidr_ignore_entry_works(): void
    {
        config()->set('security-guard.permanent_block.ignored_ips', ['2001:db8::/32']);

        $this->fromIp('2001:db8:1234::9')->get('/wp-admin')->assertNotFound();
        $this->fromIp('2001:db9::1')->get('/wp-admin')->assertForbidden();
    }

    public function test_a_malformed_ignore_entry_does_not_exempt_everyone(): void
    {
        config()->set('security-guard.permanent_block.ignored_ips', ['203.0.113.*']);

        // Failing closed: the typo protects nobody rather than everybody.
        $this->fromIp('203.0.113.10')->get('/wp-admin')->assertForbidden();
    }

    // -----------------------------------------------------------------
    // Admin allowlist
    // -----------------------------------------------------------------

    public function test_a_cidr_rule_admits_any_address_in_the_network(): void
    {
        config()->set('security-guard.admin_ip.enabled', true);

        $admin = $this->admin();
        $this->app->make(AdminAllowedIpRepositoryContract::class)
            ->allow($this->subjectFor($admin), '203.0.113.0/24', 'office');

        $this->actingAs($admin, 'admin')->fromIp('203.0.113.77')
            ->get('/admin/dashboard')->assertOk();
        $this->actingAs($admin, 'admin')->fromIp('203.0.114.77')
            ->get('/admin/dashboard')->assertForbidden();
    }

    public function test_exact_and_cidr_rules_coexist_for_one_subject(): void
    {
        config()->set('security-guard.admin_ip.enabled', true);

        $admin = $this->admin();
        $repository = $this->app->make(AdminAllowedIpRepositoryContract::class);
        $repository->allow($this->subjectFor($admin), '198.51.100.7');
        $repository->allow($this->subjectFor($admin), '2001:db8::/48');

        $this->actingAs($admin, 'admin')->fromIp('198.51.100.7')
            ->get('/admin/dashboard')->assertOk();
        $this->actingAs($admin, 'admin')->fromIp('2001:db8:0:5::2')
            ->get('/admin/dashboard')->assertOk();
        $this->actingAs($admin, 'admin')->fromIp('198.51.100.8')
            ->get('/admin/dashboard')->assertForbidden();
    }

    public function test_a_disabled_cidr_rule_grants_nothing(): void
    {
        config()->set('security-guard.admin_ip.enabled', true);

        $admin = $this->admin();
        $this->app->make(AdminAllowedIpRepositoryContract::class)
            ->allow($this->subjectFor($admin), '203.0.113.0/24');

        AdminAllowedIp::query()->update(['enabled' => false]);

        $this->actingAs($admin, 'admin')->fromIp('203.0.113.77')
            ->get('/admin/dashboard')->assertForbidden();
    }

    public function test_rules_do_not_leak_between_subjects(): void
    {
        config()->set('security-guard.admin_ip.enabled', true);

        $first = $this->admin();
        $second = TestUser::query()->create([
            'name' => 'Second',
            'email' => 'second@example.test',
            'password' => bcrypt('secret'),
        ]);

        $this->app->make(AdminAllowedIpRepositoryContract::class)
            ->allow($this->subjectFor($first), '203.0.113.0/24');

        $this->actingAs($second, 'admin')->fromIp('203.0.113.77')
            ->get('/admin/dashboard')->assertForbidden();
    }

    public function test_an_unparseable_row_locks_its_owner_out_rather_than_admitting_everyone(): void
    {
        config()->set('security-guard.admin_ip.enabled', true);

        $admin = $this->admin();

        // Written straight to the table, bypassing canonicalisation.
        AdminAllowedIp::query()->create([
            'subject_type' => self::SUBJECT_TYPE,
            'subject_id' => (string) $admin->getKey(),
            'ip_address' => '203.0.113.*',
            'enabled' => true,
        ]);

        $this->actingAs($admin, 'admin')->fromIp('203.0.113.10')
            ->get('/admin/dashboard')->assertForbidden();
    }

    public function test_the_allowlist_lookup_is_one_query_per_subject(): void
    {
        config()->set('security-guard.admin_ip.enabled', true);

        $admin = $this->admin();
        $repository = $this->app->make(AdminAllowedIpRepositoryContract::class);

        foreach (['203.0.113.0/24', '198.51.100.0/24', '2001:db8::/48'] as $rule) {
            $repository->allow($this->subjectFor($admin), $rule);
        }

        $queries = 0;
        $this->app->make('db')->listen(function () use (&$queries): void {
            $queries++;
        });

        $this->assertTrue($repository->isAllowed($this->subjectFor($admin), '203.0.113.9'));

        // Rule count must not drive query count.
        $this->assertSame(1, $queries);
    }

    public function test_a_large_allowlist_still_costs_one_query_and_answers_correctly(): void
    {
        config()->set('security-guard.admin_ip.enabled', true);

        $subject = new AdminSubjectData(self::SUBJECT_TYPE, '900');
        $now = now();
        $rows = [];

        for ($i = 0; $i < 1000; $i++) {
            $rows[] = [
                'subject_type' => self::SUBJECT_TYPE,
                'subject_id' => '900',
                'ip_address' => match ($i % 4) {
                    0 => sprintf('10.%d.%d.%d', ($i >> 16) & 255, ($i >> 8) & 255, $i & 255),
                    1 => sprintf('172.%d.%d.0/24', 16 + (($i >> 8) % 16), $i & 255),
                    2 => sprintf('2001:db8:%x::%x', ($i >> 8) & 0xFFFF, $i & 0xFFFF),
                    default => sprintf('2001:db9:%x::/64', $i & 0xFFFF),
                },
                'enabled' => true,
                'created_at' => $now,
                'updated_at' => $now,
            ];
        }

        // A row the matcher cannot parse, mixed in with the rest.
        $rows[] = [
            'subject_type' => self::SUBJECT_TYPE,
            'subject_id' => '900',
            'ip_address' => '10.0.0.1-10.0.0.99',
            'enabled' => true,
            'created_at' => $now,
            'updated_at' => $now,
        ];

        foreach (array_chunk($rows, 200) as $chunk) {
            AdminAllowedIp::query()->insert($chunk);
        }

        $repository = $this->app->make(AdminAllowedIpRepositoryContract::class);

        $queries = 0;
        $this->app->make('db')->listen(function () use (&$queries): void {
            $queries++;
        });

        // The "no migration, match in PHP" decision rests on rule count not
        // driving query count. If that ever stops holding, the binary columns
        // become necessary and this test is where it surfaces.
        $this->assertTrue($repository->isAllowed($subject, '10.0.0.0'));
        $this->assertSame(1, $queries);

        // Correctness must not drift with size, and the corrupt row must not
        // become a wildcard.
        $this->assertTrue($repository->isAllowed($subject, '2001:db9:3::99'));
        $this->assertFalse($repository->isAllowed($subject, '198.51.100.200'));
        $this->assertFalse($repository->isAllowed($subject, '10.0.0.50'));
    }

    // -----------------------------------------------------------------
    // Canonical storage
    // -----------------------------------------------------------------

    public function test_a_host_bit_rule_is_stored_as_its_network(): void
    {
        $admin = $this->admin();
        $this->app->make(AdminAllowedIpRepositoryContract::class)
            ->allow($this->subjectFor($admin), '203.0.113.42/24');

        $this->assertDatabaseHas('security_guard_admin_allowed_ips', ['ip_address' => '203.0.113.0/24']);
    }

    public function test_a_single_host_rule_drops_its_suffix(): void
    {
        $admin = $this->admin();
        $repository = $this->app->make(AdminAllowedIpRepositoryContract::class);

        $repository->allow($this->subjectFor($admin), '203.0.113.10/32');
        $repository->allow($this->subjectFor($admin), '2001:db8::1/128');

        $this->assertDatabaseHas('security_guard_admin_allowed_ips', ['ip_address' => '203.0.113.10']);
        $this->assertDatabaseHas('security_guard_admin_allowed_ips', ['ip_address' => '2001:db8::1']);
    }

    public function test_the_same_rule_written_differently_reuses_one_row(): void
    {
        $admin = $this->admin();
        $repository = $this->app->make(AdminAllowedIpRepositoryContract::class);

        $repository->allow($this->subjectFor($admin), '203.0.113.10');
        $repository->allow($this->subjectFor($admin), '203.0.113.10/32');

        $this->assertSame(1, AdminAllowedIp::query()->count());
    }

    public function test_a_rule_can_be_revoked_using_a_different_notation(): void
    {
        $admin = $this->admin();
        $repository = $this->app->make(AdminAllowedIpRepositoryContract::class);
        $repository->allow($this->subjectFor($admin), '203.0.113.42/24');

        // Stored as 203.0.113.0/24; without shared canonicalisation the
        // operator could never remove it with what they originally typed.
        $this->assertTrue($repository->revoke($this->subjectFor($admin), '203.0.113.42/24'));
        $this->assertSame(0, AdminAllowedIp::query()->count());
    }

    // -----------------------------------------------------------------
    // CLI
    // -----------------------------------------------------------------

    public function test_the_allow_command_accepts_a_network(): void
    {
        $this->artisan('security-guard:admin-ip:allow', ['subject' => '1', 'ip' => '203.0.113.0/24'])
            ->assertExitCode(0);

        $this->assertDatabaseHas('security_guard_admin_allowed_ips', ['ip_address' => '203.0.113.0/24']);
    }

    public function test_the_allow_command_reports_dropped_host_bits(): void
    {
        $this->artisan('security-guard:admin-ip:allow', ['subject' => '1', 'ip' => '203.0.113.42/24'])
            ->expectsOutputToContain('203.0.113.0/24')
            ->assertExitCode(0);
    }

    public function test_the_allow_command_rejects_a_malformed_entry(): void
    {
        $this->artisan('security-guard:admin-ip:allow', ['subject' => '1', 'ip' => '203.0.113.0/33'])
            ->assertExitCode(1);

        $this->assertSame(0, AdminAllowedIp::query()->count());
    }

    public function test_the_allow_command_refuses_a_rule_that_admits_everything(): void
    {
        $this->artisan('security-guard:admin-ip:allow', ['subject' => '1', 'ip' => '0.0.0.0/0'])
            ->assertExitCode(1);

        $this->assertSame(0, AdminAllowedIp::query()->count());
    }

    public function test_a_rule_that_admits_everything_needs_an_explicit_force(): void
    {
        $this->artisan('security-guard:admin-ip:allow', [
            'subject' => '1',
            'ip' => '0.0.0.0/0',
            '--force' => true,
        ])->assertExitCode(0);

        $this->assertDatabaseHas('security_guard_admin_allowed_ips', ['ip_address' => '0.0.0.0/0']);
    }

    public function test_the_revoke_command_canonicalises_its_argument(): void
    {
        $this->artisan('security-guard:admin-ip:allow', ['subject' => '1', 'ip' => '203.0.113.0/24'])
            ->assertExitCode(0);

        $this->artisan('security-guard:admin-ip:revoke', ['subject' => '1', 'ip' => '203.0.113.99/24'])
            ->assertExitCode(0);

        $this->assertSame(0, AdminAllowedIp::query()->count());
    }

    public function test_the_revoke_command_rejects_a_malformed_entry(): void
    {
        $this->artisan('security-guard:admin-ip:revoke', ['subject' => '1', 'ip' => 'nonsense'])
            ->assertExitCode(1);
    }

    public function test_the_list_command_labels_rule_kinds(): void
    {
        $this->artisan('security-guard:admin-ip:allow', ['subject' => '1', 'ip' => '203.0.113.10']);
        $this->artisan('security-guard:admin-ip:allow', ['subject' => '1', 'ip' => '198.51.100.0/24']);

        $this->artisan('security-guard:admin-ip:list', ['subject' => '1'])
            ->expectsOutputToContain('exact')
            ->expectsOutputToContain('CIDR')
            ->assertExitCode(0);
    }

    // -----------------------------------------------------------------
    // Doctor
    // -----------------------------------------------------------------

    /**
     * @return array<string, mixed>
     */
    private function doctorCheck(string $name): array
    {
        Artisan::call('security-guard:doctor', ['--json' => true]);
        $report = json_decode(Artisan::output(), true);

        foreach ($report['results'] as $result) {
            if ($result['check'] === $name) {
                return $result;
            }
        }

        $this->fail("The doctor did not report {$name}.");
    }

    public function test_the_doctor_reports_an_unparseable_config_rule(): void
    {
        config()->set('security-guard.permanent_block.ignored_ips', ['203.0.113.*']);

        $check = $this->doctorCheck('ip_rules.ignored_ips');

        $this->assertSame('failure', $check['severity']);
    }

    public function test_the_doctor_reports_host_bits_in_a_config_rule(): void
    {
        config()->set('security-guard.permanent_block.ignored_ips', ['203.0.113.42/24']);

        $check = $this->doctorCheck('ip_rules.ignored_ips');

        $this->assertSame('warning', $check['severity']);
        $this->assertStringContainsString('host bits', $check['message']);
    }

    public function test_the_doctor_reports_semantic_duplicates(): void
    {
        config()->set('security-guard.permanent_block.ignored_ips', [
            '203.0.113.0/24',
            '203.0.113.0/24',
        ]);

        $check = $this->doctorCheck('ip_rules.ignored_ips');

        $this->assertSame('warning', $check['severity']);
        $this->assertStringContainsString('same thing', $check['message']);
    }

    public function test_the_doctor_reports_an_excessively_wide_rule(): void
    {
        config()->set('security-guard.permanent_block.ignored_ips', ['10.0.0.0/8']);

        $check = $this->doctorCheck('ip_rules.ignored_ips');

        $this->assertSame('warning', $check['severity']);
        $this->assertStringContainsString('wide', $check['message']);
    }

    public function test_the_doctor_accepts_a_well_formed_rule_set(): void
    {
        config()->set('security-guard.permanent_block.ignored_ips', [
            '203.0.113.10',
            '198.51.100.0/24',
            '2001:db8::/48',
        ]);

        $check = $this->doctorCheck('ip_rules.ignored_ips');

        $this->assertSame('ok', $check['severity']);
    }

    public function test_the_doctor_reports_unparseable_rows_in_the_database(): void
    {
        config()->set('security-guard.admin_ip.enabled', true);

        AdminAllowedIp::query()->create([
            'subject_type' => self::SUBJECT_TYPE,
            'subject_id' => '1',
            'ip_address' => '203.0.113.1-50',
            'enabled' => true,
        ]);

        $check = $this->doctorCheck('ip_rules.admin_allowed_ips');

        $this->assertSame('failure', $check['severity']);
    }

    public function test_the_doctor_catches_cidr_rules_under_an_exact_only_matcher(): void
    {
        // Reachable again in v0.2.0 by opting out of the CIDR matcher: the rule
        // is written, accepted, and silently matches nothing.
        $this->app->singleton(IpMatcherContract::class, ExactIpMatcher::class);
        config()->set('security-guard.permanent_block.ignored_ips', ['203.0.113.0/24']);

        $check = $this->doctorCheck('ip_matcher');

        $this->assertSame('failure', $check['severity']);
        $this->assertStringContainsString('exact matching', $check['message']);
    }

    public function test_the_doctor_is_quiet_about_an_exact_matcher_without_cidr_rules(): void
    {
        $this->app->singleton(IpMatcherContract::class, ExactIpMatcher::class);
        config()->set('security-guard.permanent_block.ignored_ips', ['203.0.113.10']);

        $this->assertSame('ok', $this->doctorCheck('ip_matcher')['severity']);
    }
}
