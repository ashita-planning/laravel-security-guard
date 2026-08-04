<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Tests\Feature;

use Apkk\LaravelSecurityGuard\Contracts\AdminAllowedIpRepositoryContract;
use Apkk\LaravelSecurityGuard\Data\AdminSubjectData;
use Apkk\LaravelSecurityGuard\Data\BlockReason;
use Apkk\LaravelSecurityGuard\Models\AdminAllowedIp;
use Apkk\LaravelSecurityGuard\Models\BlockedIp;
use Apkk\LaravelSecurityGuard\Services\IpBlockService;
use Apkk\LaravelSecurityGuard\Tests\TestCase;
use Illuminate\Foundation\Testing\RefreshDatabase;

class ConsoleCommandTest extends TestCase
{
    use RefreshDatabase;

    private function block(string $ipAddress = '203.0.113.10'): void
    {
        $this->app->make(IpBlockService::class)->block(
            $ipAddress,
            BlockReason::KNOWN_ATTACK_PATH,
            'wordpress_probe',
        );
    }

    public function test_the_list_command_shows_blocked_addresses(): void
    {
        $this->block();

        $this->artisan('security-guard:blocked:list')
            ->expectsOutputToContain('203.0.113.10')
            ->assertSuccessful();
    }

    public function test_the_list_command_reports_an_empty_result(): void
    {
        $this->artisan('security-guard:blocked:list --active')->assertSuccessful();
    }

    public function test_the_list_command_rejects_an_invalid_filter_address(): void
    {
        $this->artisan('security-guard:blocked:list --ip=not-an-ip')->assertFailed();
    }

    public function test_the_release_command_releases_an_address(): void
    {
        $this->block();

        $this->artisan('security-guard:blocked:release 203.0.113.10 --actor=ops')
            ->assertSuccessful();

        $record = BlockedIp::query()->where('ip_address', '203.0.113.10')->first();

        $this->assertNotNull($record->released_at);
        $this->assertSame('console', $record->released_by_type);
        $this->assertSame('ops', $record->released_by_id);
    }

    public function test_the_release_command_rejects_an_invalid_address_without_touching_the_database(): void
    {
        $this->artisan('security-guard:blocked:release 999.999.999.999')->assertFailed();

        $this->assertDatabaseCount('security_guard_blocked_ips', 0);
    }

    public function test_the_release_command_accepts_any_notation_of_one_address(): void
    {
        $this->block('2001:db8::1');

        $this->artisan('security-guard:blocked:release 2001:0db8:0000:0000:0000:0000:0000:0001')
            ->assertSuccessful();

        $this->assertNotNull(BlockedIp::query()->where('ip_address', '2001:db8::1')->value('released_at'));
    }

    public function test_the_status_command_reports_an_address(): void
    {
        $this->block();

        $this->artisan('security-guard:status 203.0.113.10')
            ->expectsOutputToContain('known_attack_path')
            ->assertSuccessful();
    }

    public function test_the_status_command_rejects_an_invalid_address(): void
    {
        $this->artisan('security-guard:status hostname')->assertFailed();
    }

    public function test_admin_ip_entries_can_be_added_listed_and_revoked(): void
    {
        $this->artisan('security-guard:admin-ip:allow 42 203.0.113.10 --type=admin --label=office')
            ->assertSuccessful();

        $this->assertDatabaseHas('security_guard_admin_allowed_ips', [
            'subject_type' => 'admin',
            'subject_id' => '42',
            'ip_address' => '203.0.113.10',
            'label' => 'office',
            'enabled' => true,
        ]);

        // One substring expectation per run: each consumes a matching write.
        $this->artisan('security-guard:admin-ip:list 42 --type=admin')
            ->expectsOutputToContain('203.0.113.10')
            ->assertSuccessful();

        $this->artisan('security-guard:admin-ip:list 42 --type=admin')
            ->expectsOutputToContain('office')
            ->assertSuccessful();

        $this->artisan('security-guard:admin-ip:revoke 42 203.0.113.10 --type=admin')
            ->assertSuccessful();

        $this->assertDatabaseCount('security_guard_admin_allowed_ips', 0);
    }

    public function test_adding_the_same_entry_twice_keeps_one_row(): void
    {
        $this->artisan('security-guard:admin-ip:allow 42 203.0.113.10 --type=admin')->assertSuccessful();
        $this->artisan('security-guard:admin-ip:allow 42 203.0.113.10 --type=admin')->assertSuccessful();

        $this->assertSame(1, AdminAllowedIp::query()->count());
    }

    public function test_the_allow_command_rejects_an_invalid_address(): void
    {
        $this->artisan('security-guard:admin-ip:allow 42 nonsense --type=admin')->assertFailed();

        $this->assertDatabaseCount('security_guard_admin_allowed_ips', 0);
    }

    public function test_revoking_the_last_entry_warns_about_the_lockout(): void
    {
        config()->set('security-guard.admin_ip.enabled', true);

        $repository = $this->app->make(AdminAllowedIpRepositoryContract::class);
        $repository->allow(new AdminSubjectData('admin', '42'), '203.0.113.10');

        $this->artisan('security-guard:admin-ip:revoke 42 203.0.113.10 --type=admin')
            ->expectsOutputToContain('can no longer sign in')
            ->assertSuccessful();
    }

    public function test_the_list_command_shows_a_subject_without_entries(): void
    {
        $this->artisan('security-guard:admin-ip:list 42 --type=admin')->assertSuccessful();
    }

    public function test_commands_never_wait_for_interactive_input(): void
    {
        // Every command must be usable from a deploy script.
        $this->artisan('security-guard:blocked:list --no-interaction')->assertSuccessful();
        $this->artisan('security-guard:status 203.0.113.10 --no-interaction')->assertSuccessful();
    }
}
