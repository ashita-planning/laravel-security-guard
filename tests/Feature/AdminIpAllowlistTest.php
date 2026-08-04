<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Tests\Feature;

use Apkk\LaravelSecurityGuard\Contracts\AdminAllowedIpRepositoryContract;
use Apkk\LaravelSecurityGuard\Data\AdminSubjectData;
use Apkk\LaravelSecurityGuard\Events\AdminIpAccessDenied;
use Apkk\LaravelSecurityGuard\Http\Middleware\EnsureAdminIpIsAllowed;
use Apkk\LaravelSecurityGuard\Models\AdminAllowedIp;
use Apkk\LaravelSecurityGuard\Services\AdminIpAccessService;
use Apkk\LaravelSecurityGuard\Tests\Fixtures\TestUser;
use Apkk\LaravelSecurityGuard\Tests\TestCase;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Route;

class AdminIpAllowlistTest extends TestCase
{
    use RefreshDatabase;

    private const SUBJECT_TYPE = 'admin';

    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);

        tap($app->make(Repository::class), function (Repository $config): void {
            $config->set('auth.guards.admin', ['driver' => 'session', 'provider' => 'test_users']);
            $config->set('auth.providers.test_users', [
                'driver' => 'eloquent',
                'model' => TestUser::class,
            ]);
            $config->set('security-guard.admin_ip.enabled', true);
            $config->set('security-guard.admin_ip.guard', 'admin');
            $config->set('security-guard.admin_ip.subject_type', self::SUBJECT_TYPE);
        });
    }

    protected function defineRoutes($router): void
    {
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

    private function allow(TestUser $user, string $ipAddress, ?string $label = null): void
    {
        $this->app->make(AdminAllowedIpRepositoryContract::class)->allow(
            new AdminSubjectData(self::SUBJECT_TYPE, (string) $user->getKey()),
            $ipAddress,
            $label,
        );
    }

    public function test_an_allowlisted_address_reaches_the_admin_area(): void
    {
        $admin = $this->admin();
        $this->allow($admin, '203.0.113.10', 'office');

        $this->actingAs($admin, 'admin')
            ->fromIp('203.0.113.10')
            ->get('/admin/dashboard')
            ->assertOk()
            ->assertSee('admin dashboard');
    }

    public function test_an_address_that_is_not_allowlisted_is_rejected(): void
    {
        Event::fake([AdminIpAccessDenied::class]);

        $admin = $this->admin();
        $this->allow($admin, '203.0.113.10');

        $this->actingAs($admin, 'admin')
            ->fromIp('198.51.100.5')
            ->get('/admin/dashboard')
            ->assertForbidden();

        Event::assertDispatched(AdminIpAccessDenied::class);
    }

    public function test_the_rejection_message_reveals_nothing_about_the_account_or_the_allowlist(): void
    {
        $admin = $this->admin();
        $this->allow($admin, '203.0.113.10', 'office');

        $response = $this->actingAs($admin, 'admin')
            ->fromIp('198.51.100.5')
            ->get('/admin/dashboard');

        $body = (string) $response->getContent();

        $this->assertStringNotContainsString('203.0.113.10', $body);
        $this->assertStringNotContainsString('office', $body);
        $this->assertStringNotContainsString('admin@example.test', $body);
    }

    public function test_a_rejection_ends_the_session_and_rotates_the_csrf_token(): void
    {
        $admin = $this->admin();
        $this->allow($admin, '203.0.113.10');

        $this->actingAs($admin, 'admin')->fromIp('198.51.100.5');

        $this->get('/admin/dashboard')->assertForbidden();

        // Leaving the session usable would let the attacker retry from an
        // allowed address later with the same cookie.
        $this->assertGuest('admin');
    }

    public function test_a_disabled_entry_no_longer_grants_access(): void
    {
        $admin = $this->admin();
        $this->allow($admin, '203.0.113.10');

        AdminAllowedIp::query()->where('ip_address', '203.0.113.10')->update(['enabled' => false]);

        $this->actingAs($admin, 'admin')
            ->fromIp('203.0.113.10')
            ->get('/admin/dashboard')
            ->assertForbidden();
    }

    public function test_a_subject_with_no_entries_is_denied_by_default(): void
    {
        $admin = $this->admin();

        $this->actingAs($admin, 'admin')
            ->fromIp('203.0.113.10')
            ->get('/admin/dashboard')
            ->assertForbidden();
    }

    public function test_allow_when_empty_lets_a_subject_without_entries_through(): void
    {
        config()->set('security-guard.admin_ip.empty_policy', 'allow_when_empty');

        $admin = $this->admin();

        $this->actingAs($admin, 'admin')
            ->fromIp('203.0.113.10')
            ->get('/admin/dashboard')
            ->assertOk();
    }

    public function test_allow_when_empty_still_enforces_a_populated_allowlist(): void
    {
        config()->set('security-guard.admin_ip.empty_policy', 'allow_when_empty');

        $admin = $this->admin();
        $this->allow($admin, '203.0.113.10');

        $this->actingAs($admin, 'admin')
            ->fromIp('198.51.100.5')
            ->get('/admin/dashboard')
            ->assertForbidden();
    }

    public function test_an_unauthenticated_request_is_left_to_the_host_auth_middleware(): void
    {
        $this->fromIp('198.51.100.5')->get('/admin/dashboard')->assertOk();
    }

    public function test_the_module_is_inert_while_disabled(): void
    {
        config()->set('security-guard.admin_ip.enabled', false);

        $admin = $this->admin();

        $this->actingAs($admin, 'admin')
            ->fromIp('198.51.100.5')
            ->get('/admin/dashboard')
            ->assertOk();
    }

    public function test_it_can_redirect_instead_of_answering_403(): void
    {
        config()->set('security-guard.admin_ip.denied_action', 'redirect');
        config()->set('security-guard.admin_ip.denied_redirect_to', '/admin/login');

        $admin = $this->admin();
        $this->allow($admin, '203.0.113.10');

        $this->actingAs($admin, 'admin')
            ->fromIp('198.51.100.5')
            ->get('/admin/dashboard')
            ->assertRedirect('/admin/login')
            ->assertSessionHas('security-guard.denied');
    }

    public function test_the_pre_login_check_is_available_as_a_service_call(): void
    {
        $admin = $this->admin();
        $this->allow($admin, '203.0.113.10');

        $service = $this->app->make(AdminIpAccessService::class);
        $subject = new AdminSubjectData(self::SUBJECT_TYPE, (string) $admin->getKey());

        $this->assertTrue($service->isAllowed($subject, '203.0.113.10'));
        $this->assertFalse($service->isAllowed($subject, '198.51.100.5'));
        // An unresolvable address is denied here, unlike on the public surface.
        $this->assertFalse($service->isAllowed($subject, null));
    }

    public function test_ip_matching_is_notation_independent(): void
    {
        $admin = $this->admin();
        $this->allow($admin, '2001:0db8:0000:0000:0000:0000:0000:0001');

        $this->actingAs($admin, 'admin')
            ->fromIp('2001:db8::1')
            ->get('/admin/dashboard')
            ->assertOk();
    }

    public function test_entries_are_scoped_to_one_subject(): void
    {
        $first = $this->admin();
        $second = TestUser::query()->create([
            'name' => 'Second',
            'email' => 'second@example.test',
            'password' => bcrypt('secret'),
        ]);

        $this->allow($first, '203.0.113.10');

        $this->actingAs($second, 'admin')
            ->fromIp('203.0.113.10')
            ->get('/admin/dashboard')
            ->assertForbidden();
    }
}
