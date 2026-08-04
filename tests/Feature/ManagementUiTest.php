<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Tests\Feature;

use Apkk\LaravelSecurityGuard\Data\BlockReason;
use Apkk\LaravelSecurityGuard\Models\BlockedIp;
use Apkk\LaravelSecurityGuard\Services\IpBlockService;
use Apkk\LaravelSecurityGuard\Tests\Fixtures\TestUser;
use Apkk\LaravelSecurityGuard\Tests\TestCase;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Gate;

class ManagementUiTest extends TestCase
{
    use RefreshDatabase;

    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);

        tap($app->make(Repository::class), function (Repository $config): void {
            $config->set('security-guard.management_ui.enabled', true);
            $config->set('auth.providers.users.model', TestUser::class);
        });
    }

    protected function defineRoutes($router): void
    {
        // The `auth` middleware redirects here; the host owns this route.
        $router->get('/login', fn (): string => 'login')->name('login');
    }

    protected function setUp(): void
    {
        parent::setUp();

        Gate::define('manage-security', fn (TestUser $user): bool => $user->email === 'admin@example.test');
    }

    private function user(string $email = 'admin@example.test'): TestUser
    {
        return TestUser::query()->firstOrCreate(
            ['email' => $email],
            ['name' => 'User', 'password' => bcrypt('secret')],
        );
    }

    private function block(string $ipAddress = '203.0.113.10'): void
    {
        $this->app->make(IpBlockService::class)->block(
            $ipAddress,
            BlockReason::KNOWN_ATTACK_PATH,
            'wordpress_probe',
        );
    }

    public function test_the_routes_exist_when_the_module_is_enabled(): void
    {
        $router = $this->app->make('router');

        $this->assertTrue($router->has('security-guard.blocked-ips.index'));
        $this->assertTrue($router->has('security-guard.blocked-ips.release'));
    }

    public function test_an_unauthenticated_visitor_cannot_reach_the_list(): void
    {
        $this->block();

        $this->get('/security-guard/blocked-ips')->assertRedirect('/login');
    }

    public function test_an_authenticated_user_without_the_ability_is_rejected(): void
    {
        $this->block();

        $this->actingAs($this->user('someone@example.test'))
            ->get('/security-guard/blocked-ips')
            ->assertForbidden();
    }

    public function test_an_authorized_user_sees_the_blocked_addresses(): void
    {
        $this->block();

        $this->actingAs($this->user())
            ->get('/security-guard/blocked-ips')
            ->assertOk()
            ->assertSee('203.0.113.10')
            ->assertSee('Known attack path probed')
            ->assertSee('wordpress_probe');
    }

    public function test_releasing_requires_authorization(): void
    {
        $this->block();

        $this->actingAs($this->user('someone@example.test'))
            ->post('/security-guard/blocked-ips/release', ['ip_address' => '203.0.113.10'])
            ->assertForbidden();

        $this->assertDatabaseHas('security_guard_blocked_ips', [
            'ip_address' => '203.0.113.10',
            'released_at' => null,
        ]);
    }

    public function test_the_release_control_is_a_csrf_protected_post_form(): void
    {
        $this->block();

        // Releasing changes state, so it must never be reachable by GET, and
        // the form must carry the session token.
        $this->actingAs($this->user())
            ->get('/security-guard/blocked-ips')
            ->assertOk()
            ->assertSee('name="_token"', false)
            ->assertSee('method="POST"', false);

        $this->actingAs($this->user())
            ->get('/security-guard/blocked-ips/release')
            ->assertStatus(405);
    }

    public function test_the_release_route_runs_inside_the_configured_middleware(): void
    {
        $route = $this->app->make('router')->getRoutes()->getByName('security-guard.blocked-ips.release');

        $this->assertNotNull($route);
        $this->assertContains('web', $route->gatherMiddleware());
        $this->assertContains('auth', $route->gatherMiddleware());
        $this->assertContains('can:manage-security', $route->gatherMiddleware());
    }

    public function test_an_authorized_user_can_release_an_address(): void
    {
        $this->block();

        $this->actingAs($this->user())
            ->post('/security-guard/blocked-ips/release', ['ip_address' => '203.0.113.10'])
            ->assertRedirect(route('security-guard.blocked-ips.index'))
            ->assertSessionHas('security-guard.status');

        $this->assertNotNull(BlockedIp::query()->where('ip_address', '203.0.113.10')->value('released_at'));
    }

    public function test_the_release_form_validates_its_input(): void
    {
        $this->actingAs($this->user())
            ->post('/security-guard/blocked-ips/release', ['ip_address' => 'not-an-ip'])
            ->assertSessionHasErrors('ip_address');

        $this->actingAs($this->user())
            ->post('/security-guard/blocked-ips/release', [])
            ->assertSessionHasErrors('ip_address');
    }

    public function test_the_release_records_who_performed_it(): void
    {
        $this->block();
        $user = $this->user();

        $this->actingAs($user)->post('/security-guard/blocked-ips/release', ['ip_address' => '203.0.113.10']);

        $record = BlockedIp::query()->where('ip_address', '203.0.113.10')->first();

        $this->assertSame(TestUser::class, $record->released_by_type);
        $this->assertSame((string) $user->getKey(), $record->released_by_id);
    }

    public function test_the_list_can_include_released_addresses(): void
    {
        $this->block();
        $this->app->make(IpBlockService::class)->release('203.0.113.10');

        $this->actingAs($this->user())
            ->get('/security-guard/blocked-ips?active=0')
            ->assertOk()
            ->assertSee('203.0.113.10');
    }
}
