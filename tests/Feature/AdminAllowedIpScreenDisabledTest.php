<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Tests\Feature;

use Apkk\LaravelSecurityGuard\Tests\Fixtures\TestUser;
use Apkk\LaravelSecurityGuard\Tests\TestCase;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Route;

/**
 * The allowlist screen stays off unless it is asked for by name.
 *
 * Enabling the management UI in v0.1.x was consent to a block-release screen.
 * It was not consent to publish which networks reach the admin area, so an
 * upgrade must not register this route on the strength of that older setting.
 *
 * Routes are registered while the application boots, so the switched-off case
 * needs its own boot rather than a config change inside a test body.
 */
class AdminAllowedIpScreenDisabledTest extends TestCase
{
    use RefreshDatabase;

    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);

        tap($app->make(Repository::class), function (Repository $config): void {
            $config->set('auth.providers.test_users', ['driver' => 'eloquent', 'model' => TestUser::class]);
            $config->set('auth.guards.web.provider', 'test_users');
            // The management UI is on; the allowlist screen is not.
            $config->set('security-guard.management_ui.enabled', true);
            $config->set('security-guard.management_ui.admin_allowed_ips.enabled', false);
            $config->set('security-guard.management_ui.middleware', ['web']);
        });
    }

    public function test_the_block_screen_is_registered(): void
    {
        $this->assertTrue(Route::has('security-guard.blocked-ips.index'));
    }

    public function test_the_allowlist_route_is_not_registered(): void
    {
        $this->assertFalse(Route::has('security-guard.admin-allowed-ips.index'));
    }

    public function test_the_allowlist_url_is_not_routable(): void
    {
        $this->get('/security-guard/admin-allowed-ips')->assertNotFound();
    }
}
