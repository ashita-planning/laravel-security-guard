<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Tests\Feature;

use Apkk\LaravelSecurityGuard\Contracts\AdminAllowedIpRepositoryContract;
use Apkk\LaravelSecurityGuard\Contracts\AdminSubjectResolverContract;
use Apkk\LaravelSecurityGuard\Contracts\AttackPathMatcherContract;
use Apkk\LaravelSecurityGuard\Contracts\BlockedIpRepositoryContract;
use Apkk\LaravelSecurityGuard\Contracts\ClientIpResolverContract;
use Apkk\LaravelSecurityGuard\Contracts\IpMatcherContract;
use Apkk\LaravelSecurityGuard\Contracts\SecurityEventDispatcherContract;
use Apkk\LaravelSecurityGuard\Http\Middleware\GuardPublicRequests;
use Apkk\LaravelSecurityGuard\SecurityGuardServiceProvider;
use Apkk\LaravelSecurityGuard\Services\LaravelRequestIpResolver;
use Apkk\LaravelSecurityGuard\Services\RemoteAddrIpResolver;
use Apkk\LaravelSecurityGuard\Tests\TestCase;
use Illuminate\Contracts\Http\Kernel;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use PHPUnit\Framework\Attributes\DataProvider;

class PackageIntegrationTest extends TestCase
{
    use RefreshDatabase;

    protected function defineRoutes($router): void
    {
        Route::get('/', fn (): string => 'home');
    }

    public function test_the_provider_is_registered(): void
    {
        $this->assertArrayHasKey(
            SecurityGuardServiceProvider::class,
            $this->app->getLoadedProviders(),
        );
    }

    #[DataProvider('contracts')]
    public function test_every_contract_resolves_out_of_the_box(string $contract): void
    {
        $this->assertInstanceOf($contract, $this->app->make($contract));
    }

    /**
     * @return array<string, array{class-string}>
     */
    public static function contracts(): array
    {
        return [
            'client ip resolver' => [ClientIpResolverContract::class],
            'attack path matcher' => [AttackPathMatcherContract::class],
            'blocked ip repository' => [BlockedIpRepositoryContract::class],
            'admin allowed ip repository' => [AdminAllowedIpRepositoryContract::class],
            'admin subject resolver' => [AdminSubjectResolverContract::class],
            'security event dispatcher' => [SecurityEventDispatcherContract::class],
            'ip matcher' => [IpMatcherContract::class],
        ];
    }

    public function test_the_migrations_run_without_publishing_them(): void
    {
        $this->assertTrue($this->app->make('db')->getSchemaBuilder()->hasTable('security_guard_blocked_ips'));
        $this->assertTrue($this->app->make('db')->getSchemaBuilder()->hasTable('security_guard_admin_allowed_ips'));
    }

    public function test_config_migrations_and_views_publish_under_separate_tags(): void
    {
        $groups = SecurityGuardServiceProvider::publishableGroups();

        // A host that only wants the config must not be handed migrations too.
        $this->assertContains('security-guard-config', $groups);
        $this->assertContains('security-guard-migrations', $groups);
        $this->assertContains('security-guard-views', $groups);

        $config = SecurityGuardServiceProvider::pathsToPublish(
            SecurityGuardServiceProvider::class,
            'security-guard-config',
        );

        $this->assertCount(1, $config);
        $this->assertStringEndsWith('security-guard.php', array_key_first($config));
    }

    public function test_the_middleware_aliases_are_available(): void
    {
        $middleware = $this->app->make('router')->getMiddleware();

        $this->assertSame(GuardPublicRequests::class, $middleware['security-guard'] ?? null);
        $this->assertArrayHasKey('security-guard.admin-ip', $middleware);
    }

    public function test_the_middleware_is_not_registered_globally_on_its_own(): void
    {
        // Adding a middleware to every request is the host's decision, made in
        // its own kernel or bootstrap file where it is visible.
        $this->assertFalse(
            $this->app->make(Kernel::class)->hasMiddleware(GuardPublicRequests::class),
        );
    }

    public function test_the_management_ui_routes_are_absent_by_default(): void
    {
        $this->assertFalse($this->app->make('router')->has('security-guard.blocked-ips.index'));
    }

    public function test_the_default_configuration_leaves_optional_modules_off(): void
    {
        $this->assertFalse(config('security-guard.public_rate_limit.enabled'));
        $this->assertFalse(config('security-guard.admin_ip.enabled'));
        $this->assertFalse(config('security-guard.sensitive_routes.enabled'));
        $this->assertFalse(config('security-guard.submission_token.enabled'));
        $this->assertFalse(config('security-guard.notifications.enabled'));
        $this->assertFalse(config('security-guard.error_notifications.enabled'));
        $this->assertFalse(config('security-guard.management_ui.enabled'));

        // Detection and permanent blocking are the safe-by-default pair.
        $this->assertTrue(config('security-guard.permanent_block.enabled'));
    }

    public function test_the_empty_allowlist_policy_defaults_to_deny(): void
    {
        $this->assertSame('deny', config('security-guard.admin_ip.empty_policy'));
    }

    public function test_installing_the_package_does_not_change_request_behaviour(): void
    {
        // Nothing is registered globally, so an untouched application answers
        // exactly as it did before the package was installed.
        $this->fromIp('203.0.113.10')->get('/')->assertOk()->assertSee('home');
        $this->fromIp('203.0.113.10')->get('/wp-admin')->assertNotFound();

        $this->assertDatabaseCount('security_guard_blocked_ips', 0);
    }

    public function test_the_ip_resolver_driver_is_configurable(): void
    {
        $this->assertInstanceOf(
            LaravelRequestIpResolver::class,
            $this->app->make(ClientIpResolverContract::class),
        );

        config()->set('security-guard.ip_resolver.driver', 'remote_addr');
        $this->app->forgetInstance(ClientIpResolverContract::class);

        $this->assertInstanceOf(
            RemoteAddrIpResolver::class,
            $this->app->make(ClientIpResolverContract::class),
        );
    }

    public function test_the_resolver_normalizes_and_rejects_unusable_addresses(): void
    {
        $resolver = $this->app->make(ClientIpResolverContract::class);

        $this->assertSame('::1', $resolver->resolve(
            Request::create('/', 'GET', [], [], [], ['REMOTE_ADDR' => '0:0:0:0:0:0:0:1']),
        ));

        $this->assertNull($resolver->resolve(
            Request::create('/', 'GET', [], [], [], ['REMOTE_ADDR' => 'not-an-ip']),
        ));
    }

    public function test_the_package_does_not_reference_any_host_application_class(): void
    {
        // The extraction is only real if nothing under src/ still points at the
        // application it came from.
        $offenders = [];

        $files = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator(__DIR__.'/../../src'),
        );

        foreach ($files as $file) {
            if ($file->getExtension() !== 'php') {
                continue;
            }

            // Inspect name tokens only: a class name mentioned in a comment is
            // documentation, not a dependency.
            foreach (token_get_all((string) file_get_contents($file->getPathname())) as $token) {
                if (! is_array($token) || ! in_array($token[0], [T_NAME_QUALIFIED, T_NAME_FULLY_QUALIFIED], true)) {
                    continue;
                }

                if (preg_match('/^\\\\?App\\\\/', $token[1]) === 1) {
                    $offenders[] = $file->getFilename().': '.$token[1];
                }
            }
        }

        $this->assertSame([], $offenders);
    }
}
