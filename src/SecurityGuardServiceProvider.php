<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard;

use Apkk\LaravelSecurityGuard\Console\AdminIpAllowCommand;
use Apkk\LaravelSecurityGuard\Console\AdminIpListCommand;
use Apkk\LaravelSecurityGuard\Console\AdminIpRevokeCommand;
use Apkk\LaravelSecurityGuard\Console\BlockedListCommand;
use Apkk\LaravelSecurityGuard\Console\BlockedReleaseCommand;
use Apkk\LaravelSecurityGuard\Console\DoctorCommand;
use Apkk\LaravelSecurityGuard\Console\StatusCommand;
use Apkk\LaravelSecurityGuard\Contracts\AdminAllowedIpRepositoryContract;
use Apkk\LaravelSecurityGuard\Contracts\AdminSubjectResolverContract;
use Apkk\LaravelSecurityGuard\Contracts\AttackPathMatcherContract;
use Apkk\LaravelSecurityGuard\Contracts\BlockedIpRepositoryContract;
use Apkk\LaravelSecurityGuard\Contracts\ClientIpResolverContract;
use Apkk\LaravelSecurityGuard\Contracts\IpMatcherContract;
use Apkk\LaravelSecurityGuard\Contracts\SecurityEventDispatcherContract;
use Apkk\LaravelSecurityGuard\Http\Middleware\EnsureAdminIpIsAllowed;
use Apkk\LaravelSecurityGuard\Http\Middleware\GuardPublicRequests;
use Apkk\LaravelSecurityGuard\Notifications\LogErrorEventNotifier;
use Apkk\LaravelSecurityGuard\Notifications\LogSecurityEventNotifier;
use Apkk\LaravelSecurityGuard\Notifications\MailErrorEventNotifier;
use Apkk\LaravelSecurityGuard\Notifications\MailSecurityEventNotifier;
use Apkk\LaravelSecurityGuard\Notifications\NotifierRegistry;
use Apkk\LaravelSecurityGuard\Notifications\SecurityMessageBuilder;
use Apkk\LaravelSecurityGuard\Repositories\EloquentAdminAllowedIpRepository;
use Apkk\LaravelSecurityGuard\Repositories\EloquentBlockedIpRepository;
use Apkk\LaravelSecurityGuard\Services\AdminIpAccessService;
use Apkk\LaravelSecurityGuard\Services\BlockResponseFactory;
use Apkk\LaravelSecurityGuard\Services\CidrIpMatcher;
use Apkk\LaravelSecurityGuard\Services\ConfigAdminSubjectResolver;
use Apkk\LaravelSecurityGuard\Services\ConfigAttackPathMatcher;
use Apkk\LaravelSecurityGuard\Services\ConfigurationDoctor;
use Apkk\LaravelSecurityGuard\Services\DailyLimiter;
use Apkk\LaravelSecurityGuard\Services\ErrorNotificationGuard;
use Apkk\LaravelSecurityGuard\Services\IpBlockService;
use Apkk\LaravelSecurityGuard\Services\LaravelRequestIpResolver;
use Apkk\LaravelSecurityGuard\Services\NotificationDeliveryState;
use Apkk\LaravelSecurityGuard\Services\NotificationSuspension;
use Apkk\LaravelSecurityGuard\Services\PublicRateLimiter;
use Apkk\LaravelSecurityGuard\Services\QueuedSecurityEventDispatcher;
use Apkk\LaravelSecurityGuard\Services\RemoteAddrIpResolver;
use Apkk\LaravelSecurityGuard\Services\SensitiveRouteLimiter;
use Apkk\LaravelSecurityGuard\Services\SubmissionTokenService;
use Apkk\LaravelSecurityGuard\Support\CacheKeyFactory;
use Apkk\LaravelSecurityGuard\Support\FailureLogger;
use Illuminate\Cache\RateLimiter as CacheRateLimiter;
use Illuminate\Contracts\Bus\Dispatcher;
use Illuminate\Contracts\Cache\Factory as CacheFactory;
use Illuminate\Contracts\Cache\Repository as CacheRepository;
use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Database\DatabaseManager;
use Illuminate\Http\Request;
use Illuminate\Routing\Router;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Support\ServiceProvider;

class SecurityGuardServiceProvider extends ServiceProvider
{
    /** Container tag for the package's own cache repository. */
    public const CACHE = 'security-guard.cache';

    /** Container tag for the package's own rate limiter instance. */
    public const RATE_LIMITER = 'security-guard.rate-limiter';

    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/security-guard.php', 'security-guard');

        $this->registerInfrastructure();
        $this->registerContracts();
        $this->registerServices();
        $this->registerNotifiers();
    }

    public function boot(): void
    {
        $this->publishesArtifacts();

        $this->loadMigrationsFrom(__DIR__.'/../database/migrations');
        $this->loadViewsFrom(__DIR__.'/../resources/views', 'security-guard');

        $this->registerMiddlewareAliases();
        $this->registerSensitiveRouteLimiters();
        $this->registerManagementRoutes();

        if ($this->app->runningInConsole()) {
            $this->commands([
                BlockedListCommand::class,
                BlockedReleaseCommand::class,
                AdminIpAllowCommand::class,
                AdminIpListCommand::class,
                AdminIpRevokeCommand::class,
                StatusCommand::class,
                DoctorCommand::class,
            ]);
        }
    }

    private function registerInfrastructure(): void
    {
        $this->app->singleton(FailureLogger::class, fn ($app): FailureLogger => FailureLogger::make($app));

        // A dedicated store lets the guard run on a shared, lock-capable cache
        // even when the application default is something else.
        $this->app->singleton(self::CACHE, function ($app): CacheRepository {
            $store = $app->make(ConfigRepository::class)->get('security-guard.cache.store');

            return $app->make(CacheFactory::class)->store(is_string($store) && $store !== '' ? $store : null);
        });

        $this->app->singleton(self::RATE_LIMITER, fn ($app): CacheRateLimiter => new CacheRateLimiter(
            $app->make(self::CACHE),
        ));

        // Namespaces every key this package writes. Two applications sharing a
        // Redis server must not share block state or notification counters.
        $this->app->singleton(CacheKeyFactory::class, fn ($app): CacheKeyFactory => new CacheKeyFactory(
            $app->make(ConfigRepository::class)->get('security-guard.cache.prefix'),
        ));
    }

    private function registerContracts(): void
    {
        $this->app->singleton(ClientIpResolverContract::class, function ($app): ClientIpResolverContract {
            $driver = (string) $app->make(ConfigRepository::class)->get(
                'security-guard.ip_resolver.driver',
                'laravel_request',
            );

            return $driver === 'remote_addr'
                ? $app->make(RemoteAddrIpResolver::class)
                : $app->make(LaravelRequestIpResolver::class);
        });

        $this->app->singleton(IpMatcherContract::class, CidrIpMatcher::class);
        $this->app->singleton(AttackPathMatcherContract::class, ConfigAttackPathMatcher::class);
        $this->app->singleton(BlockedIpRepositoryContract::class, EloquentBlockedIpRepository::class);
        $this->app->singleton(
            AdminAllowedIpRepositoryContract::class,
            fn ($app): EloquentAdminAllowedIpRepository => new EloquentAdminAllowedIpRepository(
                $app->make(IpMatcherContract::class),
            ),
        );
        $this->app->singleton(AdminSubjectResolverContract::class, ConfigAdminSubjectResolver::class);
        $this->app->singleton(SecurityEventDispatcherContract::class, QueuedSecurityEventDispatcher::class);
    }

    private function registerServices(): void
    {
        $this->app->singleton(IpBlockService::class, fn ($app): IpBlockService => new IpBlockService(
            $app->make(BlockedIpRepositoryContract::class),
            $app->make(self::CACHE),
            $app->make(ConfigRepository::class),
            $app->make('events'),
            $app->make(SecurityEventDispatcherContract::class),
            $app->make(IpMatcherContract::class),
            $app->make(self::RATE_LIMITER),
            $app->make(CacheKeyFactory::class),
            $app->make(FailureLogger::class),
        ));

        $this->app->singleton(PublicRateLimiter::class, fn ($app): PublicRateLimiter => new PublicRateLimiter(
            $app->make(IpBlockService::class),
            $app->make(self::RATE_LIMITER),
            $app->make(CacheKeyFactory::class),
            $app->make(ConfigRepository::class),
        ));

        $this->app->singleton(SensitiveRouteLimiter::class, fn ($app): SensitiveRouteLimiter => new SensitiveRouteLimiter(
            $app->make(ClientIpResolverContract::class),
            $app->make(self::CACHE),
            $app->make(ConfigRepository::class),
            $app,
            $app->make('log'),
            $app->make(BlockResponseFactory::class),
            $app->make(CacheKeyFactory::class),
        ));

        $this->app->singleton(SubmissionTokenService::class, fn ($app): SubmissionTokenService => new SubmissionTokenService(
            $app->make(self::CACHE),
            $app->make(CacheKeyFactory::class),
            $app->make(ConfigRepository::class),
        ));

        $this->app->singleton(DailyLimiter::class, fn ($app): DailyLimiter => new DailyLimiter(
            $app->make(self::CACHE),
            $app->make(CacheKeyFactory::class),
            $app->make(FailureLogger::class),
        ));

        $this->app->singleton(NotificationSuspension::class, fn ($app): NotificationSuspension => new NotificationSuspension(
            $app->make(self::CACHE),
            $app->make(CacheKeyFactory::class),
        ));

        $this->app->singleton(
            NotificationDeliveryState::class,
            fn ($app): NotificationDeliveryState => new NotificationDeliveryState(
                $app->make(self::CACHE),
                $app->make(CacheKeyFactory::class),
                $app->make(FailureLogger::class),
            ),
        );

        $this->app->singleton(ErrorNotificationGuard::class, fn ($app): ErrorNotificationGuard => new ErrorNotificationGuard(
            $app->make(self::CACHE),
            $app->make(ConfigRepository::class),
            $app->make(Dispatcher::class),
            $app->make(CacheKeyFactory::class),
            $app->make(FailureLogger::class),
            // Optional: hosts bind this to reconcile their own report rows.
            $app->bound(Contracts\ErrorNotificationOutcomeHandlerContract::class)
                ? $app->make(Contracts\ErrorNotificationOutcomeHandlerContract::class)
                : null,
        ));

        $this->app->singleton(ConfigurationDoctor::class, fn ($app): ConfigurationDoctor => new ConfigurationDoctor(
            $app,
            $app->make(ConfigRepository::class),
            $app->make(self::CACHE),
            $app->make(CacheKeyFactory::class),
            $app->make(DatabaseManager::class),
            $app->make(ClientIpResolverContract::class),
            $app->make(AttackPathMatcherContract::class),
            $app->make(NotifierRegistry::class),
            $app->make(IpMatcherContract::class),
        ));

        $this->app->singleton(AdminIpAccessService::class);
        $this->app->singleton(BlockResponseFactory::class);
        $this->app->singleton(SecurityMessageBuilder::class);
    }

    private function registerNotifiers(): void
    {
        $this->app->singleton(NotifierRegistry::class, function ($app): NotifierRegistry {
            $registry = new NotifierRegistry($app, $app->make(FailureLogger::class));

            $registry->registerSecurityChannel(LogSecurityEventNotifier::CHANNEL, LogSecurityEventNotifier::class);
            $registry->registerSecurityChannel(MailSecurityEventNotifier::CHANNEL, MailSecurityEventNotifier::class);
            $registry->registerErrorChannel(LogErrorEventNotifier::CHANNEL, LogErrorEventNotifier::class);
            $registry->registerErrorChannel(MailErrorEventNotifier::CHANNEL, MailErrorEventNotifier::class);

            return $registry;
        });
    }

    private function publishesArtifacts(): void
    {
        if (! $this->app->runningInConsole()) {
            return;
        }

        // Separate tags: publishing the config must not drag migrations or
        // views into a host that does not want to own them.
        $this->publishes([
            __DIR__.'/../config/security-guard.php' => $this->app->configPath('security-guard.php'),
        ], 'security-guard-config');

        $this->publishes([
            __DIR__.'/../database/migrations' => $this->app->databasePath('migrations'),
        ], 'security-guard-migrations');

        $this->publishes([
            __DIR__.'/../resources/views' => $this->app->resourcePath('views/vendor/security-guard'),
        ], 'security-guard-views');
    }

    /**
     * Aliases only. Global registration is never done for the host: adding a
     * middleware to every request is a decision that belongs in the host's
     * kernel or bootstrap file, where it is visible.
     */
    private function registerMiddlewareAliases(): void
    {
        $router = $this->app->make(Router::class);

        $router->aliasMiddleware('security-guard', GuardPublicRequests::class);
        $router->aliasMiddleware('security-guard.admin-ip', EnsureAdminIpIsAllowed::class);
    }

    /**
     * Named limiters are registered whenever profiles exist, even while the
     * module is disabled: a route carrying `throttle:<profile>` must not 500
     * because the limiter is unknown. A disabled module yields Limit::none().
     */
    private function registerSensitiveRouteLimiters(): void
    {
        $profiles = (array) $this->app->make(ConfigRepository::class)
            ->get('security-guard.sensitive_routes.profiles', []);

        if ($profiles === []) {
            return;
        }

        foreach (array_keys($profiles) as $profile) {
            $profile = (string) $profile;

            RateLimiter::for($profile, fn (Request $request): array => $this->app
                ->make(SensitiveRouteLimiter::class)
                ->limits($request, $profile));
        }
    }

    private function registerManagementRoutes(): void
    {
        if (! $this->app->make(ConfigRepository::class)->get('security-guard.management_ui.enabled', false)) {
            return;
        }

        $this->loadRoutesFrom(__DIR__.'/../routes/web.php');
    }
}
