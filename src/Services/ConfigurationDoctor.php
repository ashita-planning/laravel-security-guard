<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Services;

use Apkk\LaravelSecurityGuard\Contracts\AttackPathMatcherContract;
use Apkk\LaravelSecurityGuard\Contracts\ClientIpResolverContract;
use Apkk\LaravelSecurityGuard\Contracts\IpMatcherContract;
use Apkk\LaravelSecurityGuard\Crawlers\CrawlerRangeStore;
use Apkk\LaravelSecurityGuard\Crawlers\CrawlerVerifierRegistry;
use Apkk\LaravelSecurityGuard\Data\DiagnosticResult;
use Apkk\LaravelSecurityGuard\Models\AdminAllowedIp;
use Apkk\LaravelSecurityGuard\Notifications\NotifierRegistry;
use Apkk\LaravelSecurityGuard\Support\CacheKeyFactory;
use Apkk\LaravelSecurityGuard\Support\IpRange;
use Apkk\LaravelSecurityGuard\Support\SupportedVersions;
use Illuminate\Contracts\Cache\LockProvider;
use Illuminate\Contracts\Cache\Repository as CacheRepository;
use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Database\DatabaseManager;
use Illuminate\Http\Middleware\TrustProxies;
use ReflectionClass;
use Throwable;

/**
 * Pre-flight checks for a security-guard installation.
 *
 * Most of this package's failure modes are silent by design: a defence that is
 * misconfigured does not throw, it simply stops defending, and an allowlist
 * with no entries locks out every administrator only at the moment someone
 * tries to sign in. This turns those into something you can see before
 * enabling a module rather than after.
 *
 * Every check is read-only apart from cache probes, which write and then
 * remove their own scratch keys.
 */
class ConfigurationDoctor
{
    public function __construct(
        private readonly Application $app,
        private readonly ConfigRepository $config,
        private readonly CacheRepository $cache,
        private readonly CacheKeyFactory $cacheKeys,
        private readonly DatabaseManager $database,
        private readonly ClientIpResolverContract $ipResolver,
        private readonly AttackPathMatcherContract $attackPathMatcher,
        private readonly NotifierRegistry $notifiers,
        private readonly IpMatcherContract $ipMatcher,
        private readonly CrawlerRangeStore $crawlerRanges,
        private readonly CrawlerVerifierRegistry $crawlerVerifiers,
        private readonly CrawlerRateLimiter $crawlerRateLimiter,
    ) {}

    /**
     * @return array<int, DiagnosticResult>
     */
    public function run(): array
    {
        return array_merge(
            [$this->checkLaravelVersion()],
            $this->checkDatabase(),
            $this->checkCache(),
            [$this->checkIpResolver()],
            [$this->checkAttackPatterns()],
            $this->checkRateLimitConsistency(),
            $this->checkAdminIpAllowlist(),
            $this->checkNotifications(),
            $this->checkManagementUi(),
            $this->checkSubmissionToken(),
            $this->checkCrawlerAccess(),
            $this->checkIpRules(),
        );
    }

    /**
     * Validate every IP rule this installation holds, from config and the
     * database alike.
     *
     * A rule that cannot be parsed matches nothing. On the ignore list that
     * means an address you meant to exempt is not exempt; on the admin
     * allowlist it means its owner cannot sign in. Neither raises an error at
     * runtime, so both are found here or not at all.
     *
     * @return array<int, DiagnosticResult>
     */
    private function checkIpRules(): array
    {
        $results = [$this->checkMatcherSupportsCidr()];

        $configured = array_values(array_filter(
            array_map('strval', (array) $this->config->get('security-guard.permanent_block.ignored_ips', [])),
        ));

        $results[] = $this->inspectRules('ignored_ips', $configured);

        if (! (bool) $this->config->get('security-guard.admin_ip.enabled', false)) {
            return $results;
        }

        try {
            $stored = array_map('strval', AdminAllowedIp::query()->where('enabled', true)->pluck('ip_address')->all());
        } catch (Throwable) {
            // checkAdminIpAllowlist() already reports an unreadable table.
            return $results;
        }

        $results[] = $this->inspectRules('admin_allowed_ips', $stored);

        return $results;
    }

    /**
     * The bound matcher has to actually understand the rules that are written.
     */
    private function checkMatcherSupportsCidr(): DiagnosticResult
    {
        $matcher = $this->ipMatcher;

        if ($matcher instanceof CidrIpMatcher) {
            return DiagnosticResult::ok('ip_matcher', 'CIDR networks are supported.', [
                'matcher' => $matcher::class,
            ]);
        }

        $cidrRules = array_filter(
            $this->allConfiguredRules(),
            static fn (string $entry): bool => str_contains($entry, '/'),
        );

        if ($cidrRules === []) {
            return DiagnosticResult::ok('ip_matcher', 'Exact matching only, and no CIDR rules are configured.', [
                'matcher' => $matcher::class,
            ]);
        }

        // The v0.1.x failure mode, reachable again by binding the exact matcher
        // explicitly: the rule is written, accepted, and silently matches
        // nothing at all.
        return DiagnosticResult::failure(
            'ip_matcher',
            count($cidrRules).' CIDR rule(s) exist, but the bound matcher only does exact matching.',
            'Bind CidrIpMatcher (the default), or replace the CIDR rules with individual addresses. As configured they match nothing.',
            ['matcher' => $matcher::class, 'rules' => implode(', ', array_slice($cidrRules, 0, 5))],
        );
    }

    /**
     * @return array<int, string>
     */
    private function allConfiguredRules(): array
    {
        $rules = array_map('strval', (array) $this->config->get('security-guard.permanent_block.ignored_ips', []));

        if ((bool) $this->config->get('security-guard.admin_ip.enabled', false)) {
            try {
                $rules = array_merge(
                    $rules,
                    array_map('strval', AdminAllowedIp::query()->where('enabled', true)->pluck('ip_address')->all()),
                );
            } catch (Throwable) {
                //
            }
        }

        return array_values(array_filter($rules));
    }

    /**
     * @param  array<int, string>  $entries
     */
    private function inspectRules(string $check, array $entries): DiagnosticResult
    {
        if ($entries === []) {
            return DiagnosticResult::skipped("ip_rules.{$check}", "No {$check} rules are configured.");
        }

        $unparseable = [];
        $nonCanonical = [];
        $redundantSuffix = [];
        $tooWide = [];
        /** @var array<string, array<int, string>> $byCanonical */
        $byCanonical = [];

        foreach ($entries as $entry) {
            $range = IpRange::parse($entry);

            if ($range === null) {
                $unparseable[] = $entry;

                continue;
            }

            $canonical = $range->toString();
            $byCanonical[$canonical][] = $entry;

            if (! $range->wasCanonical()) {
                $nonCanonical[] = "{$entry} -> {$canonical}";
            }

            // `203.0.113.10/32` is stored canonically without the suffix, so a
            // row still carrying one predates canonicalisation.
            if ($range->isSingleHost() && str_contains($entry, '/')) {
                $redundantSuffix[] = $entry;
            }

            if ($range->prefixLength() < $this->minimumPrefixFor($range->family())) {
                $tooWide[] = "{$canonical} (".number_format($range->size()).' addresses)';
            }
        }

        $duplicates = [];

        foreach ($byCanonical as $canonical => $written) {
            if (count($written) > 1) {
                $duplicates[] = $canonical.' <- '.implode(', ', $written);
            }
        }

        return $this->summariseRuleFindings(
            $check,
            count($entries),
            $unparseable,
            $nonCanonical,
            $redundantSuffix,
            $tooWide,
            $duplicates,
        );
    }

    /**
     * @param  array<int, string>  $unparseable
     * @param  array<int, string>  $nonCanonical
     * @param  array<int, string>  $redundantSuffix
     * @param  array<int, string>  $tooWide
     * @param  array<int, string>  $duplicates
     */
    private function summariseRuleFindings(
        string $check,
        int $total,
        array $unparseable,
        array $nonCanonical,
        array $redundantSuffix,
        array $tooWide,
        array $duplicates,
    ): DiagnosticResult {
        $name = "ip_rules.{$check}";

        if ($unparseable !== []) {
            return DiagnosticResult::failure(
                $name,
                count($unparseable).' of '.$total.' rule(s) cannot be parsed and match nothing.',
                'Correct or remove them. An unparseable rule is not a wildcard: on an allowlist it locks its owner out, on the ignore list it fails to exempt.',
                ['rules' => implode(', ', array_slice($unparseable, 0, 5))],
            );
        }

        if ($tooWide !== []) {
            return DiagnosticResult::warning(
                $name,
                count($tooWide).' rule(s) admit an unusually wide range.',
                'Confirm this is intended, or narrow the prefix. Widen security-guard.ip_rules.minimum_prefix to change the threshold.',
                ['rules' => implode(', ', array_slice($tooWide, 0, 5))],
            );
        }

        if ($nonCanonical !== []) {
            return DiagnosticResult::warning(
                $name,
                count($nonCanonical).' rule(s) carry host bits and were widened to their network.',
                'The rule admits more than the written address suggests. Re-write it as the network, or as a single address.',
                ['rules' => implode(', ', array_slice($nonCanonical, 0, 5))],
            );
        }

        if ($duplicates !== []) {
            return DiagnosticResult::warning(
                $name,
                count($duplicates).' rule(s) are written differently but mean the same thing.',
                'Remove the duplicates so the effective allowlist matches what the list appears to say.',
                ['rules' => implode('; ', array_slice($duplicates, 0, 3))],
            );
        }

        if ($redundantSuffix !== []) {
            return DiagnosticResult::warning(
                $name,
                count($redundantSuffix).' rule(s) keep a redundant /32 or /128 suffix.',
                'Harmless, but these predate canonicalisation. Re-registering them through the CLI stores the short form.',
                ['rules' => implode(', ', array_slice($redundantSuffix, 0, 5))],
            );
        }

        return DiagnosticResult::ok($name, "All {$total} rule(s) parse cleanly.", [
            'rules' => (string) $total,
        ]);
    }

    private function minimumPrefixFor(int $family): int
    {
        $configured = (array) $this->config->get('security-guard.ip_rules.minimum_prefix', []);

        return $family === IpRange::FAMILY_V4
            ? (int) ($configured['v4'] ?? 16)
            : (int) ($configured['v6'] ?? 32);
    }

    private function checkLaravelVersion(): DiagnosticResult
    {
        $version = $this->app->version();
        $major = explode('.', $version)[0];
        $floor = SupportedVersions::floorFor($major);

        if ($floor === null) {
            return DiagnosticResult::failure(
                'laravel_version',
                "Laravel {$version} is outside the supported range.",
                'Upgrade to '.SupportedVersions::describe().'. Older majors are past their upstream security-fix window.',
                ['version' => $version],
            );
        }

        if (version_compare($version, $floor, '<')) {
            return DiagnosticResult::failure(
                'laravel_version',
                "Laravel {$version} is below the supported floor for this major.",
                "Upgrade to at least {$floor}; earlier {$major}.x releases carry known security advisories.",
                ['version' => $version, 'required' => $floor],
            );
        }

        return DiagnosticResult::ok('laravel_version', "Laravel {$version} is supported.", [
            'version' => $version,
            'security_support_ends' => (string) SupportedVersions::supportEndsFor($major),
        ]);
    }

    /**
     * @return array<int, DiagnosticResult>
     */
    private function checkDatabase(): array
    {
        $connectionName = $this->config->get('security-guard.database.connection');
        $label = is_string($connectionName) && $connectionName !== '' ? $connectionName : '(default)';

        try {
            $connection = $this->database->connection(
                is_string($connectionName) && $connectionName !== '' ? $connectionName : null,
            );
            $connection->getPdo();
        } catch (Throwable $exception) {
            return [DiagnosticResult::failure(
                'database_connection',
                "The database connection {$label} is unreachable.",
                'Check the connection settings; without it no block can be stored or read.',
                ['connection' => $label, 'error' => $exception::class],
            )];
        }

        $results = [DiagnosticResult::ok('database_connection', "Connected to {$label}.", [
            'connection' => $label,
            'driver' => (string) $connection->getDriverName(),
        ])];

        $tables = [
            'blocked_ips' => (string) $this->config->get(
                'security-guard.database.tables.blocked_ips',
                'security_guard_blocked_ips',
            ),
            'admin_allowed_ips' => (string) $this->config->get(
                'security-guard.database.tables.admin_allowed_ips',
                'security_guard_admin_allowed_ips',
            ),
        ];

        $missing = [];

        foreach ($tables as $table) {
            try {
                if (! $connection->getSchemaBuilder()->hasTable($table)) {
                    $missing[] = $table;
                }
            } catch (Throwable) {
                $missing[] = $table;
            }
        }

        $adminIpEnabled = (bool) $this->config->get('security-guard.admin_ip.enabled', false);

        if ($missing === []) {
            $results[] = DiagnosticResult::ok('database_tables', 'All required tables exist.', [
                'tables' => implode(', ', $tables),
            ]);

            return $results;
        }

        // A missing admin table only matters once that module is switched on.
        $onlyAdminMissing = $missing === [$tables['admin_allowed_ips']];

        $results[] = $onlyAdminMissing && ! $adminIpEnabled
            ? DiagnosticResult::warning(
                'database_tables',
                'The admin allowlist table is missing.',
                'Run `php artisan migrate`. Required before enabling admin_ip.',
                ['missing' => implode(', ', $missing)],
            )
            : DiagnosticResult::failure(
                'database_tables',
                'Required tables are missing.',
                'Run `php artisan migrate` (publish them first with the security-guard-migrations tag if you manage schema yourself).',
                ['missing' => implode(', ', $missing)],
            );

        return $results;
    }

    /**
     * @return array<int, DiagnosticResult>
     */
    private function checkCache(): array
    {
        [$storeName, $driver] = $this->configuredCacheDriver();

        $results = [$this->checkCacheSharing($storeName, $driver)];

        $store = $this->cache->getStore();

        $results[] = $store instanceof LockProvider
            ? DiagnosticResult::ok('cache_atomic_lock', "The {$driver} store supports atomic locks.")
            : DiagnosticResult::failure(
                'cache_atomic_lock',
                "The {$driver} store does not support atomic locks.",
                'Use redis, memcached, dynamodb or database. Without locks the daily notification limits are approximate and can be overshot under load.',
                ['driver' => $driver],
            );

        $results[] = $this->probeAtomicAdd($driver);
        $results[] = $this->checkCachePrefix();

        return $results;
    }

    private function checkCacheSharing(string $storeName, string $driver): DiagnosticResult
    {
        // `array` lives and dies with one PHP process, so nothing it records
        // survives to the next request, let alone to another worker.
        if ($driver === 'array' || $driver === 'null') {
            return DiagnosticResult::failure(
                'cache_shared',
                "The {$driver} cache store keeps no state between requests.",
                'Point security-guard.cache.store at a shared store (redis, memcached, database).',
                ['store' => $storeName, 'driver' => $driver],
            );
        }

        if ($driver === 'file') {
            return DiagnosticResult::warning(
                'cache_shared',
                'The file cache store is local to one node.',
                'Fine on a single server. On multiple nodes each keeps its own counters and block cache, so limits apply per node.',
                ['store' => $storeName, 'driver' => $driver],
            );
        }

        return DiagnosticResult::ok('cache_shared', "The {$driver} store is shared across processes.", [
            'store' => $storeName,
            'driver' => $driver,
        ]);
    }

    /**
     * `add()` must be a real test-and-set: the one-time submission token and
     * the log-once suppression both rely on exactly one caller winning.
     */
    private function probeAtomicAdd(string $driver): DiagnosticResult
    {
        $key = $this->cacheKeys->dailyCounter('doctor-probe', (string) getmypid());

        try {
            $this->cache->forget($key);
            $first = $this->cache->add($key, true, 10);
            $second = $this->cache->add($key, true, 10);
            $this->cache->forget($key);
        } catch (Throwable $exception) {
            return DiagnosticResult::failure(
                'cache_atomic_add',
                'The cache store rejected an add() probe.',
                'Verify the store is reachable and writable.',
                ['driver' => $driver, 'error' => $exception::class],
            );
        }

        if ($first === true && $second === false) {
            return DiagnosticResult::ok('cache_atomic_add', "The {$driver} store implements add() correctly.");
        }

        return DiagnosticResult::failure(
            'cache_atomic_add',
            'add() did not behave as a test-and-set operation.',
            'One-time submission tokens and duplicate suppression need this. Use a store with a real add() implementation.',
            ['driver' => $driver, 'first' => var_export($first, true), 'second' => var_export($second, true)],
        );
    }

    private function checkCachePrefix(): DiagnosticResult
    {
        $configured = $this->config->get('security-guard.cache.prefix');
        $prefix = $this->cacheKeys->prefix();

        if (! is_string($configured) || trim($configured) === '') {
            return DiagnosticResult::warning(
                'cache_prefix',
                'No cache prefix is configured; the package default is in use.',
                'Set security-guard.cache.prefix per application. Two apps sharing a cache server otherwise share block state and notification quotas.',
                ['prefix' => $prefix],
            );
        }

        if ($prefix === CacheKeyFactory::DEFAULT_PREFIX) {
            return DiagnosticResult::warning(
                'cache_prefix',
                'The cache prefix is still the package default.',
                'Use a value unique to this application, such as its name and environment.',
                ['prefix' => $prefix],
            );
        }

        return DiagnosticResult::ok('cache_prefix', "Cache keys are namespaced under {$prefix}.", [
            'prefix' => $prefix,
        ]);
    }

    private function checkIpResolver(): DiagnosticResult
    {
        $driver = (string) $this->config->get('security-guard.ip_resolver.driver', 'laravel_request');

        if (! in_array($driver, ['laravel_request', 'remote_addr'], true)) {
            return DiagnosticResult::failure(
                'ip_resolver',
                "Unknown IP resolver driver: {$driver}.",
                'Use laravel_request (default) or remote_addr, or bind your own ClientIpResolverContract.',
                ['driver' => $driver],
            );
        }

        $resolverClass = $this->ipResolver::class;

        if ($driver === 'remote_addr') {
            return DiagnosticResult::ok(
                'ip_resolver',
                'Using REMOTE_ADDR directly, ignoring proxy headers.',
                ['driver' => $driver, 'resolver' => $resolverClass],
            );
        }

        if ($this->trustedProxiesConfigured()) {
            return DiagnosticResult::ok(
                'ip_resolver',
                'Using Request::ip() with trusted proxies configured.',
                ['driver' => $driver, 'resolver' => $resolverClass],
            );
        }

        // Getting this wrong collapses every visitor onto the proxy's address,
        // so one client can trip a rate limit that then blocks everyone.
        return DiagnosticResult::warning(
            'ip_resolver',
            'No trusted proxies could be detected.',
            'Correct if this application is not behind a proxy or load balancer. If it is, configure TrustProxies first and confirm with `php artisan security-guard:status <ip>`.',
            ['driver' => $driver, 'resolver' => $resolverClass],
        );
    }

    private function trustedProxiesConfigured(): bool
    {
        if (! class_exists(TrustProxies::class)) {
            return false;
        }

        try {
            $property = (new ReflectionClass(TrustProxies::class))->getProperty('alwaysTrustProxies');
            $property->setAccessible(true);

            return $property->getValue() !== null;
        } catch (Throwable) {
            return false;
        }
    }

    private function checkAttackPatterns(): DiagnosticResult
    {
        $matcher = $this->attackPathMatcher;

        if (! $matcher instanceof ConfigAttackPathMatcher) {
            return DiagnosticResult::skipped('attack_patterns', 'A custom attack path matcher is bound.');
        }

        $invalid = [];
        $categories = 0;

        foreach ($matcher->patterns() as $category => $definition) {
            $categories++;

            foreach ($definition['regex'] ?? [] as $regex) {
                if (@preg_match($regex, '') === false) {
                    $invalid[] = (string) $category;

                    break;
                }
            }
        }

        if ($categories === 0) {
            return DiagnosticResult::warning(
                'attack_patterns',
                'No attack path patterns are active.',
                'Set permanent_block.use_default_patterns to true, or define your own categories.',
            );
        }

        if ($invalid !== []) {
            return DiagnosticResult::failure(
                'attack_patterns',
                'Some categories contain an invalid regular expression.',
                'Fix the pattern. Invalid ones are skipped at runtime, so those probes go undetected.',
                ['categories' => implode(', ', $invalid)],
            );
        }

        return DiagnosticResult::ok('attack_patterns', "{$categories} attack path categories compiled cleanly.", [
            'categories' => (string) $categories,
        ]);
    }

    /**
     * @return array<int, DiagnosticResult>
     */
    private function checkRateLimitConsistency(): array
    {
        $results = [];
        $blockEnabled = (bool) $this->config->get('security-guard.permanent_block.enabled', true);
        $rateEnabled = (bool) $this->config->get('security-guard.public_rate_limit.enabled', false);
        $action = (string) $this->config->get('security-guard.public_rate_limit.action', 'permanent_block');

        if ($rateEnabled && $action === 'permanent_block' && ! $blockEnabled) {
            $results[] = DiagnosticResult::failure(
                'rate_limit_consistency',
                'The rate limit blocks permanently, but permanent blocking is disabled.',
                'Enable permanent_block, or switch the action to reject_only or temporary_block. As configured, offenders are recorded but never actually kept out.',
                ['action' => $action],
            );
        } else {
            $results[] = DiagnosticResult::ok('rate_limit_consistency', $rateEnabled
                ? "Public rate limiting is enabled with action {$action}."
                : 'Public rate limiting is disabled.', ['action' => $action]);
        }

        $excluded = (array) $this->config->get('security-guard.permanent_block.excluded_paths', []);

        if ($excluded !== []) {
            $results[] = DiagnosticResult::warning(
                'permanent_block_exclusions',
                count($excluded).' path(s) are excluded from blocking and attack path detection.',
                'On these paths a blocked address is served normally. Keep the list as small as possible.',
                ['paths' => implode(', ', array_map('strval', $excluded))],
            );
        }

        if ($rateEnabled) {
            $limit = (int) $this->config->get('security-guard.public_rate_limit.requests_per_minute', 120);

            if ($limit < 1) {
                $results[] = DiagnosticResult::warning(
                    'rate_limit_threshold',
                    "requests_per_minute is {$limit}, which is normalised to 1.",
                    'Set a deliberate value; 1 request per minute will block ordinary visitors.',
                    ['configured' => (string) $limit],
                );
            }
        }

        return $results;
    }

    /**
     * @return array<int, DiagnosticResult>
     */
    private function checkAdminIpAllowlist(): array
    {
        if (! (bool) $this->config->get('security-guard.admin_ip.enabled', false)) {
            return [DiagnosticResult::skipped('admin_ip_allowlist', 'The admin IP allowlist is disabled.')];
        }

        $policy = (string) $this->config->get('security-guard.admin_ip.empty_policy', 'deny');

        try {
            $entries = AdminAllowedIp::query()->where('enabled', true)->count();
        } catch (Throwable $exception) {
            return [DiagnosticResult::failure(
                'admin_ip_allowlist',
                'The allowlist table could not be read.',
                'Run the migrations. This module denies access when the lookup fails, so administrators would be locked out.',
                ['error' => $exception::class],
            )];
        }

        if ($entries === 0 && $policy === 'deny') {
            // Enabling this with an empty table is the classic way to lock
            // every administrator out of a production system at once.
            return [DiagnosticResult::failure(
                'admin_ip_allowlist',
                'The allowlist is enabled with no entries and empty_policy is "deny".',
                'Register an address first: `php artisan security-guard:admin-ip:allow <subject> <ip>`. Nobody can sign in until you do.',
                ['entries' => '0', 'empty_policy' => $policy],
            )];
        }

        if ($policy === 'allow_when_empty') {
            return [DiagnosticResult::warning(
                'admin_ip_allowlist',
                'empty_policy is "allow_when_empty".',
                'Intended for migration only. Subjects with no entries are unrestricted; switch to "deny" once addresses are registered.',
                ['entries' => (string) $entries, 'empty_policy' => $policy],
            )];
        }

        return [DiagnosticResult::ok('admin_ip_allowlist', "{$entries} allowed address(es) registered.", [
            'entries' => (string) $entries,
            'empty_policy' => $policy,
        ])];
    }

    /**
     * @return array<int, DiagnosticResult>
     */
    private function checkNotifications(): array
    {
        if (! (bool) $this->config->get('security-guard.notifications.enabled', false)) {
            return [DiagnosticResult::skipped('notifications', 'Security event notifications are disabled.')];
        }

        $results = [];
        $channels = array_map('strval', (array) $this->config->get('security-guard.notifications.channels', []));

        if ($channels === []) {
            $results[] = DiagnosticResult::failure(
                'notification_channels',
                'Notifications are enabled but no channels are configured.',
                'Add at least one channel, for example ["log"].',
            );
        } else {
            $unresolvable = array_values(array_filter(
                $channels,
                fn (string $channel): bool => $this->notifiers->securityNotifier($channel) === null,
            ));

            $results[] = $unresolvable === []
                ? DiagnosticResult::ok('notification_channels', 'All channels resolve: '.implode(', ', $channels).'.')
                : DiagnosticResult::failure(
                    'notification_channels',
                    'Some channels cannot be resolved: '.implode(', ', $unresolvable).'.',
                    'Register them on NotifierRegistry, or remove them from the channel list.',
                    ['channels' => implode(', ', $channels)],
                );

            if (in_array('mail', $channels, true)) {
                $recipients = $this->config->get('security-guard.notifications.mail.to', []);
                $recipients = is_string($recipients) ? [$recipients] : (array) $recipients;
                $valid = array_filter(
                    array_map('strval', $recipients),
                    static fn (string $address): bool => filter_var($address, FILTER_VALIDATE_EMAIL) !== false,
                );

                $results[] = $valid === []
                    ? DiagnosticResult::failure(
                        'notification_recipients',
                        'The mail channel is enabled with no valid recipients.',
                        'Set security-guard.notifications.mail.to. Deliveries are skipped entirely until you do.',
                    )
                    : DiagnosticResult::ok(
                        'notification_recipients',
                        count($valid).' mail recipient(s) configured.',
                    );
            }
        }

        $limit = (int) $this->config->get('security-guard.notifications.daily_limit', 10);

        if ($limit < 1) {
            $results[] = DiagnosticResult::failure(
                'notification_daily_limit',
                "daily_limit is {$limit}, so nothing will ever be sent.",
                'Set it to 1 or more.',
                ['daily_limit' => (string) $limit],
            );
        }

        $results[] = $this->checkQueueConnection();

        return $results;
    }

    private function checkQueueConnection(): DiagnosticResult
    {
        $connection = $this->config->get('security-guard.notifications.connection');
        $connection = is_string($connection) && $connection !== ''
            ? $connection
            : (string) $this->config->get('queue.default');

        if ($this->config->get("queue.connections.{$connection}") === null) {
            return DiagnosticResult::failure(
                'queue_connection',
                "The queue connection {$connection} is not defined.",
                'Point security-guard.notifications.connection at a configured queue connection.',
                ['connection' => $connection],
            );
        }

        $driver = (string) $this->config->get("queue.connections.{$connection}.driver");

        if ($driver === 'sync') {
            return DiagnosticResult::warning(
                'queue_connection',
                'Notifications run on the sync queue.',
                'Delivery then happens inside the request that triggered the block, so a slow provider slows that request. Use a real queue with a running worker.',
                ['connection' => $connection, 'driver' => $driver],
            );
        }

        return DiagnosticResult::ok('queue_connection', "Notifications are queued on {$connection} ({$driver}).", [
            'connection' => $connection,
            'driver' => $driver,
        ]);
    }

    /**
     * @return array<int, DiagnosticResult>
     */
    private function checkManagementUi(): array
    {
        if (! (bool) $this->config->get('security-guard.management_ui.enabled', false)) {
            return [DiagnosticResult::skipped('management_ui', 'The bundled management UI is disabled.')];
        }

        $middleware = array_map('strval', (array) $this->config->get('security-guard.management_ui.middleware', []));

        $hasAuth = (bool) array_filter(
            $middleware,
            static fn (string $m): bool => $m === 'auth' || str_starts_with($m, 'auth:'),
        );
        $hasAuthorization = (bool) array_filter(
            $middleware,
            static fn (string $m): bool => str_starts_with($m, 'can:') || str_starts_with($m, 'authorize'),
        );

        $missing = [];

        if (! $hasAuth) {
            $missing[] = 'authentication (auth)';
        }

        if (! $hasAuthorization) {
            $missing[] = 'authorization (can:)';
        }

        if ($missing !== []) {
            // The UI releases blocks. Exposing it without both checks hands an
            // attacker the ability to unblock themselves.
            $exposes = 'This screen can release blocked addresses.';

            if ((bool) $this->config->get('security-guard.management_ui.admin_allowed_ips.enabled', false)) {
                // Worse: the allowlist screen tells a reader exactly which
                // networks reach the admin area, and for which subjects.
                $exposes .= ' The allowlist screen is also enabled, which publishes which networks reach the admin area.';
            }

            return [DiagnosticResult::failure(
                'management_ui',
                'The management UI is missing '.implode(' and ', $missing).'.',
                'Add them to security-guard.management_ui.middleware. '.$exposes,
                ['middleware' => implode(', ', $middleware)],
            )];
        }

        $results = [DiagnosticResult::ok('management_ui', 'The management UI requires authentication and authorization.', [
            'middleware' => implode(', ', $middleware),
            'prefix' => (string) $this->config->get('security-guard.management_ui.prefix', 'security-guard'),
        ])];

        if ((bool) $this->config->get('security-guard.management_ui.admin_allowed_ips.enabled', false)) {
            $results[] = DiagnosticResult::ok(
                'management_ui.admin_allowed_ips',
                'The allowlist screen is enabled and read-only.',
                ['middleware' => implode(', ', $middleware)],
            );
        }

        return $results;
    }

    /**
     * @return array<int, DiagnosticResult>
     */
    private function checkSubmissionToken(): array
    {
        if (! (bool) $this->config->get('security-guard.submission_token.enabled', false)) {
            return [DiagnosticResult::skipped('submission_token', 'One-time submission tokens are disabled.')];
        }

        [, $driver] = $this->configuredCacheDriver();

        if (in_array($driver, ['array', 'null'], true)) {
            return [DiagnosticResult::failure(
                'submission_token',
                "Submission tokens need a shared cache, but the store is {$driver}.",
                'Use redis, memcached or database. Otherwise the used-token record disappears and a confirmed submission can run twice.',
                ['driver' => $driver],
            )];
        }

        if ($driver === 'file') {
            return [DiagnosticResult::warning(
                'submission_token',
                'Submission tokens are stored in a node-local file cache.',
                'On multiple nodes a resubmission routed elsewhere is not recognised as a duplicate.',
                ['driver' => $driver],
            )];
        }

        return [DiagnosticResult::ok('submission_token', "Submission tokens use the shared {$driver} store.", [
            'driver' => $driver,
        ])];
    }

    /**
     * @return array<int, DiagnosticResult>
     */
    private function checkCrawlerAccess(): array
    {
        if (! (bool) $this->config->get('security-guard.crawler_access.enabled', false)) {
            return [DiagnosticResult::skipped('crawler_access', 'Verified crawler handling is disabled.')];
        }

        return array_merge(
            [$this->checkCrawlerProviders()],
            [$this->checkCrawlerCache()],
            $this->checkCrawlerRanges(),
            $this->checkCrawlerRateLimit(),
            [$this->checkCrawlerVerificationTrust()],
            $this->checkCrawlerGuardExemption(),
            [$this->checkRobotsTxt()],
        );
    }

    private function checkCrawlerProviders(): DiagnosticResult
    {
        $providers = $this->crawlerVerifiers->providers();

        if ($providers === []) {
            return DiagnosticResult::failure(
                'crawler_providers',
                'Crawler access is enabled, but no provider is registered.',
                'Enable at least one entry under crawler_access.verified_crawlers, or register your own verifier. As configured nothing ever verifies, and every crawler stays on the public policy this module was meant to take it off.',
            );
        }

        return DiagnosticResult::ok(
            'crawler_providers',
            count($providers).' crawler provider(s) registered: '.implode(', ', $providers).'.',
            ['providers' => implode(', ', $providers)],
        );
    }

    private function checkCrawlerCache(): DiagnosticResult
    {
        [$storeName, $driver] = $this->configuredCacheDriver();

        if (in_array($driver, ['array', 'null'], true)) {
            return DiagnosticResult::failure(
                'crawler_cache',
                "Crawler range data is kept in the {$driver} store, which keeps no state between requests.",
                'Point security-guard.cache.store at a shared store. Ranges written by crawler-ranges:refresh die with the process that fetched them, so no crawler ever verifies.',
                ['store' => $storeName, 'driver' => $driver],
            );
        }

        if ($driver === 'file') {
            return DiagnosticResult::warning(
                'crawler_cache',
                'Crawler range data lives in a node-local file cache.',
                'Fine on a single server. On multiple nodes the refresh has to run on every node, and each node counts crawler requests on its own.',
                ['store' => $storeName, 'driver' => $driver],
            );
        }

        return DiagnosticResult::ok('crawler_cache', "Crawler range data uses the shared {$driver} store.", [
            'store' => $storeName,
            'driver' => $driver,
        ]);
    }

    /**
     * @return array<int, DiagnosticResult>
     */
    private function checkCrawlerRanges(): array
    {
        return array_map(
            fn (string $provider): DiagnosticResult => $this->inspectCrawlerRanges($provider),
            $this->crawlerVerifiers->providers(),
        );
    }

    /**
     * One provider's stored range document: present, intact, and fresh.
     *
     * All three failure modes end the same way at runtime — the provider
     * verifies nobody and its crawler silently falls back to the public
     * policy — but they are distinct problems: "never fetched" needs the
     * command run once, "stale" needs it scheduled, "corrupt" means the
     * cached document was edited or damaged, which the refresh would never
     * store.
     */
    private function inspectCrawlerRanges(string $provider): DiagnosticResult
    {
        $name = "crawler_ranges.{$provider}";
        $stored = $this->crawlerRanges->current($provider);

        if ($stored === null) {
            return DiagnosticResult::failure(
                $name,
                "No published ranges are stored for {$provider}.",
                'Run `php artisan security-guard:crawler-ranges:refresh` and schedule it. Until ranges exist this provider verifies nobody, and its crawler is treated like any other client.',
            );
        }

        $entries = array_merge($stored['v4'], $stored['v6']);

        if ($entries === []) {
            return DiagnosticResult::failure(
                $name,
                "The stored range document for {$provider} is empty.",
                'Re-run `php artisan security-guard:crawler-ranges:refresh`. The refresh never stores an empty document, so this one did not come from it intact.',
            );
        }

        $invalid = array_values(array_filter($entries, static function (string $entry): bool {
            $range = IpRange::parse($entry);

            return $range === null || ! $range->wasCanonical();
        }));

        if ($invalid !== []) {
            return DiagnosticResult::failure(
                $name,
                count($invalid).' of '.count($entries)." stored range(s) for {$provider} are not canonical CIDR networks.",
                'Re-run `php artisan security-guard:crawler-ranges:refresh`. The refresh validates before storing, so invalid entries mean the cached document was edited or corrupted. Verification fails closed on them.',
                ['ranges' => implode(', ', array_slice($invalid, 0, 5))],
            );
        }

        if ($this->crawlerRanges->freshRanges($provider) === null) {
            return DiagnosticResult::failure(
                $name,
                "The stored ranges for {$provider} are past their freshness window.",
                'Refresh them, and schedule the command to run more often than crawler_access.ranges.fresh_for_hours. Stale ranges verify nobody, so the crawler is back on the public policy it was meant to be kept off.',
                ['fetched_at' => $stored['fetched_at'], 'fresh_until' => $stored['fresh_until']],
            );
        }

        return DiagnosticResult::ok(
            $name,
            count($stored['v4']).' IPv4 and '.count($stored['v6'])." IPv6 network(s) stored for {$provider} and fresh.",
            ['fetched_at' => $stored['fetched_at'], 'fresh_until' => $stored['fresh_until']],
        );
    }

    /**
     * @return array<int, DiagnosticResult>
     */
    private function checkCrawlerRateLimit(): array
    {
        $results = [];

        if ($this->crawlerRateLimiter->actionWasDowngraded()) {
            $configured = (string) $this->config->get('security-guard.crawler_access.rate_limit.action');

            // The limiter already refuses to honour this, so the runtime is
            // safe; the failure exists because a config that says one thing
            // while the system does another is a debugging trap.
            $results[] = DiagnosticResult::failure(
                'crawler_rate_limit',
                "The crawler action \"{$configured}\" is not honoured; requests run as reject_only.",
                'Use reject_only or service_unavailable. Anything that persists a block is refused for crawlers: a search crawler kept on 403s until someone releases it costs crawling, index refresh and search presence.',
                ['action' => $configured],
            );
        } else {
            $results[] = DiagnosticResult::ok(
                'crawler_rate_limit',
                'Verified crawlers are limited to '.$this->crawlerRateLimiter->limit().' request(s)/minute with '.$this->crawlerRateLimiter->action().'.',
                ['action' => $this->crawlerRateLimiter->action(), 'limit' => (string) $this->crawlerRateLimiter->limit()],
            );
        }

        $configuredLimit = (int) $this->config->get('security-guard.crawler_access.rate_limit.requests_per_minute', 300);

        if ($configuredLimit < 1) {
            $results[] = DiagnosticResult::warning(
                'crawler_rate_limit_threshold',
                "requests_per_minute is {$configuredLimit}, which is normalised to 1.",
                'Set a deliberate value; one request per minute keeps a verified crawler on near-permanent 429s.',
                ['configured' => (string) $configuredLimit],
            );
        }

        return $results;
    }

    /**
     * No verifier may confirm an address nobody's crawler can own.
     *
     * 192.0.2.1 and 2001:db8::1 sit in documentation space (RFC 5737 and
     * RFC 3849): never routed, never inside a provider's published ranges.
     * A verifier that answers "yes" for either is verifying on the
     * User-Agent claim alone — the spoofing door this module exists to
     * keep shut. The bundled verifiers cannot fail this; it guards the
     * ones hosts register themselves.
     */
    private function checkCrawlerVerificationTrust(): DiagnosticResult
    {
        $trusting = [];

        foreach ($this->crawlerVerifiers->providers() as $provider) {
            $verifier = $this->crawlerVerifiers->verifierFor($provider);

            if ($verifier === null) {
                continue;
            }

            foreach (['192.0.2.1', '2001:db8::1'] as $address) {
                try {
                    $owns = $verifier->ownsAddress($address);
                } catch (Throwable) {
                    // The registry degrades a throwing verifier to
                    // `unverified` at runtime, and the range checks above
                    // surface the data problems behind it.
                    continue;
                }

                if ($owns === true) {
                    $trusting[] = $provider;

                    break;
                }
            }
        }

        if ($trusting !== []) {
            return DiagnosticResult::failure(
                'crawler_verification',
                'Verifier(s) confirmed a documentation address: '.implode(', ', $trusting).'.',
                'A verifier must confirm addresses only from its provider\'s published data. One that confirms an address no provider can own is trusting the User-Agent claim, which any client can send.',
                ['providers' => implode(', ', $trusting)],
            );
        }

        return DiagnosticResult::ok(
            'crawler_verification',
            'No verifier trusts a User-Agent claim without confirming the address.',
        );
    }

    /**
     * Published crawler ranges do not belong on the ignore list.
     *
     * An ignored address skips attack path detection, blocking and rate
     * limits alike, so pasting a provider's networks there widens far more
     * than the rate limit relief the host was after — and crawler_access
     * already provides that relief without giving up the defences.
     *
     * @return array<int, DiagnosticResult>
     */
    private function checkCrawlerGuardExemption(): array
    {
        $rules = [];

        foreach ((array) $this->config->get('security-guard.permanent_block.ignored_ips', []) as $entry) {
            $range = IpRange::parse((string) $entry);

            if ($range !== null) {
                $rules[(string) $entry] = $range;
            }
        }

        if ($rules === []) {
            return [];
        }

        /** @var array<string, array<string, true>> $overlapping rule => provider set */
        $overlapping = [];

        foreach ($this->crawlerVerifiers->providers() as $provider) {
            $stored = $this->crawlerRanges->current($provider);

            if ($stored === null) {
                continue;
            }

            foreach (array_merge($stored['v4'], $stored['v6']) as $entry) {
                $published = IpRange::parse($entry);

                if ($published === null) {
                    continue;
                }

                foreach ($rules as $written => $rule) {
                    // CIDR blocks nest or miss entirely, so overlap means one
                    // network contains the other's first address.
                    if ($rule->family() === $published->family()
                        && ($rule->contains($published->network()) || $published->contains($rule->network()))) {
                        $overlapping[$written][$provider] = true;
                    }
                }
            }
        }

        if ($overlapping === []) {
            return [];
        }

        $described = [];

        foreach ($overlapping as $written => $providers) {
            $described[] = $written.' ('.implode(', ', array_keys($providers)).')';
        }

        return [DiagnosticResult::warning(
            'crawler_guard_exemption',
            count($overlapping).' ignore rule(s) cover published crawler ranges.',
            'Remove them from permanent_block.ignored_ips. Ignored addresses bypass attack path detection and blocking entirely; crawler_access already keeps verified crawlers off permanent blocks without giving that up.',
            ['rules' => implode('; ', array_slice($described, 0, 5))],
        )];
    }

    /**
     * robots.txt steers crawl traffic; it is not a security boundary, and
     * this package never generates one. The check exists because a site
     * that starts caring about crawler behaviour without one is usually an
     * oversight, not a decision.
     */
    private function checkRobotsTxt(): DiagnosticResult
    {
        $path = $this->app->publicPath('robots.txt');

        if (is_file($path)) {
            return DiagnosticResult::ok('crawler_robots_txt', 'robots.txt is present.', ['path' => $path]);
        }

        return DiagnosticResult::warning(
            'crawler_robots_txt',
            'No robots.txt was found in the public directory.',
            'Add one in the host application to steer crawl traffic. It is a hint to well-behaved crawlers, not an access control: keep protecting admin and authenticated areas with middleware.',
            ['path' => $path],
        );
    }

    /**
     * The store and driver every module-level cache check reasons about.
     *
     * @return array{0: string, 1: string} store name, driver
     */
    private function configuredCacheDriver(): array
    {
        $storeName = $this->config->get('security-guard.cache.store');
        $storeName = is_string($storeName) && $storeName !== ''
            ? $storeName
            : (string) $this->config->get('cache.default');

        return [$storeName, (string) $this->config->get("cache.stores.{$storeName}.driver", $storeName)];
    }
}
