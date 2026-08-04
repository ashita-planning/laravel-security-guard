<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Services;

use Apkk\LaravelSecurityGuard\Contracts\AttackPathMatcherContract;
use Apkk\LaravelSecurityGuard\Contracts\ClientIpResolverContract;
use Apkk\LaravelSecurityGuard\Contracts\IpMatcherContract;
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
        $storeName = $this->config->get('security-guard.cache.store');
        $storeName = is_string($storeName) && $storeName !== ''
            ? $storeName
            : (string) $this->config->get('cache.default');
        $driver = (string) $this->config->get("cache.stores.{$storeName}.driver", $storeName);

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

        $storeName = $this->config->get('security-guard.cache.store');
        $storeName = is_string($storeName) && $storeName !== ''
            ? $storeName
            : (string) $this->config->get('cache.default');
        $driver = (string) $this->config->get("cache.stores.{$storeName}.driver", $storeName);

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
}
