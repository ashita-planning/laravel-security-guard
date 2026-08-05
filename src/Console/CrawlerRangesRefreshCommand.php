<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Console;

use Apkk\LaravelSecurityGuard\Contracts\CrawlerRangeFetcherContract;
use Apkk\LaravelSecurityGuard\Crawlers\CrawlerRangeParser;
use Apkk\LaravelSecurityGuard\Crawlers\CrawlerRangeStore;
use Illuminate\Console\Command;
use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Throwable;

/**
 * Fetches and stores the published crawler ranges.
 *
 * This command is the only path to the network for crawler data. The package
 * does not schedule it: whether and how often to refresh is the host's
 * decision, made visibly in its own scheduler —
 *
 *     Schedule::command('security-guard:crawler-ranges:refresh')->daily();
 *
 * A failed provider keeps its previous data and fails the exit code, so an
 * unattended cron run cannot quietly degrade into "no ranges at all".
 */
class CrawlerRangesRefreshCommand extends Command
{
    protected $signature = 'security-guard:crawler-ranges:refresh
        {--provider=* : Refresh only the named providers}';

    protected $description = 'Fetch and store the published IP ranges of the known search crawlers';

    public function handle(
        CrawlerRangeFetcherContract $fetcher,
        CrawlerRangeStore $store,
        ConfigRepository $config,
    ): int {
        $sources = $this->sources($config);

        if ($sources === null) {
            return self::FAILURE;
        }

        $failed = [];

        foreach ($sources as $provider => $url) {
            try {
                $body = $fetcher->fetch($url);
                $parsed = CrawlerRangeParser::parse($body);
                $outcome = $store->store($provider, $parsed, $url, hash('sha256', $body));

                $this->components->info(sprintf(
                    '%s: %s — %d IPv4, %d IPv6 prefix(es)%s.',
                    $provider,
                    $outcome === CrawlerRangeStore::OUTCOME_UNCHANGED ? 'unchanged' : 'updated',
                    count($parsed['v4']),
                    count($parsed['v6']),
                    $outcome === CrawlerRangeStore::OUTCOME_UNCHANGED ? ' (freshness renewed)' : '',
                ));
            } catch (Throwable $exception) {
                $failed[] = $provider;

                // The message may carry the URL (config-owned) but the
                // document body never reaches it: parser reasons are fixed
                // strings, and transport errors are truncated.
                $this->components->error(sprintf(
                    '%s: refresh failed — %s. The previously stored data was kept.',
                    $provider,
                    mb_strimwidth($exception->getMessage(), 0, 200, '…'),
                ));
            }
        }

        return $failed === [] ? self::SUCCESS : self::FAILURE;
    }

    /**
     * @return array<string, string>|null null when the invocation cannot proceed
     */
    private function sources(ConfigRepository $config): ?array
    {
        $configured = [];

        foreach ((array) $config->get('security-guard.crawler_access.ranges.sources', []) as $provider => $url) {
            if (is_string($url) && $url !== '') {
                $configured[(string) $provider] = $url;
            }
        }

        if ($configured === []) {
            // Loud on purpose: a cron job pointing at an empty source list
            // should page someone, not report success forever.
            $this->components->error('No crawler range sources are configured (security-guard.crawler_access.ranges.sources).');

            return null;
        }

        $only = array_values(array_filter(array_map('strval', (array) $this->option('provider'))));

        if ($only === []) {
            return $configured;
        }

        $unknown = array_diff($only, array_keys($configured));

        if ($unknown !== []) {
            $this->components->error('Unknown provider(s): '.implode(', ', $unknown).'.');
            $this->line('  Configured: '.implode(', ', array_keys($configured)));

            return null;
        }

        return array_intersect_key($configured, array_flip($only));
    }
}
