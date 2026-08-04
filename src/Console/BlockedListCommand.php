<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Console;

use Apkk\LaravelSecurityGuard\Data\BlockedIpRecord;
use Apkk\LaravelSecurityGuard\Services\IpBlockService;
use Apkk\LaravelSecurityGuard\Support\Ip;
use Illuminate\Console\Command;

class BlockedListCommand extends Command
{
    protected $signature = 'security-guard:blocked:list
        {--active : Only list addresses that are still blocked}
        {--ip= : Filter by a single address}
        {--page=1 : Page number}
        {--per-page=50 : Rows per page}';

    protected $description = 'List blocked IP addresses';

    public function handle(IpBlockService $blockService): int
    {
        $filters = [];

        if ((bool) $this->option('active')) {
            $filters['active'] = true;
        }

        $ip = $this->option('ip');

        if (is_string($ip) && $ip !== '') {
            $normalized = Ip::normalize($ip);

            if ($normalized === null) {
                $this->components->error('Invalid IP address.');

                return self::FAILURE;
            }

            $filters['ip_address'] = $normalized;
        }

        $result = $blockService->paginate(
            $filters,
            (int) $this->option('per-page'),
            (int) $this->option('page'),
        );

        if ($result['items'] === []) {
            $this->components->info('No blocked IP addresses found.');

            return self::SUCCESS;
        }

        $this->table(
            ['IP', 'State', 'Reason', 'Pattern', 'Count', 'Blocked at', 'Last attempt', 'Released at'],
            array_map(static fn (BlockedIpRecord $record): array => [
                $record->ipAddress,
                $record->isActive() ? 'blocked' : 'released',
                $record->reasonCode,
                $record->matchedPattern ?? '-',
                $record->requestCount,
                $record->blockedAt?->format('Y-m-d H:i:s') ?? '-',
                $record->lastAttemptedAt?->format('Y-m-d H:i:s') ?? '-',
                $record->releasedAt?->format('Y-m-d H:i:s') ?? '-',
            ], $result['items']),
        );

        $this->line(sprintf(
            'Page %d of %d (%d total)',
            $result['page'],
            (int) max(1, ceil($result['total'] / $result['per_page'])),
            $result['total'],
        ));

        return self::SUCCESS;
    }
}
