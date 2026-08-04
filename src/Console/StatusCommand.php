<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Console;

use Apkk\LaravelSecurityGuard\Services\IpBlockService;
use Apkk\LaravelSecurityGuard\Services\PublicRateLimiter;
use Apkk\LaravelSecurityGuard\Support\Ip;
use Illuminate\Console\Command;

class StatusCommand extends Command
{
    protected $signature = 'security-guard:status {ip : The address to inspect}';

    protected $description = 'Show the guard status of an IP address';

    public function handle(IpBlockService $blockService, PublicRateLimiter $rateLimiter): int
    {
        $normalized = Ip::normalize((string) $this->argument('ip'));

        if ($normalized === null) {
            $this->components->error('Invalid IP address.');

            return self::FAILURE;
        }

        $record = $blockService->find($normalized);
        $status = $rateLimiter->status($normalized);

        $this->table(['Field', 'Value'], [
            ['ip_address', $normalized],
            ['ignored', $blockService->isIgnored($normalized) ? 'yes' : 'no'],
            ['blocked', $status['blocked'] ? 'yes' : 'no'],
            ['reason', $record?->reasonCode ?? '-'],
            ['matched_pattern', $record?->matchedPattern ?? '-'],
            ['request_count', (string) ($record?->requestCount ?? 0)],
            ['blocked_at', $record?->blockedAt?->format('Y-m-d H:i:s') ?? '-'],
            ['last_attempted_at', $record?->lastAttemptedAt?->format('Y-m-d H:i:s') ?? '-'],
            ['released_at', $record?->releasedAt?->format('Y-m-d H:i:s') ?? '-'],
            ['current_minute_attempts', (string) $status['attempts']],
            ['rate_limit_per_minute', (string) $rateLimiter->limit()],
        ]);

        return self::SUCCESS;
    }
}
