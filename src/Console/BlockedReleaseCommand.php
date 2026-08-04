<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Console;

use Apkk\LaravelSecurityGuard\Data\ActorData;
use Apkk\LaravelSecurityGuard\Services\IpBlockService;
use Apkk\LaravelSecurityGuard\Support\Ip;
use Illuminate\Console\Command;

class BlockedReleaseCommand extends Command
{
    protected $signature = 'security-guard:blocked:release
        {ip : The address to release}
        {--actor= : Identifier recorded as the operator}';

    protected $description = 'Release a blocked IP address';

    public function handle(IpBlockService $blockService): int
    {
        $ip = (string) $this->argument('ip');
        $normalized = Ip::normalize($ip);

        if ($normalized === null) {
            $this->components->error('Invalid IP address.');

            return self::FAILURE;
        }

        $actor = $this->option('actor');
        $released = $blockService->release(
            $normalized,
            ActorData::console(is_string($actor) && $actor !== '' ? $actor : null),
        );

        if (! $released) {
            $this->components->warn('No active block found. Cached state and counters were cleared anyway.');

            return self::SUCCESS;
        }

        $this->components->info('Released '.$normalized.'.');

        return self::SUCCESS;
    }
}
