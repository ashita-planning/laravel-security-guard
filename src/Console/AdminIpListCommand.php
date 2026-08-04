<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Console;

use Apkk\LaravelSecurityGuard\Console\Concerns\ResolvesAdminSubject;
use Apkk\LaravelSecurityGuard\Contracts\AdminAllowedIpRepositoryContract;
use Apkk\LaravelSecurityGuard\Data\AdminAllowedIpRecord;
use Apkk\LaravelSecurityGuard\Services\ConfigAdminSubjectResolver;
use Illuminate\Console\Command;

class AdminIpListCommand extends Command
{
    use ResolvesAdminSubject;

    protected $signature = 'security-guard:admin-ip:list
        {subject : The administrative subject identifier}
        {--type= : Subject type, defaults to the configured admin_ip.subject_type}';

    protected $description = 'List the allowed IP addresses of an administrative subject';

    public function handle(
        AdminAllowedIpRepositoryContract $repository,
        ConfigAdminSubjectResolver $resolver,
    ): int {
        $records = $repository->listFor($this->adminSubject($resolver));

        if ($records === []) {
            $this->components->warn('No allowed IP addresses are registered for this subject.');

            return self::SUCCESS;
        }

        $this->table(
            ['IP', 'Label', 'Enabled'],
            array_map(static fn (AdminAllowedIpRecord $record): array => [
                $record->ipAddress,
                $record->label ?? '-',
                $record->enabled ? 'yes' : 'no',
            ], $records),
        );

        return self::SUCCESS;
    }
}
