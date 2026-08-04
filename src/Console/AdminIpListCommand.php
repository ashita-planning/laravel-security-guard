<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Console;

use Apkk\LaravelSecurityGuard\Console\Concerns\ResolvesAdminSubject;
use Apkk\LaravelSecurityGuard\Contracts\AdminAllowedIpRepositoryContract;
use Apkk\LaravelSecurityGuard\Data\AdminAllowedIpRecord;
use Apkk\LaravelSecurityGuard\Services\ConfigAdminSubjectResolver;
use Apkk\LaravelSecurityGuard\Support\IpRange;
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
            ['Rule', 'Kind', 'Admits', 'Label', 'Enabled'],
            array_map(static function (AdminAllowedIpRecord $record): array {
                $range = IpRange::parse($record->ipAddress);

                return [
                    $record->ipAddress,
                    // Derived from the stored value; no schema column needed.
                    match (true) {
                        $range === null => '<fg=red>unparseable</>',
                        $range->isSingleHost() => 'exact',
                        default => 'CIDR',
                    },
                    $range === null ? 'nothing' : number_format($range->size()),
                    $record->label ?? '-',
                    $record->enabled ? 'yes' : 'no',
                ];
            }, $records),
        );

        // A row the matcher cannot parse admits nothing, which locks its owner
        // out rather than letting anyone in. Worth saying out loud.
        $unparseable = array_filter(
            $records,
            static fn (AdminAllowedIpRecord $record): bool => IpRange::parse($record->ipAddress) === null,
        );

        if ($unparseable !== []) {
            $this->components->warn(sprintf(
                '%d row(s) cannot be parsed and match nothing. Run `security-guard:doctor` for details.',
                count($unparseable),
            ));
        }

        return self::SUCCESS;
    }
}
