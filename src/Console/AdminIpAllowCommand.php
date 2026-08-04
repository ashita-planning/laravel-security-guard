<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Console;

use Apkk\LaravelSecurityGuard\Console\Concerns\ResolvesAdminSubject;
use Apkk\LaravelSecurityGuard\Contracts\AdminAllowedIpRepositoryContract;
use Apkk\LaravelSecurityGuard\Services\ConfigAdminSubjectResolver;
use Apkk\LaravelSecurityGuard\Support\Ip;
use Illuminate\Console\Command;

class AdminIpAllowCommand extends Command
{
    use ResolvesAdminSubject;

    protected $signature = 'security-guard:admin-ip:allow
        {subject : The administrative subject identifier}
        {ip : The address to allow}
        {--type= : Subject type, defaults to the configured admin_ip.subject_type}
        {--label= : Free-form label for the entry}';

    protected $description = 'Allow an IP address for an administrative subject';

    public function handle(
        AdminAllowedIpRepositoryContract $repository,
        ConfigAdminSubjectResolver $resolver,
    ): int {
        $normalized = Ip::normalize((string) $this->argument('ip'));

        if ($normalized === null) {
            $this->components->error('Invalid IP address.');

            return self::FAILURE;
        }

        $label = $this->option('label');

        $repository->allow(
            $this->adminSubject($resolver),
            $normalized,
            is_string($label) && $label !== '' ? $label : null,
        );

        $this->components->info('Allowed '.$normalized.'.');

        return self::SUCCESS;
    }
}
