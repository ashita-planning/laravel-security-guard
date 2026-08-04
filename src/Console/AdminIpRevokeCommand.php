<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Console;

use Apkk\LaravelSecurityGuard\Console\Concerns\ResolvesAdminSubject;
use Apkk\LaravelSecurityGuard\Contracts\AdminAllowedIpRepositoryContract;
use Apkk\LaravelSecurityGuard\Services\AdminIpAccessService;
use Apkk\LaravelSecurityGuard\Services\ConfigAdminSubjectResolver;
use Apkk\LaravelSecurityGuard\Support\Ip;
use Illuminate\Console\Command;

class AdminIpRevokeCommand extends Command
{
    use ResolvesAdminSubject;

    protected $signature = 'security-guard:admin-ip:revoke
        {subject : The administrative subject identifier}
        {ip : The address to revoke}
        {--type= : Subject type, defaults to the configured admin_ip.subject_type}';

    protected $description = 'Revoke an allowed IP address from an administrative subject';

    public function handle(
        AdminAllowedIpRepositoryContract $repository,
        ConfigAdminSubjectResolver $resolver,
        AdminIpAccessService $accessService,
    ): int {
        $normalized = Ip::normalize((string) $this->argument('ip'));

        if ($normalized === null) {
            $this->components->error('Invalid IP address.');

            return self::FAILURE;
        }

        $subject = $this->adminSubject($resolver);

        if (! $repository->revoke($subject, $normalized)) {
            $this->components->warn('No matching entry was found.');

            return self::SUCCESS;
        }

        $this->components->info('Revoked '.$normalized.'.');

        // Removing the last entry silently changes what the allowlist means.
        if ($accessService->enabled()
            && $repository->countEnabled($subject) === 0
            && $accessService->emptyPolicy() === AdminIpAccessService::EMPTY_POLICY_DENY) {
            $this->components->warn(
                'This subject now has no allowed addresses and empty_policy is "deny", so it can no longer sign in.',
            );
        }

        return self::SUCCESS;
    }
}
