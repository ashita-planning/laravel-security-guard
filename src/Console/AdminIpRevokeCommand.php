<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Console;

use Apkk\LaravelSecurityGuard\Console\Concerns\ResolvesAdminSubject;
use Apkk\LaravelSecurityGuard\Contracts\AdminAllowedIpRepositoryContract;
use Apkk\LaravelSecurityGuard\Services\AdminIpAccessService;
use Apkk\LaravelSecurityGuard\Services\ConfigAdminSubjectResolver;
use Apkk\LaravelSecurityGuard\Support\IpRange;
use Illuminate\Console\Command;

class AdminIpRevokeCommand extends Command
{
    use ResolvesAdminSubject;

    protected $signature = 'security-guard:admin-ip:revoke
        {subject : The administrative subject identifier}
        {ip : The address or CIDR network to revoke}
        {--type= : Subject type, defaults to the configured admin_ip.subject_type}';

    protected $description = 'Revoke an allowed IP address or CIDR network from an administrative subject';

    public function handle(
        AdminAllowedIpRepositoryContract $repository,
        ConfigAdminSubjectResolver $resolver,
        AdminIpAccessService $accessService,
    ): int {
        $input = (string) $this->argument('ip');

        // Canonicalised exactly as `allow` does. Without this an entry
        // registered as 203.0.113.42/24 is stored as 203.0.113.0/24 and could
        // never be removed with the string the operator originally typed.
        $range = IpRange::parse($input);

        if ($range === null) {
            $this->components->error('Invalid IP address or CIDR network.');

            return self::FAILURE;
        }

        $canonical = $range->toString();
        $subject = $this->adminSubject($resolver);

        if (! $repository->revoke($subject, $canonical)) {
            $this->components->warn("No matching entry was found for {$canonical}.");

            return self::SUCCESS;
        }

        $this->components->info("Revoked {$canonical}.");

        if ($canonical !== trim($input)) {
            $this->line("  (matched by canonical form of {$input})");
        }

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
