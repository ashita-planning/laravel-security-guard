<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Console;

use Apkk\LaravelSecurityGuard\Console\Concerns\ResolvesAdminSubject;
use Apkk\LaravelSecurityGuard\Contracts\AdminAllowedIpRepositoryContract;
use Apkk\LaravelSecurityGuard\Services\ConfigAdminSubjectResolver;
use Apkk\LaravelSecurityGuard\Support\IpRange;
use Illuminate\Console\Command;

class AdminIpAllowCommand extends Command
{
    use ResolvesAdminSubject;

    protected $signature = 'security-guard:admin-ip:allow
        {subject : The administrative subject identifier}
        {ip : An address or CIDR network to allow}
        {--type= : Subject type, defaults to the configured admin_ip.subject_type}
        {--label= : Free-form label for the entry}
        {--force : Register a rule that admits every address in its family}';

    protected $description = 'Allow an IP address or CIDR network for an administrative subject';

    public function handle(
        AdminAllowedIpRepositoryContract $repository,
        ConfigAdminSubjectResolver $resolver,
    ): int {
        $input = (string) $this->argument('ip');
        $range = IpRange::parse($input);

        if ($range === null) {
            $this->components->error('Invalid IP address or CIDR network.');
            $this->line('  Accepted: 203.0.113.10, 203.0.113.0/24, 2001:db8::1, 2001:db8::/48');

            return self::FAILURE;
        }

        // A /0 allowlist entry is not an allowlist. Refusing by default turns a
        // typo that silently disables the module into an explicit decision.
        if ($range->prefixLength() === 0 && ! (bool) $this->option('force')) {
            $this->components->error('This rule would admit every address in its family.');
            $this->line("  {$range->toString()} makes the allowlist meaningless for this subject.");
            $this->line('  Re-run with --force if that is genuinely intended.');

            return self::FAILURE;
        }

        $canonical = $range->toString();

        if (! $range->wasCanonical()) {
            // Registering 203.0.113.42/24 grants the whole /24, which is not
            // what someone typing a specific host address usually expects.
            $this->components->warn("Host bits were dropped: {$input} was stored as {$canonical}.");
        }

        $label = $this->option('label');

        $repository->allow(
            $this->adminSubject($resolver),
            $canonical,
            is_string($label) && $label !== '' ? $label : null,
        );

        $this->components->info(sprintf(
            'Allowed %s (%s).',
            $canonical,
            $range->isSingleHost() ? 'exact address' : 'network of '.$this->describeSize($range),
        ));

        return self::SUCCESS;
    }

    private function describeSize(IpRange $range): string
    {
        $size = $range->size();

        return $size >= 1.0e9
            ? sprintf('%.3g addresses', $size)
            : number_format($size).' addresses';
    }
}
