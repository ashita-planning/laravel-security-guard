<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Console\Concerns;

use Apkk\LaravelSecurityGuard\Data\AdminSubjectData;
use Apkk\LaravelSecurityGuard\Services\ConfigAdminSubjectResolver;

trait ResolvesAdminSubject
{
    /**
     * Build the subject from the CLI arguments.
     *
     * `--type` wins, then the configured `admin_ip.subject_type`, so a host
     * that pins a type never has to repeat it on every command.
     */
    protected function adminSubject(ConfigAdminSubjectResolver $resolver): AdminSubjectData
    {
        $type = $this->option('type');

        return new AdminSubjectData(
            is_string($type) && $type !== '' ? $type : $resolver->subjectType(),
            (string) $this->argument('subject'),
        );
    }
}
