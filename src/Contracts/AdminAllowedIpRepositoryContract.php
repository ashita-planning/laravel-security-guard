<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Contracts;

use Apkk\LaravelSecurityGuard\Data\AdminAllowedIpRecord;
use Apkk\LaravelSecurityGuard\Data\AdminSubjectData;

interface AdminAllowedIpRepositoryContract
{
    public function isAllowed(AdminSubjectData $subject, string $ipAddress): bool;

    public function countEnabled(AdminSubjectData $subject): int;

    public function allow(AdminSubjectData $subject, string $ipAddress, ?string $label = null): AdminAllowedIpRecord;

    public function revoke(AdminSubjectData $subject, string $ipAddress): bool;

    /**
     * @return array<int, AdminAllowedIpRecord>
     */
    public function listFor(AdminSubjectData $subject): array;
}
