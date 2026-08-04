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

    /**
     * Read-only listing for the bundled management screen.
     *
     * @param  array{subject_type?: string|null, subject_id?: string|null, ip?: string|null, kind?: string|null, enabled?: bool|null}  $filters
     * @return array{items: array<int, AdminAllowedIpRecord>, total: int, page: int, per_page: int}
     */
    public function paginate(array $filters = [], int $perPage = 50, int $page = 1): array;

    /**
     * How many rows resolve to each canonical rule, for the given subjects.
     *
     * Needed to flag semantic duplicates across pages rather than only within
     * the one being displayed.
     *
     * @param  array<int, AdminSubjectData>  $subjects
     * @return array<string, int> keyed by "subjectType|subjectId|canonicalRule"
     */
    public function canonicalCounts(array $subjects): array;
}
