<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Repositories;

use Apkk\LaravelSecurityGuard\Contracts\AdminAllowedIpRepositoryContract;
use Apkk\LaravelSecurityGuard\Contracts\IpMatcherContract;
use Apkk\LaravelSecurityGuard\Data\AdminAllowedIpRecord;
use Apkk\LaravelSecurityGuard\Data\AdminSubjectData;
use Apkk\LaravelSecurityGuard\Models\AdminAllowedIp;
use Apkk\LaravelSecurityGuard\Support\Ip;
use Apkk\LaravelSecurityGuard\Support\IpRange;
use InvalidArgumentException;

class EloquentAdminAllowedIpRepository implements AdminAllowedIpRepositoryContract
{
    public function __construct(private readonly IpMatcherContract $ipMatcher) {}

    /**
     * Fetch this subject's enabled rules once, then decide in PHP.
     *
     * A CIDR rule cannot be answered by `where ip_address = ?`, so the
     * comparison moves out of SQL. It stays one query per subject: the row
     * count per administrator is small, and pushing network containment into
     * the database would mean the binary columns this release deliberately
     * avoids adding.
     *
     * An unparseable row is skipped by the matcher rather than treated as a
     * wildcard, so a corrupt entry locks its owner out instead of letting
     * everyone in.
     */
    public function isAllowed(AdminSubjectData $subject, string $ipAddress): bool
    {
        $normalized = Ip::normalize($ipAddress);

        if ($normalized === null) {
            return false;
        }

        $entries = AdminAllowedIp::query()
            ->where('subject_type', $subject->type)
            ->where('subject_id', $subject->id)
            ->where('enabled', true)
            ->pluck('ip_address')
            ->all();

        return $this->ipMatcher->matches($normalized, array_map('strval', $entries));
    }

    public function countEnabled(AdminSubjectData $subject): int
    {
        return AdminAllowedIp::query()
            ->where('subject_type', $subject->type)
            ->where('subject_id', $subject->id)
            ->where('enabled', true)
            ->count();
    }

    public function allow(AdminSubjectData $subject, string $ipAddress, ?string $label = null): AdminAllowedIpRecord
    {
        // Store the canonical form so `2001:db8::1`, its expanded notation and
        // `2001:db8::1/128` are one entry rather than three that only
        // sometimes match.
        $canonical = self::canonicalize($ipAddress);

        if ($canonical === null) {
            throw new InvalidArgumentException(
                'An allowed IP entry must be a valid IPv4/IPv6 address or CIDR network.',
            );
        }

        $model = AdminAllowedIp::query()->firstOrNew([
            'subject_type' => $subject->type,
            'subject_id' => $subject->id,
            'ip_address' => $canonical,
        ]);

        $model->forceFill([
            'subject_type' => $subject->type,
            'subject_id' => $subject->id,
            'ip_address' => $canonical,
            'label' => $label ?? $model->label,
            'enabled' => true,
        ])->save();

        return $this->toRecord($model);
    }

    /**
     * Canonicalised the same way as `allow()`.
     *
     * Without this, an entry registered as `203.0.113.42/24` is stored as
     * `203.0.113.0/24` and could never be removed using the string the
     * operator originally typed.
     */
    public function revoke(AdminSubjectData $subject, string $ipAddress): bool
    {
        $canonical = self::canonicalize($ipAddress);

        if ($canonical === null) {
            return false;
        }

        return AdminAllowedIp::query()
            ->where('subject_type', $subject->type)
            ->where('subject_id', $subject->id)
            ->where('ip_address', $canonical)
            ->delete() > 0;
    }

    /**
     * The single storage form for an allowlist entry, shared by every writer.
     */
    public static function canonicalize(string $entry): ?string
    {
        return IpRange::parse($entry)?->toString();
    }

    public function listFor(AdminSubjectData $subject): array
    {
        return AdminAllowedIp::query()
            ->where('subject_type', $subject->type)
            ->where('subject_id', $subject->id)
            ->orderBy('ip_address')
            ->get()
            ->map(fn (AdminAllowedIp $model): AdminAllowedIpRecord => $this->toRecord($model))
            ->all();
    }

    protected function toRecord(AdminAllowedIp $model): AdminAllowedIpRecord
    {
        return AdminAllowedIpRecord::fromArray([
            'id' => $model->getKey(),
            'subject_type' => $model->subject_type,
            'subject_id' => $model->subject_id,
            'ip_address' => $model->ip_address,
            'label' => $model->label,
            'enabled' => $model->enabled,
        ]);
    }
}
