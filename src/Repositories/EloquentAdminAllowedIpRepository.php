<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Repositories;

use Apkk\LaravelSecurityGuard\Contracts\AdminAllowedIpRepositoryContract;
use Apkk\LaravelSecurityGuard\Data\AdminAllowedIpRecord;
use Apkk\LaravelSecurityGuard\Data\AdminSubjectData;
use Apkk\LaravelSecurityGuard\Models\AdminAllowedIp;
use Apkk\LaravelSecurityGuard\Support\Ip;
use InvalidArgumentException;

class EloquentAdminAllowedIpRepository implements AdminAllowedIpRepositoryContract
{
    public function isAllowed(AdminSubjectData $subject, string $ipAddress): bool
    {
        $normalized = Ip::normalize($ipAddress);

        if ($normalized === null) {
            return false;
        }

        return AdminAllowedIp::query()
            ->where('subject_type', $subject->type)
            ->where('subject_id', $subject->id)
            ->where('ip_address', $normalized)
            ->where('enabled', true)
            ->exists();
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
        // Store the canonical form so `2001:db8::1` and its expanded notation
        // are one entry rather than two that only sometimes match.
        $normalized = Ip::normalize($ipAddress);

        if ($normalized === null) {
            throw new InvalidArgumentException('An allowed IP address must be a valid IPv4 or IPv6 address.');
        }

        $model = AdminAllowedIp::query()->firstOrNew([
            'subject_type' => $subject->type,
            'subject_id' => $subject->id,
            'ip_address' => $normalized,
        ]);

        $model->forceFill([
            'subject_type' => $subject->type,
            'subject_id' => $subject->id,
            'ip_address' => $normalized,
            'label' => $label ?? $model->label,
            'enabled' => true,
        ])->save();

        return $this->toRecord($model);
    }

    public function revoke(AdminSubjectData $subject, string $ipAddress): bool
    {
        $normalized = Ip::normalize($ipAddress);

        if ($normalized === null) {
            return false;
        }

        return AdminAllowedIp::query()
            ->where('subject_type', $subject->type)
            ->where('subject_id', $subject->id)
            ->where('ip_address', $normalized)
            ->delete() > 0;
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
