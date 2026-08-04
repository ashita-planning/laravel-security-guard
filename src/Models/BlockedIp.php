<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Models;

use Apkk\LaravelSecurityGuard\Data\BlockReason;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;

/**
 * @property int $id
 * @property string $ip_address
 * @property string $reason_code
 * @property string|null $matched_pattern
 * @property int $request_count
 */
class BlockedIp extends Model
{
    protected $guarded = [];

    protected $casts = [
        'request_count' => 'integer',
        'blocked_at' => 'datetime',
        'last_attempted_at' => 'datetime',
        'notified_at' => 'datetime',
        'released_at' => 'datetime',
    ];

    public function getTable(): string
    {
        return (string) config('security-guard.database.tables.blocked_ips', 'security_guard_blocked_ips');
    }

    public function getConnectionName(): ?string
    {
        return config('security-guard.database.connection') ?: parent::getConnectionName();
    }

    public function scopeActive(Builder $query): Builder
    {
        return $query->whereNull('released_at');
    }

    public function isActive(): bool
    {
        return $this->released_at === null;
    }

    public function reasonLabel(): string
    {
        return BlockReason::label($this->reason_code);
    }
}
