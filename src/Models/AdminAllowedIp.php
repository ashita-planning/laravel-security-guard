<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Models;

use Illuminate\Database\Eloquent\Model;

/**
 * @property int $id
 * @property string $subject_type
 * @property string $subject_id
 * @property string $ip_address
 * @property string|null $label
 * @property bool $enabled
 */
class AdminAllowedIp extends Model
{
    protected $guarded = [];

    protected $casts = [
        'enabled' => 'boolean',
    ];

    public function getTable(): string
    {
        return (string) config('security-guard.database.tables.admin_allowed_ips', 'security_guard_admin_allowed_ips');
    }

    public function getConnectionName(): ?string
    {
        return config('security-guard.database.connection') ?: parent::getConnectionName();
    }
}
