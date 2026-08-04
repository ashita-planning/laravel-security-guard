<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\Schema\Builder;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        $this->schema()->create($this->table(), function (Blueprint $table): void {
            $table->id();
            $table->string('subject_type', 100);
            // String width covers integer, UUID and ULID host primary keys.
            $table->string('subject_id', 191);
            $table->string('ip_address', 45);
            $table->string('label', 255)->nullable();
            $table->boolean('enabled')->default(true);
            $table->timestamps();

            $table->unique(
                ['subject_type', 'subject_id', 'ip_address'],
                'security_guard_admin_ip_unique',
            );
        });
    }

    public function down(): void
    {
        $this->schema()->dropIfExists($this->table());
    }

    private function table(): string
    {
        return (string) config('security-guard.database.tables.admin_allowed_ips', 'security_guard_admin_allowed_ips');
    }

    private function schema(): Builder
    {
        return Schema::connection(config('security-guard.database.connection'));
    }
};
