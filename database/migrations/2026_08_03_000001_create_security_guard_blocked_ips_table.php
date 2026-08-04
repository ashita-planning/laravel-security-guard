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
            $table->string('ip_address', 45)->unique();
            $table->string('reason_code', 50)->index();
            // Category name only. Raw paths and URLs are never stored here.
            $table->string('matched_pattern', 100)->nullable();
            $table->unsignedInteger('request_count')->default(1);
            $table->dateTime('blocked_at')->index();
            $table->dateTime('last_attempted_at')->nullable();
            $table->dateTime('notified_at')->nullable();
            $table->dateTime('released_at')->nullable()->index();
            // Deliberately no foreign key: the host user table is unknown.
            $table->string('released_by_type', 100)->nullable();
            $table->string('released_by_id', 191)->nullable();
            $table->timestamps();
        });
    }

    public function down(): void
    {
        $this->schema()->dropIfExists($this->table());
    }

    private function table(): string
    {
        return (string) config('security-guard.database.tables.blocked_ips', 'security_guard_blocked_ips');
    }

    private function schema(): Builder
    {
        return Schema::connection(config('security-guard.database.connection'));
    }
};
