<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Contracts;

use Apkk\LaravelSecurityGuard\Data\ActorData;
use Apkk\LaravelSecurityGuard\Data\BlockedIpRecord;
use Apkk\LaravelSecurityGuard\Data\BlockIpData;
use Apkk\LaravelSecurityGuard\Data\BlockOperationResult;

interface BlockedIpRepositoryContract
{
    public function findActive(string $ipAddress): ?BlockedIpRecord;

    public function find(string $ipAddress): ?BlockedIpRecord;

    public function findById(int|string $id): ?BlockedIpRecord;

    /**
     * Create or re-activate the block row for an address.
     *
     * Concurrent calls for the same address must resolve to a single row, and
     * exactly one of them may report `isNewBlock`. Implementations must decide
     * that flag atomically rather than by reading the row first.
     */
    public function block(BlockIpData $data): BlockOperationResult;

    public function release(string $ipAddress, ?ActorData $actor = null): bool;

    public function markNotified(int|string $id): void;

    /**
     * @param  array{active?: bool, ip_address?: string|null}  $filters
     * @return array{items: array<int, BlockedIpRecord>, total: int, page: int, per_page: int}
     */
    public function paginate(array $filters = [], int $perPage = 50, int $page = 1): array;
}
