<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Repositories;

use Apkk\LaravelSecurityGuard\Contracts\BlockedIpRepositoryContract;
use Apkk\LaravelSecurityGuard\Data\ActorData;
use Apkk\LaravelSecurityGuard\Data\BlockedIpRecord;
use Apkk\LaravelSecurityGuard\Data\BlockIpData;
use Apkk\LaravelSecurityGuard\Models\BlockedIp;
use Apkk\LaravelSecurityGuard\Support\Ip;
use Illuminate\Database\QueryException;
use Illuminate\Support\Carbon;
use InvalidArgumentException;

class EloquentBlockedIpRepository implements BlockedIpRepositoryContract
{
    public function findActive(string $ipAddress): ?BlockedIpRecord
    {
        $normalized = Ip::normalize($ipAddress);

        if ($normalized === null) {
            return null;
        }

        $model = BlockedIp::query()
            ->where('ip_address', $normalized)
            ->whereNull('released_at')
            ->first();

        return $model ? $this->toRecord($model) : null;
    }

    public function find(string $ipAddress): ?BlockedIpRecord
    {
        $normalized = Ip::normalize($ipAddress);

        if ($normalized === null) {
            return null;
        }

        $model = BlockedIp::query()->where('ip_address', $normalized)->first();

        return $model ? $this->toRecord($model) : null;
    }

    public function findById(int|string $id): ?BlockedIpRecord
    {
        $model = BlockedIp::query()->find($id);

        return $model ? $this->toRecord($model) : null;
    }

    /**
     * One row per address, reused across release and re-block cycles.
     *
     * A concurrent insert loses the unique constraint race; we swallow only
     * integrity violations (SQLSTATE class 23) and update the winning row so
     * two simultaneous probes cannot produce duplicates.
     */
    public function block(BlockIpData $data): BlockedIpRecord
    {
        $ipAddress = Ip::normalize($data->ipAddress);

        if ($ipAddress === null) {
            throw new InvalidArgumentException('A blocked IP address must be a valid IPv4 or IPv6 address.');
        }

        $now = Carbon::now();
        $model = BlockedIp::query()->firstOrNew(['ip_address' => $ipAddress]);
        $wasActive = $model->exists && $model->released_at === null;

        if ($wasActive) {
            $model->forceFill([
                'request_count' => max((int) $model->request_count, $data->requestCount),
                'last_attempted_at' => $now,
            ])->save();

            return $this->toRecord($model);
        }

        try {
            $model->forceFill([
                'ip_address' => $ipAddress,
                'reason_code' => $data->reasonCode,
                'matched_pattern' => $data->matchedPattern,
                'request_count' => max(1, $data->requestCount),
                'blocked_at' => $now,
                'last_attempted_at' => $now,
                'notified_at' => null,
                'released_at' => null,
                'released_by_type' => null,
                'released_by_id' => null,
            ])->save();
        } catch (QueryException $exception) {
            $sqlState = (string) ($exception->errorInfo[0] ?? $exception->getCode());

            if (! str_starts_with($sqlState, '23')) {
                throw $exception;
            }

            $existing = BlockedIp::query()->where('ip_address', $ipAddress)->first();

            if (! $existing) {
                throw $exception;
            }

            $existing->forceFill([
                'request_count' => max((int) $existing->request_count, $data->requestCount),
                'last_attempted_at' => $now,
            ])->save();

            return $this->toRecord($existing);
        }

        return $this->toRecord($model);
    }

    public function release(string $ipAddress, ?ActorData $actor = null): bool
    {
        $normalized = Ip::normalize($ipAddress);

        if ($normalized === null) {
            return false;
        }

        $model = BlockedIp::query()
            ->where('ip_address', $normalized)
            ->whereNull('released_at')
            ->first();

        if (! $model) {
            return false;
        }

        $model->forceFill([
            'released_at' => Carbon::now(),
            'released_by_type' => $actor?->type,
            'released_by_id' => $actor?->id,
        ])->save();

        return true;
    }

    public function markNotified(int|string $id): void
    {
        BlockedIp::query()->whereKey($id)->update(['notified_at' => Carbon::now()]);
    }

    public function paginate(array $filters = [], int $perPage = 50, int $page = 1): array
    {
        $perPage = max(1, min(200, $perPage));
        $page = max(1, $page);

        $query = BlockedIp::query();

        if (($filters['active'] ?? false) === true) {
            $query->whereNull('released_at');
        }

        if (! empty($filters['ip_address'])) {
            // An unparseable filter must return nothing rather than everything.
            $query->where('ip_address', Ip::normalize((string) $filters['ip_address']) ?? '');
        }

        $total = (clone $query)->count();

        $models = $query
            ->orderByDesc('blocked_at')
            ->orderByDesc('id')
            ->forPage($page, $perPage)
            ->get();

        return [
            'items' => $models->map(fn (BlockedIp $model): BlockedIpRecord => $this->toRecord($model))->all(),
            'total' => $total,
            'page' => $page,
            'per_page' => $perPage,
        ];
    }

    protected function toRecord(BlockedIp $model): BlockedIpRecord
    {
        return BlockedIpRecord::fromArray([
            'id' => $model->getKey(),
            'ip_address' => $model->ip_address,
            'reason_code' => $model->reason_code,
            'matched_pattern' => $model->matched_pattern,
            'request_count' => $model->request_count,
            'blocked_at' => $model->blocked_at,
            'last_attempted_at' => $model->last_attempted_at,
            'notified_at' => $model->notified_at,
            'released_at' => $model->released_at,
            'released_by_type' => $model->released_by_type,
            'released_by_id' => $model->released_by_id,
        ]);
    }
}
