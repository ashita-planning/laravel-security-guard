<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Repositories;

use Apkk\LaravelSecurityGuard\Contracts\BlockedIpRepositoryContract;
use Apkk\LaravelSecurityGuard\Data\ActorData;
use Apkk\LaravelSecurityGuard\Data\BlockedIpRecord;
use Apkk\LaravelSecurityGuard\Data\BlockIpData;
use Apkk\LaravelSecurityGuard\Data\BlockOperationResult;
use Apkk\LaravelSecurityGuard\Models\BlockedIp;
use Apkk\LaravelSecurityGuard\Support\Ip;
use Illuminate\Database\QueryException;
use Illuminate\Support\Carbon;
use InvalidArgumentException;
use RuntimeException;

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
     * Ownership of the "this call blocked the address" decision belongs to the
     * database, not to a read performed beforehand:
     *
     *  1. A successful INSERT means the row did not exist, so this call is
     *     unambiguously the new block. A concurrent insert loses the unique
     *     constraint race and continues at step 2.
     *  2. A conditional UPDATE guarded by `released_at IS NOT NULL` re-activates
     *     a released row. The database applies it for at most one caller, so the
     *     affected-row count answers "was this new" without a race.
     *  3. Otherwise the row was already active and only the counters move.
     */
    public function block(BlockIpData $data): BlockOperationResult
    {
        $ipAddress = Ip::normalize($data->ipAddress);

        if ($ipAddress === null) {
            throw new InvalidArgumentException('A blocked IP address must be a valid IPv4 or IPv6 address.');
        }

        $now = Carbon::now();
        $requestCount = max(1, $data->requestCount);

        try {
            $model = new BlockedIp;
            $model->forceFill([
                'ip_address' => $ipAddress,
                'reason_code' => $data->reasonCode,
                'matched_pattern' => $data->matchedPattern,
                'request_count' => $requestCount,
                'blocked_at' => $now,
                'last_attempted_at' => $now,
                'notified_at' => null,
                'released_at' => null,
                'released_by_type' => null,
                'released_by_id' => null,
            ])->save();

            return new BlockOperationResult($this->toRecord($model), true);
        } catch (QueryException $exception) {
            if (! $this->isIntegrityViolation($exception)) {
                throw $exception;
            }
        }

        $reactivated = BlockedIp::query()
            ->where('ip_address', $ipAddress)
            ->whereNotNull('released_at')
            ->update([
                'reason_code' => $data->reasonCode,
                'matched_pattern' => $data->matchedPattern,
                'request_count' => $requestCount,
                'blocked_at' => $now,
                'last_attempted_at' => $now,
                'notified_at' => null,
                'released_at' => null,
                'released_by_type' => null,
                'released_by_id' => null,
                'updated_at' => $now,
            ]);

        if ($reactivated === 0) {
            $this->bumpActiveRow($ipAddress, $requestCount, $now);
        }

        $record = $this->find($ipAddress);

        if ($record === null) {
            // The row vanished between the failed insert and this read, so the
            // caller is told the write did not stick rather than handed a lie.
            throw new RuntimeException('The blocked IP row disappeared while blocking.');
        }

        return new BlockOperationResult($record, $reactivated > 0);
    }

    /**
     * Move an already-active row's counters forward.
     *
     * `request_count` is kept monotonic with a guarded update rather than
     * GREATEST()/MAX(), which are spelled differently on MySQL and SQLite.
     */
    private function bumpActiveRow(string $ipAddress, int $requestCount, Carbon $now): void
    {
        BlockedIp::query()
            ->where('ip_address', $ipAddress)
            ->where('request_count', '<', $requestCount)
            ->update(['request_count' => $requestCount, 'updated_at' => $now]);

        BlockedIp::query()
            ->where('ip_address', $ipAddress)
            ->update(['last_attempted_at' => $now, 'updated_at' => $now]);
    }

    private function isIntegrityViolation(QueryException $exception): bool
    {
        return str_starts_with((string) ($exception->errorInfo[0] ?? $exception->getCode()), '23');
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
