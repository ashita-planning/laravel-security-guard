<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Tests\Fixtures;

use Illuminate\Contracts\Cache\Store;
use RuntimeException;

/**
 * A cache store where every operation fails, standing in for an unreachable
 * Redis or Memcached node.
 */
class BrokenCacheStore implements Store
{
    public function get($key): mixed
    {
        throw new RuntimeException('Cache unavailable.');
    }

    public function many(array $keys): array
    {
        throw new RuntimeException('Cache unavailable.');
    }

    public function put($key, $value, $seconds): bool
    {
        throw new RuntimeException('Cache unavailable.');
    }

    public function putMany(array $values, $seconds): bool
    {
        throw new RuntimeException('Cache unavailable.');
    }

    public function increment($key, $value = 1): bool
    {
        throw new RuntimeException('Cache unavailable.');
    }

    public function decrement($key, $value = 1): bool
    {
        throw new RuntimeException('Cache unavailable.');
    }

    public function forever($key, $value): bool
    {
        throw new RuntimeException('Cache unavailable.');
    }

    public function forget($key): bool
    {
        throw new RuntimeException('Cache unavailable.');
    }

    public function flush(): bool
    {
        throw new RuntimeException('Cache unavailable.');
    }

    public function getPrefix(): string
    {
        return '';
    }
}
