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

    /**
     * Added to Illuminate\Contracts\Cache\Store in Laravel 13. Declaring it
     * unconditionally is harmless on 10-12, where it is simply an extra
     * method, and required on 13, where a missing implementation is a fatal
     * error at class-definition time.
     */
    public function touch($key, $seconds): bool
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
