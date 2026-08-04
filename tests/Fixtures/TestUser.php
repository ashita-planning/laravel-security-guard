<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Tests\Fixtures;

use Illuminate\Foundation\Auth\User as Authenticatable;

/**
 * Stands in for whatever the host calls its administrator model. The package
 * must never need to know this class exists.
 */
class TestUser extends Authenticatable
{
    protected $table = 'users';

    protected $guarded = [];
}
