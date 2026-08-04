<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Events;

use Apkk\LaravelSecurityGuard\Data\ActorData;

final class IpReleased
{
    public function __construct(
        public readonly string $ipAddress,
        public readonly ?ActorData $actor = null,
    ) {}
}
