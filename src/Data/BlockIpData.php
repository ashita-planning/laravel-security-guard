<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Data;

final class BlockIpData
{
    public function __construct(
        public readonly string $ipAddress,
        public readonly string $reasonCode,
        public readonly ?string $matchedPattern = null,
        public readonly int $requestCount = 1,
    ) {}
}
