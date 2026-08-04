<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Services;

use Apkk\LaravelSecurityGuard\Data\BlockReason;
use Apkk\LaravelSecurityGuard\Support\CacheKeyFactory;
use Illuminate\Cache\RateLimiter;
use Illuminate\Contracts\Config\Repository as ConfigRepository;

/**
 * Per-IP request counting for the public surface.
 *
 * Everything here may throw; the middleware treats a limiter outage as
 * fail-open so a broken cache cannot amplify into site-wide rejections.
 */
class PublicRateLimiter
{
    public const ACTION_PERMANENT_BLOCK = 'permanent_block';

    public const ACTION_TEMPORARY_BLOCK = 'temporary_block';

    public const ACTION_REJECT_ONLY = 'reject_only';

    public function __construct(
        private readonly IpBlockService $blockService,
        private readonly RateLimiter $rateLimiter,
        private readonly CacheKeyFactory $cacheKeys,
        private readonly ConfigRepository $config,
    ) {}

    /**
     * @return array{allowed: bool, attempts: int, action: string|null, blocked_now: bool, retry_after: int}
     */
    public function consume(string $normalizedIp): array
    {
        $key = $this->cacheKeys->publicRequests($normalizedIp);
        $attempts = $this->rateLimiter->hit($key, 60);
        $limit = $this->limit();

        if ($attempts <= $limit) {
            return [
                'allowed' => true,
                'attempts' => $attempts,
                'action' => null,
                'blocked_now' => false,
                'retry_after' => 0,
            ];
        }

        $action = $this->action();
        $blockedNow = false;

        if ($action === self::ACTION_PERMANENT_BLOCK) {
            // Only the call that actually transitioned the address reports
            // `blocked_now`, so a sustained flood logs once, not per request.
            $blockedNow = $this->blockService->block(
                $normalizedIp,
                BlockReason::RATE_LIMIT,
                requestCount: $attempts,
            )?->isNewBlock ?? false;
        } elseif ($action === self::ACTION_TEMPORARY_BLOCK) {
            $blockedNow = $this->blockService->blockTemporarily($normalizedIp, $this->temporaryMinutes());
        }

        return [
            'allowed' => false,
            'attempts' => $attempts,
            'action' => $action,
            'blocked_now' => $blockedNow,
            'retry_after' => $this->rateLimiter->availableIn($key),
        ];
    }

    /**
     * @return array{attempts: int, blocked: bool}
     */
    public function status(string $normalizedIp): array
    {
        return [
            'attempts' => $this->rateLimiter->attempts($this->cacheKeys->publicRequests($normalizedIp)),
            'blocked' => $this->blockService->isBlocked($normalizedIp),
        ];
    }

    public function limit(): int
    {
        return max(1, (int) $this->config->get('security-guard.public_rate_limit.requests_per_minute', 120));
    }

    public function action(): string
    {
        $action = (string) $this->config->get('security-guard.public_rate_limit.action', self::ACTION_PERMANENT_BLOCK);

        return in_array($action, [
            self::ACTION_PERMANENT_BLOCK,
            self::ACTION_TEMPORARY_BLOCK,
            self::ACTION_REJECT_ONLY,
        ], true) ? $action : self::ACTION_PERMANENT_BLOCK;
    }

    private function temporaryMinutes(): int
    {
        return max(1, (int) $this->config->get('security-guard.public_rate_limit.temporary_block_minutes', 60));
    }
}
