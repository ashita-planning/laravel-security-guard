<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Http\Middleware;

use Apkk\LaravelSecurityGuard\Contracts\AttackPathMatcherContract;
use Apkk\LaravelSecurityGuard\Contracts\ClientIpResolverContract;
use Apkk\LaravelSecurityGuard\Data\BlockReason;
use Apkk\LaravelSecurityGuard\Services\BlockResponseFactory;
use Apkk\LaravelSecurityGuard\Services\IpBlockService;
use Apkk\LaravelSecurityGuard\Services\PublicRateLimiter;
use Apkk\LaravelSecurityGuard\Support\FailureLogger;
use Closure;
use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;
use Throwable;

/**
 * The public request gate.
 *
 * Evaluation order is fixed: excluded path, IP resolution, ignore list,
 * existing block, known attack path, rate limit. Each step is individually
 * fail-open except the attack path branch, which answers 403 even when the
 * block cannot be recorded.
 */
class GuardPublicRequests
{
    public function __construct(
        private readonly ClientIpResolverContract $ipResolver,
        private readonly AttackPathMatcherContract $attackPathMatcher,
        private readonly IpBlockService $blockService,
        private readonly PublicRateLimiter $rateLimiter,
        private readonly BlockResponseFactory $responses,
        private readonly ConfigRepository $config,
        private readonly FailureLogger $failureLogger,
    ) {}

    /**
     * @param  Closure(Request): Response  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        if (! $this->config->get('security-guard.enabled', true)) {
            return $next($request);
        }

        $ipAddress = $this->ipResolver->resolve($request);

        // No trustworthy address means no safe decision: let it through.
        if ($ipAddress === null) {
            return $next($request);
        }

        if ($this->blockService->isIgnored($ipAddress)) {
            return $next($request);
        }

        // Each module honours its own exclusion list. Excusing a webhook from
        // request counting must not also stop serving 403s to an address that
        // is already blocked, nor stop detecting attack paths underneath it.
        if ($this->config->get('security-guard.permanent_block.enabled', true)
            && ! $this->matchesAny($request, 'security-guard.permanent_block.excluded_paths')) {
            if ($this->blockService->isBlocked($ipAddress)) {
                return $this->responses->blocked();
            }

            $response = $this->handleAttackPath($request, $ipAddress);

            if ($response !== null) {
                return $response;
            }
        }

        if (! $this->config->get('security-guard.public_rate_limit.enabled', false)
            || $this->matchesAny($request, 'security-guard.public_rate_limit.excluded_paths')) {
            return $next($request);
        }

        return $this->handleRateLimit($request, $ipAddress, $next);
    }

    private function handleAttackPath(Request $request, string $ipAddress): ?Response
    {
        $match = $this->attackPathMatcher->match($request->path());

        if ($match === null) {
            return null;
        }

        try {
            $this->blockService->block(
                $ipAddress,
                BlockReason::KNOWN_ATTACK_PATH,
                $match->category,
            );
        } catch (Throwable $exception) {
            // The request is an unambiguous probe. Losing the audit row is a
            // reason to log, not a reason to serve the page.
            $this->failureLogger->always('Known attack path block could not be stored.', $exception, [
                'category' => $match->category,
            ]);
        }

        return $this->responses->blocked();
    }

    /**
     * @param  Closure(Request): Response  $next
     */
    private function handleRateLimit(Request $request, string $ipAddress, Closure $next): Response
    {
        try {
            $result = $this->rateLimiter->consume($ipAddress);
        } catch (Throwable $exception) {
            $this->failureLogger->once('Public rate limiter failed open.', $exception);

            return $next($request);
        }

        if ($result['allowed']) {
            return $next($request);
        }

        if ($result['blocked_now']) {
            $this->failureLogger->always('Public request rate limit exceeded.', null, [
                'action' => $result['action'],
                'attempts' => $result['attempts'],
                'method' => $request->method(),
            ]);
        }

        if ($result['action'] === PublicRateLimiter::ACTION_REJECT_ONLY) {
            return $this->responses->tooManyRequests($result['retry_after']);
        }

        return $this->responses->blocked();
    }

    private function matchesAny(Request $request, string $configKey): bool
    {
        foreach ((array) $this->config->get($configKey, []) as $pattern) {
            if (is_string($pattern) && $pattern !== '' && $request->is($pattern)) {
                return true;
            }
        }

        return false;
    }
}
