<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Http\Middleware;

use Apkk\LaravelSecurityGuard\Contracts\AttackPathMatcherContract;
use Apkk\LaravelSecurityGuard\Contracts\ClientIpResolverContract;
use Apkk\LaravelSecurityGuard\Crawlers\CrawlerVerifierRegistry;
use Apkk\LaravelSecurityGuard\Data\BlockReason;
use Apkk\LaravelSecurityGuard\Services\BlockResponseFactory;
use Apkk\LaravelSecurityGuard\Services\CrawlerRateLimiter;
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
 * Evaluation order is fixed: IP resolution, ignore list, existing block,
 * known attack path, rate-limit exclusions, crawler classification, then one
 * of the two rate limits. Each step is individually fail-open except the
 * attack path branch, which answers 403 even when the block cannot be
 * recorded.
 *
 * A verified crawler swaps only the rate limit — never the defences. It is
 * classified after the block and attack-path checks precisely so that
 * verification can never excuse either, and the rate-limit exclusion list is
 * evaluated before classification so an excluded webhook path costs no
 * verification work and no counter, whoever is calling it.
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
        private readonly CrawlerVerifierRegistry $crawlerVerifiers,
        private readonly CrawlerRateLimiter $crawlerRateLimiter,
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

        $crawlersEnabled = (bool) $this->config->get('security-guard.crawler_access.enabled', false);
        $publicLimitEnabled = (bool) $this->config->get('security-guard.public_rate_limit.enabled', false);

        if (! $crawlersEnabled && ! $publicLimitEnabled) {
            return $next($request);
        }

        // One exclusion list for both limits: a webhook excused from request
        // counting is excused whoever calls it. Exclusion never reaches the
        // block or attack-path checks above.
        if ($this->matchesAny($request, 'security-guard.public_rate_limit.excluded_paths')) {
            return $next($request);
        }

        if ($crawlersEnabled) {
            $provider = $this->verifiedCrawlerProvider($request, $ipAddress);

            if ($provider !== null) {
                return $this->handleCrawlerRateLimit($request, $provider, $ipAddress, $next);
            }
        }

        if (! $publicLimitEnabled) {
            return $next($request);
        }

        return $this->handleRateLimit($request, $ipAddress, $next);
    }

    /**
     * The provider of a positively verified crawler, or null for everyone
     * else — including every failure mode.
     *
     * `unverified` and `unknown` deliberately collapse to the same answer
     * here: the normal public policy. A Googlebot User-Agent from an address
     * we cannot confirm gets neither crawler treatment nor punishment,
     * because stale range data and an actual impostor are indistinguishable
     * at this point.
     */
    private function verifiedCrawlerProvider(Request $request, string $ipAddress): ?string
    {
        try {
            $result = $this->crawlerVerifiers->classify($request->userAgent(), $ipAddress);
        } catch (Throwable $exception) {
            // The registry already degrades a failing verifier to
            // `unverified`; this catches the registry itself. Verification
            // failure must never widen access, so the request continues under
            // the normal public policy. No User-Agent, address or URL in the
            // log — only what identifies the failure.
            $this->failureLogger->once('Crawler classification failed; the normal public policy applies.', $exception, [
                'stage' => 'classification',
            ]);

            return null;
        }

        return $result->isVerified() ? $result->provider : null;
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
     * The dedicated budget for a verified crawler.
     *
     * On limiter failure this fails open and stops — it does NOT fall back
     * to the public limiter. The public default action is permanent_block,
     * and permanently blocking a verified search crawler because our own
     * counter broke is the exact outcome this module exists to prevent. An
     * uncounted crawler request is the cheaper mistake.
     *
     * Exceeding the limit rejects the request and nothing more: no block
     * row, no `blocked_now` bookkeeping, no notification. The crawler is
     * told to back off, always with a Retry-After it can act on.
     *
     * @param  Closure(Request): Response  $next
     */
    private function handleCrawlerRateLimit(
        Request $request,
        string $provider,
        string $ipAddress,
        Closure $next,
    ): Response {
        try {
            $result = $this->crawlerRateLimiter->consume($provider, $ipAddress);
        } catch (Throwable $exception) {
            $this->failureLogger->once('Crawler rate limiter failed open.', $exception, [
                'provider' => $provider,
                'stage' => 'rate_limit',
            ]);

            return $next($request);
        }

        if ($result['allowed']) {
            return $next($request);
        }

        // Suppressed like every other repeating condition: a crawler over its
        // budget stays over it for the rest of the window, and one line says
        // as much as a thousand.
        $this->failureLogger->once('Verified crawler rate limit exceeded.', null, [
            'provider' => $provider,
            'action' => $result['action'],
            'attempts' => $result['attempts'],
            'method' => $request->method(),
        ]);

        if ($result['action'] === CrawlerRateLimiter::ACTION_SERVICE_UNAVAILABLE) {
            return $this->responses->serviceUnavailable($result['retry_after']);
        }

        return $this->responses->tooManyRequests($result['retry_after']);
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
