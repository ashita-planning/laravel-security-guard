<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Services;

use Apkk\LaravelSecurityGuard\Support\CacheKeys;
use Illuminate\Contracts\Cache\Repository as CacheRepository;
use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Http\Request;
use Illuminate\Support\Str;

/**
 * One-time submission tokens for confirm-then-submit flows.
 *
 * This complements CSRF protection, it does not replace it: CSRF proves the
 * request came from your form, this proves the same confirmed submission is
 * not executed twice.
 */
class SubmissionTokenService
{
    public function __construct(
        private readonly CacheRepository $cache,
        private readonly ConfigRepository $config,
    ) {}

    public function issue(Request $request, string $purpose): string
    {
        $token = Str::random(64);
        $request->session()->put($this->sessionKey($purpose), $token);

        return $token;
    }

    /**
     * Consume a token. A given token succeeds exactly once, even when two
     * requests arrive at the same instant.
     */
    public function consume(Request $request, string $purpose, ?string $submittedToken): bool
    {
        // pull(), not get(): a failed attempt must burn the token too,
        // otherwise a mismatch leaves it available for another guess.
        $expected = $request->session()->pull($this->sessionKey($purpose));

        if (! is_string($expected) || ! is_string($submittedToken) || $submittedToken === '') {
            return false;
        }

        if (! hash_equals($expected, $submittedToken)) {
            return false;
        }

        // add() is atomic on a shared store: the first of two concurrent
        // submissions wins and the second is rejected.
        return $this->cache->add(
            CacheKeys::usedSubmissionToken($submittedToken),
            true,
            $this->usedTokenTtl(),
        );
    }

    public function enabled(): bool
    {
        return (bool) $this->config->get('security-guard.submission_token.enabled', false);
    }

    private function usedTokenTtl(): int
    {
        return max(60, (int) $this->config->get('security-guard.submission_token.used_token_ttl_seconds', 3600));
    }

    private function sessionKey(string $purpose): string
    {
        return 'security-guard.submission_token.'.$purpose;
    }
}
