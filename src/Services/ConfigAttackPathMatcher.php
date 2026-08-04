<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Services;

use Apkk\LaravelSecurityGuard\Contracts\AttackPathMatcherContract;
use Apkk\LaravelSecurityGuard\Data\AttackMatch;
use Apkk\LaravelSecurityGuard\Support\DefaultAttackPatterns;
use Apkk\LaravelSecurityGuard\Support\FailureLogger;
use Illuminate\Contracts\Config\Repository as ConfigRepository;

class ConfigAttackPathMatcher implements AttackPathMatcherContract
{
    /** @var array<string, array<string, array<int, string>>>|null */
    private ?array $patterns = null;

    public function __construct(
        private readonly ConfigRepository $config,
        private readonly FailureLogger $failureLogger,
    ) {}

    public function match(string $path): ?AttackMatch
    {
        $normalizedPath = $this->normalizePath($path);

        if ($normalizedPath === '') {
            return null;
        }

        foreach ($this->patterns() as $category => $definition) {
            foreach ($definition['exact'] ?? [] as $exact) {
                if ($normalizedPath === $this->normalizePath($exact)) {
                    return new AttackMatch($category, AttackMatch::TYPE_EXACT);
                }
            }

            foreach ($definition['prefix'] ?? [] as $prefix) {
                $normalizedPrefix = $this->normalizePath($prefix);

                if ($normalizedPrefix !== '' && str_starts_with($normalizedPath, $normalizedPrefix)) {
                    return new AttackMatch($category, AttackMatch::TYPE_PREFIX);
                }
            }

            foreach ($definition['regex'] ?? [] as $regex) {
                if ($this->matchesRegex($regex, $normalizedPath, $category)) {
                    return new AttackMatch($category, AttackMatch::TYPE_REGEX);
                }
            }
        }

        return null;
    }

    /**
     * A broken host-supplied pattern must not turn every request into a 500.
     * The pattern is skipped and reported once per process.
     */
    private function matchesRegex(string $regex, string $path, string $category): bool
    {
        $result = @preg_match($regex, $path);

        if ($result === false) {
            $this->failureLogger->once(
                'Invalid attack path regex ignored.',
                null,
                ['category' => $category],
            );

            return false;
        }

        return $result === 1;
    }

    /**
     * @return array<string, array<string, array<int, string>>>
     */
    public function patterns(): array
    {
        if ($this->patterns !== null) {
            return $this->patterns;
        }

        $defaults = $this->config->get('security-guard.permanent_block.use_default_patterns', true)
            ? DefaultAttackPatterns::all()
            : [];

        $overrides = (array) $this->config->get('security-guard.permanent_block.attack_patterns', []);

        $merged = $defaults;

        foreach ($overrides as $category => $definition) {
            // `false` (or null) disables a category outright; an array replaces it.
            if ($definition === false || $definition === null) {
                unset($merged[$category]);

                continue;
            }

            $merged[(string) $category] = (array) $definition;
        }

        return $this->patterns = array_map(
            fn (array $definition): array => [
                'exact' => array_map('strval', (array) ($definition['exact'] ?? [])),
                'prefix' => array_map('strval', (array) ($definition['prefix'] ?? [])),
                'regex' => array_map('strval', (array) ($definition['regex'] ?? [])),
            ],
            $merged,
        );
    }

    /**
     * Fold away the encodings a scanner uses to dodge a literal comparison.
     *
     * Percent decoding runs at most twice; unbounded decoding would let a
     * deeply nested payload burn CPU on every request.
     */
    public function normalizePath(string $path): string
    {
        $decoded = rawurldecode(rawurldecode($path));
        $decoded = str_replace(['\\', "\0"], ['/', ''], $decoded);
        $decoded = preg_replace('#/+#', '/', $decoded) ?? $decoded;

        return mb_strtolower(trim($decoded, '/'));
    }
}
