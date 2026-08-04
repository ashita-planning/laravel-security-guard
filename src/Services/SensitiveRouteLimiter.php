<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Services;

use Apkk\LaravelSecurityGuard\Contracts\ClientIpResolverContract;
use Apkk\LaravelSecurityGuard\Contracts\IdentifierResolverContract;
use Apkk\LaravelSecurityGuard\Support\CacheKeyFactory;
use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Contracts\Cache\Repository as CacheRepository;
use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Container\Container;
use Illuminate\Http\Request;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\Response;
use Throwable;

/**
 * Multi-axis limits for login, contact, application and password reset routes.
 *
 * Each profile produces one limit per axis: always the client IP, plus any
 * configured identifier such as the submitted e-mail address. Identifiers are
 * lower-cased, trimmed and hashed before they touch a cache key or a log line,
 * so limiting on an e-mail address never stores one.
 */
class SensitiveRouteLimiter
{
    public function __construct(
        private readonly ClientIpResolverContract $ipResolver,
        private readonly CacheRepository $cache,
        private readonly ConfigRepository $config,
        private readonly Container $container,
        private readonly LoggerInterface $logger,
        private readonly BlockResponseFactory $responses,
        private readonly CacheKeyFactory $cacheKeys,
    ) {}

    /**
     * @return array<int, Limit>
     */
    public function limits(Request $request, string $profile): array
    {
        if (! $this->enabled()) {
            return [Limit::none()];
        }

        $definition = (array) $this->config->get("security-guard.sensitive_routes.profiles.{$profile}", []);

        if ($definition === []) {
            return [Limit::none()];
        }

        $decayMinutes = max(1, (int) ($definition['decay_minutes'] ?? 1));
        $ipAddress = $this->ipResolver->resolve($request);
        $limits = [];

        if ($ipAddress !== null) {
            $limits[] = $this->limit(
                $profile,
                'ip',
                $ipAddress,
                $decayMinutes,
                max(1, (int) ($definition['ip_attempts'] ?? 1)),
            );
        } else {
            // Never bucket unidentified clients together. A shared "unresolved"
            // key means one visitor's attempts throttle everyone whose address
            // could not be read, turning a proxy misconfiguration into a
            // site-wide 429. Identifier limits below still apply.
            $this->logger->warning(
                '[security-guard] Client IP could not be resolved; the IP limit was skipped for this request.',
                ['profile' => $profile],
            );
        }

        foreach ((array) ($definition['identifiers'] ?? []) as $name => $identifier) {
            $value = $this->identifierValue($request, (array) $identifier);

            if ($value === null || $value === '') {
                continue;
            }

            $limits[] = $this->limit(
                $profile,
                (string) $name,
                $value,
                $decayMinutes,
                max(1, (int) ($identifier['attempts'] ?? 1)),
            );
        }

        // With no resolvable IP and no identifier present there is nothing to
        // key on. An empty array would be read as "unlimited" by the throttle
        // middleware, so say so explicitly.
        return $limits === [] ? [Limit::none()] : $limits;
    }

    public function enabled(): bool
    {
        return (bool) $this->config->get('security-guard.enabled', true)
            && (bool) $this->config->get('security-guard.sensitive_routes.enabled', false);
    }

    /**
     * @return array<int, string>
     */
    public function profileNames(): array
    {
        return array_map(
            'strval',
            array_keys((array) $this->config->get('security-guard.sensitive_routes.profiles', [])),
        );
    }

    /**
     * @param  array<string, mixed>  $identifier
     */
    private function identifierValue(Request $request, array $identifier): ?string
    {
        $resolverClass = $identifier['resolver'] ?? null;

        if (is_string($resolverClass) && $resolverClass !== '') {
            try {
                $resolver = $this->container->make($resolverClass);

                $value = $resolver instanceof IdentifierResolverContract
                    ? $resolver->resolve($request)
                    : null;
            } catch (Throwable $exception) {
                // A misconfigured resolver drops one axis; it must not turn the
                // limiter itself into a 500 on a login form.
                $this->logger->warning('[security-guard] Sensitive route identifier resolver failed.', [
                    'resolver' => $resolverClass,
                    'exception' => $exception->getMessage(),
                ]);

                return null;
            }

            return $value === null ? null : $this->normalizeIdentifier($value);
        }

        $field = $identifier['field'] ?? null;

        if (! is_string($field) || $field === '') {
            return null;
        }

        $value = $request->input($field);

        return is_scalar($value) ? $this->normalizeIdentifier((string) $value) : null;
    }

    private function normalizeIdentifier(string $value): string
    {
        return mb_strtolower(trim($value));
    }

    private function limit(
        string $profile,
        string $dimension,
        string $value,
        int $decayMinutes,
        int $attempts,
    ): Limit {
        $valueHash = CacheKeyFactory::hash($value);

        return Limit::perMinutes($decayMinutes, $attempts)
            ->by($this->cacheKeys->sensitive($profile, $dimension, $value))
            ->response(fn (Request $request, array $headers): Response => $this->rejected(
                $request,
                $headers,
                $profile,
                $dimension,
                $valueHash,
                $attempts,
                $decayMinutes,
            ));
    }

    /**
     * @param  array<string, mixed>  $headers
     */
    private function rejected(
        Request $request,
        array $headers,
        string $profile,
        string $dimension,
        string $valueHash,
        int $attempts,
        int $decayMinutes,
    ): Response {
        $this->logOnce($request, $headers, $profile, $dimension, $valueHash, $attempts, $decayMinutes);

        $response = $this->responses->tooManyRequests((int) ($headers['Retry-After'] ?? 0));

        foreach ($headers as $name => $value) {
            $response->headers->set((string) $name, (string) $value);
        }

        return $response;
    }

    /**
     * One log line per limited identifier per window: an attacker hammering a
     * limited endpoint must not be able to flood the log through it.
     *
     * @param  array<string, mixed>  $headers
     */
    private function logOnce(
        Request $request,
        array $headers,
        string $profile,
        string $dimension,
        string $valueHash,
        int $attempts,
        int $decayMinutes,
    ): void {
        try {
            $key = $this->cacheKeys->sensitiveLogOnce($profile, $dimension, $valueHash);

            if (! $this->cache->add($key, true, $decayMinutes * 60)) {
                return;
            }

            $this->logger->warning('[security-guard] Sensitive route rate limit exceeded.', [
                'profile' => $profile,
                'dimension' => $dimension,
                // A truncated hash is enough to correlate without storing the value.
                'value_hash' => substr($valueHash, 0, 12),
                'method' => $request->method(),
                'route' => $request->route()?->getName(),
                'attempts' => $attempts,
                'retry_after' => (int) ($headers['Retry-After'] ?? 0),
            ]);
        } catch (Throwable) {
            // Logging must never break the rejection response.
        }
    }
}
