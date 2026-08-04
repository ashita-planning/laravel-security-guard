<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Services;

use Apkk\LaravelSecurityGuard\Contracts\AdminAllowedIpRepositoryContract;
use Apkk\LaravelSecurityGuard\Data\AdminSubjectData;
use Apkk\LaravelSecurityGuard\Support\FailureLogger;
use Apkk\LaravelSecurityGuard\Support\Ip;
use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Throwable;

/**
 * Per-administrator IP allowlist.
 *
 * This module is fail-closed on purpose: unlike the public surface, the safe
 * answer for an administrative area during an outage is "no".
 */
class AdminIpAccessService
{
    public const EMPTY_POLICY_DENY = 'deny';

    public const EMPTY_POLICY_ALLOW = 'allow_when_empty';

    public const REASON_NOT_ALLOWED = 'ip_not_allowed';

    public const REASON_UNRESOLVED_IP = 'ip_unresolved';

    public const REASON_NO_ENTRIES = 'no_allowed_ips';

    public const REASON_LOOKUP_FAILED = 'lookup_failed';

    public function __construct(
        private readonly AdminAllowedIpRepositoryContract $repository,
        private readonly ConfigRepository $config,
        private readonly FailureLogger $failureLogger,
    ) {}

    public function enabled(): bool
    {
        return (bool) $this->config->get('security-guard.enabled', true)
            && (bool) $this->config->get('security-guard.admin_ip.enabled', false);
    }

    /**
     * @return array{allowed: bool, reason: string|null}
     */
    public function check(AdminSubjectData $subject, ?string $ipAddress): array
    {
        if (! $this->enabled()) {
            return ['allowed' => true, 'reason' => null];
        }

        $normalized = Ip::normalize($ipAddress);

        if ($normalized === null) {
            return ['allowed' => false, 'reason' => self::REASON_UNRESOLVED_IP];
        }

        try {
            if ($this->repository->isAllowed($subject, $normalized)) {
                return ['allowed' => true, 'reason' => null];
            }

            if ($this->repository->countEnabled($subject) === 0) {
                return $this->emptyPolicy() === self::EMPTY_POLICY_ALLOW
                    ? ['allowed' => true, 'reason' => null]
                    : ['allowed' => false, 'reason' => self::REASON_NO_ENTRIES];
            }
        } catch (Throwable $exception) {
            $this->failureLogger->once('Admin IP allowlist lookup failed, denying access.', $exception);

            return ['allowed' => false, 'reason' => self::REASON_LOOKUP_FAILED];
        }

        return ['allowed' => false, 'reason' => self::REASON_NOT_ALLOWED];
    }

    /**
     * Convenience wrapper for pre-login checks, where the host knows the
     * subject before a session exists.
     */
    public function isAllowed(AdminSubjectData $subject, ?string $ipAddress): bool
    {
        return $this->check($subject, $ipAddress)['allowed'];
    }

    public function emptyPolicy(): string
    {
        $policy = (string) $this->config->get('security-guard.admin_ip.empty_policy', self::EMPTY_POLICY_DENY);

        return $policy === self::EMPTY_POLICY_ALLOW ? self::EMPTY_POLICY_ALLOW : self::EMPTY_POLICY_DENY;
    }
}
