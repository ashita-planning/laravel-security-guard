<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Services;

use Apkk\LaravelSecurityGuard\Contracts\AdminSubjectResolverContract;
use Apkk\LaravelSecurityGuard\Data\AdminSubjectData;
use Illuminate\Contracts\Auth\Factory as AuthFactory;
use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Http\Request;

/**
 * Resolves the administrative subject from a configured guard.
 *
 * `subject_type` defaults to the authenticated class name but can be pinned in
 * config, which is what lets a host rename or replace its user model without
 * orphaning the allowlist rows.
 */
class ConfigAdminSubjectResolver implements AdminSubjectResolverContract
{
    public function __construct(
        private readonly AuthFactory $auth,
        private readonly ConfigRepository $config,
    ) {}

    public function resolve(Request $request): ?AdminSubjectData
    {
        $guard = $this->config->get('security-guard.admin_ip.guard');
        $user = $this->auth->guard($guard === null ? null : (string) $guard)->user();

        return $this->fromAuthenticatable($user);
    }

    public function fromAuthenticatable(mixed $user): ?AdminSubjectData
    {
        if (! is_object($user) || ! method_exists($user, 'getAuthIdentifier')) {
            return null;
        }

        $id = $user->getAuthIdentifier();

        if ($id === null || $id === '') {
            return null;
        }

        return new AdminSubjectData($this->subjectType($user), (string) $id);
    }

    public function subjectType(mixed $user = null): string
    {
        $configured = $this->config->get('security-guard.admin_ip.subject_type');

        if (is_string($configured) && $configured !== '') {
            return $configured;
        }

        return is_object($user) ? $user::class : 'default';
    }
}
