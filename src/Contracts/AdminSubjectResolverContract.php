<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Contracts;

use Apkk\LaravelSecurityGuard\Data\AdminSubjectData;
use Illuminate\Http\Request;

interface AdminSubjectResolverContract
{
    /**
     * Identify the authenticated administrative subject for a request.
     *
     * Returns null when nobody is authenticated; deciding what to do with an
     * unauthenticated request is the host's auth middleware's job.
     */
    public function resolve(Request $request): ?AdminSubjectData;
}
