<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Http\Middleware;

use Apkk\LaravelSecurityGuard\Contracts\AdminSubjectResolverContract;
use Apkk\LaravelSecurityGuard\Contracts\ClientIpResolverContract;
use Apkk\LaravelSecurityGuard\Data\AdminSubjectData;
use Apkk\LaravelSecurityGuard\Events\AdminIpAccessDenied;
use Apkk\LaravelSecurityGuard\Services\AdminIpAccessService;
use Closure;
use Illuminate\Contracts\Auth\Factory as AuthFactory;
use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Events\Dispatcher as EventDispatcher;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Rejects an authenticated administrator whose current IP is not allowlisted.
 *
 * Unauthenticated requests pass straight through: deciding what to do with
 * them belongs to the host's own auth middleware, which must run first.
 */
class EnsureAdminIpIsAllowed
{
    public function __construct(
        private readonly AdminIpAccessService $accessService,
        private readonly AdminSubjectResolverContract $subjectResolver,
        private readonly ClientIpResolverContract $ipResolver,
        private readonly AuthFactory $auth,
        private readonly ConfigRepository $config,
        private readonly EventDispatcher $events,
    ) {}

    /**
     * @param  Closure(Request): Response  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        if (! $this->accessService->enabled()) {
            return $next($request);
        }

        $subject = $this->subjectResolver->resolve($request);

        if ($subject === null) {
            return $next($request);
        }

        $ipAddress = $this->ipResolver->resolve($request);
        $result = $this->accessService->check($subject, $ipAddress);

        if ($result['allowed']) {
            return $next($request);
        }

        return $this->deny($request, $subject, $ipAddress, (string) $result['reason']);
    }

    private function deny(Request $request, AdminSubjectData $subject, ?string $ipAddress, string $reason): Response
    {
        // The audit trail gets the detail; the response never does.
        $this->events->dispatch(new AdminIpAccessDenied($subject, $ipAddress, $reason));

        if ((bool) $this->config->get('security-guard.admin_ip.logout_on_denied', true)) {
            $this->logout($request);
        }

        $message = (string) $this->config->get(
            'security-guard.admin_ip.denied_message',
            'Access from this network is not permitted.',
        );

        $redirectTo = $this->config->get('security-guard.admin_ip.denied_redirect_to');

        if ($this->config->get('security-guard.admin_ip.denied_action', 'forbid') === 'redirect'
            && is_string($redirectTo) && $redirectTo !== '') {
            $sessionKey = (string) $this->config->get(
                'security-guard.admin_ip.denied_message_session_key',
                'security-guard.denied',
            );

            return redirect()->to($redirectTo)->with($sessionKey, $message);
        }

        return new Response($message, Response::HTTP_FORBIDDEN, [
            'Content-Type' => 'text/plain; charset=UTF-8',
        ]);
    }

    private function logout(Request $request): void
    {
        $guardName = $this->config->get('security-guard.admin_ip.guard');
        $guard = $this->auth->guard($guardName === null ? null : (string) $guardName);

        if (method_exists($guard, 'logout')) {
            $guard->logout();
        }

        if (! $request->hasSession()) {
            return;
        }

        // Invalidate then regenerate: the old session id must not stay usable
        // and the next form needs a fresh CSRF token.
        $request->session()->invalidate();
        $request->session()->regenerateToken();
    }
}
