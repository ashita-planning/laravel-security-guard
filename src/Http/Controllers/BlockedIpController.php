<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Http\Controllers;

use Apkk\LaravelSecurityGuard\Data\ActorData;
use Apkk\LaravelSecurityGuard\Http\Requests\ReleaseBlockedIpRequest;
use Apkk\LaravelSecurityGuard\Services\IpBlockService;
use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\View\View;

/**
 * The bundled block management screen.
 *
 * Publish the views to restyle it, or point the routes at your own controller;
 * neither the layout nor the authorisation rule is fixed by the package.
 */
class BlockedIpController extends Controller
{
    public function __construct(
        private readonly IpBlockService $blockService,
        private readonly ConfigRepository $config,
    ) {}

    public function index(Request $request): View
    {
        $result = $this->blockService->paginate(
            [
                'active' => $request->boolean('active', true),
                'ip_address' => $this->filterIp($request),
            ],
            (int) $this->config->get('security-guard.management_ui.per_page', 50),
            max(1, (int) $request->integer('page', 1)),
        );

        return view('security-guard::blocked-ips.index', [
            'records' => $result['items'],
            'total' => $result['total'],
            'page' => $result['page'],
            'perPage' => $result['per_page'],
            'activeOnly' => $request->boolean('active', true),
            'ipFilter' => $this->filterIp($request),
            'routeNamePrefix' => (string) $this->config->get('security-guard.management_ui.route_name_prefix', 'security-guard.'),
        ]);
    }

    public function release(ReleaseBlockedIpRequest $request): RedirectResponse
    {
        $ipAddress = (string) $request->validated()['ip_address'];

        $released = $this->blockService->release(
            $ipAddress,
            ActorData::fromAuthenticatable($request->user()),
        );

        $prefix = (string) $this->config->get('security-guard.management_ui.route_name_prefix', 'security-guard.');

        return redirect()
            ->route($prefix.'blocked-ips.index')
            ->with('security-guard.status', $released
                ? 'The address was released.'
                : 'No active block was found for that address.');
    }

    private function filterIp(Request $request): ?string
    {
        $ip = $request->query('ip');

        return is_string($ip) && filter_var($ip, FILTER_VALIDATE_IP) !== false ? $ip : null;
    }
}
