<?php

declare(strict_types=1);

use Apkk\LaravelSecurityGuard\Http\Controllers\AdminAllowedIpController;
use Apkk\LaravelSecurityGuard\Http\Controllers\BlockedIpController;
use Illuminate\Support\Facades\Route;

/*
| Loaded only when `security-guard.management_ui.enabled` is true. Prefix,
| route name prefix and middleware all come from config so the screen can live
| inside an existing admin area.
*/

Route::middleware((array) config('security-guard.management_ui.middleware', ['web']))
    ->prefix((string) config('security-guard.management_ui.prefix', 'security-guard'))
    ->name((string) config('security-guard.management_ui.route_name_prefix', 'security-guard.'))
    ->group(function (): void {
        Route::get('blocked-ips', [BlockedIpController::class, 'index'])
            ->name('blocked-ips.index');

        Route::post('blocked-ips/release', [BlockedIpController::class, 'release'])
            ->name('blocked-ips.release');

        /*
        | The allowlist screen needs its own opt-in on top of management_ui.
        | Enabling the management UI in v0.1.x was consent to a release screen;
        | it was not consent to publish which networks reach the admin area, so
        | an upgrade must not add that surface on its own.
        |
        | Read-only by design: no create, update or delete route exists here.
        */
        if (config('security-guard.management_ui.admin_allowed_ips.enabled', false)) {
            Route::get('admin-allowed-ips', [AdminAllowedIpController::class, 'index'])
                ->name('admin-allowed-ips.index');
        }
    });
