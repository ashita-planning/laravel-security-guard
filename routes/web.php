<?php

declare(strict_types=1);

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
    });
