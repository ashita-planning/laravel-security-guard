<?php

declare(strict_types=1);

/*
|--------------------------------------------------------------------------
| Laravel Security Guard
|--------------------------------------------------------------------------
|
| Every module ships disabled unless it is safe to run from the first
| request. Enable modules one at a time and verify the effect on a staging
| environment before touching production. Only this file may read env().
|
*/

return [

    'enabled' => env('SECURITY_GUARD_ENABLED', true),

    /*
    |--------------------------------------------------------------------------
    | Client IP resolution
    |--------------------------------------------------------------------------
    |
    | "laravel_request" uses Request::ip(). Behind a reverse proxy you must
    | configure Laravel's trusted proxies first; this package never reads
    | X-Forwarded-For on its own. Verify with `php artisan security-guard:status`.
    |
    */

    'ip_resolver' => [
        'driver' => env('SECURITY_GUARD_IP_DRIVER', 'laravel_request'),
    ],

    /*
    |--------------------------------------------------------------------------
    | Storage
    |--------------------------------------------------------------------------
    */

    'database' => [
        'connection' => env('SECURITY_GUARD_DB_CONNECTION'),
        'tables' => [
            'blocked_ips' => 'security_guard_blocked_ips',
            'admin_allowed_ips' => 'security_guard_admin_allowed_ips',
        ],
    ],

    'cache' => [
        'store' => env('SECURITY_GUARD_CACHE_STORE'),
        'prefix' => 'security-guard',
    ],

    /*
    |--------------------------------------------------------------------------
    | Permanent IP block + known attack path detection
    |--------------------------------------------------------------------------
    */

    'permanent_block' => [
        'enabled' => true,

        // Paths that skip block checks AND attack path detection entirely.
        // Deliberately separate from the rate limit list below and empty by
        // default: excusing a path here means a already-blocked address is
        // served normally there, so add only paths you fully trust.
        'excluded_paths' => [],

        // Exact-match only in v1. CIDR and subnets are not supported.
        'ignored_ips' => [],

        'cache_minutes' => 5,

        'response_status' => 403,
        'response_body' => 'Forbidden',

        // Merged over the package defaults. Set a category to false to disable
        // it, or to an array to replace the package definition entirely.
        'use_default_patterns' => true,
        'attack_patterns' => [],
    ],

    /*
    |--------------------------------------------------------------------------
    | Public rate limit
    |--------------------------------------------------------------------------
    |
    | action: permanent_block | temporary_block | reject_only
    |
    */

    'public_rate_limit' => [
        'enabled' => false,
        'requests_per_minute' => 120,
        'action' => 'permanent_block',
        'temporary_block_minutes' => 60,

        // Request::is() compatible patterns. These bypass the ENTIRE guard --
        // attack path detection and existing blocks included -- so list only
        // paths you are willing to leave unguarded: admin panels, tracking
        // pixels, external webhooks and authentication callbacks.
        'excluded_paths' => [],
    ],

    /*
    |--------------------------------------------------------------------------
    | Admin area IP allowlist
    |--------------------------------------------------------------------------
    |
    | empty_policy: deny (recommended) | allow_when_empty (migration only)
    | denied_action: forbid | redirect
    |
    */

    'admin_ip' => [
        'enabled' => false,
        'guard' => null,
        'subject_type' => null,
        'empty_policy' => 'deny',
        'denied_action' => 'forbid',
        'denied_redirect_to' => null,
        'denied_message' => 'Access from this network is not permitted.',
        'denied_message_session_key' => 'security-guard.denied',
        'logout_on_denied' => true,
    ],

    /*
    |--------------------------------------------------------------------------
    | Sensitive route limits
    |--------------------------------------------------------------------------
    |
    | Each profile registers a named RateLimiter. Apply it explicitly with
    | ->middleware('throttle:<profile>') on the host route.
    |
    */

    'sensitive_routes' => [
        'enabled' => false,
        'profiles' => [
            // 'customer_login' => [
            //     'decay_minutes' => 10,
            //     'ip_attempts' => 20,
            //     'identifiers' => [
            //         'email' => ['field' => 'email', 'attempts' => 5],
            //     ],
            // ],
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | One-time submission token
    |--------------------------------------------------------------------------
    |
    | Complements CSRF protection, it does not replace it.
    |
    */

    'submission_token' => [
        'enabled' => false,
        'used_token_ttl_seconds' => 3600,
    ],

    /*
    |--------------------------------------------------------------------------
    | Security event notification
    |--------------------------------------------------------------------------
    */

    'notifications' => [
        'enabled' => false,
        'connection' => null,
        'queue' => 'default',
        'channels' => ['log'],
        'daily_limit' => 10,
        'mask_ip' => false,
        'log' => [
            'channel' => null,
            'level' => 'warning',
        ],
        'mail' => [
            'to' => [],
            'subject' => '[security-guard] Automatic IP block',
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Error notification guard
    |--------------------------------------------------------------------------
    |
    | on_limit: mark_handled | hold
    |
    */

    'error_notifications' => [
        'enabled' => false,
        'connection' => null,
        'queue' => 'default',
        'aggregation_delay_seconds' => 60,
        'cooldown_minutes' => 10,
        'daily_limits' => ['line' => 4, 'mail' => 4],
        'on_limit' => 'mark_handled',
        // Ceiling on retained events per aggregation window. Occurrences past
        // this are still counted, just not stored: during a storm the buffer
        // is what grows fastest.
        'max_aggregated_events' => 50,
        'url_max_bytes' => 255,
        'masked_query_keys' => [
            'token', 'password', 'password_confirmation', 'secret', 'signature',
            'api_key', 'apikey', 'access_token', 'refresh_token', 'auth', 'key',
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Diagnostic logging
    |--------------------------------------------------------------------------
    |
    | Exception messages from a failing driver can carry a DSN, credentials or
    | the bound values of a statement. Turn this off when logs leave your
    | infrastructure; the exception class is always recorded either way.
    |
    */

    'logging' => [
        'include_exception_messages' => true,
    ],

    /*
    |--------------------------------------------------------------------------
    | Bundled management UI
    |--------------------------------------------------------------------------
    */

    'management_ui' => [
        'enabled' => false,
        'prefix' => 'security-guard',
        'route_name_prefix' => 'security-guard.',
        'middleware' => ['web', 'auth', 'can:manage-security'],
        'per_page' => 50,
    ],
];
