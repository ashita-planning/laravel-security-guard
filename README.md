# Laravel Security Guard

[![tests](https://github.com/ashita-planning/laravel-security-guard/actions/workflows/tests.yml/badge.svg)](https://github.com/ashita-planning/laravel-security-guard/actions/workflows/tests.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

[English](README.md) | [日本語](README.ja.md) | [Detailed Japanese reference](docs/ja/configuration-and-operations.md)

Laravel Security Guard adds an application-level layer of protection to Laravel applications. It detects known attack paths, can persistently block abusive IP addresses, and provides opt-in rate limits, administrator IP allowlists, one-time submission tokens, and safe security notifications.

It is **not** a replacement for a WAF, CDN, web-server hardening, or secure application code. Use it as one layer in a defence-in-depth design.

## Requirements

- PHP `^8.2`
- Laravel `12.61.1+` or `13.12.0+`
- A database connection for the package tables
- A shared, atomic cache store when the application runs in more than one process or server

## Support policy

Only Laravel majors that are within Laravel's security-fix window are supported.

| Laravel | PHP | Support status |
| --- | --- | --- |
| 13.x | 8.3 / 8.4 / 8.5 | Supported |
| 12.x | 8.2 / 8.3 / 8.4 | Supported |
| 11.x | — | Unsupported |
| 10.x | — | Unsupported |

## Install

```bash
composer require apkk/laravel-security-guard
php artisan vendor:publish --tag=security-guard-config --no-interaction
php artisan migrate --no-interaction
```

Migrations are loaded by the package. Publish them only when your application needs to own the migration files:

```bash
php artisan vendor:publish --tag=security-guard-migrations --no-interaction
```

Installing the package does not change request handling. Public request protection is only active after you deliberately register its middleware.

## Safe first deployment

Apply the package in staging before production, and enable one capability at a time.

### 1. Give the package its own cache namespace

In `config/security-guard.php`, replace the default `security-guard` prefix with a value unique to the application and environment:

```php
'cache' => [
    'store' => env('SECURITY_GUARD_CACHE_STORE'),
    'prefix' => 'my-application:production',
],
```

This prevents separate applications or environments sharing a cache server from sharing block state, notification quotas, or one-time tokens.

### 2. Resolve the real client IP safely

The default `laravel_request` driver uses Laravel's `Request::ip()`. If a reverse proxy, CDN, or load balancer is in front of PHP, configure Laravel's trusted proxies **before** enabling the public middleware. Trust only the known proxy address or CIDR; do not trust arbitrary forwarding headers.

```php
// bootstrap/app.php, inside withMiddleware(...)
$middleware->trustProxies(at: [
    '192.0.2.0/24', // Replace with the address range of your actual proxy.
]);
```

If PHP receives connections directly from clients, use `REMOTE_ADDR` instead:

```php
'ip_resolver' => [
    'driver' => 'remote_addr',
],
```

Verify the resolved address with a real staging request. `security-guard:status <ip>` reports the guard state of the IP you supply; it does not show the client IP resolved from an HTTP request.

### 3. Run the configuration doctor

```bash
php artisan security-guard:doctor --strict
```

Fix every warning before continuing. In strict mode the command exits with `2` for warnings and `1` for failures, making it suitable for CI and deployment checks.

### 4. Register public request protection

Known attack-path detection and persistent blocking need to run before Laravel routes a request, including requests for routes that do not exist. Register the middleware globally in `bootstrap/app.php`:

```php
use Apkk\LaravelSecurityGuard\Http\Middleware\GuardPublicRequests;
use Illuminate\Foundation\Configuration\Middleware;

->withMiddleware(function (Middleware $middleware): void {
    $middleware->prepend(GuardPublicRequests::class);

    // Keep your application's existing middleware configuration here.
})
```

Before production, add monitoring, office, and maintenance addresses to `permanent_block.ignored_ips` where appropriate, then test blocking, release, and re-blocking in staging.

## Capabilities

| Capability | Default state | Use it for |
| --- | --- | --- |
| Known attack-path detection and persistent IP blocks | Ready when public middleware is registered | Blocking requests for common probe paths and repeated abuse |
| Public rate limiting | Disabled | Limiting public traffic by IP |
| Verified crawler access | Disabled | Giving verified Googlebot and Bingbot a separate, non-persistent limit |
| Administrator IP allowlists | Disabled | Restricting authenticated administration by subject and IP/CIDR |
| Sensitive-route profiles | Disabled | Adding IP and identifier limits to login, reset, or other sensitive routes |
| One-time submission tokens | Disabled | Preventing duplicate confirmation-page submissions |
| Security event notifications | Disabled | Sending bounded, queued security alerts |
| Management UI | Disabled | Reviewing and releasing blocked IP addresses behind authentication and authorization |

Every module has its own enablement and exclusion rules. Do not enable rate limits, allowlists, notifications, or crawler handling until their dependencies and failure behaviour have been reviewed.

## CIDR safety

Ignored-IP and administrator allowlist rules accept individual IP addresses and CIDR networks. An IPv4 rule **does not cross IP families**: it never matches an IPv4-mapped IPv6 address. An invalid or unparseable rule **matches nothing**, never every address.

## Common commands

```bash
# Validate configuration for deployment
php artisan security-guard:doctor --strict --json

# Inspect and release a blocked address
php artisan security-guard:blocked:list --active
php artisan security-guard:blocked:release 203.0.113.10 --actor=ops

# Inspect the stored guard state for one address
php artisan security-guard:status 203.0.113.10
```

Run `php artisan list security-guard` to see all package commands, including administrator IP allowlist and verified-crawler range maintenance commands.

## Documentation

This README intentionally covers the safe first deployment. The full configuration and operations reference is being prepared for the documentation site.

Until then, the published configuration file, `config/security-guard.php`, is the source of truth for defaults. The current detailed reference is available in Japanese: [configuration and operations reference](docs/ja/configuration-and-operations.md).

## Support and security

- Report reproducible bugs and feature requests through [GitHub Issues](https://github.com/ashita-planning/laravel-security-guard/issues).
- Read [CONTRIBUTING.md](CONTRIBUTING.md) before submitting a pull request.
- Do **not** report vulnerabilities in a public issue. Follow [SECURITY.md](SECURITY.md) instead.
- See [CHANGELOG.md](CHANGELOG.md) before upgrading.

## Development

```bash
composer check
```

## License

Laravel Security Guard is open-sourced software licensed under the [MIT license](LICENSE).
