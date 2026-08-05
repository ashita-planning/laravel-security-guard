# Changelog

All notable changes to `apkk/laravel-security-guard` are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

While the version is below `1.0.0`, breaking changes may land in a minor
release. They will always be listed under **Changed** or **Removed** with a
migration note.

## [Unreleased]

Nothing yet.

## [0.3.0] - 2026-08-05

### Added

- **Verified search crawler handling** (#14). Off by default
  (`crawler_access.enabled` is `false`, and while it is, the middleware never
  consults a verifier — v0.2.0 behaviour exactly). When enabled it works
  independently of the public rate limit: verified crawlers get their own
  budget even with `public_rate_limit.enabled=false`.
  - `GuardPublicRequests` classifies after the ignore list, existing blocks
    and attack-path detection — verification swaps the rate limit, never the
    defences — and after the rate-limit exclusion list, which now excuses
    both limiters at once. A verified crawler goes to `CrawlerRateLimiter`;
    `unverified` and `unknown` go to the public limiter as before. A
    classification failure logs once (provider, exception class, stage — no
    User-Agent, no URL) and applies the normal public policy; a crawler
    limiter failure after verification fails open and does not fall back to
    the public limiter, whose default `permanent_block` would otherwise
    punish a genuine crawler for our broken counter.
  - `CrawlerVerifierContract` and `CrawlerVerificationResult`: requests
    classify as *verified*, *claimed-but-unverified* or *unknown*. The
    User-Agent only nominates a candidate; verification happens exclusively
    against the provider's published IP ranges, already cached — never by DNS
    or HTTP during request handling, and every failure mode degrades to
    `unverified`, which means the normal public policy.
  - `security-guard:crawler-ranges:refresh` fetches the published CIDR
    documents for Google and Bing. Validation is all-or-nothing per document,
    storage goes through a staged write with readback so a mangling cache
    cannot replace known-good data, and a failed provider keeps its previous
    ranges while failing the exit code. The package never schedules the
    command; the host registers it in its own scheduler.
  - Range data is trusted for `fresh_for_hours`, then retained (readable, but
    verifying nobody) for `retain_for_days` so the doctor can tell "stale"
    from "missing".
  - `CrawlerRateLimiter`: a per-provider, per-address budget in its own key
    space — crawler traffic never spends the public budget of the humans
    behind the same address, and vice versa. Exceeding it answers `429` or
    `503`, always with `Retry-After`, and never persists a block.
    `permanent_block` is not an accepted action: configuring it runs as
    `reject_only` and the doctor reports the mismatch as a failure, because a
    permanently blocked search crawler keeps eating 403s until a human
    notices, which costs crawling, index refresh and search presence.
  - Doctor checks behind `crawler_access.enabled`: no provider registered;
    range data missing, corrupted or past its freshness window; crawler data
    on a non-shared cache; a rate-limit action that would persist a block; a
    limit that normalises to one request per minute; verifiers that confirm
    documentation addresses (that is, ones trusting the User-Agent alone);
    `ignored_ips` rules that cover published crawler ranges — a verified
    crawler must lose the rate limit, not the defences; and a missing
    `robots.txt` (warning — it steers crawlers, it protects nothing).
  - README: the three-way classification, refresh scheduling, freshness
    semantics, why permanent blocks are refused for crawlers, and the
    `robots.txt` boundary.
  - `security-guard:crawler-ranges:refresh` reports a non-2xx answer as its
    status code alone. Laravel's `RequestException` embeds the start of the
    response body in its message, so printing it verbatim would put an error
    page — or whatever an intercepting proxy or hijacked CDN chose to return
    — into the operator's terminal and into whatever aggregates cron output.
    Connection errors, parser rejections and store failures already carry
    messages that quote nothing remote.

### Upgrading from 0.2.x

No migration and no configuration change is required. While
`crawler_access.enabled` is false — the default, including for a config file
published under 0.2.x that has no `crawler_access` key at all — request
handling is byte-for-byte the v0.2.0 behaviour and no verifier is ever
constructed.

To enable it, add the `crawler_access` block to your published config (Laravel
merges only the top level of a package config file, so a published file that
predates this release will not inherit the new key), then:

1. Schedule `security-guard:crawler-ranges:refresh` and run it once.
2. Confirm `php artisan security-guard:doctor --strict` reports the range data
   as stored and fresh.
3. Set `crawler_access.enabled` to true.

Enabling it before the first refresh is safe but pointless: with no range data
nothing verifies, so every crawler stays on the public policy.

### Notes

**This release adds an outbound network path.** It is used by
`security-guard:crawler-ranges:refresh` only — never during request handling,
which reads cached data and performs no HTTP request and no DNS lookup.
Installations behind an egress policy need `developers.google.com` and
`www.bing.com` reachable from wherever the scheduler runs.

The package does not schedule the command; register it yourself. No database
table is added — range data and crawler counters live in the cache, which
should be shared across nodes so a refresh on one node serves all of them.

`guzzlehttp/guzzle` is a `suggest`, not a `require`: Laravel applications
already ship it, and hosts that bind their own `CrawlerRangeFetcherContract`
need not install it at all.

## [0.2.0] - 2026-08-04

### Added

- **CIDR matching for IP rules** (#11). `permanent_block.ignored_ips` and the
  administrative allowlist now accept networks (`203.0.113.0/24`,
  `2001:db8::/48`) alongside individual addresses.
- `security-guard:admin-ip:allow` and `:revoke` share one canonical form, so a
  rule registered as `203.0.113.42/24` — stored as `203.0.113.0/24` — can still
  be removed using what the operator originally typed.
- `security-guard:admin-ip:list` labels each rule exact or CIDR and reports how
  many addresses it admits.
- **Read-only administrative allowlist screen** at
  `security-guard/admin-allowed-ips`, behind its own
  `management_ui.admin_allowed_ips.enabled` switch in addition to
  `management_ui.enabled`. Shows the subject, the canonical rule, whether it is
  exact or a network, how many addresses it admits, and the same findings the
  doctor reports. Filtering and pagination included. No create, update or
  delete route exists: granting administrative access stays in the CLI, where a
  misconfigured authorisation rule cannot reach it. Nothing is joined onto the
  host's user table.
- Doctor checks for IP rules: unparseable entries in config or the database,
  host bits, semantic duplicates, redundant `/32` and `/128` suffixes, rules
  wider than `ip_rules.minimum_prefix`, and CIDR rules configured while an
  exact-only matcher is bound.

### Changed

- `IpMatcherContract` resolves to `CidrIpMatcher` instead of `ExactIpMatcher`.
  Exact behaviour is unchanged — a bare address is a rule with the widest
  prefix for its family — so every v0.1.x entry matches exactly what it matched
  before. `ExactIpMatcher` remains available as an explicit opt-out, with the
  caveat that under it a CIDR entry silently matches nothing.
- `security-guard:admin-ip:allow` refuses a `/0` rule unless `--force` is
  given. Such a rule admits every address in its family, which is not an
  allowlist.

### Fixed

- `ExactIpMatcher` normalised the entry but not the candidate, so
  `matches('0:0:0:0:0:0:0:1', ['::1'])` answered false for what is the same
  address. Every caller normalises first, so this never bit in practice.

### Upgrading from 0.1.x

No migration and no configuration change is required. Existing rows keep their
ids and values, and every exact rule matches exactly what it matched before.

If you published `config/security-guard.php` under 0.1.x, it has no
`management_ui.admin_allowed_ips` key. Laravel merges only the top level of a
package config file, so your published `management_ui` array replaces the
package default wholesale and the new key resolves to null — the allowlist
screen stays off, which is the intended default. Add the key by hand to opt in.

### Notes

No migration. Canonical storage keeps the widest possible value —
`ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128`, 43 characters — inside the
existing `varchar(45)` column, so v0.1.x rows are untouched and the unique
constraint still holds. An IPv4 rule never admits an IPv4-mapped IPv6 address:
allowlisting `203.0.113.0/24` is not consent to admit a v6 client encoding the
same digits.

## [0.1.0] - 2026-08-04

First public release.

### Added

- **Known attack path detection.** Exact, prefix and regex matching against a
  bundled catalogue (`wordpress_probe`, `secret_file_probe`,
  `database_admin_probe`, `phpunit_probe`, `server_probe`). Paths are
  normalised before matching — leading and trailing slashes, repeated slashes,
  backslashes, NUL bytes, case, and up to two rounds of percent-decoding.
  Query strings and request bodies are never inspected. Categories can be
  extended, replaced or disabled.
- **Persistent IP blocking.** One row per address, reused across release and
  re-block cycles, cached for fast lookup. The database decides which caller
  owns a block transition, so concurrent probes cannot each announce the same
  block.
- **Public rate limiting.** Per-IP request counting with `permanent_block`,
  `temporary_block` or `reject_only` as the response.
- **Administrative IP allowlist.** Per-subject, independent of any host user
  model, guard or primary key type. Denials return a fixed message that reveals
  nothing about the account or the registered addresses.
- **Sensitive route limits.** Named rate limiter profiles keyed on the client
  IP plus any configured identifier. Identifiers are trimmed, lower-cased and
  hashed before reaching a cache key or a log line.
- **One-time submission tokens.** For confirm-then-submit flows. Complements
  CSRF protection rather than replacing it.
- **Security event notifications.** Queued, deduplicated per block, rate
  limited per day, with `log` and `mail` channels included.
- **Error notification guard.** Aggregates a storm of host errors into a few
  messages, with a cooldown and per-channel daily limits.
- **Bundled management UI.** Optional list-and-release screen. Routes, views,
  middleware and authorisation are all replaceable.
- **Artisan commands.** `security-guard:doctor`, `security-guard:status`,
  `security-guard:blocked:list`, `security-guard:blocked:release`,
  `security-guard:admin-ip:allow`, `security-guard:admin-ip:list`,
  `security-guard:admin-ip:revoke`.
- **`security-guard:doctor`.** Pre-flight configuration checks with `--json`
  and `--strict`. This package fails quietly by design: a misconfigured module
  does not throw, it stops defending, and an empty allowlist locks out every
  administrator only when someone first tries to sign in. The doctor makes
  those visible before a module is enabled.

### Security

- Notification payloads have no field for a URL, query string, header, request
  body, exception message or stack trace, and re-validate the identifier-shaped
  values they do accept. Keeping attacker-controlled text out of outbound
  messages is enforced by the type rather than by convention.
- Rejection responses are fixed strings. No part of the request is reflected.
- Cache keys never contain a raw IP address or e-mail address; both are
  SHA-256 hashed first.
- Exception messages written to logs are truncated and can be suppressed
  entirely, because database and mail drivers put connection strings and bound
  statement values in them.
- Failure behaviour is fixed per feature rather than globally configurable.
  Public read paths fail open so a cache or database outage cannot lock out
  every visitor; known attack paths and the administrative allowlist fail
  closed.

### Notes on supported versions

Official support is limited to Laravel majors that are still inside their
upstream security-fix window, and constraint floors are the oldest patch
releases free of known advisories (`^12.61.1 || ^13.12.0`) rather than each
major's `.0`.

Laravel 10 and 11 are **not** supported. Both are past their security-fix
windows and every release of each carries unfixed advisories, so Composer 2.9+
declines to resolve them. Installing this package there would require
disabling Composer's advisory blocking, which is not a defensible instruction
for a security package. No legacy branch is offered: the unfixed
vulnerabilities are in the framework, where this package cannot reach them.

Laravel 12 leaves official support on **2027-02-24**. Releases published after
that date will target Laravel 13 and later.

### Known limitations

- IP matching is exact only. CIDR notation, IPv6 subnets and trusted internal
  networks are not supported. A CIDR entry does not raise an error — it simply
  matches nothing, which is how a monitoring address ends up unprotected.
  Planned for `v0.2.0`; the comparison is already isolated behind
  `IpMatcherContract`, so it can be added without a breaking change.
  *(Shipped in 0.2.0.)*
- The LINE Messaging API adapter is not part of this package. Register a custom
  channel on `NotifierRegistry`.

[Unreleased]: https://github.com/ashita-planning/laravel-security-guard/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/ashita-planning/laravel-security-guard/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/ashita-planning/laravel-security-guard/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/ashita-planning/laravel-security-guard/releases/tag/v0.1.0
