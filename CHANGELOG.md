# Changelog

All notable changes to `apkk/laravel-security-guard` are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

While the version is below `1.0.0`, breaking changes may land in a minor
release. They will always be listed under **Changed** or **Removed** with a
migration note.

## [Unreleased]

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
- The LINE Messaging API adapter is not part of this package. Register a custom
  channel on `NotifierRegistry`.

[Unreleased]: https://github.com/ashita-planning/laravel-security-guard/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/ashita-planning/laravel-security-guard/releases/tag/v0.1.0
