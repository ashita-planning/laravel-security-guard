# Security Policy

## Supported versions

Security fixes are published only for releases running on a Laravel major that
is still inside its own upstream security-fix window.

| Package | Laravel | PHP | Status | Laravel security fixes end |
| --- | --- | --- | --- | --- |
| `0.1.x` | 13.x (>= 13.12.0) | 8.3, 8.4, 8.5 | Supported | 2028-03-17 |
| `0.1.x` | 12.x (>= 12.61.1) | 8.2, 8.3, 8.4 | Supported | 2027-02-24 |
| — | 11.x | — | Not supported | ended 2026-03-12 |
| — | 10.x | — | Not supported | ended 2025-02-04 |

Constraint floors are the oldest patch releases of each line free of known
advisories, not each major's `.0`. Running below them means Composer's advisory
policy would refuse the install.

Laravel 12 support ends on **2027-02-24**. Package versions published after
that date will target Laravel 13 and later.

## Reporting a vulnerability

**Do not open a public issue for a security problem.**

Report it privately through GitHub's advisory form:

<https://github.com/ashita-planning/laravel-security-guard/security/advisories/new>

Please include:

- affected package version, Laravel version and PHP version
- which module is involved (attack path detection, IP blocking, rate limiting,
  admin allowlist, submission tokens, notifications, management UI)
- what an attacker gains, and the conditions required
- a minimal reproduction if you have one

### What to expect

| Stage | Target |
| --- | --- |
| Acknowledgement | 3 business days |
| Initial assessment | 10 business days |
| Fix or mitigation for a confirmed high-severity issue | 30 days |

If a report is disputed you will get the reasoning, not silence.

Credit is given in the advisory and the changelog unless you ask otherwise.

## Scope

### In scope

- Bypassing attack path detection, IP blocking or rate limiting
- Blocking or locking out addresses that should not be affected, where the
  cause is in this package
- Attacker-controlled data reaching a notification body, log entry or the
  management UI
- Privilege or authorisation flaws in the bundled management UI
- Insufficient randomness or a race in one-time submission tokens
- Injection through configuration this package parses

### Out of scope

- Vulnerabilities in Laravel itself, or in an unsupported Laravel version
- Denial of service from a deliberately misconfigured threshold, for example
  `requests_per_minute` set to `1`
- Missing hardening on paths a host explicitly listed in
  `permanent_block.excluded_paths`, which documents itself as waiving the guard
- Attacks needing a cache or database an attacker can already write to
- Anything requiring an already-compromised administrator session
- Absence of features this package documents as out of scope, including CIDR
  matching, WAF behaviour, CAPTCHA and MFA

## What this package does not do

It is one application-layer control, not a replacement for a WAF, a CDN, or
web server and network configuration. It does not fix SQL injection, XSS or
broken authorisation in the host application, and it does not validate the
input of business routes — those still need their own FormRequests.

## Design decisions relevant to review

- **Failure behaviour is fixed per feature, not configurable.** Public read
  paths fail open, because a cache or database outage must not reject every
  visitor. Known attack paths and the administrative allowlist fail closed.
- **Notification DTOs cannot carry request data.** There is no field for a URL,
  query string, header, body, exception message or stack trace, and the
  identifier-shaped fields that do exist are re-validated on construction.
- **Cache keys are hashed.** No raw IP address or e-mail address appears in a
  key.
- **Responses are fixed strings.** Nothing from the request is reflected back.
- **Host-supplied regular expressions are attacker-adjacent.** They are
  compiled defensively and an invalid pattern is skipped rather than raised,
  but a pathological pattern can still cause backtracking. Review additions to
  `attack_patterns` for ReDoS.

## Verifying an installation

```bash
php artisan security-guard:doctor --strict
```

This checks the running Laravel version against the supported floors, the
database and cache prerequisites, the IP resolver and trusted proxies, the
attack path patterns, and whether the administrative allowlist or management UI
are configured in a way that would lock people out or expose the release
action. Exit codes: `0` healthy, `1` failure, `2` warnings under `--strict`.
