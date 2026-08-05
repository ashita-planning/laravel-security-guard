# Security Policy

## Supported versions

Security fixes are published only for releases running on a Laravel major that
is still inside its own upstream security-fix window.

| Package | Laravel | PHP | Status | Laravel security fixes end |
| --- | --- | --- | --- | --- |
| `0.3.x` | 13.x (>= 13.12.0) | 8.3, 8.4, 8.5 | Supported | 2028-03-17 |
| `0.3.x` | 12.x (>= 12.61.1) | 8.2, 8.3, 8.4 | Supported | 2027-02-24 |
| `0.2.x` | 13.x (>= 13.12.0) | 8.3, 8.4, 8.5 | Supported | 2028-03-17 |
| `0.2.x` | 12.x (>= 12.61.1) | 8.2, 8.3, 8.4 | Supported | 2027-02-24 |
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
  admin allowlist, submission tokens, notifications, management UI, verified
  crawler access)
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
- A CIDR boundary decided wrongly, so a rule admits or refuses an address
  outside what its prefix describes
- An IPv4 rule admitting an IPv6 address, or the reverse
- A non-canonical rule quietly granting or refusing more than it appears to
- Information disclosure from the administrative allowlist screen, including
  anything that reveals host account attributes rather than the stored
  `subject_type` and `subject_id`
- Any write path reaching the allowlist screen, which is read-only by design
- A request reaching `verified` crawler status without its address being
  inside the provider's published ranges — including through a spoofed
  User-Agent, missing, stale or corrupted range data, or a failure in the
  verifier, registry or cache
- A verified crawler bypassing IP blocking, attack path detection or the
  ignore list, which verification must never excuse
- Range data written from a source other than the configured provider URLs, or
  a malformed document replacing known-good ranges

### Out of scope

- Vulnerabilities in Laravel itself, or in an unsupported Laravel version
- Denial of service from a deliberately misconfigured threshold, for example
  `requests_per_minute` set to `1`
- Missing hardening on paths a host explicitly listed in
  `permanent_block.excluded_paths`, which documents itself as waiving the guard
- Attacks needing a cache or database an attacker can already write to
- Anything requiring an already-compromised administrator session
- Absence of features this package documents as out of scope, including WAF
  behaviour, CAPTCHA and MFA

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
- **IP rules fail closed.** An entry that cannot be parsed matches nothing
  rather than everything, so a typo locks its owner out instead of admitting
  strangers. Families never cross: an IPv4 rule does not admit an IPv4-mapped
  IPv6 address.
- **Administrative access is granted from the CLI only.** The bundled allowlist
  screen is read-only and ships disabled behind its own opt-in; the package
  registers no route that creates, edits or deletes an allowlist rule.
- **Responses are fixed strings.** Nothing from the request is reflected back.
- **A User-Agent never verifies a crawler.** Both Google and Bing document
  theirs as spoofable, so the header only nominates a candidate; the decision
  is made against published address ranges. Every failure to confirm —
  including no data, expired data and a throwing verifier — yields
  `unverified`, which means the ordinary public policy: neither crawler
  privileges nor punishment.
- **Request handling never reaches the network.** Crawler verification reads
  cached data only. The single outbound path in the package is
  `security-guard:crawler-ranges:refresh`, which validates a document
  completely before storing it and keeps the previous data on any failure.
- **A verified crawler is never permanently blocked for its rate.** Exceeding
  the crawler budget answers 429 or 503 with `Retry-After` and records
  nothing, and a failure in the crawler limiter itself fails open rather than
  falling back to a public policy that could block the crawler outright.
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
