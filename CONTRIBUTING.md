# Contributing

Thanks for taking the time. This document covers what the tooling expects and
the conventions that are specific to a security package.

**Found a vulnerability? Do not open an issue.** Follow [SECURITY.md](SECURITY.md).

## Getting set up

Requires PHP 8.2 or newer.

```bash
git clone https://github.com/ashita-planning/laravel-security-guard.git
```

```bash
cd laravel-security-guard && composer install
```

`composer.lock` is intentionally not committed. This is a library: pinning a
lock file here would test one dependency resolution rather than the range the
package claims to support.

## The checks

```bash
composer check
```

That runs the three gates CI enforces:

```bash
vendor/bin/pint --test
```

```bash
vendor/bin/phpstan analyse --no-progress --memory-limit=512M
```

```bash
vendor/bin/phpunit
```

PHPStan runs at **level 6 with no baseline**. If analysis complains, fix the
type rather than adding an ignore. The one existing entry in
`phpstan.neon.dist` documents why it is there.

`vendor/bin/pint` fixes formatting.

### Testing against a database server

The suite runs on SQLite by default. MySQL and MariaDB are exercised in CI, and
you can run them locally:

```bash
SECURITY_GUARD_TEST_DB=mysql DB_HOST=127.0.0.1 DB_PORT=3306 DB_USERNAME=root DB_PASSWORD=secret vendor/bin/phpunit
```

MariaDB matters separately from MySQL: it reports affected rows differently,
and the atomic block path uses that count to decide who owns a block
transition.

## Supported versions

Support is tied to Laravel's upstream security-fix window, not to whatever the
code happens to run on. Constraint floors are the oldest patch releases free of
known advisories.

`SupportMatrixTest` asserts that `composer.json`, the CI matrix, the README
table and `SupportedVersions` all agree. If you change one, change them all —
the test will tell you which you missed.

Composer's advisory blocking stays enabled in CI. A version that cannot be
resolved without switching off a security check is not a supported version, so
please do not add `--no-blocking` or `policy.advisories.block: false`.

## Conventions

### Fail-open and fail-closed are per feature

These are deliberate and documented in the README. Public read paths fail open
so an outage cannot reject every visitor; known attack paths and the
administrative allowlist fail closed. If a change alters which way something
fails, say so explicitly in the pull request — it is a security decision, not
an implementation detail.

### Nothing from a request reaches an outbound message

`SecurityEventData` and `ErrorEventData` have no field for a URL, query string,
header, body, exception message or stack trace, and they re-validate what they
do accept. Please do not add one. If a notification needs more context, the
host should store it and pass a reference id.

The same applies to responses: rejection bodies are fixed strings and must not
reflect any part of the request.

### Cache keys are hashed

Addresses and identifiers such as e-mail addresses are SHA-256 hashed before
they reach a key or a log line. Use `CacheKeyFactory`; do not build keys by
hand.

### New configuration

Read it with a default at the point of use. `mergeConfigFrom` only merges the
top level of the config file, so a host that publishes a partial file must not
break. Only `config/security-guard.php` may call `env()`.

## Tests

A bug fix should come with a test that fails without it. For anything touching
blocking, limiting or notification delivery, please cover the degraded path as
well: a broken cache, a database that cannot be read, a channel that fails.
Those paths are where this package either holds up or quietly stops working,
and they are easy to regress.

Test names read as sentences describing the behaviour
(`test_a_rate_limit_exclusion_does_not_lift_an_existing_block`), and comments
explain why a case matters rather than restating the code.

## Pull requests

- Branch from `main`.
- Keep one concern per pull request.
- Update `CHANGELOG.md` under `## [Unreleased]`.
- Update the README when behaviour or configuration changes.
- Make sure `composer check` passes locally; CI runs the same gates across
  Laravel 12 and 13, PHP 8.2 to 8.5, MySQL and MariaDB.

For a behavioural change, please describe what an operator would observe
differently, and whether an existing installation needs to do anything.

## Scope

Deliberately outside this package: WAF and CDN behaviour, CAPTCHA and MFA,
geolocation and IP reputation, automatic input validation for business routes,
and any coupling to a specific user model, guard or admin panel. Host
integration belongs behind the existing contracts.

CIDR support is planned for `v0.2.0` and tracked in
[#11](https://github.com/ashita-planning/laravel-security-guard/issues/11).
