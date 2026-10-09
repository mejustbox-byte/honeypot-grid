# Changelog

## Unreleased — 2026-10-09

No product release/tag has been issued.

### Added

- Architecture, threat model, private vulnerability reporting and contribution/release workflow.
- Strict bounded configuration/scope, dry-run, hash-bound approval and TTL lifecycle manager.
- Private SQLite/key storage, quotas, clock rollback rejection and local metadata audit.
- Synthetic HTTP/SSH sensors and opt-in Docker network-none adapter with inspection, durable transitions and compensating cleanup.
- HMAC telemetry ingestion, retention, aggregate suppression and reviewed synthetic IoC/report export.
- Opaque quarantine, expiry purge, bounded static metadata worker and explicit unavailable VM executor plan.
- Offline analysis and structured proposal validation without tools or network requests.
- Installed CLI, pinned development lock/CI, wheel/sdist and end-to-end CLI smoke.
- Reproducible cloud install/offline check scripts and Docker/KVM capability report.

### Changed

- All product documentation distinguishes implemented code, locally verified behavior and unverified infrastructure gates.
- Source distribution includes public docs/scripts/examples and excludes private/cache directories.
- CI uses private temporary state instead of a database directly under writable /tmp.
- Original LICENSE is preserved.
- Key permission test explicitly sets its non-private fixture mode and passes under umask 0077.

### Validation and limits

- Local: 84 tests, Ruff lint/format, CLI smoke, docs/link checks, source/wheel build and fresh wheel installation passed.
- Documentation-era Cloud restore at commit 4220023 passed; product snapshot update is in progress and is not yet accepted.
- Hosted CI, real Docker/VM containment, VM sample execution, independent TTL teardown and automatic sensor transport are not established by these local results.

## Initial scaffold

- Initial project requirements, isolation/privacy goals, MIT LICENSE and security notice.
