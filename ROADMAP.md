# Roadmap

The project remains unreleased. Completed implementation and infrastructure acceptance are tracked separately; passing mocked tests does not complete a laboratory milestone.

## Implemented and locally verified

- [x] Architecture, threat model, fixed development stack and documentation checks.
- [x] Strict configuration/scope, digest allowlist, dry-run, owner/expiry/single-use approval.
- [x] Mock lifecycle, concurrency/restart idempotency, private SQLite, quotas and clock checkpoints.
- [x] Opt-in Docker network-none adapter: resource/security inspection, durable provisioning, cleanup and inventory recovery (fake runner tests).
- [x] Bounded synthetic localhost HTTP/SSH sensors without shell or credentials.
- [x] HMAC ingestion, versioned minimal schema, retention, aggregate privacy canaries.
- [x] Opaque bounded quarantine and expiry purge; archive metadata limits on harmless fixtures.
- [x] Synthetic IoC profile with provenance/confidence/expiry and one-use reviewed export.
- [x] Offline analysis and hash/schema/evidence-bound proposal validation without tools.
- [x] Installed CLI, wheel/sdist, pinned CI and reproducible cloud install/check scripts.

## Development environment acceptance

- [x] Documentation-era Cloud snapshot restored at 4220023 with Python 3.14.7 and smoke exit 0.
- [x] New product bootstrap and offline checks pass locally (84 tests).
- [x] Product snapshot 71de654 installed and fully checked in Cloud setup VM (84 tests; checks exit 0).
- [x] Updated install/start instructions saved and Republish completed; private access and internet disabled retained.
- [x] New task restored at 71de654; actual HEAD/versions and clean tracked state verified.
- [ ] Full new-task checks: offline sync exit 0, cloud_check exit 1 (81 passed, 3 localhost socket failures). Resolve the execution-environment compatibility without weakening isolation.

The published product snapshot supersedes the previous documentation snapshot. Follow [CLOUD-DEVELOPMENT.md](CLOUD-DEVELOPMENT.md) for the current setup and any publication blockers.

## Laboratory and product work remaining

- [ ] Dedicated lab infrastructure, approved scope, routes, resource budget and authenticated control plane.
- [ ] Actual Docker start/stop, crash recovery, independent TTL supervisor and orphan checks.
- [ ] IPv4/IPv6 DNS/metadata/sibling/control-plane/production sentinel tests.
- [ ] Approved ingress topology; current network-none profile has no external ingress.
- [ ] Sensor-to-ingest transport with schema validation, bounded delivery and failure recovery.
- [ ] Disposable file VM/microVM executor, bounded output and verified teardown.
- [ ] Optional selected LLM provider, secret handling and offline evaluation against false findings.
- [ ] Supply-chain review, license inventory/SBOM and independent security review before product release.

## Release gate

The owner's permission to merge and release applies when readiness is established. Current package version 0.1.0 is not an issued release. Draft PRs stay unmerged until the relevant acceptance gates and [RELEASE-CHECKLIST.md](RELEASE-CHECKLIST.md) are complete. STIX interoperability, multi-tenancy and scale-out orchestration remain future scope.
