# Roadmap

The first alpha release is v0.1.0-alpha.1 (package 0.1.0a1); stable/production readiness remains open. Completed implementation and infrastructure acceptance are tracked separately; passing mocked tests does not complete a laboratory milestone.

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
- [x] Versioned sensor delivery, atomic receipts, replay/rotation/retention and bounded local/Docker collectors.
- [x] Hash-approved opt-in QEMU TCG executor, sealed artifacts/input, bounded results and process cleanup.
- [x] Reviewed-file deterministic initramfs packer and fixed lab-probe command.

## Development environment acceptance

- [x] Documentation-era Cloud snapshot restored at 4220023 with Python 3.14.7 and smoke exit 0.
- [x] Published product bootstrap snapshot checks passed locally (84 tests); current VM/delivery implementation passes 129 local tests.
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
- [x] Local sensor-to-ingest transport, schema validation, bounded delivery and retry recovery.
- [ ] Actual Docker-log delivery and outage recovery on an approved lab host.
- [x] Disposable file VM executor adapter, bounded output and fail-closed approval.
- [ ] Actual approved guest boot, hostile-output/deadline tests and verified VM teardown.
- [ ] Optional selected LLM provider, secret handling and offline evaluation against false findings.
- [ ] Supply-chain review, license inventory/SBOM and independent security review before product release.

## Release gate

The owner explicitly authorized the first release with local-infrastructure acceptance documented as user work. Alpha may be merged/released after code/package/docs checks with unverified lab gates clearly recorded in [LOCAL-PC.md](LOCAL-PC.md). These gates still block a stable production release. See [RELEASE-NOTES.md](RELEASE-NOTES.md) and [RELEASE-CHECKLIST.md](RELEASE-CHECKLIST.md). STIX interoperability, multi-tenancy and scale-out remain future scope.
