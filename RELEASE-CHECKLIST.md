# Product release readiness

Status: not ready. The owner authorized merge/release once ready; no merge, tag or GitHub release is issued by this checklist. Version 0.1.0 in pyproject.toml is package metadata.

| Gate | Required evidence | Current status |
| --- | --- | --- |
| Reproducible development | Current Cloud snapshot, pinned versions, new-task restore and recorded check exits | Snapshot 71de654 published; restore/versions/sync pass; full task check exit 1 (81 pass, 3 socket failures) |
| Code validation | Unit/integration, lint/format, CLI smoke, wheel/sdist and clean diff | 129 tests, lint/format, CLI, 14 docs/46 links, wheel/sdist and fresh wheel install pass |
| Runtime containment | Actual dedicated VM Docker lifecycle, IPv4/IPv6 synthetic sentinels and host boundary review | Not run |
| TTL and recovery | Independent supervisor, Docker/manager failure, bounded cleanup and no orphan resources | Fake adapter tests pass; real acceptance pending |
| End-to-end observations | Sensor-to-ingest delivery with bounds, privacy canaries, retention and outage recovery | Local end-to-end pipeline and retry pass; Docker collector implemented, real acceptance open |
| File analysis | Disposable VM executor, no network/credentials, time/output limits and verified destruction | QEMU adapter/initramfs packer implemented; real approved boot/teardown not run |
| Export and analysis | Evidence-bound outputs, one-use review, provenance/privacy evaluation | Synthetic offline profile tested; production review pending |
| Supply chain | Approved image provenance, dependency/license inventory, SBOM, artifact hashes | Container images/release inventory not approved |
| Operations | Closed scope, budget, ownership, incident contacts, teardown and independent security review | Infrastructure not selected |

Once gates pass: review draft documentation PR #1 and product PR #2; merge the documentation base first, retarget the product PR to main and rerun required checks on the final merge candidate. Publish only from the reviewed commit with version/tag alignment, artifact hashes, test evidence, known limits and rollback/teardown instructions. Do not label mock-only or partial lab functionality as a complete production release.

Latest local acceptance (2026-10-09): cloud_check.sh exit 0 under umask 0077 on Python 3.14.7; 129 tests, lint/format, docs 14/46, CLI and packaging pass. Fresh wheel installation and CLI outside checkout passed. lab_preflight.py exit 2: QEMU/Docker/socket/KVM absent, account root, approved boot artifacts absent. No VM boot or Docker lab probe ran. This evidence does not update the published Cloud snapshot 71de654 or close its isolated-task socket failures.
