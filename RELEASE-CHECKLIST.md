# Product release readiness

Scope: first alpha v0.1.0-alpha.1 (package 0.1.0a1), explicitly authorized by the owner with local-infrastructure work documented in [LOCAL-PC.md](LOCAL-PC.md). Alpha requires code/docs/package checks and truthful limits; it does not assert production readiness. Stable release remains blocked by the lab gates below.

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

The first alpha is already published at tag v0.1.0-alpha.1 on a59f6af82a471dde95ce1fcf058273b45c5f489b; documentation and product PRs #1–#4 are merged. CI and the release workflow succeeded on main a175a559f4e625f3dd5351b602e559582478a701. Existing published assets and the tag must not be replaced by a documentation recheck. For stable release, all gates above must pass. Publish only from the reviewed commit with version/tag alignment, artifact hashes, test evidence, known limits and rollback/teardown instructions. Do not label mock-only or partial lab functionality as a complete production release.

Latest local acceptance (2026-10-09): cloud_check.sh exit 0 under umask 0077 on Python 3.14.7; 129 tests, lint/format, docs 14/46, CLI and packaging pass. Fresh wheel installation and CLI outside checkout passed. lab_preflight.py exit 2: QEMU/Docker/socket/KVM absent, account root, approved boot artifacts absent. No VM boot or Docker lab probe ran. This evidence does not update the published Cloud snapshot 71de654 or close its isolated-task socket failures.

Repeat verification (2026-10-09, main a175a55): 129 tests, Ruff lint/format, 16 documents/60 links, installed CLI smoke, wheel/sdist, fresh wheel installation and CLI outside checkout, private-umask key regression and shell syntax checks passed. Lab preflight exit 2: no Docker/QEMU/socket/KVM, root account and no approved boot artifacts. This is current-container evidence, not a saved Cloud snapshot restore or real lab acceptance. No stable release is justified by these checks.

Budget decision (2026-10-09): no budget is available for paid cloud resources.
Do not provision paid VMs/subscriptions. The owner will supply an existing or
local dedicated Linux lab and perform the real acceptance steps in
[LOCAL-PC.md](LOCAL-PC.md). Deferred checks remain not-run; this decision does
not waive stable gates or promote v0.1.0-alpha.1 to stable.
