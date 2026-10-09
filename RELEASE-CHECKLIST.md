# Product release readiness

Status: not ready. The owner authorized merge/release once ready; no merge, tag or GitHub release is issued by this checklist. Version 0.1.0 in pyproject.toml is package metadata.

| Gate | Required evidence | Current status |
| --- | --- | --- |
| Reproducible development | Current Cloud snapshot, pinned versions, new-task restore and recorded check exits | Local checks pass; Cloud update pending |
| Code validation | Unit/integration, lint/format, CLI smoke, wheel/sdist and clean diff | 84 tests and local checks pass |
| Runtime containment | Actual dedicated VM Docker lifecycle, IPv4/IPv6 synthetic sentinels and host boundary review | Not run |
| TTL and recovery | Independent supervisor, Docker/manager failure, bounded cleanup and no orphan resources | Fake adapter tests pass; real acceptance pending |
| End-to-end observations | Sensor-to-ingest delivery with bounds, privacy canaries, retention and outage recovery | Automatic transport missing |
| File analysis | Disposable VM executor, no network/credentials, time/output limits and verified destruction | Executor missing |
| Export and analysis | Evidence-bound outputs, one-use review, provenance/privacy evaluation | Synthetic offline profile tested; production review pending |
| Supply chain | Approved image provenance, dependency/license inventory, SBOM, artifact hashes | Container images/release inventory not approved |
| Operations | Closed scope, budget, ownership, incident contacts, teardown and independent security review | Infrastructure not selected |

Once gates pass: review draft documentation PR #1 and product PR #2; merge the documentation base first, retarget the product PR to main and rerun required checks on the final merge candidate. Publish only from the reviewed commit with version/tag alignment, artifact hashes, test evidence, known limits and rollback/teardown instructions. Do not label mock-only or partial lab functionality as a complete production release.
