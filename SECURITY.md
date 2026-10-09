# Security Policy

Report vulnerabilities privately through GitHub Security Advisories. Do not publish live addresses, credentials, personal data, raw captures or weaponized samples. Use only harmless synthetic fixtures in git, CI and public reports.

## Current boundaries

Mock is the default runtime. The opt-in Docker network-none adapter is for a separately approved dedicated lab VM, with no production routes or host credentials. The operator's VM attestation is an assertion, not independent containment evidence. No host paths, runtime socket, ports or devices may be mounted into a sensor. The trusted manager uses the Docker socket only on the approved lab host; never expose it to samples, sensors or a public API.

Scope, checkout, local OS identity and SQLite ownership are trusted. --operator is not authentication. Private database/key permissions, size quotas, hash-bound approval and clock high-water checks reject several accidental or hostile inputs; an OS administrator can still edit state or clock. Audit is transactional locally, not externally tamper-proof. Runtime operations require durable transitions and compensating cleanup because external effects cannot be rolled back by SQLite.

Reconciliation must run under an independent supervisor. CLI TTL checks do not guarantee shutdown when the manager or host is stopped. Quarantine only copies bounded opaque bytes. The opt-in QEMU executor requires reviewed kernel/initramfs hashes, one-use scope-bound approval and a non-root dedicated Linux lab account. It has no NIC, host mounts, credentials, monitor or writable persistent disk; input and artifacts are sealed, output/time are bounded, and process cleanup/parent-death enforcement is implemented. These controls have not yet been accepted through a real guest boot. Never run static_metadata on untrusted files on the development host. Resource limits alone are not a sandbox.

Telemetry HMAC is pseudonymization, not anonymity. Aggregates require human privacy review; SHA256 indicators can also reveal sensitive file provenance. Export approval is local, single-use and hash-bound; output goes to stdout, not a publication service. Structured model proposals cannot execute tools or change runtime policy.

## Deployment status

Real Docker/VM containment tests, production routing isolation, sample VM cleanup and Docker sensor transport are not verified. The stdout delivery protocol and local/Docker collectors are implemented; local end-to-end delivery and restart/replay checks pass, while the Docker path uses fake runners here. Remote authentication is not implemented. Development test results do not establish production readiness. Release gates are in [RELEASE-CHECKLIST.md](RELEASE-CHECKLIST.md), operational details in [RUNBOOK.md](RUNBOOK.md).

For a suspected containment incident, isolate the affected lab, stop provisioning, preserve only necessary evidence privately and review credentials and routes before recovery. Do not publish samples or raw logs.
