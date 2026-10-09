# Development Stack

## Runtime and tooling

| Area | Choice | Purpose |
| --- | --- | --- |
| Runtime | CPython 3.14.7 on Linux x86_64 | Manager, policy, telemetry, and command-line tools |
| Dependency management | uv 0.12.19 with `uv.lock` | Reproducible development dependencies |
| Tests | pytest 9.1.1 | Unit and synthetic integration coverage |
| Lint and format | Ruff 0.16.10 | Static checks and formatting |
| Packaging | setuptools 80.9.0 | Wheel, source distribution, and console entry point |
| State and evidence | SQLite, JSON, HMAC-SHA256 | Bounded local state with integrity checks |
| Sensor runtime | Docker Engine on Linux | Disposable network-isolated lab workloads |
| Optional file sandbox | QEMU TCG on a dedicated Linux host | Isolated analysis of approved test samples |

The application has no third-party runtime dependencies. Python coordinates
policy and evidence processing; containment is enforced by the host runtime
and laboratory configuration.

## Reproducibility

Use the pinned versions in `.python-version`, `pyproject.toml`, and
`uv.lock`. CI runs tests, lint, formatting, packaging, and documentation
checks. Sensor and VM acceptance requires the dedicated laboratory described
in [lab/README.md](lab/README.md) and [RUNBOOK.md](RUNBOOK.md).

Never place provider credentials, customer data, or production samples in the
source tree. Synthetic fixtures do not prove runtime isolation or the behavior
of a live deployment.
