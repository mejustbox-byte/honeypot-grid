# Development stack

## Decision and fixed versions

Python provides one maintainable language for manager policy, privacy, bounded metadata processing and local tooling. Enforcement belongs to the lab VM/runtime; Python is not a sandbox. The project has no third-party runtime dependencies.

| Area | Current choice | Reason / boundary |
| --- | --- | --- |
| Runtime | CPython 3.14.7, Linux x86_64 cloud development | Verified target, fixed in .python-version; package requires >=3.14,<3.15 |
| Package manager | uv 0.12.19 | Locked sync and offline cache; uv.lock records development dependencies |
| Tests | pytest 9.1.1 | Unit, fake-runtime integration and harmless localhost sensor tests |
| Lint / format | Ruff 0.16.10 | Unified checks configured in pyproject.toml |
| Packaging | setuptools 80.9.0 | Console entry point, wheel/sdist; private/cache directories excluded |
| Storage | stdlib SQLite, JSON and HMAC-SHA256 | Private single-host state with quotas; not multi-tenant authentication |
| Sensor runtime | Docker Engine on approved dedicated Linux VM | cgroup v2 + seccomp + AppArmor/SELinux; fixed local image digest; network none |
| File sandbox | Disposable VM/microVM required, executor absent | A container or process resource limit is insufficient |
| Analysis | Offline rules and validated proposal files | No installed LLM SDK/provider, no tool execution |
| CI | GitHub Actions, read-only contents | checkout v4.2.2/setup-python v5.6.0 pinned to SHA; Python 3.14.7 |

Go, Kubernetes, brokers and PostgreSQL are deferred until delivery/scale measurements justify another runtime or service. Compose and rootless support are not supplied by the current adapter. No strict type checker or web UI/API is currently configured.

## Reproducibility and supply chain

Use uv sync --locked; dependency updates require manifest/lock review. uv build caches the exact build requirement before offline checks. MANIFEST.in includes docs/scripts/examples and excludes .cloud-env, .venv, quarantine and lab-private. LICENSE remains the original MIT text. Do not use floating container tags; examples contain a fictional digest that must never be treated as a real approved image.

CI runs lint/format, pytest, documentation and installed CLI smoke, packaging and cloud-script syntax/capability checks. Hosted CI status must be checked separately; local success does not establish a hosted run. Dependency vulnerability/license inventory and release SBOM are release gates, not yet completed.

## Cloud acceptance

Only mejustbox-byte/honeypot-grid belongs to this environment. Keep access private, project secrets absent and agent internet disabled. Do not read or print platform authentication. Use [CLOUD-DEVELOPMENT.md](CLOUD-DEVELOPMENT.md) for installation/startup and [RUNBOOK.md](RUNBOOK.md) for lab limits.

On 2026-10-09, product snapshot 71de654 passed full setup VM checks (84 tests, lint/format, documentation, CLI, wheel/sdist; exit 0) and was saved/published. A fresh task restored the same HEAD and pinned versions with clean tracked state and offline sync exit 0. Full cloud_check exited 1: 81 passed, 3 localhost socket failures in tests/test_sensor.py. Setup success therefore does not establish full verification in an isolated task. Keep those integration tests mandatory in a loopback-capable environment; do not weaken network isolation or report excluded tests as passed. See [ROADMAP.md](ROADMAP.md).

A GitHub proxy 403 was observed during setup; verified code bundles and the official hash-checked setuptools wheel were imported using standard attachments, with internet disabled/private access retained. This single network result is not proof of all containment. Docker presence and absent KVM do not qualify Cloud as a sample laboratory.

## Primary references

- [uv project locking/sync](https://docs.astral.sh/uv/concepts/projects/sync/)
- [pytest](https://docs.pytest.org/en/stable/getting-started.html)
- [Ruff](https://docs.astral.sh/ruff/)
- [Docker container options](https://docs.docker.com/engine/containers/run/)
- [OpenAI Cloud environments](https://learn.chatgpt.com/docs/environments/cloud-environments)
