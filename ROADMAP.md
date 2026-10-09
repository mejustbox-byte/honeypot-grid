# Roadmap

## Implemented

- Scoped configuration, digest allowlists, dry-run planning, and expiring
  single-use approvals for laboratory actions.
- Local telemetry, bounded storage, synthetic event processing, and report
  generation.
- Opt-in Docker and QEMU adapters with explicit runtime and cleanup checks.
- CLI packaging, CI workflows, and documentation for installation and lab use.

## Before stable release

- Validate Docker and QEMU containment on the dedicated Linux laboratory host.
- Exercise crash recovery, TTL cleanup, and orphan-process handling.
- Verify IPv4 and IPv6 egress restrictions with sentinel tests.
- Review resource limits, retention behavior, and recovery procedures.

## Future scope

STIX interoperability, multi-tenant operation, and scale-out require separate
design and security review. Real production deployment is outside the current
alpha scope.
