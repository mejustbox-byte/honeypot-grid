# Security Policy

Deploy honeypots only in isolated, monitored environments with egress control
and no route to production assets. Sanitize captured data before sharing it.

Report vulnerabilities privately through GitHub Security Advisories. Do not
publish live addresses, credentials, personal data, or weaponized samples.


## Offline MVP boundary

The current manager is mock-only: no network, container or VM provisioning.
Scope files, clock, checkout and SQLite storage are trusted local inputs.
The operator CLI flag is not authentication; restrict access through OS permissions.
Isolation declarations are validated but do not enforce host/cloud containment.
Aggregated synthetic output requires human privacy review before publication.
Do not use this MVP to process production captures or execute untrusted files.
