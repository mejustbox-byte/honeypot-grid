# Release Checklist

- [ ] Source commit has passing CI for tests, lint, formatting, docs, and package.
- [ ] Wheel and source archive install from a clean environment.
- [ ] Release notes describe supported behavior and known limitations.
- [ ] Synthetic examples contain no customer or provider data.
- [ ] Docker/QEMU containment, recovery, egress, and cleanup checks pass on the
      dedicated laboratory host.
- [ ] SBOM and dependency/security review are attached to the release.
- [ ] Published assets match the reviewed source commit and checksums.
- [ ] Alpha and stable status are labeled accurately; untested lab gates remain
      explicit.
