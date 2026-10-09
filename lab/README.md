# Disposable metadata VM laboratory

The adapter exists; no real guest boot or Docker isolation acceptance has run in
the development workspace. Unit fixtures are harmless bytes, not boot images.
This directory contains public templates only. Private artifacts/configs belong
under lab-private and must never be committed or attached to public reports.

## Required host and boot artifacts

Use an approved dedicated Linux x86_64 lab host without production routes or
credentials. Run QEMU as a non-root lab user. A root-owned, non-writable,
non-setuid /usr/bin/qemu-system-x86_64 with seccomp support is required. Record
its exact vendor version/provenance and dependency/license review. The fixed
profile uses QEMU TCG, so KVM is optional; CPU/memory/deadline limits do not
replace host cgroup/MAC policy or a hypervisor security review.

Choose and review a Linux kernel with built-in initramfs, serial console,
devtmpfs, proc/sysfs and virtio PCI/block support. Provide trusted BusyBox,
setpriv, CPython 3.14 and every required shared library/standard-library file
from official vendor packages. No login service, network configuration,
credentials, remote agent or sample goes into the guest image. The packer does
not discover dependencies, install packages or declare their provenance valid.

Copy the reviewed vendor files into a private 0700 directory as regular 0600
files, resolving vendor symlinks explicitly. A bounded JSON build manifest has
exactly this shape; SHA256 values below are placeholders, not approved hashes:

```json
{
  "credentials_absent": true,
  "files": [
    {"source": "/ABSOLUTE/lab-private/vendor/busybox", "target": "bin/busybox", "sha256": "REPLACE_WITH_ACTUAL_SHA256", "executable": true},
    {"source": "/ABSOLUTE/lab-private/vendor/python3", "target": "usr/bin/python3", "sha256": "REPLACE_WITH_ACTUAL_SHA256", "executable": true},
    {"source": "/ABSOLUTE/lab-private/vendor/setpriv", "target": "usr/bin/setpriv", "sha256": "REPLACE_WITH_ACTUAL_SHA256", "executable": true}
  ]
}
```

Add all reviewed dependencies with guest targets under lib/, lib64/, usr/lib/
or usr/lib64/. Manifest input is limited to 16 KiB; a reviewed vendor standard-library ZIP at usr/lib/python314.zip can keep the file list bounded. Source files must be private
regular files with trusted parents; symlinks, special files, path traversal,
unknown boot binaries, home/config directories and mismatched hashes fail closed.
The credentials_absent assertion requires operator review; it is not a scanner.

```sh
uv run --locked python scripts/build_vm_initramfs.py --manifest lab-private/guest-files.json --output lab-private/guest.cpio
```

The deterministic newc image adds the reviewed repository vm-init template as
/init and project Python modules under /opt. It uses fixed root ownership and
zero timestamps; size is bounded to 128 MiB. No sample filesystem is mounted.
The guest init mounts proc/sysfs/devtmpfs, exposes the single raw /dev/vda input,
then runs the worker as UID/GID 65532 with all capabilities removed and
no-new-privileges. Python isolated mode loads only the fixed /opt code path and
vendor standard library. The trusted init powers off after the worker exits.

## Private execution manifest and scope

Hash the kernel and resulting initramfs. Both files require private 0600 copies.
Execution manifest fields are exact; placeholders below must be replaced with
real reviewed artifacts and your closed authorization record:

```json
{
  "operator": "lab-operator",
  "authorization_ref": "approved-lab",
  "dedicated_lab_vm": true,
  "no_production_routes": true,
  "no_host_credentials": true,
  "kernel": "/ABSOLUTE/lab-private/kernel",
  "initrd": "/ABSOLUTE/lab-private/guest.cpio",
  "kernel_sha256": "REPLACE_WITH_ACTUAL_SHA256",
  "initrd_sha256": "REPLACE_WITH_ACTUAL_SHA256"
}
```

The separate trusted scope has only operator, authorization_ref, kernel_sha256
and initrd_sha256. It is not supplied by a file sample or event. See
[RUNBOOK.md](../RUNBOOK.md) for vm-plan/approve/run commands. Plan hashing binds
paths, artifact hashes, sample hash/size, scope, nonce, policy and expiry.
Kernel/initramfs/sample are checked again and copied into sealed memfd inputs
before launch, preventing a path swap from changing the data already approved.

QEMU has a fixed device list, no NIC/display/monitor/host filesystem sharing,
read-only format=raw input disk, one TCG vCPU and 256 MiB RAM. The guest worker
parses at most 1 MiB of sample bytes, never executes them, and never extracts
archive contents. The host only hashes opaque sample bytes. It accepts one
bounded HPG/1 result with matching nonce/sample hash and allowlisted metadata;
guest output is untrusted and its no-NIC report is not independent attestation.

The launcher caps stdout/stderr at 64 KiB, wall time at 30 seconds, CPU/address
space and core/file output. It uses a clean environment, closes other FDs,
no-new-privileges, process-group kill/reap and a Linux parent-death signal.
There are no persistent writable VM disks to remove. A killed manager leaves
a terminal running database record; verify host process inventory and prepare
a new job rather than resetting or reusing approval. Root/admin compromise,
host OOM/reboot, storage snapshots and hypervisor escapes require separate review.

## Actual acceptance checklist

- Verify guest boot and poweroff with harmless opaque and ZIP fixtures; compare
  exact SHA256/size and check no filenames/contents survive in returned metadata.
- Run bad hash/nonce/schema, huge output, busy loop and guest failure cases using
  reviewed harmless guest test images. Confirm deadline/output rejection and no
  live QEMU process, memfd or writable disk remains after normal/error/parent death.
- Check no NIC, no shared host paths, no credentials and enforced host cgroup/MAC
  policy independently of guest self-report. Review boot/package provenance.
- On an approved Docker observing plan, use lab-probe for fixed harmless IPv4/IPv6
  documentation-range route denial and guest privilege/rootfs checks. Preserve
  only the summarized result; run independent closed-scope host/provider sentinel,
  failure/TTL and orphan-inventory checks before ingress or release.
- Validate real Docker sensor logs → collect-docker → private report, repeated
  snapshots, quota/outage recovery and collector-before-teardown ordering. The
  sensor emits at most 1000 events; local log rotation is not a remote durable broker.

References: [QEMU invocation](https://www.qemu.org/docs/master/system/qemu-manpage.html),
[QEMU security](https://www.qemu.org/docs/master/system/security.html).
