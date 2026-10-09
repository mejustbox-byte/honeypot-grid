"""Presence only. Exit 2 if lab prerequisites are absent; no services or probes."""

import json
import os
from pathlib import Path


def main():
    qemu = Path("/usr/bin/qemu-system-x86_64").is_file()
    docker = Path("/usr/bin/docker").is_file()
    socket = Path("/var/run/docker.sock").exists()
    value = {
        "schema_version": 1,
        "qemu_executable": qemu,
        "docker_executable": docker,
        "docker_socket_present": socket,
        "non_root_account": os.getuid() != 0,
        "kvm_present": Path("/dev/kvm").exists(),
        "boot_artifacts_approved": False,
        "containment_verified": False,
    }
    print(json.dumps(value, sort_keys=True))
    return 0 if qemu and docker and socket and os.getuid() != 0 else 2


if __name__ == "__main__":
    raise SystemExit(main())
