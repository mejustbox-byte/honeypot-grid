"""Presence-only development capability report; never claims containment or lists env values."""

import json
import os
import shutil
import stat
from pathlib import Path


def main():
    docker = Path("/usr/bin/docker")
    socket = Path("/var/run/docker.sock")
    kvm = Path("/dev/kvm")
    try:
        socket_present = stat.S_ISSOCK(socket.stat().st_mode)
    except OSError:
        socket_present = False
    report = {
        "profile": "development-only",
        "docker_cli_at_required_path": docker.is_file() and os.access(docker, os.X_OK),
        "docker_socket_present": socket_present,
        "kvm_device_present": kvm.exists(),
        "qemu_system_x86_64_present": shutil.which("qemu-system-x86_64") is not None,
        "cgroup_v2_present": Path("/sys/fs/cgroup/cgroup.controllers").is_file(),
        "lab_containment_verified": False,
        "vm_sample_executor_available": False,
        "services_started": False,
    }
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
