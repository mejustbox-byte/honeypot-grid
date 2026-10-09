import hashlib
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

from honeypot_grid.policy import Rejected
from scripts.build_vm_initramfs import BINARIES, build


def manifest(tmp_path):
    rows = []
    for index, name in enumerate(sorted(BINARIES)):
        source = tmp_path / f"vendor-{index}"
        source.write_bytes(b"harmless vendor artifact placeholder")
        source.chmod(0o600)
        rows.append(
            {
                "source": str(source),
                "target": name,
                "sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                "executable": True,
            }
        )
    return {"credentials_absent": True, "files": rows}


def parse_cpio(data):
    offset = 0
    result = {}
    while True:
        assert data[offset : offset + 6] == b"070701"
        header = [int(data[offset + 6 + i * 8 : offset + 14 + i * 8], 16) for i in range(13)]
        mode, size, namesize = header[1], header[6], header[11]
        offset += 110
        name = data[offset : offset + namesize - 1].decode()
        offset += namesize
        offset += -offset % 4
        value = data[offset : offset + size]
        offset += size
        offset += -offset % 4
        if name == "TRAILER!!!":
            return result
        assert header[2:4] == [0, 0] and header[5] == 0
        result[name] = (mode, value)


def test_deterministic_reviewed_guest_image_has_only_fixed_init_and_code(tmp_path):
    config = manifest(tmp_path)
    image = build(config)
    assert image == build(config)
    assert len(image) % 512 == 0
    files = parse_cpio(image)
    assert files["init"][0] == 0o100755
    assert b"setpriv" in files["init"][1] and b"poweroff -f" in files["init"][1]
    assert "opt/honeypot_grid/vm_guest.py" in files
    assert not any(name.startswith(("home/", "root/", "etc/")) for name in files)


@pytest.mark.parametrize(
    "target",
    ["../init", "/init", "etc/token", "bin/shell", "usr/lib/../secret", "usr/lib//duplicate"],
)
def test_guest_builder_rejects_escape_and_unapproved_paths(tmp_path, target):
    config = manifest(tmp_path)
    config["files"][0]["target"] = target
    with pytest.raises(Rejected):
        build(config)


def test_guest_builder_rejects_hash_symlink_and_secret_declaration(tmp_path):
    config = manifest(tmp_path)
    with pytest.raises(Rejected):
        build(config | {"credentials_absent": False})
    original = config["files"][0]["source"]
    config["files"][0]["sha256"] = "0" * 64
    with pytest.raises(Rejected):
        build(config)
    config = manifest(tmp_path)
    link = tmp_path / "link"
    link.symlink_to(original)
    config["files"][0]["source"] = str(link)
    with pytest.raises(OSError):
        build(config)


def test_actual_parent_death_terminates_bounded_child(tmp_path):
    pidfile = tmp_path / "child.pid"
    child = (
        "import os,time; from pathlib import Path; "
        + f"Path({str(pidfile)!r}).write_text(str(os.getpid())); time.sleep(30)"
    )
    parent_code = (
        "import sys; from honeypot_grid.process import bounded_run; "
        f"bounded_run([sys.executable, '-I', '-c', {child!r}], timeout=30)"
    )
    root = Path(__file__).resolve().parents[1]
    parent = subprocess.Popen(
        [sys.executable, "-c", parent_code],
        cwd=root,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    child_pid = None
    try:
        deadline = time.monotonic() + 5
        while not pidfile.exists() and time.monotonic() < deadline:
            time.sleep(0.02)
        assert pidfile.exists()
        child_pid = int(pidfile.read_text())
        parent.kill()
        parent.wait(timeout=5)
        while time.monotonic() < deadline:
            status = Path(f"/proc/{child_pid}/stat")
            if not status.exists() or status.read_text().split()[2] == "Z":
                break
            time.sleep(0.02)
        else:
            pytest.fail("child survived parent death")
    finally:
        if parent.poll() is None:
            parent.kill()
            parent.wait(timeout=5)
        if child_pid:
            try:
                os.kill(child_pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
