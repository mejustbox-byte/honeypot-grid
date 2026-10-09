"""Pack only reviewed local guest boot files. No downloads or sample processing.

Input manifest: credentials_absent=true, files=[{source,target,sha256,executable}].
Use explicit private regular copies of vendor binaries/dependencies; no symlinks,
devices, homes, config files or arbitrary boot scripts. Output is deterministic newc.
"""

import argparse
import hashlib
import os
from pathlib import Path, PurePosixPath

from honeypot_grid.policy import Rejected, digest_identifier, fields, load_json
from honeypot_grid.storage import private_file, private_parent

ROOT = Path(__file__).resolve().parents[1]
MAX_IMAGE = 128 * 1024**2
BINARIES = {"bin/busybox", "usr/bin/python3", "usr/bin/setpriv"}


def entry(name, data, mode, number):
    encoded = name.encode() + b"\0"
    values = [number, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(encoded), 0]
    header = b"070701" + b"".join(f"{value:08x}".encode() for value in values)
    prefix = header + encoded
    prefix += b"\0" * (-len(prefix) % 4)
    return prefix + data + b"\0" * (-len(data) % 4)


def build(manifest):
    fields(manifest, {"credentials_absent", "files"})
    if manifest["credentials_absent"] is not True:
        raise Rejected("reviewed secret-free guest tree required")
    rows = manifest["files"]
    if type(rows) is not list or not 3 <= len(rows) <= 1000:
        raise Rejected("bounded guest manifest required")
    files = {}
    total = 0
    for row in rows:
        fields(row, {"source", "target", "sha256", "executable"})
        name = row["target"]
        if type(name) is not str or len(name) > 256 or not name.isascii():
            raise Rejected("invalid guest path")
        parts = PurePosixPath(name).parts
        if (
            not parts
            or any(p in (".", "..") for p in parts)
            or name.startswith("/")
            or name != "/".join(parts)
            or "\\" in name
            or ":" in name
            or any(ord(c) < 32 for c in name)
            or name in files
        ):
            raise Rejected("invalid guest path")
        library = name.startswith(("lib/", "lib64/", "usr/lib/", "usr/lib64/"))
        if name not in BINARIES and not library:
            raise Rejected("guest file outside boot allowlist")
        if type(row["executable"]) is not bool or type(row["source"]) is not str:
            raise Rejected("invalid guest file declaration")
        digest_identifier(row["sha256"])
        if not Path(row["source"]).is_absolute():
            raise Rejected("absolute private source required")
        fd = private_file(Path(row["source"]))
        with os.fdopen(fd, "rb") as stream:
            data = stream.read(MAX_IMAGE - total + 1)
        total += len(data)
        if total > MAX_IMAGE or not data or hashlib.sha256(data).hexdigest() != row["sha256"]:
            raise Rejected("guest artifact integrity or size mismatch")
        files[name] = (data, 0o100755 if row["executable"] else 0o100644)
    if not BINARIES <= files.keys() or any(files[name][1] != 0o100755 for name in BINARIES):
        raise Rejected("guest executables missing")
    files["init"] = ((ROOT / "lab/vm-init").read_bytes(), 0o100755)
    for path in sorted((ROOT / "honeypot_grid").glob("*.py")):
        files["opt/honeypot_grid/" + path.name] = (path.read_bytes(), 0o100644)
    directories = {"proc", "sys", "dev", "opt"}
    for name in files:
        parent = PurePosixPath(name).parent
        while str(parent) != ".":
            directories.add(str(parent))
            parent = parent.parent
    if directories & files.keys():
        raise Rejected("guest file/directory collision")
    output = bytearray()
    number = 1
    for name in sorted(directories, key=lambda value: (value.count("/"), value)):
        output.extend(entry(name, b"", 0o040755, number))
        number += 1
    for name, (data, mode) in sorted(files.items()):
        output.extend(entry(name, data, mode, number))
        number += 1
    output.extend(entry("TRAILER!!!", b"", 0, number))
    output.extend(b"\0" * (-len(output) % 512))
    if len(output) > MAX_IMAGE:
        raise Rejected("guest image size limit exceeded")
    return bytes(output)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        data = build(load_json(args.manifest))
        private_parent(args.output)
        fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        print(hashlib.sha256(data).hexdigest())
        return 0
    except Rejected, OSError:
        print("REJECTED: invalid guest manifest or unavailable private output")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
