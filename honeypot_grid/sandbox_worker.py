"""Static metadata worker for a disposable no-network VM; never a host sandbox.

This module is intentionally absent from the main CLI. OS limits below are defense
in depth. An external VM launcher must enforce the trust boundary and destroy the VM.
"""

import hashlib
import io
import resource
import stat
import zipfile
from pathlib import PurePosixPath

from .policy import Rejected
from .quarantine import MAX_FILE


def static_metadata(data: bytes) -> dict:
    if type(data) is not bytes or len(data) > MAX_FILE:
        raise Rejected("bounded sample required")
    result = {
        "sha256": hashlib.sha256(data).hexdigest(),
        "bytes": len(data),
        "kind": "opaque",
        "members": 0,
        "expanded_bytes": 0,
    }
    if not data.startswith(b"PK"):
        return result
    result["kind"] = "zip"
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            members = archive.infolist()
            if len(members) > 100:
                raise Rejected("archive member limit exceeded")
            total, names = 0, set()
            for member in members:
                name = member.filename
                parts = PurePosixPath(name).parts
                mode = member.external_attr >> 16
                if (
                    not name
                    or len(name) > 256
                    or name.startswith("/")
                    or "\\" in name
                    or ":" in name
                    or ".." in parts
                    or len(parts) > 8
                    or any(ord(c) < 32 for c in name)
                    or name in names
                    or stat.S_ISLNK(mode)
                    or member.flag_bits & 1
                    or (stat.S_IFMT(mode) not in (0, stat.S_IFREG, stat.S_IFDIR))
                ):
                    raise Rejected("unsafe archive metadata")
                if name.lower().endswith((".zip", ".tar", ".gz", ".7z", ".rar")):
                    raise Rejected("nested archive rejected")
                names.add(name)
                total += member.file_size
                if total > 8 * MAX_FILE or member.file_size > 20 * max(1, member.compress_size):
                    raise Rejected("archive expansion limit exceeded")
                if member.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
                    raise Rejected("unsupported archive compression")
            result.update(members=len(members), expanded_bytes=total)
        # No extraction, decompression, member contents or filenames returned.
        return result
    except (zipfile.BadZipFile, UnicodeError, ValueError) as exc:
        raise Rejected("invalid archive") from exc


def limits():
    resource.setrlimit(resource.RLIMIT_CPU, (2, 2))
    resource.setrlimit(resource.RLIMIT_AS, (128 * MAX_FILE, 128 * MAX_FILE))
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_FILE, MAX_FILE))
    resource.setrlimit(resource.RLIMIT_NOFILE, (16, 16))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
