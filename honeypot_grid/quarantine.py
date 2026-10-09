"""Bounded opaque copying only. File parsing belongs inside a separate VM."""

import fcntl
import hashlib
import os
import secrets
import stat
import time
from pathlib import Path

from .policy import Rejected, integer
from .storage import private_file, private_parent

MAX_FILE = 1_048_576
MAX_FILES = 100


def quarantine(source: Path, directory: Path) -> dict:
    private_parent(directory)
    if directory.is_symlink():
        raise Rejected("symlink quarantine directory")
    directory.mkdir(mode=0o700, exist_ok=True)
    info = directory.stat()
    if info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise Rejected("private quarantine directory required")
    lock_fd = private_file(directory / ".lock", create=True)
    try:
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise Rejected("quarantine busy") from exc
        if len([p for p in directory.iterdir() if p.name != ".lock"]) >= MAX_FILES:
            raise Rejected("quarantine quota exceeded")
        return _copy(source, directory)
    finally:
        os.close(lock_fd)


def _copy(source, directory):
    fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_FILE:
        os.close(fd)
        raise Rejected("bounded regular sample required")
    temporary = directory / ("pending-" + secrets.token_hex(16))
    digest, size = hashlib.sha256(), 0
    try:
        with os.fdopen(fd, "rb") as input_stream:
            destination_fd = os.open(
                temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
            )
            with os.fdopen(destination_fd, "wb") as output:
                while block := input_stream.read(65536):
                    size += len(block)
                    if size > MAX_FILE:
                        raise Rejected("sample size limit exceeded")
                    digest.update(block)
                    output.write(block)
                output.flush()
                os.fsync(output.fileno())
        name = digest.hexdigest()
        target = directory / name
        try:
            os.link(temporary, target, follow_symlinks=False)
        except FileExistsError:
            existing_fd = private_file(target)
            with os.fdopen(existing_fd, "rb") as existing:
                value = existing.read(MAX_FILE + 1)
            if len(value) != size or hashlib.sha256(value).hexdigest() != name:
                raise Rejected("quarantine integrity failure") from None
        return {"sha256": name, "bytes": size, "requires_vm_analysis": True}
    finally:
        temporary.unlink(missing_ok=True)


def sandbox_plan(receipt: dict) -> dict:
    from .policy import fields, integer

    fields(receipt, {"sha256", "bytes", "requires_vm_analysis"})
    if (
        type(receipt["sha256"]) is not str
        or len(receipt["sha256"]) != 64
        or any(c not in "0123456789abcdef" for c in receipt["sha256"])
        or receipt["requires_vm_analysis"] is not True
    ):
        raise Rejected("invalid quarantine receipt")
    integer(receipt["bytes"], 0, MAX_FILE)
    return {
        "sample_sha256": receipt["sha256"],
        "dry_run": True,
        "boundary": "disposable-vm",
        "network": "none",
        "credentials": "none",
        "shared_host_paths": False,
        "max_seconds": 5,
        "memory_mib": 128,
        "max_input_bytes": MAX_FILE,
        "cleanup_required": True,
        "executor_available": False,
    }


def purge_samples(directory: Path, older_than=86400, now=None) -> int:
    integer(older_than, 60, 604800)
    now = integer(int(time.time()) if now is None else now, 0, 2**53)
    private_parent(directory / ".lock")
    if directory.stat().st_mode & 0o077:
        raise Rejected("private quarantine directory required")
    lock_fd = private_file(directory / ".lock", create=True)
    try:
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise Rejected("quarantine busy") from exc
        candidates = []
        for path in directory.iterdir():
            if len(path.name) != 64 or any(c not in "0123456789abcdef" for c in path.name):
                continue
            fd = private_file(path)
            try:
                if os.fstat(fd).st_mtime <= now - older_than:
                    candidates.append(path)
            finally:
                os.close(fd)
        for path in candidates:
            path.unlink()
        return len(candidates)
    finally:
        os.close(lock_fd)
