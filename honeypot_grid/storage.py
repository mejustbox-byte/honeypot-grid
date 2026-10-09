"""Private local files: trusted owner and non-writable parent boundary."""

import os
import sqlite3
import stat
from pathlib import Path

from .policy import Rejected, integer


def private_parent(path: Path):
    parent = path.parent.resolve(strict=True)
    info = parent.stat()
    if info.st_uid != os.getuid() or info.st_mode & 0o022:
        raise Rejected("untrusted storage directory")
    if path.parent.absolute() != parent:
        raise Rejected("symlink storage directory")


def private_file(path: Path, create: bool = False) -> int:
    private_parent(path)
    flags = os.O_RDWR if create else os.O_RDONLY
    if create:
        flags |= os.O_CREAT
    fd = os.open(path, flags | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    info = os.fstat(fd)
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.getuid()
        or info.st_mode & 0o077
        or info.st_nlink != 1
    ):
        os.close(fd)
        raise Rejected("private regular file required")
    return fd


def connect(path: Path) -> sqlite3.Connection:
    fd = private_file(path, create=True)
    os.close(fd)
    db = sqlite3.connect(path, timeout=5)
    db.execute("PRAGMA foreign_keys=ON")
    db.execute("PRAGMA secure_delete=ON")
    db.execute("PRAGMA journal_mode=DELETE")
    db.execute("PRAGMA max_page_count=16384")  # 64 MiB with default 4 KiB pages
    db.executescript("""
        CREATE TABLE IF NOT EXISTS clock_state (
          singleton INTEGER PRIMARY KEY CHECK(singleton=1), highwater INTEGER NOT NULL
        );
        INSERT OR IGNORE INTO clock_state VALUES (1, 0);
    """)
    return db


def checkpoint(db, clock, allow_rollback=False):
    with db:
        db.execute("BEGIN IMMEDIATE")
        now = integer(clock(), 0, 2**53)
        previous = db.execute("SELECT highwater FROM clock_state WHERE singleton=1").fetchone()[0]
        if now < previous and not allow_rollback:
            raise Rejected("clock rollback detected")
        now = max(now, previous)
        db.execute("UPDATE clock_state SET highwater=? WHERE singleton=1", (now,))
        return now


def read_key(path: Path) -> bytes:
    fd = private_file(path)
    with os.fdopen(fd, "rb") as stream:
        key = stream.read(65)
    if len(key) != 32:
        raise Rejected("32-byte key required")
    return key
