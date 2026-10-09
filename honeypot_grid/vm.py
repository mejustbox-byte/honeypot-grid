"""Opt-in disposable QEMU metadata VM. Boot artifacts and lab host are trusted.

No sample format parser runs here. Approval is consumed before external effects;
failed/running jobs cannot be retried with an old approval. Real acceptance is a
separate gate from the injected-runner tests.
"""

import fcntl
import hashlib
import json
import os
import secrets
import stat
import struct
import sys
import time
from contextlib import ExitStack
from pathlib import Path

from .policy import Rejected, canonical, digest_identifier, fields, identifier, integer, plan_hash
from .quarantine import MAX_FILE
from .storage import checkpoint, connect, private_file

INPUT_HEADER = struct.Struct("!8sI32s32s")
MAGIC = b"HPGINP01"
POLICY = {
    "protocol": 1,
    "network": "none",
    "memory_mib": 256,
    "vcpus": 1,
    "max_seconds": 30,
    "max_output_bytes": 65536,
    "max_input_bytes": MAX_FILE,
    "host_mounts": False,
    "credentials": False,
    "accelerator": "tcg",
}


def bounded_file(path, maximum):
    fd = private_file(Path(path))
    with os.fdopen(fd, "rb") as stream:
        value = stream.read(maximum + 1)
    if len(value) > maximum:
        raise Rejected("VM input limit exceeded")
    return value


def sealed(data):
    if sys.platform != "linux":
        raise Rejected("Linux sealed input required")
    fd = os.memfd_create("hpg-vm", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    try:
        with os.fdopen(os.dup(fd), "wb") as stream:
            stream.write(data)
        os.lseek(fd, 0, os.SEEK_SET)
        fcntl.fcntl(
            fd,
            # Linux UAPI constants; some standalone CPython builds omit exports.
            getattr(fcntl, "F_ADD_SEALS", 1033),
            0x000F,  # SEAL_SEAL | SEAL_SHRINK | SEAL_GROW | SEAL_WRITE
        )
        if fcntl.fcntl(fd, getattr(fcntl, "F_GET_SEALS", 1034)) & 0x000F != 0x000F:
            raise Rejected("immutable VM input required")
        return fd
    except BaseException:
        os.close(fd)
        raise


def manifest_policy(manifest, scope):
    fields(
        manifest,
        {
            "operator",
            "authorization_ref",
            "dedicated_lab_vm",
            "no_production_routes",
            "no_host_credentials",
            "kernel",
            "initrd",
            "kernel_sha256",
            "initrd_sha256",
        },
    )
    fields(scope, {"operator", "authorization_ref", "kernel_sha256", "initrd_sha256"})
    for name in ("operator", "authorization_ref"):
        identifier(manifest[name])
        if manifest[name] != scope[name]:
            raise Rejected("VM outside authorized scope")
    for name in ("dedicated_lab_vm", "no_production_routes", "no_host_credentials"):
        if manifest[name] is not True:
            raise Rejected("dedicated VM attestation required")
    for name in ("kernel_sha256", "initrd_sha256"):
        digest_identifier(manifest[name])
        if manifest[name] != scope[name]:
            raise Rejected("boot artifact outside allowlist")
    for name in ("kernel", "initrd"):
        if type(manifest[name]) is not str or len(manifest[name]) > 4096:
            raise Rejected("invalid boot artifact path")
        if not Path(manifest[name]).is_absolute():
            raise Rejected("absolute private boot artifact path required")
    return manifest


def boot_data(manifest):
    result = []
    for name, maximum in (("kernel", 64 * 1024**2), ("initrd", 128 * 1024**2)):
        data = bounded_file(manifest[name], maximum)
        if not data or hashlib.sha256(data).hexdigest() != manifest[name + "_sha256"]:
            raise Rejected("boot artifact integrity mismatch")
        result.append(data)
    return result


def qemu_argv(kernel_fd, initrd_fd, sample_fd):
    # Fixed devices and args only. Input is raw; never autodetect image formats.
    return [
        "/usr/bin/qemu-system-x86_64",
        "-no-user-config",
        "-nodefaults",
        "-machine",
        "q35,mem-merge=off,dump-guest-core=off,vmport=off",
        "-accel",
        "tcg,thread=single,tb-size=16",
        "-m",
        "256",
        "-smp",
        "1",
        "-nic",
        "none",
        "-display",
        "none",
        "-monitor",
        "none",
        "-serial",
        "stdio",
        "-no-reboot",
        "-sandbox",
        "on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny",
        "-kernel",
        f"/proc/self/fd/{kernel_fd}",
        "-initrd",
        f"/proc/self/fd/{initrd_fd}",
        "-append",
        "console=ttyS0 quiet loglevel=0 panic=1 rdinit=/init",
        "-add-fd",
        f"fd={sample_fd},set=1",
        "-drive",
        "file=/dev/fdset/1,if=none,id=input,format=raw,readonly=on",
        "-device",
        "virtio-blk-pci,drive=input",
    ]


def result_metadata(output, nonce, sample):
    if type(output) is not bytes or len(output) > POLICY["max_output_bytes"]:
        raise Rejected("VM result limit exceeded")
    frames = [line[6:] for line in output.splitlines() if line.startswith(b"HPG/1 ")]
    if len(frames) != 1:
        raise Rejected("VM result framing rejected")
    from .transport import parse_line

    result = parse_line(frames[0] + b"\n")
    fields(result, {"version", "nonce", "status", "metadata", "network_devices"})
    if (
        type(result["version"]) is not int
        or result["version"] != 1
        or result["nonce"] != nonce
        or type(result["network_devices"]) is not int
        or result["network_devices"] != 0
    ):
        raise Rejected("VM result binding rejected")
    if result["status"] != "ok":
        raise Rejected("VM metadata worker rejected input")
    metadata = fields(result["metadata"], {"sha256", "bytes", "kind", "members", "expanded_bytes"})
    if (
        metadata["sha256"] != sample["sha256"]
        or type(metadata["bytes"]) is not int
        or metadata["bytes"] != sample["bytes"]
    ):
        raise Rejected("VM result sample mismatch")
    integer(metadata["members"], 0, 100)
    integer(metadata["expanded_bytes"], 0, 8 * MAX_FILE)
    if metadata["kind"] not in ("opaque", "zip"):
        raise Rejected("unsupported VM metadata")
    if metadata["kind"] == "opaque" and (metadata["members"] or metadata["expanded_bytes"]):
        raise Rejected("invalid opaque metadata")
    return dict(metadata)


class VMJobs:
    def __init__(self, database, clock=None, runner=None):
        self.db = connect(database)
        self.clock = clock or (lambda: int(time.time()))
        self.runner = runner
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS vm_jobs (
              hash TEXT PRIMARY KEY, content TEXT NOT NULL, owner TEXT NOT NULL,
              expires INTEGER NOT NULL, approved INTEGER NOT NULL DEFAULT 0,
              approval_expires INTEGER NOT NULL DEFAULT 0, state TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS vm_audit (
              sequence INTEGER PRIMARY KEY, at INTEGER NOT NULL,
              job_hash TEXT NOT NULL, action TEXT NOT NULL
            );
        """)

    def close(self):
        self.db.close()

    def prepare(self, sample, manifest, scope):
        manifest_policy(manifest, scope)
        boot_data(manifest)  # Validate approved artifacts; do not boot in dry-run.
        sample = Path(sample).absolute()
        data = bounded_file(sample, MAX_FILE)
        now = checkpoint(self.db, self.clock)
        plan = {
            "version": 1,
            "manifest": manifest,
            "scope": scope,
            "sample_path": str(sample),
            "sample": {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)},
            "policy": dict(POLICY),
            "created_at": now,
            "expires_at": now + 300,
            "nonce": secrets.token_hex(32),
        }
        digest = plan_hash(plan)
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            if self.db.execute("SELECT count(*) FROM vm_jobs").fetchone()[0] >= 1000:
                raise Rejected("VM job quota exceeded")
            self.db.execute(
                "INSERT INTO vm_jobs(hash, content, owner, expires, state) "
                "VALUES (?, ?, ?, ?, 'planned')",
                (digest, canonical(plan), manifest["operator"], now + 300),
            )
            self.db.execute(
                "INSERT INTO vm_audit(at, job_hash, action) VALUES (?, ?, 'planned')", (now, digest)
            )
        return {
            "job_hash": digest,
            "dry_run": True,
            "sample": plan["sample"],
            "policy": dict(POLICY),
            "expires_at": now + 300,
        }

    def _job(self, digest, operator, now):
        digest_identifier(digest)
        identifier(operator)
        row = self.db.execute(
            "SELECT content, owner, expires, approved, approval_expires, state "
            "FROM vm_jobs WHERE hash=?",
            (digest,),
        ).fetchone()
        if not row or row[1] != operator or row[2] <= now or row[5] != "planned":
            raise Rejected("VM job unavailable")
        try:
            plan = json.loads(row[0])
            if (
                plan_hash(plan) != digest
                or plan["policy"] != POLICY
                or plan["manifest"]["operator"] != operator
            ):
                raise Rejected("VM plan tampered")
            manifest_policy(plan["manifest"], plan["scope"])
        except (ValueError, TypeError, KeyError, RecursionError) as exc:
            raise Rejected("VM plan tampered") from exc
        return row, plan

    def approve(self, digest, operator, ttl=300):
        integer(ttl, 1, 300)
        now = checkpoint(self.db, self.clock)
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            row, _ = self._job(digest, operator, now)
            if row[3]:
                raise Rejected("VM approval already issued")
            self.db.execute(
                "UPDATE vm_jobs SET approved=1, approval_expires=? WHERE hash=?",
                (min(row[2], now + ttl), digest),
            )
            self.db.execute(
                "INSERT INTO vm_audit(at, job_hash, action) VALUES (?, ?, 'approved')",
                (now, digest),
            )

    def run(self, digest, operator):
        now = checkpoint(self.db, self.clock)
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            row, plan = self._job(digest, operator, now)
            if row[3] != 1 or row[4] <= now:
                raise Rejected("live VM approval required")
            self.db.execute(
                "UPDATE vm_jobs SET approved=0, state='running' WHERE hash=?", (digest,)
            )
            self.db.execute(
                "INSERT INTO vm_audit(at, job_hash, action) VALUES (?, ?, 'started')", (now, digest)
            )
        try:
            if self.runner is None:
                info = os.stat("/usr/bin/qemu-system-x86_64", follow_symlinks=False)
                if (
                    os.getuid() == 0
                    or not stat.S_ISREG(info.st_mode)
                    or info.st_uid != 0
                    or info.st_mode & 0o6022
                ):
                    raise Rejected("non-root lab account and trusted QEMU required")
            kernel, initrd = boot_data(plan["manifest"])
            data = bounded_file(plan["sample_path"], MAX_FILE)
            if (
                len(data) != plan["sample"]["bytes"]
                or hashlib.sha256(data).hexdigest() != plan["sample"]["sha256"]
            ):
                raise Rejected("sample integrity mismatch")
            frame = (
                INPUT_HEADER.pack(
                    MAGIC,
                    len(data),
                    bytes.fromhex(plan["sample"]["sha256"]),
                    bytes.fromhex(plan["nonce"]),
                )
                + data
            )
            frame += b"\0" * (-len(frame) % 512)
            from .process import bounded_run

            with ExitStack() as stack:
                fds = []
                for value in (kernel, initrd, frame):
                    fd = sealed(value)
                    stack.callback(os.close, fd)
                    fds.append(fd)
                current = checkpoint(self.db, self.clock)
                if current >= min(row[2], row[4]):
                    raise Rejected("VM approval expired before launch")
                output = (self.runner or bounded_run)(
                    qemu_argv(*fds),
                    pass_fds=tuple(fds),
                    timeout=POLICY["max_seconds"],
                    output_limit=POLICY["max_output_bytes"],
                    vm_limits=True,
                )
                metadata = result_metadata(output, plan["nonce"], plan["sample"])
            self._finish(digest, "completed")
            return {
                "job_hash": digest,
                "state": "completed",
                "requires_review": True,
                "metadata": metadata,
                "boundary": "disposable-vm",
            }
        except BaseException:
            self._finish(digest, "failed")
            raise

    def _finish(self, digest, state):
        now = checkpoint(self.db, self.clock, allow_rollback=True)
        with self.db:
            self.db.execute("UPDATE vm_jobs SET state=? WHERE hash=?", (state, digest))
            self.db.execute(
                "INSERT INTO vm_audit(at, job_hash, action) VALUES (?, ?, ?)", (now, digest, state)
            )
