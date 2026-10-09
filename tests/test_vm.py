import hashlib
import io
import json
import os
import sys

import pytest

from honeypot_grid.policy import Rejected, canonical
from honeypot_grid.process import bounded_run
from honeypot_grid.vm import INPUT_HEADER, MAGIC, POLICY, VMJobs, result_metadata
from honeypot_grid.vm_guest import read_frame


@pytest.fixture
def artifacts(tmp_path):
    for name in ("kernel", "initrd", "sample"):
        path = tmp_path / name
        path.write_bytes(("harmless-" + name).encode())
        path.chmod(0o600)
    manifest = {
        "operator": "lab-owner",
        "authorization_ref": "synthetic-only",
        "dedicated_lab_vm": True,
        "no_production_routes": True,
        "no_host_credentials": True,
    }
    for name in ("kernel", "initrd"):
        manifest[name] = str(tmp_path / name)
        manifest[name + "_sha256"] = hashlib.sha256((tmp_path / name).read_bytes()).hexdigest()
    scope = {
        name: manifest[name]
        for name in ("operator", "authorization_ref", "kernel_sha256", "initrd_sha256")
    }
    return tmp_path / "sample", manifest, scope


class GuestRunner:
    def __init__(self, mutation=None, failure=False):
        self.mutation = mutation or {}
        self.failure = failure
        self.calls = []
        self.fds = []

    def __call__(self, argv, **kwargs):
        self.calls.append(argv)
        self.fds = list(kwargs["pass_fds"])
        assert kwargs["timeout"] == 30 and kwargs["output_limit"] == 65536
        assert kwargs["vm_limits"] is True
        for fd in self.fds:
            with pytest.raises(PermissionError):
                os.pwrite(fd, b"changed", 0)
        if self.failure:
            raise Rejected("synthetic VM timeout")
        frame = os.pread(self.fds[-1], 1049088, 0)
        data, nonce = read_frame(io.BytesIO(frame))
        result = {
            "version": 1,
            "nonce": nonce,
            "status": "ok",
            "network_devices": 0,
            "metadata": {
                "sha256": hashlib.sha256(data).hexdigest(),
                "bytes": len(data),
                "kind": "opaque",
                "members": 0,
                "expanded_bytes": 0,
            },
        }
        result.update(self.mutation)
        return b"HPG/1 " + canonical(result).encode() + b"\n"


def prepared(tmp_path, artifacts, runner, clock=lambda: 1000):
    sample, manifest, scope = artifacts
    jobs = VMJobs(tmp_path / "jobs.sqlite3", clock, runner)
    item = jobs.prepare(sample, manifest, scope)
    return jobs, item["job_hash"]


def test_vm_fixed_isolation_flags_opaque_sealed_input_and_single_use(tmp_path, artifacts):
    runner = GuestRunner()
    jobs, digest = prepared(tmp_path, artifacts, runner)
    try:
        assert runner.calls == []
        with pytest.raises(Rejected):
            jobs.run(digest, "lab-owner")
        with pytest.raises(Rejected):
            jobs.approve(digest, "other-owner")
        jobs.approve(digest, "lab-owner")
        result = jobs.run(digest, "lab-owner")
        assert result["state"] == "completed"
        assert result["metadata"]["sha256"] == hashlib.sha256(artifacts[0].read_bytes()).hexdigest()
        argv = runner.calls[0]
        assert argv[argv.index("-nic") + 1] == "none"
        assert argv[argv.index("-monitor") + 1] == "none"
        assert argv[argv.index("-accel") + 1].startswith("tcg,")
        assert "accel=" not in argv[argv.index("-machine") + 1]
        assert "format=raw,readonly=on" in argv[argv.index("-drive") + 1]
        assert "spawn=deny" in argv[argv.index("-sandbox") + 1]
        assert not any(x in argv for x in ("-netdev", "-virtfs", "-fsdev", "-usb", "-daemonize"))
        for fd in runner.fds:
            with pytest.raises(OSError):
                os.fstat(fd)
        with pytest.raises(Rejected):
            jobs.run(digest, "lab-owner")
        with pytest.raises(Rejected):
            jobs.approve(digest, "lab-owner")
    finally:
        jobs.close()


@pytest.mark.parametrize(
    "change",
    [
        {"nonce": "0" * 64},
        {"version": True},
        {"network_devices": 1},
        {"metadata": {"payload": "canary"}},
        {"status": "rejected"},
    ],
)
def test_vm_untrusted_result_failure_consumes_approval_and_closes_fds(tmp_path, artifacts, change):
    runner = GuestRunner(change)
    jobs, digest = prepared(tmp_path, artifacts, runner)
    try:
        jobs.approve(digest, "lab-owner")
        with pytest.raises(Rejected):
            jobs.run(digest, "lab-owner")
        assert jobs.db.execute("SELECT state, approved FROM vm_jobs").fetchone() == ("failed", 0)
        for fd in runner.fds:
            with pytest.raises(OSError):
                os.fstat(fd)
    finally:
        jobs.close()


@pytest.mark.parametrize("name", ["sample", "kernel", "initrd"])
def test_vm_rechecks_sample_and_boot_artifacts_after_approval(tmp_path, artifacts, name):
    runner = GuestRunner()
    jobs, digest = prepared(tmp_path, artifacts, runner)
    try:
        jobs.approve(digest, "lab-owner")
        (tmp_path / name).write_bytes(b"changed-after-approval")
        with pytest.raises(Rejected):
            jobs.run(digest, "lab-owner")
        assert runner.calls == []
        assert jobs.db.execute("SELECT state FROM vm_jobs").fetchone() == ("failed",)
    finally:
        jobs.close()


def test_vm_expiry_rollback_tamper_and_timeout(tmp_path, artifacts):
    now = [1000]
    jobs, digest = prepared(tmp_path, artifacts, GuestRunner(failure=True), lambda: now[0])
    try:
        jobs.approve(digest, "lab-owner", ttl=1)
        now[0] = 1001
        with pytest.raises(Rejected):
            jobs.run(digest, "lab-owner")
        now[0] = 1000
        with pytest.raises(Rejected):
            jobs.run(digest, "lab-owner")
        now[0] = 1002
        fresh = jobs.prepare(*artifacts)
        jobs.approve(fresh["job_hash"], "lab-owner")
        with pytest.raises(Rejected):
            jobs.run(fresh["job_hash"], "lab-owner")
        assert jobs.db.execute(
            "SELECT state FROM vm_jobs WHERE hash=?", (fresh["job_hash"],)
        ).fetchone() == ("failed",)
        other = jobs.prepare(*artifacts)
        content = json.loads(
            jobs.db.execute(
                "SELECT content FROM vm_jobs WHERE hash=?", (other["job_hash"],)
            ).fetchone()[0]
        )
        content["policy"]["network"] = "host"
        with jobs.db:
            jobs.db.execute(
                "UPDATE vm_jobs SET content=? WHERE hash=?", (canonical(content), other["job_hash"])
            )
        with pytest.raises(Rejected):
            jobs.approve(other["job_hash"], "lab-owner")
    finally:
        jobs.close()


@pytest.mark.parametrize(
    "mutation",
    [
        {"dedicated_lab_vm": False},
        {"kernel_sha256": "0" * 64},
        {"kernel": "/tmp/not-a-boot-artifact"},
        {"command": "shell"},
    ],
)
def test_vm_scope_and_manifest_rejection(tmp_path, artifacts, mutation):
    sample, manifest, scope = artifacts
    jobs = VMJobs(tmp_path / "jobs.sqlite3", lambda: 1000, GuestRunner())
    try:
        with pytest.raises((Rejected, OSError)):
            jobs.prepare(sample, manifest | mutation, scope)
        assert jobs.db.execute("SELECT count(*) FROM vm_jobs").fetchone() == (0,)
    finally:
        jobs.close()


def test_vm_frame_and_result_bounds():
    nonce = b"n" * 32
    data = b"harmless"
    frame = INPUT_HEADER.pack(MAGIC, len(data), hashlib.sha256(data).digest(), nonce) + data
    assert read_frame(io.BytesIO(frame)) == (data, nonce.hex())
    for invalid in (frame[:-1], b"changed!" + frame[8:], frame[: INPUT_HEADER.size] + b"different"):
        with pytest.raises(Rejected):
            read_frame(io.BytesIO(invalid))
    with pytest.raises(Rejected):
        result_metadata(b"x" * (POLICY["max_output_bytes"] + 1), nonce.hex(), {})
    with pytest.raises(Rejected):
        result_metadata(b'HPG/1 {"version":1,"version":1}\n', nonce.hex(), {})


def test_actual_process_output_deadline_and_environment_bounds():
    argv = [sys.executable, "-I", "-c"]
    output = bounded_run(argv + ["import os; print(sorted(os.environ))"], timeout=2)
    assert b"TOKEN" not in output and b"SECRET" not in output
    with pytest.raises(Rejected, match="output limit"):
        bounded_run(argv + ["print('x' * 10000)"], timeout=2, output_limit=512)
    with pytest.raises(Rejected, match="deadline"):
        bounded_run(argv + ["import time; time.sleep(3)"], timeout=1)
    with pytest.raises(Rejected):
        bounded_run(argv + ["raise SystemExit(2)"], timeout=2)
